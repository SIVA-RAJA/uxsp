/**
 * Core Sealing / Cryptographic Packaging
 */
import { UXSPEnvelope, PublicCard } from "./types.js";
import { Identity } from "./identity.js";
import {
  generateX25519KeyPair,
  deriveSharedSecret,
  hkdf,
  aesGcmEncrypt,
  aesGcmDecrypt,
  signEd25519,
  verifyEd25519
} from "./crypto.js";
import {
  encapsulateMLKEM,
  decapsulateMLKEM,
  signMLDSA,
  verifyMLDSA
} from "./pqc.js";
import { encodeBase64, decodeBase64, encodeUTF8, encodeHex, decodeHex } from "./utils.js";

function bindFields(...fields: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const f of fields) totalLen += 4 + f.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const f of fields) {
    new DataView(result.buffer).setUint32(offset, f.length, false); // big-endian
    result.set(f, offset + 4);
    offset += 4 + f.length;
  }
  return result;
}

/**
 * Seal data for a recipient card.
 */
export async function seal(
  sender: Identity,
  recipientCard: PublicCard,
  plaintext: Uint8Array
): Promise<UXSPEnvelope> {
  const timestamp = Math.floor(Date.now() / 1000);
  
  // 1. Generate Ephemeral ECDH Keypair for Forward Secrecy
  const ephemeral = await generateX25519KeyPair();
  
  // 2. Perform ECDH (Ephemeral Priv -> Recipient Pub)
  const sharedX25519 = await deriveSharedSecret(
    ephemeral.privateKey,
    recipientCard.public_keys.exchange_pub
  );

  // 3. Perform ML-KEM Encapsulation (Against Recipient PQC Pub)
  const kemData = await encapsulateMLKEM(recipientCard.public_keys.kem_pub);
  const isPqcStubbed = kemData.ciphertext.length === 32;

  // 4. Combine secrets via HKDF
  const ephemeralPubBytes = decodeBase64(ephemeral.publicKey);
  const salt = ephemeralPubBytes;
  
  // Combine classical and PQC secrets
  let combinedSecret: Uint8Array;
  if (isPqcStubbed) {
    combinedSecret = sharedX25519;
  } else {
    combinedSecret = new Uint8Array(sharedX25519.length + kemData.sharedSecret.length);
    combinedSecret.set(sharedX25519, 0);
    combinedSecret.set(kemData.sharedSecret, sharedX25519.length);
  }

  const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
  const symmetricKey = await hkdf(combinedSecret, salt, info, 32);

  // 5. Encrypt plaintext
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const ad = encodeUTF8(sender.entity_id + recipientCard.entity_id);
  const ciphertext = await aesGcmEncrypt(symmetricKey, nonce, plaintext, ad);

  const envNonceBytes = new Uint8Array(16);
  crypto.getRandomValues(envNonceBytes);
  const envNonceHex = encodeHex(envNonceBytes);

  // 6. Signatures
  // Sign all fields matching Python's bind_fields
  const sigPayload = bindFields(
    encodeUTF8("UXSP-1"),
    ciphertext,
    nonce,
    encodeUTF8(sender.entity_id),
    encodeUTF8(recipientCard.entity_id),
    encodeUTF8(timestamp.toString()),
    encodeUTF8(envNonceHex),
    ephemeralPubBytes,
    isPqcStubbed ? new Uint8Array(0) : kemData.ciphertext
  );

  const classicalSig = await signEd25519(sender.keys.signing.privateKey, sigPayload);
  
  let pqcSig: Uint8Array = new Uint8Array(0);
  if (!isPqcStubbed) {
    pqcSig = await signMLDSA(sender.keys.pqc_sig.privateKey, sigPayload);
  }


  const envelope: any = {
    version: "UXSP-1",
    sender_id: sender.entity_id,
    recipient_id: recipientCard.entity_id,
    timestamp: timestamp,
    envelope_nonce: envNonceHex,
    ciphertext: encodeHex(ciphertext),
    nonce: encodeHex(nonce),
    ephemeral_pub: encodeHex(ephemeralPubBytes),
    classical_sig: encodeHex(classicalSig)
  };

  if (isPqcStubbed) {
    envelope.pqc_mode = "none";
  } else {
    envelope.kem_ciphertext = encodeHex(kemData.ciphertext);
    envelope.pqc_sig = encodeHex(pqcSig);
  }

  return envelope as UXSPEnvelope;
}

const seenNonces = new Set<string>();
const MAX_NONCES = 10000;

/**
 * Open a sealed envelope from a sender.
 */
export async function openSeal(
  receiver: Identity,
  senderCard: PublicCard,
  envelope: UXSPEnvelope
): Promise<Uint8Array> {
  if (envelope.recipient_id !== receiver.entity_id) {
    throw new Error("Envelope is not addressed to this receiver.");
  }
  if (envelope.sender_id !== senderCard.entity_id) {
    throw new Error("Envelope sender_id does not match the provided senderCard.");
  }

  // Replay Protection
  if (seenNonces.has(envelope.envelope_nonce)) {
    throw new Error("ReplayError: Envelope replay detected");
  }
  seenNonces.add(envelope.envelope_nonce);
  if (seenNonces.size > MAX_NONCES) {
    // Basic cleanup: remove the oldest (iterators yield in insertion order)
    const oldest = seenNonces.keys().next().value;
    if (oldest) seenNonces.delete(oldest);
  }

  const ciphertext = decodeHex(envelope.ciphertext);
  const nonce = decodeHex(envelope.nonce);
  
  const pqcMode = (envelope as any).pqc_mode;
  const isPqcStubbed = pqcMode === "none";
  const ephemeralPubBytes = decodeHex(envelope.ephemeral_pub);

  // Verify Signatures
  const sigPayload = bindFields(
    encodeUTF8("UXSP-1"),
    ciphertext,
    nonce,
    encodeUTF8(envelope.sender_id),
    encodeUTF8(envelope.recipient_id),
    encodeUTF8(envelope.timestamp.toString()),
    encodeUTF8(envelope.envelope_nonce),
    ephemeralPubBytes,
    isPqcStubbed ? new Uint8Array(0) : decodeHex(envelope.kem_ciphertext)
  );

  const classicalValid = await verifyEd25519(
    senderCard.public_keys.signing_pub,
    decodeHex(envelope.classical_sig),
    sigPayload
  );

  if (!classicalValid) {
    throw new Error("Classical signature verification failed.");
  }


  if (!isPqcStubbed) {
    if (!envelope.pqc_sig) {
      throw new Error("Envelope is missing PQC signature but is not in classical-only mode.");
    }
    const pqcValid = await verifyMLDSA(
      senderCard.public_keys.pqc_sig_pub,
      decodeHex(envelope.pqc_sig),
      sigPayload
    );

    if (!pqcValid) {
      throw new Error("PQC signature verification failed.");
    }
  }

  // Decapsulate & Derive Key
  const ephemeralPubBase64 = encodeBase64(ephemeralPubBytes);
  const sharedX25519 = await deriveSharedSecret(
    receiver.keys.exchange.privateKey,
    ephemeralPubBase64
  );

  let combinedSecret: Uint8Array;
  if (isPqcStubbed) {
    combinedSecret = sharedX25519;
  } else {
    if (!envelope.kem_ciphertext) {
      throw new Error("Envelope is missing kem_ciphertext but is not in classical-only mode.");
    }
    const kemSharedSecret = await decapsulateMLKEM(
      decodeHex(envelope.kem_ciphertext),
      receiver.keys.kem.privateKey
    );
    combinedSecret = new Uint8Array(sharedX25519.length + kemSharedSecret.length);
    combinedSecret.set(sharedX25519, 0);
    combinedSecret.set(kemSharedSecret, sharedX25519.length);
  }

  const salt = ephemeralPubBytes; // Salt is ephemeral_pub bytes
  const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
  const symmetricKey = await hkdf(combinedSecret, salt, info, 32);

  // Decrypt
  const ad = encodeUTF8(envelope.sender_id + envelope.recipient_id);
  const plaintext = await aesGcmDecrypt(symmetricKey, nonce, ciphertext, ad);
  return plaintext;
}
