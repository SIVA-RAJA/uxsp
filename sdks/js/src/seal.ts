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
  verifyEd25519,
  encodeBase64,
  decodeBase64,
  encodeUTF8
} from "./crypto.js";
import {
  encapsulateMLKEM,
  decapsulateMLKEM,
  signMLDSA,
  verifyMLDSA
} from "./pqc.js";

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

  // 4. Combine secrets via HKDF
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  
  // Combine classical and PQC secrets
  const combinedSecret = new Uint8Array(sharedX25519.length + kemData.sharedSecret.length);
  combinedSecret.set(sharedX25519, 0);
  combinedSecret.set(kemData.sharedSecret, sharedX25519.length);

  const info = encodeUTF8("UXSP-HYBRID-KEY-DERIVATION-V1");
  const symmetricKey = await hkdf(combinedSecret, salt, info, 32);

  // 5. Encrypt plaintext
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const ciphertext = await aesGcmEncrypt(symmetricKey, nonce, plaintext);

  // 6. Signatures
  // Sign the ciphertext + nonce + timestamp
  const tBytes = new Uint8Array(new Float64Array([timestamp]).buffer);
  const sigPayload = new Uint8Array(ciphertext.length + nonce.length + tBytes.length);
  sigPayload.set(ciphertext, 0);
  sigPayload.set(nonce, ciphertext.length);
  sigPayload.set(tBytes, ciphertext.length + nonce.length);

  const classicalSig = await signEd25519(sender.keys.signing.privateKey, sigPayload);
  const pqcSig = await signMLDSA(sender.keys.pqc_sig.privateKey, sigPayload);

  return {
    version: "UXSP-1",
    sender_id: sender.entity_id,
    recipient_id: recipientCard.entity_id,
    timestamp: timestamp,
    envelope_nonce: encodeBase64(salt),
    ciphertext: encodeBase64(ciphertext),
    nonce: encodeBase64(nonce),
    ephemeral_pub: ephemeral.publicKey,
    kem_ciphertext: encodeBase64(kemData.ciphertext),
    classical_sig: encodeBase64(classicalSig),
    pqc_sig: encodeBase64(pqcSig)
  };
}

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

  const ciphertext = decodeBase64(envelope.ciphertext);
  const nonce = decodeBase64(envelope.nonce);
  const tBytes = new Uint8Array(new Float64Array([envelope.timestamp]).buffer);

  // Verify Signatures
  const sigPayload = new Uint8Array(ciphertext.length + nonce.length + tBytes.length);
  sigPayload.set(ciphertext, 0);
  sigPayload.set(nonce, ciphertext.length);
  sigPayload.set(tBytes, ciphertext.length + nonce.length);

  const classicalValid = await verifyEd25519(
    senderCard.public_keys.signing_pub,
    decodeBase64(envelope.classical_sig),
    sigPayload
  );

  if (!classicalValid) {
    throw new Error("Classical signature verification failed.");
  }

  const pqcValid = await verifyMLDSA(
    senderCard.public_keys.pqc_sig_pub,
    decodeBase64(envelope.pqc_sig),
    sigPayload
  );

  if (!pqcValid) {
    throw new Error("PQC signature verification failed.");
  }

  // Decapsulate & Derive Key
  const sharedX25519 = await deriveSharedSecret(
    receiver.keys.exchange.privateKey,
    envelope.ephemeral_pub
  );

  const kemSharedSecret = await decapsulateMLKEM(
    decodeBase64(envelope.kem_ciphertext),
    receiver.keys.kem.privateKey
  );

  const combinedSecret = new Uint8Array(sharedX25519.length + kemSharedSecret.length);
  combinedSecret.set(sharedX25519, 0);
  combinedSecret.set(kemSharedSecret, sharedX25519.length);

  const salt = decodeBase64(envelope.envelope_nonce);
  const info = encodeUTF8("UXSP-HYBRID-KEY-DERIVATION-V1");
  const symmetricKey = await hkdf(combinedSecret, salt, info, 32);

  // Decrypt
  const plaintext = await aesGcmDecrypt(symmetricKey, nonce, ciphertext);
  return plaintext;
}
