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
  plaintext: Uint8Array,
  associatedData?: Uint8Array
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
  const ad = associatedData || new Uint8Array(0);
  const ciphertext = await aesGcmEncrypt(symmetricKey, nonce, plaintext, ad);

  const envNonceBytes = new Uint8Array(32);
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

const seenNonces = new Map<string, number>();
export const MAX_SEEN_NONCES = 100_000;
export const MAX_AGE_SECONDS = 300;
export const CLOCK_SKEW_SECONDS = 30;
export const NONCE_TTL_MS = (MAX_AGE_SECONDS + CLOCK_SKEW_SECONDS) * 1000; // 330,000 ms

/**
 * Clear the seen nonces cache (primarily for test isolation).
 */
export function _clearSeenNonces(): void {
  seenNonces.clear();
}

/**
 * Open a sealed envelope from a sender.
 */
export async function openSeal(
  receiver: Identity,
  senderCard: PublicCard,
  envelope: UXSPEnvelope,
  associatedData?: Uint8Array
): Promise<Uint8Array> {
  if (envelope.recipient_id !== receiver.entity_id) {
    throw new Error("Envelope is not addressed to this receiver.");
  }
  if (envelope.sender_id !== senderCard.entity_id) {
    throw new Error("Envelope sender_id does not match the provided senderCard.");
  }

  // 1. Timestamp Freshness Check
  if (typeof envelope.timestamp !== "number" || isNaN(envelope.timestamp)) {
    throw new Error("EnvelopeValidationError: Envelope timestamp must be a valid integer Unix timestamp.");
  }
  const now = Date.now();
  const nowSec = Math.floor(now / 1000);
  const age = nowSec - envelope.timestamp;

  if (age > MAX_AGE_SECONDS) {
    throw new Error(`ReplayError: Envelope is ${age}s old. Possible replay attack.`);
  }
  if (age < -CLOCK_SKEW_SECONDS) {
    throw new Error(`TimestampError: Envelope timestamp is ${-age}s in the future. Clock skew too large.`);
  }

  // 2. Replay Protection: Check if nonce was already seen
  if (!envelope.envelope_nonce || typeof envelope.envelope_nonce !== "string") {
    throw new Error("EnvelopeValidationError: Envelope envelope_nonce must be a non-empty string.");
  }

  if (seenNonces.has(envelope.envelope_nonce)) {
    throw new Error("ReplayError: Envelope replay detected");
  }

  const ciphertext = decodeHex(envelope.ciphertext);
  const nonce = decodeHex(envelope.nonce);
  
  const pqcMode = (envelope as any).pqc_mode;
  const isPqcStubbed = pqcMode === "none";

  if (isPqcStubbed) {
    if (senderCard.public_keys.pqc_sig_pub && senderCard.public_keys.pqc_sig_pub.length > 32) {
      throw new Error("Sender card advertises PQC capability but envelope specifies pqc_mode: 'none'");
    }
  }

  const ephemeralPubBytes = decodeHex(envelope.ephemeral_pub);

  if (!isPqcStubbed && !envelope.kem_ciphertext) {
    throw new Error("Envelope is missing kem_ciphertext but is not in classical-only mode.");
  }

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

  // 3. Replay Protection: Commit nonce after signature verification succeeds
  // Evict expired entries
  for (const [nonceKey, ts] of seenNonces.entries()) {
    if (now - ts > NONCE_TTL_MS) {
      seenNonces.delete(nonceKey);
    } else {
      break;
    }
  }

  // Enforce maximum capacity hard cap (evict oldest entries if capacity exceeded)
  while (seenNonces.size >= MAX_SEEN_NONCES) {
    const oldestKey = seenNonces.keys().next().value;
    if (oldestKey !== undefined) {
      seenNonces.delete(oldestKey);
    } else {
      break;
    }
  }

  seenNonces.set(envelope.envelope_nonce, now);

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
  const ad = associatedData || new Uint8Array(0);
  const plaintext = await aesGcmDecrypt(symmetricKey, nonce, ciphertext, ad);
  return plaintext;
}
