/**
 * Web Crypto API Wrappers for UXSP
 */
import { encodeBase64, decodeBase64 } from "./utils.js";

// Basic wrappers for X25519 and Ed25519 (Requires modern browser Web Crypto)
// Note: Depending on TS version, we may need to cast algorithm names.

export interface KeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

/**
 * Generate X25519 keypair for ECDH.
 */
export async function generateX25519KeyPair(): Promise<KeyPairBase64> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"]
  )) as CryptoKeyPair;

  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: encodeBase64(pubRaw),
    privateKey: encodeBase64(privRaw)
  };
}

/**
 * Generate Ed25519 keypair for Signing.
 */
export async function generateEd25519KeyPair(): Promise<KeyPairBase64> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;

  const pubRaw = await crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privRaw = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKey: encodeBase64(pubRaw),
    privateKey: encodeBase64(privRaw)
  };
}

/**
 * Perform ECDH with our private key and peer's public key to derive shared secret.
 */
export async function deriveSharedSecret(
  ourPrivateKeyBase64: string,
  peerPublicKeyBase64: string
): Promise<Uint8Array> {
  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    decodeBase64(ourPrivateKeyBase64) as any,
    { name: "X25519" },
    false,
    ["deriveBits"]
  );

  const pubKey = await crypto.subtle.importKey(
    "raw",
    decodeBase64(peerPublicKeyBase64) as any,
    { name: "X25519" },
    false,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "X25519", public: pubKey } as any,
    privKey,
    256
  );

  return new Uint8Array(sharedBits);
}

/**
 * HKDF extraction/expansion.
 */
export async function hkdf(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number = 32
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    ikm as any,
    { name: "HKDF" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as any,
      info: info as any
    },
    keyMaterial,
    length * 8
  );

  return new Uint8Array(derivedBits);
}

/**
 * AES-256-GCM Encryption
 */
export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  associatedData?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as any,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const algo: any = {
    name: "AES-GCM",
    iv: nonce as any,
    tagLength: 128
  };
  
  if (associatedData) {
    algo.additionalData = associatedData as any;
  }

  const ciphertext = await crypto.subtle.encrypt(
    algo,
    cryptoKey,
    plaintext as any
  );

  return new Uint8Array(ciphertext);
}

/**
 * AES-256-GCM Decryption
 */
export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  associatedData?: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as any,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const algo: any = {
    name: "AES-GCM",
    iv: nonce as any,
    tagLength: 128
  };
  
  if (associatedData) {
    algo.additionalData = associatedData as any;
  }

  const plaintext = await crypto.subtle.decrypt(
    algo,
    cryptoKey,
    ciphertext as any
  );

  return new Uint8Array(plaintext);
}

/**
 * Ed25519 Sign
 */
export async function signEd25519(
  privateKeyBase64: string,
  data: Uint8Array
): Promise<Uint8Array> {
  const privKey = await crypto.subtle.importKey(
    "pkcs8",
    decodeBase64(privateKeyBase64) as any,
    { name: "Ed25519" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    privKey,
    data as any
  );

  return new Uint8Array(signature);
}

/**
 * Ed25519 Verify
 */
export async function verifyEd25519(
  publicKeyBase64: string,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  const pubKey = await crypto.subtle.importKey(
    "raw",
    decodeBase64(publicKeyBase64) as any,
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  return await crypto.subtle.verify(
    { name: "Ed25519" },
    pubKey,
    signature as any,
    data as any
  );
}
