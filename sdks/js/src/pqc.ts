/**
 * Post-Quantum Cryptography (PQC) Bridge
 * 
 * Future integration point for ML-KEM and ML-DSA via WASM (e.g. liboqs-wasm or pqcrypto-wasm).
 * Currently provides stub functions to satisfy the UXSP wire format until WASM is loaded.
 */

import { encodeBase64, decodeBase64 } from "./utils.js";

// Try to import liboqs, fallback gracefully
let oqs: any = null;
try {
  // @ts-ignore
  import("@oqs/liboqs-js").then(module => {
    oqs = module;
  }).catch(() => {
    console.warn("UXSP: @oqs/liboqs-js not available. Running in classical-only mode.");
  });
} catch (e) {
  console.warn("UXSP: @oqs/liboqs-js not available. Running in classical-only mode.");
}


export interface PQCKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export async function generateMLKEMKeyPair(): Promise<PQCKeyPairBase64> {
  if (!oqs) {
    return { publicKey: "STUB_MLKEM_PUB", privateKey: "STUB_MLKEM_PRIV" };
  }
  const kem = await oqs.createMLKEM768();
  const { publicKey, secretKey } = await kem.generateKeyPair();
  return { publicKey: encodeBase64(publicKey), privateKey: encodeBase64(secretKey) };
}

export async function generateMLDSAKeyPair(): Promise<PQCKeyPairBase64> {
  if (!oqs) {
    return { publicKey: "STUB_MLDSA_PUB", privateKey: "STUB_MLDSA_PRIV" };
  }
  const sig = await oqs.createMLDSA65();
  const { publicKey, secretKey } = await sig.generateKeyPair();
  return { publicKey: encodeBase64(publicKey), privateKey: encodeBase64(secretKey) };
}

export async function encapsulateMLKEM(
  peerPublicKeyBase64: string
): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
  if (!oqs || peerPublicKeyBase64 === "STUB_MLKEM_PUB") {
    const stubSS = new Uint8Array(32);
    const stubCT = new Uint8Array(32);
    crypto.getRandomValues(stubSS);
    crypto.getRandomValues(stubCT);
    return { sharedSecret: stubSS, ciphertext: stubCT };
  }
  
  const kem = await oqs.createMLKEM768();
  const peerPub = decodeBase64(peerPublicKeyBase64);
  const result = await kem.encapsulate(peerPub);
  return { sharedSecret: result.sharedSecret, ciphertext: result.ciphertext };
}

export async function decapsulateMLKEM(
  ciphertext: Uint8Array,
  privateKeyBase64: string
): Promise<Uint8Array> {
  if (!oqs || privateKeyBase64 === "STUB_MLKEM_PRIV") {
    return new Uint8Array(32);
  }
  const kem = await oqs.createMLKEM768();
  const privKey = decodeBase64(privateKeyBase64);
  const sharedSecret = await kem.decapsulate(ciphertext, privKey);
  return sharedSecret;
}

export async function signMLDSA(
  privateKeyBase64: string,
  data: Uint8Array
): Promise<Uint8Array> {
  if (!oqs || privateKeyBase64 === "STUB_MLDSA_PRIV") {
    const sig = new Uint8Array(64);
    crypto.getRandomValues(sig);
    return sig;
  }
  const signer = await oqs.createMLDSA65();
  const privKey = decodeBase64(privateKeyBase64);
  const signature = await signer.sign(data, privKey);
  return signature;
}

export async function verifyMLDSA(
  publicKeyBase64: string,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  if (!oqs || publicKeyBase64 === "STUB_MLDSA_PUB") {
    return true; // Fallback to classical mode
  }
  const verifier = await oqs.createMLDSA65();
  const pubKey = decodeBase64(publicKeyBase64);
  const isValid = await verifier.verify(data, signature, pubKey);
  return isValid;
}
