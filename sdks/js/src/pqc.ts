/**
 * Post-Quantum Cryptography (PQC) Bridge
 * 
 * Future integration point for ML-KEM and ML-DSA via WASM (e.g. liboqs-wasm or pqcrypto-wasm).
 * Currently provides stub functions to satisfy the UXSP wire format until WASM is loaded.
 */

import { encodeBase64 } from "./utils.js";

// Stubs for Keypairs
export interface PQCKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export async function generateMLKEMKeyPair(): Promise<PQCKeyPairBase64> {
  // TODO: Replace with real ML-KEM WASM call
  return { publicKey: "STUB_MLKEM_PUB", privateKey: "STUB_MLKEM_PRIV" };
}

export async function generateMLDSAKeyPair(): Promise<PQCKeyPairBase64> {
  // TODO: Replace with real ML-DSA WASM call
  return { publicKey: "STUB_MLDSA_PUB", privateKey: "STUB_MLDSA_PRIV" };
}

export async function encapsulateMLKEM(
  peerPublicKeyBase64: string
): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }> {
  // TODO: Replace with real ML-KEM WASM call
  const stubSS = new Uint8Array(32); // 32 bytes
  const stubCT = new Uint8Array(32);
  crypto.getRandomValues(stubSS);
  crypto.getRandomValues(stubCT);
  return { sharedSecret: stubSS, ciphertext: stubCT };
}

export async function decapsulateMLKEM(
  ciphertext: Uint8Array,
  privateKeyBase64: string
): Promise<Uint8Array> {
  // TODO: Replace with real ML-KEM WASM call
  return new Uint8Array(32);
}

export async function signMLDSA(
  privateKeyBase64: string,
  data: Uint8Array
): Promise<Uint8Array> {
  // TODO: Replace with real ML-DSA WASM call
  const sig = new Uint8Array(64);
  crypto.getRandomValues(sig);
  return sig;
}

export async function verifyMLDSA(
  publicKeyBase64: string,
  signature: Uint8Array,
  data: Uint8Array
): Promise<boolean> {
  // TODO: Replace with real ML-DSA WASM call
  return true; // Stub always valid
}
