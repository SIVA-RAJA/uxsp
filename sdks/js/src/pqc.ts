/**
 * Post-Quantum Cryptography (PQC) Bridge
 * 
 * Future integration point for ML-KEM and ML-DSA via WASM (e.g. liboqs-wasm or pqcrypto-wasm).
 * Currently provides stub functions to satisfy the UXSP wire format until WASM is loaded.
 */

import { encodeBase64, decodeBase64 } from "./utils.js";

// Cache promise for lazy asynchronous loading of liboqs
let oqsPromise: Promise<any> | null = null;

/**
 * Asynchronously retrieve the liboqs module, caching the import promise.
 */
export async function getOQS(): Promise<any> {
  if (!oqsPromise) {
    oqsPromise = (async () => {
      try {
        // @ts-ignore
        const module = await import("@oqs/liboqs-js");
        return (module as any).default || module;
      } catch (e) {
        console.warn("UXSP: @oqs/liboqs-js not available. Running in classical-only mode.");
        return null;
      }
    })();
  }
  return oqsPromise;
}

/**
 * Check whether Post-Quantum Cryptography (liboqs) is available.
 */
export async function isPQCAvailable(): Promise<boolean> {
  const mod = await getOQS();
  return mod !== null;
}

export interface PQCKeyPairBase64 {
  publicKey: string;
  privateKey: string;
}

export async function generateMLKEMKeyPair(): Promise<PQCKeyPairBase64> {
  const oqs = await getOQS();
  if (!oqs) {
    return { publicKey: "STUB_MLKEM_PUB", privateKey: "STUB_MLKEM_PRIV" };
  }
  const kem = await oqs.createMLKEM768();
  const { publicKey, secretKey } = await kem.generateKeyPair();
  return { publicKey: encodeBase64(publicKey), privateKey: encodeBase64(secretKey) };
}

export async function generateMLDSAKeyPair(): Promise<PQCKeyPairBase64> {
  const oqs = await getOQS();
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
  const oqs = await getOQS();
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
  const oqs = await getOQS();
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
  const oqs = await getOQS();
  if (!oqs || privateKeyBase64 === "STUB_MLDSA_PRIV") {
    throw new Error("PQCUnavailableError: Cannot sign with ML-DSA: PQC module is unavailable or stub key provided.");
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
  const oqs = await getOQS();
  if (!oqs || publicKeyBase64 === "STUB_MLDSA_PUB") {
    return false;
  }
  const verifier = await oqs.createMLDSA65();
  const pubKey = decodeBase64(publicKeyBase64);
  const isValid = await verifier.verify(data, signature, pubKey);
  return isValid;
}
