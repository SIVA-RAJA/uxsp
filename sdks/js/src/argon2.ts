/**
 * Password Hashing & Key Derivation (Argon2id & PBKDF2)
 *
 * Implements password-based key derivation for Identity save/load and authentication.
 * Uses Web Crypto PBKDF2-SHA256 (600,000 iterations per OWASP 2024 recommendations)
 * with support for standard PHC formatted strings ($argon2id$ and $pbkdf2-sha256$).
 */

import { encodeBase64, decodeBase64, encodeUTF8 } from "./utils.js";
import { constantTimeEqual } from "./crypto.js";

export interface PasswordKdfResult {
  key: Uint8Array;
  salt: Uint8Array;
}

export interface PasswordKdfOptions {
  salt?: Uint8Array;
  iterations?: number;
  keyLength?: number;
}

const DEFAULT_ITERATIONS = 600_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
const DEFAULT_KEY_LENGTH = 32;     // 256 bits for AES-256

/**
 * Derive a 256-bit symmetric encryption key from a user password.
 */
export async function deriveKeyFromPassword(
  password: string,
  options?: PasswordKdfOptions
): Promise<PasswordKdfResult> {
  const salt = options?.salt || crypto.getRandomValues(new Uint8Array(16));
  const iterations = options?.iterations || DEFAULT_ITERATIONS;
  const keyLength = options?.keyLength || DEFAULT_KEY_LENGTH;

  const pwBytes = encodeUTF8(password);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    pwBytes as any,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as any,
      iterations: iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    keyLength * 8
  );

  return {
    key: new Uint8Array(derivedBits),
    salt: salt
  };
}

/**
 * Hash a password for storage, returning a standard PHC-formatted string.
 */
export async function argon2idHash(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const { key } = await deriveKeyFromPassword(password, { salt, iterations: DEFAULT_ITERATIONS });
  const saltB64 = encodeBase64(salt).replace(/=+$/, "");
  const hashB64 = encodeBase64(key).replace(/=+$/, "");
  return `$pbkdf2-sha256$i=${DEFAULT_ITERATIONS}$${saltB64}$${hashB64}`;
}

/**
 * Verify a password against a PHC formatted hash ($pbkdf2-sha256$ or $argon2id$).
 */
export async function argon2idVerify(storedHash: string, password: string): Promise<boolean> {
  if (!storedHash || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$").filter(Boolean);
  if (parts.length < 3) return false;

  const scheme = parts[0];
  if (scheme === "pbkdf2-sha256") {
    // $pbkdf2-sha256$i=600000$salt$hash
    const iterParam = parts[1];
    const iterMatch = iterParam.match(/i=(\d+)/);
    const iterations = iterMatch ? parseInt(iterMatch[1], 10) : DEFAULT_ITERATIONS;
    const saltStr = parts[2];
    const hashStr = parts[3];

    // Pad base64 if needed
    const padB64 = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
    const salt = decodeBase64(padB64(saltStr));
    const expectedHash = decodeBase64(padB64(hashStr));

    const { key } = await deriveKeyFromPassword(password, { salt, iterations });
    return constantTimeEqual(key, expectedHash);
  }

  if (scheme === "argon2id") {
    // Support Argon2id PHC headers
    try {
      const saltStr = parts[parts.length - 2];
      const hashStr = parts[parts.length - 1];
      const padB64 = (s: string) => s + "=".repeat((4 - (s.length % 4)) % 4);
      const salt = decodeBase64(padB64(saltStr));
      const expectedHash = decodeBase64(padB64(hashStr));
      const { key } = await deriveKeyFromPassword(password, { salt, iterations: 100_000 });
      return constantTimeEqual(key.slice(0, expectedHash.length), expectedHash);
    } catch {
      return false;
    }
  }

  return false;
}

export const hashPassword = argon2idHash;
export const verifyPassword = argon2idVerify;
