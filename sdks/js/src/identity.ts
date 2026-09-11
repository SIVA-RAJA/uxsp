/**
 * Identity & PublicCard Management
 */
import { PublicCard, UXSPPublicKeys } from "./types.js";
import {
  generateX25519KeyPair,
  generateEd25519KeyPair,
  KeyPairBase64,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from "./crypto.js";
import { generateMLKEMKeyPair, generateMLDSAKeyPair, PQCKeyPairBase64 } from "./pqc.js";
import { encodeHex, decodeHex, encodeUTF8, decodeUTF8 } from "./utils.js";
import { deriveKeyFromPassword, argon2idHash, argon2idVerify } from "./argon2.js";

export interface IdentityKeys {
  exchange: KeyPairBase64;
  kem: PQCKeyPairBase64;
  signing: KeyPairBase64;
  pqc_sig: PQCKeyPairBase64;
}

export interface PublicCardOptions {
  validUntil?: string | null;
  ttlSeconds?: number;
}

export class Identity {
  public entity_id: string;
  public name: string;
  public role: string;
  public keys: IdentityKeys;
  public created_at: string;
  public key_version: number;
  public keys_rotated_at: string | null;

  constructor(
    entity_id: string,
    name: string,
    role: string,
    keys: IdentityKeys,
    created_at?: string,
    key_version: number = 1,
    keys_rotated_at: string | null = null
  ) {
    this.entity_id = entity_id;
    this.name = name;
    this.role = role;
    this.keys = keys;
    this.created_at = created_at || new Date().toISOString();
    this.key_version = key_version;
    this.keys_rotated_at = keys_rotated_at;
  }

  static async create(name: string, role: string = "CLIENT"): Promise<Identity> {
    if (!name || typeof name !== "string" || name.trim() === "") {
      throw new TypeError("Identity name must be a non-empty string.");
    }
    if (!role || typeof role !== "string" || role.trim() === "") {
      throw new TypeError("Identity role must be a non-empty string.");
    }

    const exchange = await generateX25519KeyPair();
    const signing = await generateEd25519KeyPair();
    const kem = await generateMLKEMKeyPair();
    const pqc_sig = await generateMLDSAKeyPair();

    const entity_id = crypto.randomUUID().replace(/-/g, "");

    return new Identity(entity_id, name, role, {
      exchange,
      signing,
      kem,
      pqc_sig
    });
  }

  /**
   * Rotate cryptographic keys while maintaining entity_id, name, and role.
   * Increments key_version and sets keys_rotated_at timestamp.
   */
  async rotateKeys(): Promise<Identity> {
    this.keys.exchange = await generateX25519KeyPair();
    this.keys.signing = await generateEd25519KeyPair();
    this.keys.kem = await generateMLKEMKeyPair();
    this.keys.pqc_sig = await generateMLDSAKeyPair();

    this.key_version += 1;
    this.keys_rotated_at = new Date().toISOString();
    return this;
  }

  publicCard(options?: PublicCardOptions): PublicCard {
    let valid_until: string | null = options?.validUntil || null;
    if (!valid_until && options?.ttlSeconds) {
      valid_until = new Date(Date.now() + options.ttlSeconds * 1000).toISOString();
    }

    return {
      version: "UXSP-PUBCARD-1",
      entity_id: this.entity_id,
      name: this.name,
      role: this.role,
      created_at: this.created_at,
      key_version: this.key_version,
      valid_until: valid_until,
      public_keys: {
        exchange_pub: this.keys.exchange.publicKey,
        kem_pub: this.keys.kem.publicKey,
        signing_pub: this.keys.signing.publicKey,
        pqc_sig_pub: this.keys.pqc_sig.publicKey
      }
    };
  }

  /**
   * Serialize identity to an encrypted JSON dictionary protected by password.
   */
  async toEncryptedDict(password: string): Promise<Record<string, any>> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const { key } = await deriveKeyFromPassword(password, { salt });

    const privateKeys = {
      exchange_priv: this.keys.exchange.privateKey,
      signing_priv: this.keys.signing.privateKey,
      kem_priv: this.keys.kem.privateKey,
      pqc_sig_priv: this.keys.pqc_sig.privateKey
    };
    const plaintext = encodeUTF8(JSON.stringify(privateKeys));

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const associatedData = encodeUTF8(this.entity_id);
    const ciphertext = await aesGcmEncrypt(key, nonce, plaintext, associatedData);

    return {
      version: "UXSP-IDENTITY-1",
      entity_id: this.entity_id,
      name: this.name,
      role: this.role,
      created_at: this.created_at,
      key_version: this.key_version,
      keys_rotated_at: this.keys_rotated_at,
      public_keys: this.publicCard().public_keys,
      encrypted_private: {
        ciphertext: encodeHex(ciphertext),
        nonce: encodeHex(nonce),
        kdf_salt: encodeHex(salt),
        associated_data: this.entity_id
      }
    };
  }

  /**
   * Serialize identity to an encrypted JSON string protected by password.
   */
  async toEncryptedJson(password: string, indent?: number): Promise<string> {
    const dict = await this.toEncryptedDict(password);
    return JSON.stringify(dict, null, indent);
  }

  exportEncrypted = this.toEncryptedJson;

  /**
   * Deserialize an Identity from an encrypted dictionary payload.
   */
  static async fromEncryptedDict(payload: Record<string, any>, password: string): Promise<Identity> {
    if (!payload || typeof payload !== "object") {
      throw new TypeError("Payload must be an object.");
    }
    const encPriv = payload.encrypted_private;
    if (!encPriv) {
      throw new Error("Payload missing encrypted_private section.");
    }

    const salt = decodeHex(encPriv.kdf_salt);
    const { key } = await deriveKeyFromPassword(password, { salt });

    const nonce = decodeHex(encPriv.nonce);
    const ciphertext = decodeHex(encPriv.ciphertext);
    const associatedData = encodeUTF8(payload.entity_id);

    let plaintext: Uint8Array;
    try {
      plaintext = await aesGcmDecrypt(key, nonce, ciphertext, associatedData);
    } catch {
      throw new Error("Wrong password or corrupted identity file.");
    }

    const privateKeys = JSON.parse(decodeUTF8(plaintext));
    const pub = payload.public_keys;

    const keys: IdentityKeys = {
      exchange: {
        publicKey: pub.exchange_pub,
        privateKey: privateKeys.exchange_priv
      },
      signing: {
        publicKey: pub.signing_pub,
        privateKey: privateKeys.signing_priv
      },
      kem: {
        publicKey: pub.kem_pub,
        privateKey: privateKeys.kem_priv
      },
      pqc_sig: {
        publicKey: pub.pqc_sig_pub,
        privateKey: privateKeys.pqc_sig_priv
      }
    };

    return new Identity(
      payload.entity_id,
      payload.name,
      payload.role,
      keys,
      payload.created_at,
      payload.key_version || 1,
      payload.keys_rotated_at || null
    );
  }

  /**
   * Deserialize an Identity from an encrypted JSON string.
   */
  static async fromEncryptedJson(jsonStr: string, password: string): Promise<Identity> {
    const parsed = JSON.parse(jsonStr);
    return await Identity.fromEncryptedDict(parsed, password);
  }

  static importEncrypted = Identity.fromEncryptedJson;

  static hashPassword = argon2idHash;
  static verifyPassword = argon2idVerify;
}
