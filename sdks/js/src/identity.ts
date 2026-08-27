/**
 * Identity & PublicCard Management
 */
import { PublicCard, UXSPPublicKeys } from "./types.js";
import { generateX25519KeyPair, generateEd25519KeyPair, KeyPairBase64 } from "./crypto.js";
import { generateMLKEMKeyPair, generateMLDSAKeyPair, PQCKeyPairBase64 } from "./pqc.js";

export interface IdentityKeys {
  exchange: KeyPairBase64;
  kem: PQCKeyPairBase64;
  signing: KeyPairBase64;
  pqc_sig: PQCKeyPairBase64;
}

export class Identity {
  public entity_id: string;
  public name: string;
  public role: string;
  public keys: IdentityKeys;
  public created_at: string;
  
  constructor(
    entity_id: string,
    name: string,
    role: string,
    keys: IdentityKeys,
    created_at?: string
  ) {
    this.entity_id = entity_id;
    this.name = name;
    this.role = role;
    this.keys = keys;
    this.created_at = created_at || new Date().toISOString();
  }

  static async create(name: string, role: string = "CLIENT"): Promise<Identity> {
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

  publicCard(): PublicCard {
    return {
      version: "UXSP-PUBCARD-1",
      entity_id: this.entity_id,
      name: this.name,
      role: this.role,
      created_at: this.created_at,
      public_keys: {
        exchange_pub: this.keys.exchange.publicKey,
        kem_pub: this.keys.kem.publicKey,
        signing_pub: this.keys.signing.publicKey,
        pqc_sig_pub: this.keys.pqc_sig.publicKey
      }
    };
  }
}
