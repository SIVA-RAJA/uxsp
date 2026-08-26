/**
 * UXSP (Ultra Secure Protocol) TypeScript Wire Specifications & Type Definitions.
 */

export interface UXSPPublicKeys {
  exchange_pub: string;
  kem_pub: string;
  signing_pub: string;
  pqc_sig_pub: string;
}

export interface PublicCard {
  version: "UXSP-PUBCARD-1";
  entity_id: string;
  name: string;
  role: string;
  created_at: string;
  public_keys: UXSPPublicKeys;
  key_version?: number;
  valid_until?: string | null;
  is_revoked?: boolean;
  revocation_reason?: string | null;
  revoked_at?: string | null;
}

export interface UXSPEnvelope {
  version: "UXSP-1";
  sender_id: string;
  recipient_id: string;
  timestamp: number;
  envelope_nonce: string;
  ciphertext: string;
  nonce: string;
  ephemeral_pub: string;
  kem_ciphertext: string;
  classical_sig: string;
  pqc_sig: string;
}

export interface SecurePackage {
  uxsp_package_version: "1.0";
  sender_id: string;
  receiver_id: string;
  data_type: string;
  is_chunked: boolean;
  envelope: UXSPEnvelope | null;
  chunks: UXSPEnvelope[];
  metadata: Record<string, unknown>;
}

export interface CreatePackageOptions {
  sender_id: string;
  receiver_id: string;
  data_type?: string;
  envelope?: UXSPEnvelope;
  chunks?: UXSPEnvelope[];
  metadata?: Record<string, unknown>;
}
