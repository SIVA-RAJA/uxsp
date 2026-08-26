import { UXSPEnvelope, SecurePackage, PublicCard } from "./types.js";

/**
 * Validate UXSP-1 Envelope structure.
 */
export function validateEnvelope(envelope: unknown): envelope is UXSPEnvelope {
  if (!envelope || typeof envelope !== "object") return false;
  const env = envelope as Record<string, unknown>;

  return (
    env.version === "UXSP-1" &&
    typeof env.sender_id === "string" &&
    typeof env.recipient_id === "string" &&
    typeof env.timestamp === "number" &&
    typeof env.envelope_nonce === "string" &&
    typeof env.ciphertext === "string" &&
    typeof env.nonce === "string" &&
    typeof env.ephemeral_pub === "string" &&
    typeof env.kem_ciphertext === "string" &&
    typeof env.classical_sig === "string" &&
    typeof env.pqc_sig === "string"
  );
}

/**
 * Validate SecurePackage wire format structure.
 */
export function validatePackage(pkg: unknown): pkg is SecurePackage {
  if (!pkg || typeof pkg !== "object") return false;
  const p = pkg as Record<string, unknown>;

  if (
    p.uxsp_package_version !== "1.0" ||
    typeof p.sender_id !== "string" ||
    typeof p.receiver_id !== "string" ||
    typeof p.data_type !== "string" ||
    typeof p.is_chunked !== "boolean"
  ) {
    return false;
  }

  if (p.envelope !== null && p.envelope !== undefined) {
    if (!validateEnvelope(p.envelope)) return false;
  }

  if (Array.isArray(p.chunks)) {
    for (const chunk of p.chunks) {
      if (!validateEnvelope(chunk)) return false;
    }
  }

  return true;
}

/**
 * Validate PublicCard identity structure.
 */
export function validatePublicCard(card: unknown): card is PublicCard {
  if (!card || typeof card !== "object") return false;
  const c = card as Record<string, unknown>;

  if (
    c.version !== "UXSP-PUBCARD-1" ||
    typeof c.entity_id !== "string" ||
    typeof c.name !== "string" ||
    typeof c.role !== "string" ||
    typeof c.created_at !== "string" ||
    !c.public_keys ||
    typeof c.public_keys !== "object"
  ) {
    return false;
  }

  const pk = c.public_keys as Record<string, unknown>;
  return (
    typeof pk.exchange_pub === "string" &&
    typeof pk.kem_pub === "string" &&
    typeof pk.signing_pub === "string" &&
    typeof pk.pqc_sig_pub === "string"
  );
}
