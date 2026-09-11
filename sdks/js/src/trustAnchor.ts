/**
 * UXSP Trust Anchors & Certificate Authority Infrastructure
 *
 * Implements root Certificate Authorities, signed public cards with validity windows,
 * certificate revocation lists (CRL), and in-memory TrustStore verification.
 */

import { Identity } from "./identity.js";
import { PublicCard, UXSPPublicKeys } from "./types.js";
import { signEd25519, verifyEd25519 } from "./crypto.js";
import { signMLDSA, verifyMLDSA } from "./pqc.js";
import {
  encodeUTF8,
  decodeHex,
  encodeHex,
  decodeBase64,
  bindFields,
} from "./utils.js";

export class SigningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SigningError";
  }
}

export class UntrustedCardError extends SigningError {
  constructor(message: string) {
    super(message);
    this.name = "UntrustedCardError";
  }
}

export class InvalidCardSignatureError extends SigningError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidCardSignatureError";
  }
}

export class ExpiredCardError extends SigningError {
  constructor(message: string) {
    super(message);
    this.name = "ExpiredCardError";
  }
}

export class CardNotYetValidError extends SigningError {
  constructor(message: string) {
    super(message);
    this.name = "CardNotYetValidError";
  }
}

export class RevokedCardError extends SigningError {
  constructor(message: string) {
    super(message);
    this.name = "RevokedCardError";
  }
}

function cardSignable(card: PublicCard, notBefore: number, notAfter: number, certId: string): Uint8Array {
  return bindFields(
    encodeUTF8(card.entity_id),
    encodeUTF8(card.name),
    encodeUTF8(card.role),
    encodeUTF8(card.created_at),
    decodeBase64(card.public_keys.exchange_pub),
    decodeBase64(card.public_keys.kem_pub),
    decodeBase64(card.public_keys.signing_pub),
    decodeBase64(card.public_keys.pqc_sig_pub),
    encodeUTF8(String(card.key_version || 1)),
    encodeUTF8(String(notBefore)),
    encodeUTF8(String(notAfter)),
    encodeUTF8(certId)
  );
}

function crlSignable(
  issuerId: string,
  crlNumber: number,
  issuedAt: number,
  revokedCerts: Array<[string, number, string]>
): Uint8Array {
  const sorted = [...revokedCerts].sort((a, b) => a[0].localeCompare(b[0]));
  const entryBytes = sorted.map(([cid, rDate, reason]) => encodeUTF8(`${cid}:${rDate}:${reason}`));
  return bindFields(
    encodeUTF8("UXSP-CRL-1"),
    encodeUTF8(issuerId),
    encodeUTF8(String(crlNumber)),
    encodeUTF8(String(issuedAt)),
    ...entryBytes
  );
}

export class PublicAnchor {
  public anchor_id: string;
  public name: string;
  public public_keys: UXSPPublicKeys;
  public created_at: string;

  constructor(anchor_id: string, name: string, public_keys: UXSPPublicKeys, created_at: string) {
    this.anchor_id = anchor_id;
    this.name = name;
    this.public_keys = public_keys;
    this.created_at = created_at;
  }

  toDict(): Record<string, any> {
    return {
      anchor_id: this.anchor_id,
      name: this.name,
      created_at: this.created_at,
      public_keys: this.public_keys,
    };
  }

  toJson(): string {
    return JSON.stringify(this.toDict(), null, 2);
  }

  static fromDict(data: Record<string, any>): PublicAnchor {
    return new PublicAnchor(data.anchor_id, data.name, data.public_keys, data.created_at);
  }

  static fromJson(str: string): PublicAnchor {
    return PublicAnchor.fromDict(JSON.parse(str));
  }
}

export class SignedCard {
  public card: PublicCard;
  public cert_id: string;
  public issuer_id: string;
  public issuer_name: string;
  public not_before: number;
  public not_after: number;
  public classical_sig: string; // hex
  public pqc_sig: string; // hex

  constructor(
    card: PublicCard,
    cert_id: string,
    issuer_id: string,
    issuer_name: string,
    not_before: number,
    not_after: number,
    classical_sig: string,
    pqc_sig: string
  ) {
    this.card = card;
    this.cert_id = cert_id;
    this.issuer_id = issuer_id;
    this.issuer_name = issuer_name;
    this.not_before = not_before;
    this.not_after = not_after;
    this.classical_sig = classical_sig;
    this.pqc_sig = pqc_sig;
  }

  isTimeValid(now?: number): boolean {
    const t = now !== undefined ? now : Math.floor(Date.now() / 1000);
    return this.not_before <= t && t <= this.not_after;
  }

  checkTimeValidity(now?: number): void {
    const t = now !== undefined ? now : Math.floor(Date.now() / 1000);
    if (t < this.not_before) {
      throw new CardNotYetValidError(
        `SignedCard for '${this.card.name}' is not yet valid (valid from ${this.not_before}, current ${t}).`
      );
    }
    if (t > this.not_after) {
      throw new ExpiredCardError(
        `SignedCard for '${this.card.name}' expired at ${this.not_after} (current ${t}).`
      );
    }
  }

  toDict(): Record<string, any> {
    return {
      card: this.card,
      cert_id: this.cert_id,
      issuer_id: this.issuer_id,
      issuer_name: this.issuer_name,
      not_before: this.not_before,
      not_after: this.not_after,
      classical_sig: this.classical_sig,
      pqc_sig: this.pqc_sig,
    };
  }

  toJson(): string {
    return JSON.stringify(this.toDict(), null, 2);
  }

  static fromDict(data: Record<string, any>): SignedCard {
    return new SignedCard(
      data.card,
      data.cert_id,
      data.issuer_id,
      data.issuer_name,
      Number(data.not_before),
      Number(data.not_after),
      data.classical_sig,
      data.pqc_sig
    );
  }

  static fromJson(str: string): SignedCard {
    return SignedCard.fromDict(JSON.parse(str));
  }
}

export class CertificateRevocationList {
  public issuer_id: string;
  public issuer_name: string;
  public crl_number: number;
  public issued_at: number;
  public revoked_certs: Record<string, { revocation_date: number; reason: string }>;
  public classical_sig: string;
  public pqc_sig: string;

  constructor(
    issuer_id: string,
    issuer_name: string,
    crl_number: number,
    issued_at: number,
    revoked_certs: Record<string, { revocation_date: number; reason: string }>,
    classical_sig: string,
    pqc_sig: string
  ) {
    this.issuer_id = issuer_id;
    this.issuer_name = issuer_name;
    this.crl_number = crl_number;
    this.issued_at = issued_at;
    this.revoked_certs = revoked_certs;
    this.classical_sig = classical_sig;
    this.pqc_sig = pqc_sig;
  }

  isRevoked(cert_id: string): boolean {
    return cert_id in this.revoked_certs;
  }

  async verify(anchorPublicKeys: UXSPPublicKeys): Promise<boolean> {
    const entries: Array<[string, number, string]> = Object.entries(this.revoked_certs).map(
      ([cid, info]) => [cid, info.revocation_date, info.reason]
    );
    const signable = crlSignable(this.issuer_id, this.crl_number, this.issued_at, entries);

    const classicalValid = await verifyEd25519(
      anchorPublicKeys.signing_pub,
      decodeHex(this.classical_sig),
      signable
    );
    if (!classicalValid) {
      throw new InvalidCardSignatureError("CRL classical signature verification failed.");
    }

    if (this.pqc_sig && decodeHex(this.pqc_sig).length > 0) {
      const pqcValid = await verifyMLDSA(
        anchorPublicKeys.pqc_sig_pub,
        decodeHex(this.pqc_sig),
        signable
      );
      if (!pqcValid) {
        throw new InvalidCardSignatureError("CRL PQC signature verification failed.");
      }
    }
    return true;
  }

  toDict(): Record<string, any> {
    return {
      issuer_id: this.issuer_id,
      issuer_name: this.issuer_name,
      crl_number: this.crl_number,
      issued_at: this.issued_at,
      revoked_certs: this.revoked_certs,
      classical_sig: this.classical_sig,
      pqc_sig: this.pqc_sig,
    };
  }

  toJson(): string {
    return JSON.stringify(this.toDict(), null, 2);
  }

  static fromDict(data: Record<string, any>): CertificateRevocationList {
    return new CertificateRevocationList(
      data.issuer_id,
      data.issuer_name,
      Number(data.crl_number),
      Number(data.issued_at),
      data.revoked_certs || {},
      data.classical_sig,
      data.pqc_sig
    );
  }

  static fromJson(str: string): CertificateRevocationList {
    return CertificateRevocationList.fromDict(JSON.parse(str));
  }
}

export const CRL = CertificateRevocationList;

export class TrustAnchor {
  private _identity: Identity;

  constructor(identity: Identity) {
    this._identity = identity;
  }

  static async create(name: string): Promise<TrustAnchor> {
    const identity = await Identity.create(name, "TRUST-ANCHOR");
    return new TrustAnchor(identity);
  }

  publicAnchor(): PublicAnchor {
    const card = this._identity.publicCard();
    return new PublicAnchor(
      this._identity.entity_id,
      this._identity.name,
      card.public_keys,
      this._identity.created_at
    );
  }

  async issue(
    card: PublicCard,
    validityDays: number = 365,
    notBefore?: number
  ): Promise<SignedCard> {
    if (validityDays <= 0) throw new Error("validityDays must be positive");
    if (validityDays > 730) throw new Error("validityDays cannot exceed 730");

    const nb = notBefore !== undefined ? notBefore : Math.floor(Date.now() / 1000);
    const na = nb + validityDays * 86400;
    const certId = crypto.randomUUID();

    const signable = cardSignable(card, nb, na, certId);
    const classicalSig = await signEd25519(this._identity.keys.signing.privateKey, signable);
    const isPqcStubbed = this._identity.keys.pqc_sig.privateKey === "STUB_MLDSA_PRIV";
    let pqcSig: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    if (!isPqcStubbed) {
      pqcSig = await signMLDSA(this._identity.keys.pqc_sig.privateKey, signable);
    }

    return new SignedCard(
      card,
      certId,
      this._identity.entity_id,
      this._identity.name,
      nb,
      na,
      encodeHex(classicalSig),
      encodeHex(pqcSig)
    );
  }

  async issueCRL(
    revokedCerts: Array<{ cert_id: string; reason?: string; revocation_date?: number }> = [],
    crlNumber: number = 1,
    issuedAt?: number
  ): Promise<CertificateRevocationList> {
    const ts = issuedAt !== undefined ? issuedAt : Math.floor(Date.now() / 1000);
    const registry: Record<string, { revocation_date: number; reason: string }> = {};
    const entryList: Array<[string, number, string]> = [];

    for (const item of revokedCerts) {
      const rDate = item.revocation_date !== undefined ? item.revocation_date : ts;
      const reason = item.reason || "unspecified";
      registry[item.cert_id] = { revocation_date: rDate, reason };
      entryList.push([item.cert_id, rDate, reason]);
    }

    const signable = crlSignable(this._identity.entity_id, crlNumber, ts, entryList);
    const classicalSig = await signEd25519(this._identity.keys.signing.privateKey, signable);
    const isPqcStubbed = this._identity.keys.pqc_sig.privateKey === "STUB_MLDSA_PRIV";
    let pqcSig: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    if (!isPqcStubbed) {
      pqcSig = await signMLDSA(this._identity.keys.pqc_sig.privateKey, signable);
    }

    return new CertificateRevocationList(
      this._identity.entity_id,
      this._identity.name,
      crlNumber,
      ts,
      registry,
      encodeHex(classicalSig),
      encodeHex(pqcSig)
    );
  }

  get entity_id(): string {
    return this._identity.entity_id;
  }

  get name(): string {
    return this._identity.name;
  }
}

export class TrustStore {
  private anchors = new Map<string, PublicAnchor>();
  private revokedCerts = new Map<string, { revocation_date: number; reason: string }>();

  add(anchor: PublicAnchor): void {
    this.anchors.set(anchor.anchor_id, anchor);
  }

  remove(anchorId: string): void {
    this.anchors.delete(anchorId);
  }

  has(anchorId: string): boolean {
    return this.anchors.has(anchorId);
  }

  revoke(certId: string, reason: string = "unspecified", revocationDate?: number): void {
    this.revokedCerts.set(certId, {
      revocation_date: revocationDate !== undefined ? revocationDate : Math.floor(Date.now() / 1000),
      reason,
    });
  }

  isRevoked(certId: string): boolean {
    return this.revokedCerts.has(certId);
  }

  addCRL(crl: CertificateRevocationList): void {
    for (const [cid, info] of Object.entries(crl.revoked_certs)) {
      this.revokedCerts.set(cid, info);
    }
  }

  async verify(
    signedCard: SignedCard,
    options?: { expectedEntityId?: string; now?: number }
  ): Promise<boolean> {
    const anchor = this.anchors.get(signedCard.issuer_id);
    if (!anchor) {
      throw new UntrustedCardError(
        `SignedCard issuer '${signedCard.issuer_id}' (${signedCard.issuer_name}) is not in trust store.`
      );
    }

    if (this.isRevoked(signedCard.cert_id)) {
      throw new RevokedCardError(`SignedCard cert '${signedCard.cert_id}' has been revoked.`);
    }

    signedCard.checkTimeValidity(options?.now);

    if (options?.expectedEntityId && signedCard.card.entity_id !== options.expectedEntityId) {
      throw new SigningError(
        `SignedCard entity_id mismatch: expected '${options.expectedEntityId}', got '${signedCard.card.entity_id}'`
      );
    }

    const signable = cardSignable(
      signedCard.card,
      signedCard.not_before,
      signedCard.not_after,
      signedCard.cert_id
    );

    const classicalValid = await verifyEd25519(
      anchor.public_keys.signing_pub,
      decodeHex(signedCard.classical_sig),
      signable
    );
    if (!classicalValid) {
      throw new InvalidCardSignatureError("SignedCard classical signature verification failed.");
    }

    if (signedCard.pqc_sig && decodeHex(signedCard.pqc_sig).length > 0) {
      const pqcValid = await verifyMLDSA(
        anchor.public_keys.pqc_sig_pub,
        decodeHex(signedCard.pqc_sig),
        signable
      );
      if (!pqcValid) {
        throw new InvalidCardSignatureError("SignedCard PQC signature verification failed.");
      }
    }

    return true;
  }
}
