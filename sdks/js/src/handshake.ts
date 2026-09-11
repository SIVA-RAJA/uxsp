/**
 * UXSP Handshake Protocol
 *
 * Implements the stateful 3-way hybrid post-quantum handshake:
 * 1. initiate(): Initiator builds signed HELLO with ephemeral exchange.
 * 2. respond(): Responder verifies HELLO, proves possession of shared secret, and returns ACK.
 * 3. complete(): Initiator verifies ACK and proof, activating the stateful Session.
 */

import { Identity } from "./identity.js";
import { PublicCard } from "./types.js";
import { NonceStore, MemoryNonceStore } from "./noncestore.js";
import { Session, SessionConfig } from "./session.js";
import {
  generateX25519KeyPair,
  deriveSharedSecret,
  hkdf,
  signEd25519,
  verifyEd25519,
  hmacSha256,
  constantTimeEqual,
} from "./crypto.js";
import {
  encapsulateMLKEM,
  decapsulateMLKEM,
  signMLDSA,
  verifyMLDSA,
} from "./pqc.js";
import {
  encodeBase64,
  decodeBase64,
  encodeUTF8,
  encodeHex,
  decodeHex,
  bindFields,
} from "./utils.js";

export const SUPPORTED_VERSIONS = ["1.0", "1.1", "1.2"];

export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeError";
  }
}

export class HandshakeAuthError extends HandshakeError {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeAuthError";
  }
}

export class HandshakeProofError extends HandshakeError {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeProofError";
  }
}

export class HandshakeExpiredError extends HandshakeError {
  constructor(message: string) {
    super(message);
    this.name = "HandshakeExpiredError";
  }
}

interface ExchangeResult {
  ephemeralPub: Uint8Array;
  kemCiphertext: Uint8Array;
  sharedKey: Uint8Array;
}

export class Handshake {
  private _helloMsg: Record<string, any> | null = null;
  private _ackMsg: Record<string, any> | null = null;
  private _session: Session | null = null;
  private _exchange: ExchangeResult | null = null;
  private _sessionId: string | null = null;
  private _config: SessionConfig | null = null;
  private _initiator: Identity | null = null;
  private _respCard: PublicCard | null = null;

  get helloMessage(): Record<string, any> {
    if (!this._helloMsg) {
      throw new HandshakeError("helloMessage not available: handshake not initiated.");
    }
    return this._helloMsg;
  }

  get ackMessage(): Record<string, any> {
    if (!this._ackMsg) {
      throw new HandshakeError("ackMessage not available: response not generated.");
    }
    return this._ackMsg;
  }

  get session(): Session {
    if (!this._session) {
      throw new HandshakeError("session not ready: handshake incomplete.");
    }
    return this._session;
  }

  get sessionId(): string {
    return this._sessionId || "";
  }

  /**
   * Start a new handshake as the initiating party.
   */
  static async initiate(
    initiator: Identity,
    responderCard: PublicCard,
    config?: SessionConfig
  ): Promise<Handshake> {
    const hs = new Handshake();
    hs._sessionId = crypto.randomUUID();
    hs._config = config || new SessionConfig();
    hs._initiator = initiator;
    hs._respCard = responderCard;

    const { hello, exchange } = await Handshake._makeHello(initiator, responderCard, hs._sessionId);
    hs._helloMsg = hello;
    hs._exchange = exchange;
    return hs;
  }

  /**
   * Process a HANDSHAKE_HELLO message and produce an ACK as the responder.
   */
  static async respond(
    responder: Identity,
    hello: Record<string, any>,
    initiatorCard: PublicCard,
    nonceStore: NonceStore,
    config?: SessionConfig
  ): Promise<Handshake> {
    const hs = new Handshake();
    hs._config = config || new SessionConfig();
    hs._sessionId = String(hello?.session_id || "");

    if (!hs._sessionId) {
      throw new HandshakeAuthError("Invalid or missing session_id in HelloMessage.");
    }

    const { negotiatedVersion } = await Handshake._verifyHelloSignature(hello, initiatorCard, responder);

    const marked = await nonceStore.markUsed(`hello:${hello.session_id}`, 90);
    if (!marked) {
      throw new HandshakeExpiredError("Replay attack detected: hello message already processed.");
    }

    const sharedSecretA = await Handshake._deriveHelloSecret(hello, responder);

    const { ack, respExchange } = await Handshake._makeAck(
      responder,
      hello.session_id,
      hello.initiator_id,
      sharedSecretA,
      initiatorCard,
      negotiatedVersion
    );
    hs._ackMsg = ack;

    const sharedSecretB = respExchange.sharedKey;
    const combined = new Uint8Array(sharedSecretA.length + sharedSecretB.length);
    combined.set(sharedSecretA, 0);
    combined.set(sharedSecretB, sharedSecretA.length);

    const finalInfo = encodeUTF8(
      `UXSP-final-session-key:${hello.session_id}:${hello.initiator_id}:${responder.entity_id}`
    );
    const finalSharedSecret = await hkdf(combined, new Uint8Array(0), finalInfo, 32);

    const session = new Session(
      hello.session_id,
      responder.entity_id,
      hello.initiator_id,
      finalSharedSecret,
      false, // responder
      hs._config
    );
    await session.ready();
    session.activate();
    hs._session = session;

    return hs;
  }

  /**
   * Finalise the handshake as the initiating party after receiving responder ACK.
   */
  async complete(
    ack: Record<string, any>,
    responderCard: PublicCard,
    nonceStore: NonceStore
  ): Promise<Session> {
    if (!this._helloMsg || !this._initiator || !this._sessionId || !this._exchange) {
      throw new HandshakeError("complete() called before initiate().");
    }

    await Handshake._verifyAckSignature(ack, responderCard);

    if (ack.session_id !== this._sessionId) {
      throw new HandshakeAuthError("AckMessage session_id does not match pending handshake.");
    }
    if (ack.initiator_id !== this._initiator.entity_id) {
      throw new HandshakeAuthError("AckMessage initiator_id does not match this initiator.");
    }
    if (ack.responder_id !== responderCard.entity_id) {
      throw new HandshakeAuthError("AckMessage responder_id does not match responder card.");
    }

    const marked = await nonceStore.markUsed(`ack:${ack.session_id}`, 90);
    if (!marked) {
      throw new HandshakeExpiredError("Replay attack detected: ack message already processed.");
    }

    const sharedSecretA = this._exchange.sharedKey;
    const sharedSecretB = await Handshake._deriveAckSecret(ack, sharedSecretA, this._initiator);

    const combined = new Uint8Array(sharedSecretA.length + sharedSecretB.length);
    combined.set(sharedSecretA, 0);
    combined.set(sharedSecretB, sharedSecretA.length);

    const finalInfo = encodeUTF8(
      `UXSP-final-session-key:${this._sessionId}:${this._initiator.entity_id}:${responderCard.entity_id}`
    );
    const finalSharedSecret = await hkdf(combined, new Uint8Array(0), finalInfo, 32);

    const session = new Session(
      this._sessionId,
      this._initiator.entity_id,
      responderCard.entity_id,
      finalSharedSecret,
      true, // initiator
      this._config || undefined
    );
    await session.ready();
    session.activate();
    this._session = session;

    return session;
  }

  // ─────────────────────────────────────────
  // INTERNAL HELPERS
  // ─────────────────────────────────────────

  private static async _makeHello(
    initiator: Identity,
    responderCard: PublicCard,
    sessionId: string
  ): Promise<{ hello: Record<string, any>; exchange: ExchangeResult }> {
    const ts = Math.floor(Date.now() / 1000);

    const ephemeral = await generateX25519KeyPair();
    const ephemeralPubBytes = decodeBase64(ephemeral.publicKey);

    const sharedX25519 = await deriveSharedSecret(
      ephemeral.privateKey,
      responderCard.public_keys.exchange_pub
    );

    const kemData = await encapsulateMLKEM(responderCard.public_keys.kem_pub);
    const isPqcStubbed = kemData.ciphertext.length === 32;

    let combinedSecret: Uint8Array;
    if (isPqcStubbed) {
      combinedSecret = sharedX25519;
    } else {
      combinedSecret = new Uint8Array(sharedX25519.length + kemData.sharedSecret.length);
      combinedSecret.set(sharedX25519, 0);
      combinedSecret.set(kemData.sharedSecret, sharedX25519.length);
    }

    const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
    const sharedKey = await hkdf(combinedSecret, ephemeralPubBytes, info, 32);

    const signable = bindFields(
      encodeUTF8("UXSP-HELLO"),
      encodeUTF8(SUPPORTED_VERSIONS.join(",")),
      encodeUTF8(sessionId),
      encodeUTF8(initiator.entity_id),
      encodeUTF8(responderCard.entity_id),
      ephemeralPubBytes,
      isPqcStubbed ? new Uint8Array(0) : kemData.ciphertext,
      encodeUTF8(ts.toString())
    );

    const classicalSig = await signEd25519(initiator.keys.signing.privateKey, signable);
    let pqcSig: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    if (!isPqcStubbed) {
      pqcSig = await signMLDSA(initiator.keys.pqc_sig.privateKey, signable);
    }

    const hello: Record<string, any> = {
      type: "UXSP-HELLO",
      supported_versions: SUPPORTED_VERSIONS,
      session_id: sessionId,
      initiator_id: initiator.entity_id,
      responder_id: responderCard.entity_id,
      timestamp: ts,
      ephemeral_pub: encodeHex(ephemeralPubBytes),
      kem_ciphertext: encodeHex(kemData.ciphertext),
      classical_sig: encodeHex(classicalSig),
      pqc_sig: encodeHex(pqcSig),
    };

    return {
      hello,
      exchange: {
        ephemeralPub: ephemeralPubBytes,
        kemCiphertext: kemData.ciphertext,
        sharedKey,
      },
    };
  }

  private static async _verifyHelloSignature(
    hello: Record<string, any>,
    initiatorCard: PublicCard,
    responder: Identity,
    maxAge: number = 30
  ): Promise<{ signable: Uint8Array; negotiatedVersion: string }> {
    const required = [
      "type", "supported_versions", "session_id", "initiator_id",
      "responder_id", "timestamp", "ephemeral_pub", "kem_ciphertext",
      "classical_sig", "pqc_sig"
    ];
    for (const f of required) {
      if (hello[f] === undefined) {
        throw new HandshakeAuthError(`HelloMessage missing required field: ${f}`);
      }
    }

    if (hello.type !== "UXSP-HELLO") {
      throw new HandshakeAuthError(`Expected UXSP-HELLO message, got '${hello.type}'`);
    }

    const ts = Number(hello.timestamp);
    if (isNaN(ts)) {
      throw new HandshakeAuthError("Invalid timestamp in HelloMessage.");
    }
    const age = Math.floor(Date.now() / 1000) - ts;
    if (age < -maxAge || age > maxAge) {
      throw new HandshakeExpiredError(`HelloMessage is ${age}s old. Maximum allowed: ${maxAge}s.`);
    }

    if (hello.initiator_id !== initiatorCard.entity_id) {
      throw new HandshakeAuthError("HelloMessage initiator_id does not match initiator card.");
    }
    if (hello.responder_id !== responder.entity_id) {
      throw new HandshakeAuthError("HelloMessage responder_id is not addressed to this responder.");
    }

    const versions: string[] = Array.isArray(hello.supported_versions) ? hello.supported_versions : [];
    const common = SUPPORTED_VERSIONS.filter(v => versions.includes(v));
    if (common.length === 0) {
      throw new HandshakeAuthError(`No common protocol version supported. Peer supports: ${versions.join(",")}`);
    }
    const negotiatedVersion = common[common.length - 1];

    const isPqcStubbed = decodeHex(hello.kem_ciphertext).length === 32;

    const signable = bindFields(
      encodeUTF8("UXSP-HELLO"),
      encodeUTF8(versions.join(",")),
      encodeUTF8(hello.session_id),
      encodeUTF8(hello.initiator_id),
      encodeUTF8(hello.responder_id),
      decodeHex(hello.ephemeral_pub),
      isPqcStubbed ? new Uint8Array(0) : decodeHex(hello.kem_ciphertext),
      encodeUTF8(ts.toString())
    );

    const classicalValid = await verifyEd25519(
      initiatorCard.public_keys.signing_pub,
      decodeHex(hello.classical_sig),
      signable
    );
    if (!classicalValid) {
      throw new HandshakeAuthError("Initiator classical signature verification failed.");
    }

    if (!isPqcStubbed && hello.pqc_sig) {
      const pqcValid = await verifyMLDSA(
        initiatorCard.public_keys.pqc_sig_pub,
        decodeHex(hello.pqc_sig),
        signable
      );
      if (!pqcValid) {
        throw new HandshakeAuthError("Initiator PQC signature verification failed.");
      }
    }

    return { signable, negotiatedVersion };
  }

  private static async _deriveHelloSecret(
    hello: Record<string, any>,
    responder: Identity
  ): Promise<Uint8Array> {
    const ephemeralPubBytes = decodeHex(hello.ephemeral_pub);
    const ephemeralPubBase64 = encodeBase64(ephemeralPubBytes);

    const sharedX25519 = await deriveSharedSecret(
      responder.keys.exchange.privateKey,
      ephemeralPubBase64
    );

    const kemCiphertext = decodeHex(hello.kem_ciphertext);
    const isPqcStubbed = kemCiphertext.length === 32;

    let combinedSecret: Uint8Array;
    if (isPqcStubbed) {
      combinedSecret = sharedX25519;
    } else {
      const kemSharedSecret = await decapsulateMLKEM(
        kemCiphertext,
        responder.keys.kem.privateKey
      );
      combinedSecret = new Uint8Array(sharedX25519.length + kemSharedSecret.length);
      combinedSecret.set(sharedX25519, 0);
      combinedSecret.set(kemSharedSecret, sharedX25519.length);
    }

    const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
    return await hkdf(combinedSecret, ephemeralPubBytes, info, 32);
  }

  private static async _makeAck(
    responder: Identity,
    sessionId: string,
    initiatorId: string,
    sharedSecretA: Uint8Array,
    initiatorCard: PublicCard,
    negotiatedVersion: string
  ): Promise<{ ack: Record<string, any>; respExchange: ExchangeResult }> {
    const ts = Math.floor(Date.now() / 1000);

    const respEphemeral = await generateX25519KeyPair();
    const respEphemeralPubBytes = decodeBase64(respEphemeral.publicKey);

    const sharedX25519 = await deriveSharedSecret(
      respEphemeral.privateKey,
      initiatorCard.public_keys.exchange_pub
    );

    const respKemData = await encapsulateMLKEM(initiatorCard.public_keys.kem_pub);
    const isPqcStubbed = respKemData.ciphertext.length === 32;

    let combinedSecret: Uint8Array;
    if (isPqcStubbed) {
      combinedSecret = sharedX25519;
    } else {
      combinedSecret = new Uint8Array(sharedX25519.length + respKemData.sharedSecret.length);
      combinedSecret.set(sharedX25519, 0);
      combinedSecret.set(respKemData.sharedSecret, sharedX25519.length);
    }

    const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
    const sharedKey = await hkdf(combinedSecret, respEphemeralPubBytes, info, 32);

    const proofBytes = await hmacSha256(
      sharedSecretA,
      encodeUTF8(`${sessionId}:responder-proof`)
    );
    const proof = encodeHex(proofBytes);

    const signable = bindFields(
      encodeUTF8("UXSP-ACK"),
      encodeUTF8(negotiatedVersion),
      encodeUTF8(sessionId),
      encodeUTF8(responder.entity_id),
      encodeUTF8(initiatorId),
      encodeUTF8(proof),
      respEphemeralPubBytes,
      isPqcStubbed ? new Uint8Array(0) : respKemData.ciphertext,
      encodeUTF8(ts.toString())
    );

    const classicalSig = await signEd25519(responder.keys.signing.privateKey, signable);
    let pqcSig: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
    if (!isPqcStubbed) {
      pqcSig = await signMLDSA(responder.keys.pqc_sig.privateKey, signable);
    }

    const ack: Record<string, any> = {
      type: "UXSP-ACK",
      version: negotiatedVersion,
      session_id: sessionId,
      responder_id: responder.entity_id,
      initiator_id: initiatorId,
      timestamp: ts,
      proof: proof,
      ephemeral_pub: encodeHex(respEphemeralPubBytes),
      kem_ciphertext: encodeHex(respKemData.ciphertext),
      classical_sig: encodeHex(classicalSig),
      pqc_sig: encodeHex(pqcSig),
    };

    return {
      ack,
      respExchange: {
        ephemeralPub: respEphemeralPubBytes,
        kemCiphertext: respKemData.ciphertext,
        sharedKey,
      },
    };
  }

  private static async _verifyAckSignature(
    ack: Record<string, any>,
    responderCard: PublicCard,
    maxAge: number = 30
  ): Promise<Uint8Array> {
    const required = [
      "type", "version", "session_id", "responder_id", "initiator_id",
      "timestamp", "proof", "ephemeral_pub", "kem_ciphertext",
      "classical_sig", "pqc_sig"
    ];
    for (const f of required) {
      if (ack[f] === undefined) {
        throw new HandshakeAuthError(`AckMessage missing required field: ${f}`);
      }
    }

    if (ack.type !== "UXSP-ACK") {
      throw new HandshakeAuthError(`Expected UXSP-ACK message, got '${ack.type}'`);
    }

    const ts = Number(ack.timestamp);
    if (isNaN(ts)) {
      throw new HandshakeAuthError("Invalid timestamp in AckMessage.");
    }
    const age = Math.floor(Date.now() / 1000) - ts;
    if (age < -maxAge || age > maxAge) {
      throw new HandshakeExpiredError(`AckMessage age ${age}s is out of bounds. Maximum: ${maxAge}s.`);
    }

    const isPqcStubbed = decodeHex(ack.kem_ciphertext).length === 32;

    const signable = bindFields(
      encodeUTF8("UXSP-ACK"),
      encodeUTF8(String(ack.version)),
      encodeUTF8(String(ack.session_id)),
      encodeUTF8(String(ack.responder_id)),
      encodeUTF8(String(ack.initiator_id)),
      encodeUTF8(String(ack.proof)),
      decodeHex(ack.ephemeral_pub),
      isPqcStubbed ? new Uint8Array(0) : decodeHex(ack.kem_ciphertext),
      encodeUTF8(ts.toString())
    );

    const classicalValid = await verifyEd25519(
      responderCard.public_keys.signing_pub,
      decodeHex(ack.classical_sig),
      signable
    );
    if (!classicalValid) {
      throw new HandshakeAuthError("Responder classical signature verification failed.");
    }

    if (!isPqcStubbed && ack.pqc_sig) {
      const pqcValid = await verifyMLDSA(
        responderCard.public_keys.pqc_sig_pub,
        decodeHex(ack.pqc_sig),
        signable
      );
      if (!pqcValid) {
        throw new HandshakeAuthError("Responder PQC signature verification failed.");
      }
    }

    return signable;
  }

  private static async _deriveAckSecret(
    ack: Record<string, any>,
    sharedSecretA: Uint8Array,
    initiator: Identity
  ): Promise<Uint8Array> {
    const expectedProofBytes = await hmacSha256(
      sharedSecretA,
      encodeUTF8(`${ack.session_id}:responder-proof`)
    );
    const expectedProof = encodeHex(expectedProofBytes);

    if (!constantTimeEqual(ack.proof, expectedProof)) {
      throw new HandshakeProofError("Shared secret proof mismatch. Possible man-in-the-middle attack.");
    }

    const ephemeralPubBytes = decodeHex(ack.ephemeral_pub);
    const ephemeralPubBase64 = encodeBase64(ephemeralPubBytes);

    const sharedX25519 = await deriveSharedSecret(
      initiator.keys.exchange.privateKey,
      ephemeralPubBase64
    );

    const kemCiphertext = decodeHex(ack.kem_ciphertext);
    const isPqcStubbed = kemCiphertext.length === 32;

    let combinedSecret: Uint8Array;
    if (isPqcStubbed) {
      combinedSecret = sharedX25519;
    } else {
      const kemSharedSecret = await decapsulateMLKEM(
        kemCiphertext,
        initiator.keys.kem.privateKey
      );
      combinedSecret = new Uint8Array(sharedX25519.length + kemSharedSecret.length);
      combinedSecret.set(sharedX25519, 0);
      combinedSecret.set(kemSharedSecret, sharedX25519.length);
    }

    const info = encodeUTF8("UXSP-hybrid-key-exchange-v1");
    return await hkdf(combinedSecret, ephemeralPubBytes, info, 32);
  }
}
