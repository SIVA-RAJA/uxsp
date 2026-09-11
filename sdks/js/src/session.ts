/**
 * UXSP Stateful Session Management
 *
 * Implements sequenced, stateful, expiring sessions with cryptographically
 * decoupled bidirectional encryption keys and sequence replay protection.
 */

import { hkdf, aesGcmEncrypt, aesGcmDecrypt, zeroize, hmacSha256, constantTimeEqual } from "./crypto.js";
import { encodeUTF8, encodeHex, decodeHex } from "./utils.js";

export enum SessionState {
  PENDING = "PENDING",
  ACTIVE = "ACTIVE",
  EXPIRED = "EXPIRED",
  REVOKED = "REVOKED",
}

export class SessionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionError";
  }
}

export class SessionExpiredError extends SessionError {
  constructor(message: string = "Session expired. Re-establish via Handshake.") {
    super(message);
    this.name = "SessionExpiredError";
  }
}

export class SessionRevokedError extends SessionError {
  constructor(message: string = "Session was revoked.") {
    super(message);
    this.name = "SessionRevokedError";
  }
}

export class SessionNotActiveError extends SessionError {
  constructor(message: string = "Session is not in ACTIVE state.") {
    super(message);
    this.name = "SessionNotActiveError";
  }
}

export class SessionReorderError extends SessionError {
  constructor(message: string) {
    super(message);
    this.name = "SessionReorderError";
  }
}

export interface SessionConfigOptions {
  maxLifetimeSeconds?: number;
  maxMessages?: number;
  keyInfo?: string;
  enforceOrdering?: boolean;
}

export class SessionConfig {
  public maxLifetimeSeconds: number;
  public maxMessages: number;
  public keyInfo: string;
  public enforceOrdering: boolean;

  constructor(options?: SessionConfigOptions) {
    this.maxLifetimeSeconds = options?.maxLifetimeSeconds ?? 3600;
    this.maxMessages = options?.maxMessages ?? 10000;
    this.keyInfo = options?.keyInfo ?? "UXSP-session-key-v1";
    this.enforceOrdering = options?.enforceOrdering ?? true;

    if (this.maxLifetimeSeconds <= 0) {
      throw new Error("maxLifetimeSeconds must be positive");
    }
    if (this.maxMessages <= 0) {
      throw new Error("maxMessages must be positive");
    }
    if (!this.keyInfo) {
      throw new Error("keyInfo cannot be empty");
    }
  }
}

export interface EncryptedSessionPayload {
  session_id: string;
  seq: number;
  ciphertext: string;
  nonce: string;
}

export class Session {
  public sessionId: string;
  public localId: string;
  public remoteId: string;
  public config: SessionConfig;

  private _state: SessionState = SessionState.PENDING;
  private _createdAt: number;
  private _sendSeq: number = 0;
  private _recvSeq: number = 0;
  private _recvCount: number = 0;
  private _seenSeqs = new Set<number>();
  private _maxSeenSeq: number = -1;
  private static readonly WINDOW_SIZE = 128;

  private _sendKey: Uint8Array | null = null;
  private _recvKey: Uint8Array | null = null;
  private _keyInitPromise: Promise<void>;

  constructor(
    sessionId: string,
    localId: string,
    remoteId: string,
    sharedSecret: Uint8Array,
    isInitiator: boolean,
    config?: SessionConfig
  ) {
    this.sessionId = sessionId;
    this.localId = localId;
    this.remoteId = remoteId;
    this.config = config || new SessionConfig();
    this._createdAt = Date.now();

    // Cryptographically decouple directional keys using HKDF info strings
    const salt = new Uint8Array(0);
    const sendInfo = encodeUTF8(
      this.config.keyInfo + ":enc" + (isInitiator ? ":init_to_resp" : ":resp_to_init")
    );
    const recvInfo = encodeUTF8(
      this.config.keyInfo + ":enc" + (isInitiator ? ":resp_to_init" : ":init_to_resp")
    );

    this._keyInitPromise = (async () => {
      this._sendKey = await hkdf(sharedSecret, salt, sendInfo, 32);
      this._recvKey = await hkdf(sharedSecret, salt, recvInfo, 32);
    })();
  }

  async ready(): Promise<void> {
    await this._keyInitPromise;
  }

  activate(): void {
    if (this._state !== SessionState.PENDING) {
      throw new SessionError(`Cannot activate session in state ${this._state}`);
    }
    this._state = SessionState.ACTIVE;
  }

  get state(): SessionState {
    this.evaluateExpiry();
    return this._state;
  }

  get isActive(): boolean {
    this.evaluateExpiry();
    return this._state === SessionState.ACTIVE;
  }

  get isReady(): boolean {
    return this.isActive;
  }

  get sendSeq(): number {
    return this._sendSeq;
  }

  get recvSeq(): number {
    return this._recvSeq;
  }

  async computeAuthTag(message: Uint8Array, direction: "send" | "recv" = "send"): Promise<string> {
    await this.ready();
    const key = direction === "send" ? this._sendKey : this._recvKey;
    if (!key) {
      throw new SessionError("Session keys are not available or revoked.");
    }
    const tagBytes = await hmacSha256(key, message);
    return encodeHex(tagBytes);
  }

  async verifyAuthTag(message: Uint8Array, tagHex: string, direction: "send" | "recv" = "recv"): Promise<boolean> {
    const expected = await this.computeAuthTag(message, direction);
    return constantTimeEqual(encodeUTF8(expected), encodeUTF8(tagHex));
  }

  private evaluateExpiry(): void {
    if (this._state !== SessionState.ACTIVE) return;
    const elapsedSec = (Date.now() - this._createdAt) / 1000;
    if (elapsedSec > this.config.maxLifetimeSeconds) {
      this._state = SessionState.EXPIRED;
      return;
    }
    const recv = this.config.enforceOrdering ? this._recvSeq : this._recvCount;
    const total = this._sendSeq + recv;
    if (total >= this.config.maxMessages) {
      this._state = SessionState.EXPIRED;
    }
  }

  private checkActive(): void {
    this.evaluateExpiry();
    if (this._state === SessionState.EXPIRED) {
      throw new SessionExpiredError();
    }
    if (this._state === SessionState.REVOKED) {
      throw new SessionRevokedError();
    }
    if (this._state !== SessionState.ACTIVE) {
      throw new SessionNotActiveError(`Session is in state ${this._state}, not ACTIVE.`);
    }
  }

  revoke(): void {
    this._state = SessionState.REVOKED;
    if (this._sendKey) {
      zeroize(this._sendKey);
      this._sendKey = null;
    }
    if (this._recvKey) {
      zeroize(this._recvKey);
      this._recvKey = null;
    }
  }

  async encrypt(plaintext: Uint8Array): Promise<EncryptedSessionPayload> {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError("plaintext must be a Uint8Array");
    }
    await this._keyInitPromise;
    this.checkActive();

    if (!this._sendKey) {
      throw new SessionError("Session sendKey is not available.");
    }

    const seq = this._sendSeq;
    this._sendSeq++;

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ad = encodeUTF8(`${this.sessionId}:${seq}`);
    const ciphertext = await aesGcmEncrypt(this._sendKey, nonce, plaintext, ad);

    this.evaluateExpiry();

    return {
      session_id: this.sessionId,
      seq: seq,
      ciphertext: encodeHex(ciphertext),
      nonce: encodeHex(nonce),
    };
  }

  async decrypt(payload: EncryptedSessionPayload): Promise<Uint8Array> {
    if (!payload || typeof payload !== "object") {
      throw new TypeError("Payload must be an object");
    }
    await this._keyInitPromise;
    this.checkActive();

    if (!this._recvKey) {
      throw new SessionError("Session recvKey is not available.");
    }

    if (payload.session_id !== this.sessionId) {
      throw new SessionError(
        `Payload session_id mismatch: expected ${this.sessionId.slice(0, 8)}, got ${String(payload.session_id).slice(0, 8)}`
      );
    }

    const seq = payload.seq;
    if (typeof seq !== "number" || seq < 0) {
      throw new SessionError("Invalid sequence number");
    }

    if (this.config.enforceOrdering) {
      if (seq < this._recvSeq) {
        throw new SessionReorderError(`Sequence replay: seq=${seq} already received (expected ${this._recvSeq})`);
      }
      if (seq > this._recvSeq) {
        throw new SessionReorderError(`Sequence reorder: seq=${seq} arrived out of order (expected ${this._recvSeq})`);
      }
      this._recvSeq++;
    } else {
      // Sliding window logic
      if (this._seenSeqs.has(seq)) {
        throw new SessionReorderError(`Sequence replay: seq=${seq} already seen in session.`);
      }
      if (seq < this._maxSeenSeq - Session.WINDOW_SIZE) {
        throw new SessionReorderError(`Sequence number ${seq} is too old (outside sliding window).`);
      }
      this._seenSeqs.add(seq);
      if (seq > this._maxSeenSeq) {
        this._maxSeenSeq = seq;
      }
      this._recvCount++;
    }

    const nonce = decodeHex(payload.nonce);
    const ciphertext = decodeHex(payload.ciphertext);
    const ad = encodeUTF8(`${this.sessionId}:${seq}`);

    try {
      const plaintext = await aesGcmDecrypt(this._recvKey, nonce, ciphertext, ad);
      this.evaluateExpiry();
      return plaintext;
    } catch (e: any) {
      throw new SessionError(`Failed to authenticate/decrypt session payload: ${e.message}`);
    }
  }
}
