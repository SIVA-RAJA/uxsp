/**
 * UXSP WebSocket Transport & Framing Layer
 *
 * Provides typed framing, handshake negotiation, encrypted data transmission,
 * keepalive ping/pong, and authenticated session teardown over WebSocket.
 */

import { Identity } from "./identity.js";
import { PublicCard } from "./types.js";
import { NonceStore, MemoryNonceStore } from "./noncestore.js";
import { Session, SessionConfig } from "./session.js";
import { Handshake } from "./handshake.js";
import { RateLimiterBase } from "./rateLimit.js";
import { encodeUTF8, decodeUTF8, encodeHex, decodeHex } from "./utils.js";

export const MAX_FRAME_BYTES = 1024 * 1024; // 1 MB

export enum FrameType {
  HANDSHAKE_HELLO = "UXSP-HELLO",
  HANDSHAKE_ACK = "UXSP-ACK",
  HANDSHAKE_COMPLETE = "UXSP-COMPLETE",
  DATA = "UXSP-DATA",
  ERROR = "UXSP-ERROR",
  CLOSE = "UXSP-CLOSE",
  PING = "UXSP-PING",
  PONG = "UXSP-PONG",
  RESUME = "UXSP-RESUME",
  RESUME_ACK = "UXSP-RESUME-ACK",
}

export class UXSPWebSocketError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UXSPWebSocketError";
  }
}

export class UnexpectedFrameError extends UXSPWebSocketError {
  constructor(message: string) {
    super(message);
    this.name = "UnexpectedFrameError";
  }
}

export class SessionNotEstablishedError extends UXSPWebSocketError {
  constructor(message: string = "Session not established. Complete handshake first.") {
    super(message);
    this.name = "SessionNotEstablishedError";
  }
}

export class FrameTooLargeError extends UXSPWebSocketError {
  constructor(message: string = "Frame size exceeds maximum allowed limit.") {
    super(message);
    this.name = "FrameTooLargeError";
  }
}

export class UXSPFrame {
  public type: FrameType;
  public payload: Record<string, any>;
  public timestamp: number;

  constructor(type: FrameType, payload?: Record<string, any>, timestamp?: number) {
    this.type = type;
    this.payload = payload || {};
    this.timestamp = timestamp !== undefined ? timestamp : Math.floor(Date.now() / 1000);
  }

  static build(type: FrameType, payload?: Record<string, any>): UXSPFrame {
    return new UXSPFrame(type, payload);
  }

  toJson(): string {
    return JSON.stringify({
      uxsp_frame: this.type,
      timestamp: this.timestamp,
      payload: this.payload,
    });
  }

  static fromJson(text: string | Uint8Array, maxBytes: number = MAX_FRAME_BYTES): UXSPFrame {
    let rawStr: string;
    let byteLen: number;

    if (typeof text === "string") {
      rawStr = text;
      byteLen = encodeUTF8(text).length;
    } else if (text instanceof Uint8Array) {
      byteLen = text.length;
      rawStr = decodeUTF8(text);
    } else {
      throw new UXSPWebSocketError("Frame input must be a string or Uint8Array.");
    }

    if (byteLen > maxBytes) {
      throw new FrameTooLargeError(`Frame size ${byteLen} bytes exceeds maximum ${maxBytes} bytes.`);
    }

    let data: any;
    try {
      data = JSON.parse(rawStr);
    } catch (e: any) {
      throw new UXSPWebSocketError(`Invalid JSON frame: ${e.message}`);
    }

    if (!data || typeof data !== "object") {
      throw new UXSPWebSocketError("JSON frame must be an object.");
    }

    if (!data.uxsp_frame) {
      throw new UXSPWebSocketError("Missing 'uxsp_frame' field. Is this a UXSP message?");
    }

    const frameType = Object.values(FrameType).find(ft => ft === data.uxsp_frame);
    if (!frameType) {
      throw new UXSPWebSocketError(`Unknown frame type: '${data.uxsp_frame}'`);
    }

    const payload = data.payload || {};
    if (typeof payload !== "object") {
      throw new UXSPWebSocketError("Frame payload must be an object.");
    }

    const ts = typeof data.timestamp === "number" ? data.timestamp : Math.floor(Date.now() / 1000);

    return new UXSPFrame(frameType, payload, ts);
  }
}

export class UXSPWebSocket {
  private _identity: Identity;
  private _config: SessionConfig | null = null;
  private _nonceStore: NonceStore;
  private _session: Session | null = null;
  private _hs: Handshake | null = null;
  private _role: "initiator" | "responder" | null = null;
  private _remoteCard: PublicCard | null = null;
  private _limiter: RateLimiterBase | null = null;

  constructor(
    identity: Identity,
    config?: SessionConfig,
    nonceStore?: NonceStore
  ) {
    this._identity = identity;
    this._config = config || null;
    this._nonceStore = nonceStore || new MemoryNonceStore();
  }

  static asInitiator(
    identity: Identity,
    remoteCard: PublicCard,
    config?: SessionConfig,
    nonceStore?: NonceStore
  ): UXSPWebSocket {
    const ws = new UXSPWebSocket(identity, config, nonceStore);
    ws._role = "initiator";
    ws._remoteCard = remoteCard;
    return ws;
  }

  static asResponder(
    identity: Identity,
    limiter?: RateLimiterBase,
    config?: SessionConfig,
    nonceStore?: NonceStore
  ): UXSPWebSocket {
    const ws = new UXSPWebSocket(identity, config, nonceStore);
    ws._role = "responder";
    ws._limiter = limiter || null;
    return ws;
  }

  // ─────────────────────────────────────────
  // INITIATOR METHODS
  // ─────────────────────────────────────────

  async startHandshake(): Promise<UXSPFrame> {
    if (!this._remoteCard) {
      throw new UXSPWebSocketError("No remote card. Use UXSPWebSocket.asInitiator() with responder card.");
    }
    this._hs = await Handshake.initiate(this._identity, this._remoteCard, this._config || undefined);
    return UXSPFrame.build(FrameType.HANDSHAKE_HELLO, this._hs.helloMessage);
  }

  async completeHandshake(ackFrame: UXSPFrame): Promise<UXSPFrame> {
    if (!this._hs || !this._remoteCard) {
      throw new SessionNotEstablishedError("completeHandshake() called before startHandshake().");
    }
    if (ackFrame.type !== FrameType.HANDSHAKE_ACK) {
      throw new UnexpectedFrameError(`Expected HANDSHAKE_ACK, got ${ackFrame.type}`);
    }
    this._session = await this._hs.complete(ackFrame.payload, this._remoteCard, this._nonceStore);
    return UXSPFrame.build(FrameType.HANDSHAKE_COMPLETE, { session_id: this._session.sessionId });
  }

  async startResume(): Promise<UXSPFrame> {
    if (!this._session || !this._session.isActive) {
      throw new SessionNotEstablishedError("Cannot resume: no active session found.");
    }
    const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
    const nonce = encodeHex(nonceBytes);
    const lastSeq = this._session.recvSeq;
    const msg = encodeUTF8(`RESUME:${this._session.sessionId}:${lastSeq}:${nonce}`);
    const authTag = await this._session.computeAuthTag(msg, "send");

    return UXSPFrame.build(FrameType.RESUME, {
      session_id: this._session.sessionId,
      last_seq: lastSeq,
      nonce: nonce,
      auth_tag: authTag,
    });
  }

  async completeResume(ackFrame: UXSPFrame): Promise<void> {
    if (!this._session || !this._session.isActive) {
      throw new SessionNotEstablishedError("Cannot complete resume: session is not active.");
    }
    if (ackFrame.type !== FrameType.RESUME_ACK) {
      throw new UnexpectedFrameError(`Expected UXSP-RESUME-ACK, got ${ackFrame.type}`);
    }
    const payload = ackFrame.payload;
    const sid = payload.session_id;
    if (sid !== this._session.sessionId) {
      throw new UXSPWebSocketError(
        `RESUME_ACK session_id '${sid}' does not match session '${this._session.sessionId}'`
      );
    }
    const lastSeq = payload.last_seq || 0;
    const nonce = payload.nonce || "";
    const authTag = payload.auth_tag || "";
    const msg = encodeUTF8(`RESUME_ACK:${this._session.sessionId}:${lastSeq}:${nonce}`);
    const valid = await this._session.verifyAuthTag(msg, authTag, "recv");
    if (!valid) {
      throw new UXSPWebSocketError("Invalid resume ack authentication tag: verification failed.");
    }
  }

  // ─────────────────────────────────────────
  // RESPONDER METHODS
  // ─────────────────────────────────────────

  async handleHello(helloFrame: UXSPFrame, initiatorCard: PublicCard): Promise<UXSPFrame> {
    if (this._hs !== null) {
      throw new UXSPWebSocketError("handleHello() called twice. Possible handshake replay.");
    }
    if (helloFrame.type !== FrameType.HANDSHAKE_HELLO) {
      throw new UnexpectedFrameError(`Expected HANDSHAKE_HELLO, got ${helloFrame.type}`);
    }

    if (this._limiter) {
      this._limiter.check(initiatorCard.entity_id);
    }

    this._hs = await Handshake.respond(
      this._identity,
      helloFrame.payload,
      initiatorCard,
      this._nonceStore,
      this._config || undefined
    );
    this._remoteCard = initiatorCard;
    return UXSPFrame.build(FrameType.HANDSHAKE_ACK, this._hs.ackMessage);
  }

  async handleComplete(completeFrame: UXSPFrame): Promise<void> {
    if (!this._hs) {
      throw new SessionNotEstablishedError("handleComplete() called before handleHello().");
    }
    if (completeFrame.type !== FrameType.HANDSHAKE_COMPLETE) {
      throw new UnexpectedFrameError(`Expected HANDSHAKE_COMPLETE, got ${completeFrame.type}`);
    }
    if (this._session !== null) {
      throw new UXSPWebSocketError("Handshake already completed. Possible replay of COMPLETE frame.");
    }

    const expectedSid = this._hs.session.sessionId;
    const receivedSid = completeFrame.payload?.session_id;
    if (receivedSid !== expectedSid) {
      throw new UXSPWebSocketError(
        `COMPLETE frame session_id '${receivedSid}' does not match handshake session '${expectedSid}'.`
      );
    }
    this._session = this._hs.session;
  }

  async handleResume(resumeFrame: UXSPFrame, session?: Session): Promise<UXSPFrame> {
    if (resumeFrame.type !== FrameType.RESUME) {
      throw new UnexpectedFrameError(`Expected UXSP-RESUME, got ${resumeFrame.type}`);
    }
    const sess = session || this._session;
    if (!sess || !sess.isActive) {
      throw new SessionNotEstablishedError("Cannot resume: session not found or expired.");
    }

    const payload = resumeFrame.payload;
    const sid = payload.session_id;
    if (sid !== sess.sessionId) {
      throw new UXSPWebSocketError(`Session ID mismatch: expected ${sess.sessionId}, got ${sid}`);
    }

    const lastSeq = payload.last_seq || 0;
    const nonce = payload.nonce || "";
    const authTag = payload.auth_tag || "";
    const msg = encodeUTF8(`RESUME:${sess.sessionId}:${lastSeq}:${nonce}`);
    const valid = await sess.verifyAuthTag(msg, authTag, "recv");
    if (!valid) {
      throw new UXSPWebSocketError("Invalid resume authentication tag: verification failed.");
    }

    this._session = sess;
    const respNonceBytes = crypto.getRandomValues(new Uint8Array(16));
    const respNonce = encodeHex(respNonceBytes);
    const respLastSeq = sess.recvSeq;
    const respMsg = encodeUTF8(`RESUME_ACK:${sess.sessionId}:${respLastSeq}:${respNonce}`);
    const respTag = await sess.computeAuthTag(respMsg, "send");

    return UXSPFrame.build(FrameType.RESUME_ACK, {
      session_id: sess.sessionId,
      last_seq: respLastSeq,
      nonce: respNonce,
      auth_tag: respTag,
    });
  }

  // ─────────────────────────────────────────
  // DATA TRANSMISSION
  // ─────────────────────────────────────────

  async encode(plaintext: Uint8Array): Promise<UXSPFrame> {
    if (!this._session) {
      throw new SessionNotEstablishedError("Cannot send data before handshake is complete.");
    }
    const encrypted = await this._session.encrypt(plaintext);
    return UXSPFrame.build(FrameType.DATA, encrypted);
  }

  async decode(frame: UXSPFrame): Promise<Uint8Array> {
    if (!this._session) {
      throw new SessionNotEstablishedError("Cannot receive data before handshake is complete.");
    }
    if (frame.type !== FrameType.DATA) {
      throw new UnexpectedFrameError(`Expected DATA frame, got ${frame.type}`);
    }
    return await this._session.decrypt(frame.payload as any);
  }

  // ─────────────────────────────────────────
  // KEEPALIVE AND TEARDOWN
  // ─────────────────────────────────────────

  async ping(): Promise<UXSPFrame> {
    const payload: Record<string, any> = { ts: Math.floor(Date.now() / 1000) };
    if (this._session) {
      const encrypted = await this._session.encrypt(encodeUTF8(JSON.stringify(payload)));
      return UXSPFrame.build(FrameType.PING, encrypted);
    }
    return UXSPFrame.build(FrameType.PING, payload);
  }

  async pong(pingFrame: UXSPFrame): Promise<UXSPFrame> {
    let ts: number;
    if (this._session && pingFrame.payload.ciphertext) {
      try {
        const decrypted = await this._session.decrypt(pingFrame.payload as any);
        const parsed = JSON.parse(decodeUTF8(decrypted));
        ts = parsed.ts;
      } catch {
        ts = pingFrame.payload.ts || Math.floor(Date.now() / 1000);
      }
    } else {
      ts = pingFrame.payload.ts || Math.floor(Date.now() / 1000);
    }

    const payload = { echo_ts: ts };
    if (this._session) {
      const encrypted = await this._session.encrypt(encodeUTF8(JSON.stringify(payload)));
      return UXSPFrame.build(FrameType.PONG, encrypted);
    }
    return UXSPFrame.build(FrameType.PONG, payload);
  }

  async close(reason: string = "normal"): Promise<UXSPFrame> {
    if (this._session) {
      const payload = encodeUTF8(JSON.stringify({ reason }));
      const encrypted = await this._session.encrypt(payload);
      this._session.revoke();
      this._session = null;
      return UXSPFrame.build(FrameType.CLOSE, encrypted);
    }
    return UXSPFrame.build(FrameType.CLOSE, { reason });
  }

  async handleClose(frame: UXSPFrame): Promise<string> {
    if (frame.type !== FrameType.CLOSE) {
      throw new UnexpectedFrameError(`Expected CLOSE frame, got ${frame.type}`);
    }
    if (this._session) {
      let reason = "unknown";
      try {
        if (frame.payload.ciphertext) {
          const decrypted = await this._session.decrypt(frame.payload as any);
          const parsed = JSON.parse(decodeUTF8(decrypted));
          reason = parsed.reason || "normal";
        } else {
          reason = frame.payload.reason || "unauthenticated-close";
        }
      } catch {
        reason = "unauthenticated-close";
      } finally {
        this._session.revoke();
        this._session = null;
      }
      return reason;
    }
    return frame.payload.reason || "unknown";
  }

  get session(): Session {
    if (!this._session) {
      throw new SessionNotEstablishedError();
    }
    return this._session;
  }

  get isReady(): boolean {
    return this._session !== null && this._session.isReady;
  }
}

export interface ReconnectingWebSocketOptions {
  maxRetries?: number;
  initialBackoffMs?: number;
  maxBackoffMs?: number;
  config?: SessionConfig;
  nonceStore?: NonceStore;
  WebSocketClass?: any;
}

export class UXSPReconnectingWebSocket {
  private _url: string;
  private _identity: Identity;
  private _remoteCard: PublicCard;
  private _options: ReconnectingWebSocketOptions;
  private _ws: any = null;
  private _uxsp: UXSPWebSocket;
  private _listeners: Record<string, ((...args: any[]) => void)[]> = {};
  private _retryCount: number = 0;
  private _isClosedExplicitly: boolean = false;
  private _pendingQueue: Uint8Array[] = [];

  constructor(
    url: string,
    identity: Identity,
    remoteCard: PublicCard,
    options?: ReconnectingWebSocketOptions
  ) {
    this._url = url;
    this._identity = identity;
    this._remoteCard = remoteCard;
    this._options = options || {};
    this._uxsp = UXSPWebSocket.asInitiator(identity, remoteCard, options?.config, options?.nonceStore);
  }

  on(event: "open" | "message" | "close" | "error" | "resumed", cb: (...args: any[]) => void): this {
    if (!this._listeners[event]) this._listeners[event] = [];
    this._listeners[event].push(cb);
    return this;
  }

  private emit(event: string, ...args: any[]): void {
    const list = this._listeners[event];
    if (list) {
      for (const cb of list) {
        try {
          cb(...args);
        } catch {
          // ignore callback error
        }
      }
    }
  }

  async connect(): Promise<void> {
    this._isClosedExplicitly = false;
    await this._connectInternal();
  }

  private async _connectInternal(): Promise<void> {
    const WS = this._options.WebSocketClass || (typeof globalThis.WebSocket !== "undefined" ? globalThis.WebSocket : null);
    if (!WS) {
      throw new Error("No WebSocket implementation found in global scope.");
    }

    return new Promise<void>((resolve, reject) => {
      let opened = false;
      const ws = new WS(this._url);
      this._ws = ws;

      ws.onopen = async () => {
        try {
          if (this._uxsp.isReady) {
            // Attempt resumption
            const resumeFrame = await this._uxsp.startResume();
            ws.send(resumeFrame.toJson());
          } else {
            // New handshake
            const helloFrame = await this._uxsp.startHandshake();
            ws.send(helloFrame.toJson());
          }
        } catch (err) {
          this.emit("error", err);
          if (!opened) reject(err);
        }
      };

      ws.onmessage = async (event: any) => {
        try {
          const rawData = typeof event.data === "string" ? event.data : new TextDecoder().decode(event.data);
          const frame = UXSPFrame.fromJson(rawData);

          if (frame.type === FrameType.HANDSHAKE_ACK) {
            const comp = await this._uxsp.completeHandshake(frame);
            ws.send(comp.toJson());
            this._retryCount = 0;
            opened = true;
            this.emit("open");
            this._flushQueue();
            resolve();
          } else if (frame.type === FrameType.RESUME_ACK) {
            await this._uxsp.completeResume(frame);
            this._retryCount = 0;
            opened = true;
            this.emit("resumed");
            this.emit("open");
            this._flushQueue();
            resolve();
          } else if (frame.type === FrameType.DATA) {
            const plaintext = await this._uxsp.decode(frame);
            this.emit("message", plaintext);
          } else if (frame.type === FrameType.PING) {
            const pong = await this._uxsp.pong(frame);
            ws.send(pong.toJson());
          } else if (frame.type === FrameType.CLOSE) {
            await this._uxsp.handleClose(frame);
            this.emit("close");
          }
        } catch (err) {
          this.emit("error", err);
        }
      };

      ws.onerror = (event: any) => {
        this.emit("error", event);
        if (!opened) reject(new Error("WebSocket connection error during handshake."));
      };

      ws.onclose = () => {
        this._ws = null;
        if (!this._isClosedExplicitly) {
          this._scheduleReconnect();
        } else {
          this.emit("close");
        }
      };
    });
  }

  private _scheduleReconnect(): void {
    const maxRetries = this._options.maxRetries ?? 10;
    if (this._retryCount >= maxRetries) {
      this.emit("error", new Error(`Max reconnect retries (${maxRetries}) exceeded.`));
      this.emit("close");
      return;
    }

    const initBackoff = this._options.initialBackoffMs ?? 200;
    const maxBackoff = this._options.maxBackoffMs ?? 5000;
    const delay = Math.min(initBackoff * Math.pow(1.5, this._retryCount), maxBackoff);
    this._retryCount++;

    setTimeout(() => {
      if (!this._isClosedExplicitly) {
        this._connectInternal().catch((err) => {
          this.emit("error", err);
        });
      }
    }, delay);
  }

  private _flushQueue(): void {
    while (this._pendingQueue.length > 0 && this._ws && this._uxsp.isReady) {
      const data = this._pendingQueue.shift()!;
      this.send(data).catch((err) => this.emit("error", err));
    }
  }

  async send(data: Uint8Array | string): Promise<void> {
    const bytes = typeof data === "string" ? encodeUTF8(data) : data;
    if (!this._ws || !this._uxsp.isReady) {
      this._pendingQueue.push(bytes);
      return;
    }
    const frame = await this._uxsp.encode(bytes);
    this._ws.send(frame.toJson());
  }

  async close(reason: string = "normal"): Promise<void> {
    this._isClosedExplicitly = true;
    if (this._ws && this._uxsp.isReady) {
      try {
        const closeFrame = await this._uxsp.close(reason);
        this._ws.send(closeFrame.toJson());
      } catch {
        // ignore send error on close
      }
      this._ws.close();
    }
  }

  get isReady(): boolean {
    return this._uxsp.isReady;
  }

  get session(): Session {
    return this._uxsp.session;
  }
}
