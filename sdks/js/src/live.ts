/**
 * UXSP Live Streaming Module (`live.ts`)
 * 
 * High-performance, zero-parsing symmetric encryption for WebRTC video frames,
 * DataChannels, or raw WebSockets in the browser.
 */

import { UXSPEnvelope, PublicCard } from "./types.js";
import { Identity } from "./identity.js";
import { seal, openSeal } from "./seal.js";
import { aesGcmEncrypt, aesGcmDecrypt } from "./crypto.js";

const KEY_SIZE = 32;
const NONCE_SIZE = 12;

export class LiveSession {
  public key: Uint8Array;

  constructor(key: Uint8Array) {
    if (key.byteLength !== KEY_SIZE) {
      throw new Error(`LiveSession key must be ${KEY_SIZE} bytes.`);
    }
    this.key = key;
  }

  /**
   * Encrypt a raw binary frame (e.g., from WebRTC Insertable Streams or DataChannel).
   * Optionally attaches unencrypted (but mathematically authenticated) metadata.
   * 
   * Format: [2-byte Metadata Length] [Metadata Bytes] [12-byte Nonce] [Ciphertext]
   */
  async encryptFrame(frame: Uint8Array, metadata?: Uint8Array): Promise<Uint8Array> {
    const meta = metadata || new Uint8Array(0);
    if (meta.byteLength > 65535) {
      throw new Error("Metadata too large (max 65535 bytes).");
    }

    const nonce = new Uint8Array(NONCE_SIZE);
    crypto.getRandomValues(nonce);

    const ciphertext = await aesGcmEncrypt(this.key, nonce, frame, meta);

    // Combine: [2-byte length] + [metadata] + [nonce] + [ciphertext]
    const payload = new Uint8Array(2 + meta.byteLength + nonce.byteLength + ciphertext.byteLength);
    
    // Write 2-byte length (Big Endian)
    const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
    view.setUint16(0, meta.byteLength, false);

    payload.set(meta, 2);
    payload.set(nonce, 2 + meta.byteLength);
    payload.set(ciphertext, 2 + meta.byteLength + nonce.byteLength);

    return payload;
  }

  /**
   * Decrypt a raw binary frame.
   * Returns both the decrypted frame and the unencrypted metadata.
   */
  async decryptFrame(encryptedFrame: Uint8Array): Promise<{ frame: Uint8Array; metadata: Uint8Array }> {
    if (encryptedFrame.byteLength < 2) {
      throw new Error("Encrypted frame is too small to contain length header.");
    }

    const view = new DataView(encryptedFrame.buffer, encryptedFrame.byteOffset, encryptedFrame.byteLength);
    const metaLen = view.getUint16(0, false);

    if (encryptedFrame.byteLength < 2 + metaLen + NONCE_SIZE) {
      throw new Error("Encrypted frame is too small to contain metadata and nonce.");
    }

    const metadata = encryptedFrame.slice(2, 2 + metaLen);
    const nonce = encryptedFrame.slice(2 + metaLen, 2 + metaLen + NONCE_SIZE);
    const ciphertext = encryptedFrame.slice(2 + metaLen + NONCE_SIZE);

    const frame = await aesGcmDecrypt(this.key, nonce, ciphertext, metadata);
    return { frame, metadata };
  }

  /**
   * Create a new LiveSession, returning the AES-GCM wrapper and the sealed envelope
   * to transmit to the peer via signaling.
   */
  static async create(
    sender: Identity,
    receiverCard: PublicCard
  ): Promise<{ envelope: UXSPEnvelope; session: LiveSession }> {
    const key = new Uint8Array(KEY_SIZE);
    crypto.getRandomValues(key);

    const envelope = await seal(sender, receiverCard, key);
    const session = new LiveSession(key);

    return { envelope, session };
  }

  /**
   * Accept an incoming LiveSession envelope from a peer, decrypting the 32-byte key.
   */
  static async accept(
    receiver: Identity,
    senderCard: PublicCard,
    envelope: UXSPEnvelope
  ): Promise<LiveSession> {
    const key = await openSeal(receiver, senderCard, envelope);
    return new LiveSession(key);
  }
}

export interface AudioMetadata {
  type: string;
  codec: string;
  sampleRate: number;
  channels: number;
  sequence: number;
  isMuted: boolean;
  extra?: string;
  extraBytes?: Uint8Array;
  [key: string]: any;
}

export class LiveVoiceSession extends LiveSession {
  public codec: string;
  public sampleRate: number;
  public channels: number;
  public sequence: number = 0;
  public isMuted: boolean = false;

  constructor(key: Uint8Array, codec = "opus", sampleRate = 48000, channels = 1) {
    super(key);
    this.codec = codec;
    this.sampleRate = sampleRate;
    this.channels = channels;
  }

  mute(): void {
    this.isMuted = true;
  }

  unmute(): void {
    this.isMuted = false;
  }

  nextSequence(): number {
    this.sequence += 1;
    return this.sequence;
  }

  async encryptVoiceFrame(
    frame: Uint8Array,
    options?: {
      codec?: string;
      sampleRate?: number;
      channels?: number;
      sequence?: number;
      isMuted?: boolean;
      metadata?: Uint8Array;
    }
  ): Promise<Uint8Array> {
    const seq = options?.sequence !== undefined ? options.sequence : this.nextSequence();
    const muted = options?.isMuted !== undefined ? options.isMuted : this.isMuted;
    const cd = options?.codec || this.codec;
    const sr = options?.sampleRate || this.sampleRate;
    const ch = options?.channels || this.channels;

    const audioMeta: Record<string, any> = {
      type: "voice",
      codec: cd,
      sample_rate: sr,
      channels: ch,
      sequence: seq,
      is_muted: muted,
    };

    if (options?.metadata && options.metadata.byteLength > 0) {
      audioMeta.extra = Array.from(options.metadata)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    const metaBytes = new TextEncoder().encode(JSON.stringify(audioMeta));
    return this.encryptFrame(frame, metaBytes);
  }

  async decryptVoiceFrame(
    encryptedFrame: Uint8Array
  ): Promise<{ frame: Uint8Array; audioMetadata: AudioMetadata }> {
    const { frame, metadata } = await this.decryptFrame(encryptedFrame);
    try {
      const metaText = new TextDecoder().decode(metadata);
      const parsed = JSON.parse(metaText);
      const audioMeta: AudioMetadata = {
        type: parsed.type || "voice",
        codec: parsed.codec || "opus",
        sampleRate: parsed.sample_rate || 48000,
        channels: parsed.channels || 1,
        sequence: parsed.sequence || 0,
        isMuted: Boolean(parsed.is_muted),
      };

      if (parsed.extra && typeof parsed.extra === "string") {
        const hex = parsed.extra;
        const match = hex.match(/.{1,2}/g);
        if (match) {
          audioMeta.extraBytes = new Uint8Array(match.map((byte: string) => parseInt(byte, 16)));
        }
      }

      return { frame, audioMetadata: audioMeta };
    } catch {
      return {
        frame,
        audioMetadata: {
          type: "raw",
          codec: "unknown",
          sampleRate: 0,
          channels: 0,
          sequence: 0,
          isMuted: false,
          extraBytes: metadata,
        },
      };
    }
  }

  static async createVoice(
    sender: Identity,
    receiverCard: PublicCard,
    options?: { codec?: string; sampleRate?: number; channels?: number }
  ): Promise<{ envelope: UXSPEnvelope; session: LiveVoiceSession }> {
    const key = new Uint8Array(KEY_SIZE);
    crypto.getRandomValues(key);

    const envelope = await seal(sender, receiverCard, key);
    const session = new LiveVoiceSession(
      key,
      options?.codec || "opus",
      options?.sampleRate || 48000,
      options?.channels || 1
    );

    return { envelope, session };
  }

  static async acceptVoice(
    receiver: Identity,
    senderCard: PublicCard,
    envelope: UXSPEnvelope,
    options?: { codec?: string; sampleRate?: number; channels?: number }
  ): Promise<LiveVoiceSession> {
    const key = await openSeal(receiver, senderCard, envelope);
    return new LiveVoiceSession(
      key,
      options?.codec || "opus",
      options?.sampleRate || 48000,
      options?.channels || 1
    );
  }
}

