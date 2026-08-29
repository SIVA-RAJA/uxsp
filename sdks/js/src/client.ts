import { SecurePackage, CreatePackageOptions, PublicCard } from "./types.js";
import { validatePackage, validatePublicCard } from "./schema.js";
import { Identity } from "./identity.js";
import { seal, openSeal } from "./seal.js";

/**
 * UXSP High-Level Browser Client SDK.
 * Provides client package construction, parsing, serialization, and header generation.
 */
export class UXSPClient {
  /**
   * Create a standardized SecurePackage wire object.
   */
  static createPackage(options: CreatePackageOptions): SecurePackage {
    const pkg: SecurePackage = {
      uxsp_package_version: "1.0",
      sender_id: options.sender_id,
      receiver_id: options.receiver_id,
      data_type: options.data_type || "TEXT",
      is_chunked: Boolean(options.chunks && options.chunks.length > 0),
      envelope: options.envelope || null,
      chunks: options.chunks || [],
      metadata: options.metadata || {},
    };

    if (!validatePackage(pkg)) {
      throw new Error("Failed to validate created UXSP SecurePackage against wire schema.");
    }
    return pkg;
  }

  /**
   * Create an encrypted SecurePackage from plaintext data.
   */
  static async createEncryptedPackage(
    sender: Identity,
    recipientCard: PublicCard,
    plaintext: Uint8Array,
    dataType: string = "TEXT",
    metadata: Record<string, unknown> = {}
  ): Promise<SecurePackage> {
    const envelope = await seal(sender, recipientCard, plaintext);
    return this.createPackage({
      sender_id: sender.entity_id,
      receiver_id: recipientCard.entity_id,
      data_type: dataType,
      envelope: envelope,
      metadata: metadata,
    });
  }

  /**
   * Decrypt a SecurePackage using the receiver's identity.
   */
  static async openEncryptedPackage(
    receiver: Identity,
    senderCard: PublicCard,
    pkg: SecurePackage
  ): Promise<Uint8Array> {
    if (pkg.is_chunked) {
      if (!pkg.chunks || pkg.chunks.length === 0) {
        throw new Error("Package is marked as chunked but contains no chunks.");
      }
      const decryptedChunks: Uint8Array[] = [];
      let totalLength = 0;
      for (const chunkEnvelope of pkg.chunks) {
        const decrypted = await openSeal(receiver, senderCard, chunkEnvelope);
        decryptedChunks.push(decrypted);
        totalLength += decrypted.length;
      }
      const result = new Uint8Array(totalLength);
      let offset = 0;
      for (const chunk of decryptedChunks) {
        result.set(chunk, offset);
        offset += chunk.length;
      }
      return result;
    }
    if (!pkg.envelope) {
      throw new Error("SecurePackage is missing its envelope.");
    }
    return await openSeal(receiver, senderCard, pkg.envelope);
  }

  /**
   * Parse and validate a SecurePackage JSON string or object.
   */
  static parsePackage(input: string | Record<string, unknown>): SecurePackage {
    const data = typeof input === "string" ? JSON.parse(input) : input;
    if (!validatePackage(data)) {
      throw new Error("Invalid UXSP SecurePackage payload format.");
    }
    return data;
  }

  /**
   * Serialize a SecurePackage object to a JSON string.
   */
  static serializePackage(pkg: SecurePackage): string {
    if (!validatePackage(pkg)) {
      throw new Error("Cannot serialize invalid SecurePackage payload.");
    }
    return JSON.stringify(pkg, null, 2);
  }

  /**
   * Construct HTTP headers for UXSP requests (X-UXSP-Sender, X-UXSP-Package).
   */
  static buildHeaders(senderId: string, pkg?: SecurePackage): Record<string, string> {
    const headers: Record<string, string> = {
      "X-UXSP-Sender": senderId,
      "Content-Type": "application/json",
    };
    if (pkg) {
      headers["X-UXSP-Package"] = pkg.sender_id;
    }
    return headers;
  }

  /**
   * Parse a PublicCard JSON string or object.
   */
  static parsePublicCard(input: string | Record<string, unknown>): PublicCard {
    const card = typeof input === "string" ? JSON.parse(input) : input;
    if (!validatePublicCard(card)) {
      throw new Error("Invalid UXSP PublicCard format.");
    }
    return card;
  }

  /**
   * Create an encrypted live voice call negotiation package and session.
   */
  static async createLiveVoicePackage(
    sender: Identity,
    recipientCard: PublicCard,
    options?: { codec?: string; sampleRate?: number; channels?: number; metadata?: Record<string, unknown> }
  ): Promise<{ pkg: SecurePackage; session: import("./live.js").LiveVoiceSession }> {
    const { LiveVoiceSession } = await import("./live.js");
    const { envelope, session } = await LiveVoiceSession.createVoice(sender, recipientCard, options);
    const meta = options?.metadata || {};
    meta.codec = session.codec;
    meta.sample_rate = session.sampleRate;
    meta.channels = session.channels;
    meta.uxsp_live_voice_exchange = true;

    const pkg = this.createPackage({
      sender_id: sender.entity_id,
      receiver_id: recipientCard.entity_id,
      data_type: "live_voice_session",
      envelope: envelope,
      metadata: meta,
    });

    return { pkg, session };
  }

  /**
   * Open an incoming live voice call negotiation package and return the active LiveVoiceSession.
   */
  static async openLiveVoicePackage(
    receiver: Identity,
    senderCard: PublicCard,
    pkg: SecurePackage
  ): Promise<import("./live.js").LiveVoiceSession> {
    const { LiveVoiceSession } = await import("./live.js");
    if (!pkg.envelope) {
      throw new Error("SecurePackage is missing its envelope.");
    }
    const meta = pkg.metadata || {};
    const codec = (meta.codec as string) || "opus";
    const sampleRate = (meta.sample_rate as number) || 48000;
    const channels = (meta.channels as number) || 1;

    return await LiveVoiceSession.acceptVoice(receiver, senderCard, pkg.envelope, {
      codec,
      sampleRate,
      channels,
    });
  }
}

