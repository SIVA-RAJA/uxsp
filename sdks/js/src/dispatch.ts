/**
 * UXSP Simplified High-Level Dispatchers (Send / Receive)
 *
 * Provides effortless, developer-friendly 1-line cryptographic dispatchers
 * that manage identities, keystores, peer resolution, serialization,
 * chunking, and decryption completely under the hood.
 */

import { Identity } from "./identity.js";
import { PublicCard, SecurePackage } from "./types.js";
import { KeyStore, MemoryKeyStore } from "./keystore.js";
import { NonceStore, MemoryNonceStore } from "./noncestore.js";
import { UXSPClient } from "./client.js";
import { encodeUTF8, decodeUTF8 } from "./utils.js";
import { UXSPPayload, packText, packBinary, packFile, unpackText, unpackBinary } from "./payload.js";

export interface GlobalSecureContextConfig {
  identity?: Identity;
  keystore?: KeyStore;
  nonceStore?: NonceStore;
  autoChunkThreshold?: number;
}

class GlobalSecureContext {
  public identity: Identity | null = null;
  public keystore: KeyStore = new MemoryKeyStore();
  public nonceStore: NonceStore = new MemoryNonceStore();
  public autoChunkThreshold: number = 64 * 1024; // 64 KiB
}

const _CONTEXT = new GlobalSecureContext();

/**
 * Configure the global UXSP security context.
 */
export function configure(options: GlobalSecureContextConfig): void {
  if (options.identity !== undefined) _CONTEXT.identity = options.identity;
  if (options.keystore !== undefined) _CONTEXT.keystore = options.keystore;
  if (options.nonceStore !== undefined) _CONTEXT.nonceStore = options.nonceStore;
  if (options.autoChunkThreshold !== undefined) _CONTEXT.autoChunkThreshold = options.autoChunkThreshold;
}

/**
 * Set the default local Identity used for signing and decrypting.
 */
export function setIdentity(identity: Identity): void {
  _CONTEXT.identity = identity;
}

/**
 * Retrieve the default local Identity.
 */
export function getIdentity(): Identity {
  if (!_CONTEXT.identity) {
    throw new Error(
      "No default identity set. Call setIdentity(ident) or pass sender/receiver explicitly."
    );
  }
  return _CONTEXT.identity;
}

/**
 * Register a peer's PublicCard into the global Keystore.
 */
export async function registerPeer(card: PublicCard): Promise<void> {
  await _CONTEXT.keystore.put(card);
}

/**
 * Look up a peer's PublicCard from the global Keystore.
 */
export async function getPeer(entityId: string): Promise<PublicCard> {
  const card = await _CONTEXT.keystore.get(entityId);
  if (!card) {
    throw new Error(`Peer '${entityId}' not found in registered keystore.`);
  }
  return card;
}

export interface SendOptions {
  sender?: Identity;
  dataType?: string;
  metadata?: Record<string, unknown>;
  filename?: string;
  contentType?: string;
  autoChunk?: boolean;
  chunkSize?: number;
}

export interface ReceiveOptions {
  receiver?: Identity;
  senderCard?: PublicCard;
}

/**
 * Simplified polymorphic Send function.
 * Automatically handles serialization, typing, encryption, and chunking under the hood.
 */
export async function Send(
  recipient: PublicCard | string,
  data: string | Uint8Array | Record<string, any>,
  options?: SendOptions
): Promise<SecurePackage> {
  const sender = options?.sender || getIdentity();
  const recipientCard = typeof recipient === "string" ? await getPeer(recipient) : recipient;

  let rawBytes: Uint8Array;
  let detectedType = options?.dataType;

  if (typeof data === "string") {
    rawBytes = encodeUTF8(data);
    if (!detectedType) detectedType = "TEXT";
  } else if (data instanceof Uint8Array) {
    rawBytes = data;
    if (!detectedType) detectedType = options?.filename ? "FILE" : "BINARY";
  } else if (typeof data === "object" && data !== null) {
    rawBytes = encodeUTF8(JSON.stringify(data));
    if (!detectedType) detectedType = "JSON";
  } else {
    throw new TypeError("Data must be string, Uint8Array, or JSON-serializable object.");
  }

  const meta: Record<string, unknown> = { ...(options?.metadata || {}) };
  if (options?.filename) meta.filename = options.filename;
  if (options?.contentType) meta.content_type = options.contentType;

  return await UXSPClient.createEncryptedPackage(
    sender,
    recipientCard,
    rawBytes,
    detectedType,
    meta,
    {
      autoChunk: options?.autoChunk ?? true,
      chunkThreshold: _CONTEXT.autoChunkThreshold,
      chunkSize: options?.chunkSize,
    }
  );
}

/**
 * Simplified polymorphic Receive function.
 * Automatically verifies signatures, decrypts, reassembles chunks, and parses data.
 */
export async function Receive<T = any>(
  packageInput: SecurePackage | string,
  options?: ReceiveOptions
): Promise<T> {
  const pkg: SecurePackage = typeof packageInput === "string" ? UXSPClient.parsePackage(packageInput) : packageInput;
  const receiver = options?.receiver || getIdentity();
  const senderCard = options?.senderCard || await getPeer(pkg.sender_id);

  const decryptedBytes = await UXSPClient.openEncryptedPackage(receiver, senderCard, pkg);
  const dataType = (pkg.data_type || "TEXT").toUpperCase();

  if (dataType === "JSON") {
    const jsonStr = decodeUTF8(decryptedBytes);
    return JSON.parse(jsonStr) as T;
  }

  if (dataType === "TEXT") {
    return decodeUTF8(decryptedBytes) as unknown as T;
  }

  if (dataType === "FILE") {
    return {
      data: decryptedBytes,
      filename: (pkg.metadata?.filename as string) || "download",
      contentType: (pkg.metadata?.content_type as string) || "application/octet-stream",
      metadata: pkg.metadata || {},
    } as unknown as T;
  }

  return decryptedBytes as unknown as T;
}

// ─────────────────────────────────────────
// TYPED DISPATCHERS
// ─────────────────────────────────────────

export async function SendText(
  recipient: PublicCard | string,
  text: string,
  options?: SendOptions
): Promise<SecurePackage> {
  return await Send(recipient, text, { ...options, dataType: "TEXT" });
}

export async function ReceiveText(
  packageInput: SecurePackage | string,
  options?: ReceiveOptions
): Promise<string> {
  return await Receive<string>(packageInput, options);
}

export async function SendJSON(
  recipient: PublicCard | string,
  data: any,
  options?: SendOptions
): Promise<SecurePackage> {
  return await Send(recipient, data, { ...options, dataType: "JSON" });
}

export async function ReceiveJSON<T = any>(
  packageInput: SecurePackage | string,
  options?: ReceiveOptions
): Promise<T> {
  return await Receive<T>(packageInput, options);
}

export async function SendBinary(
  recipient: PublicCard | string,
  data: Uint8Array,
  options?: SendOptions
): Promise<SecurePackage> {
  return await Send(recipient, data, { ...options, dataType: "BINARY" });
}

export async function ReceiveBinary(
  packageInput: SecurePackage | string,
  options?: ReceiveOptions
): Promise<Uint8Array> {
  return await Receive<Uint8Array>(packageInput, options);
}

export async function SendFile(
  recipient: PublicCard | string,
  data: Uint8Array,
  filename: string,
  contentType: string = "application/octet-stream",
  options?: SendOptions
): Promise<SecurePackage> {
  return await Send(recipient, data, {
    ...options,
    filename,
    contentType,
    dataType: "FILE",
  });
}

export async function ReceiveFile(
  packageInput: SecurePackage | string,
  options?: ReceiveOptions
): Promise<{ data: Uint8Array; filename: string; contentType: string; metadata: Record<string, unknown> }> {
  return await Receive(packageInput, options);
}
