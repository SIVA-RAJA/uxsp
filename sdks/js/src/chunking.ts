/**
 * UXSP Large-Payload Chunked Transfer
 *
 * Splits large payloads into individually verified, integrity-checked chunks
 * with per-chunk and whole-file SHA-256 hash validation.
 */

import { encodeUTF8, decodeUTF8 } from "./utils.js";
import { sha256Hex } from "./crypto.js";

export type ChunkKind = "file" | "binary" | "text";

const MAGIC = encodeUTF8("UXSP-CHUNK-1");
const HEADER_LEN_BYTES = 4;
const MAX_HEADER_LEN = 64 * 1024; // 64 KiB
export const DEFAULT_CHUNK_SIZE = 64 * 1024; // 64 KiB

export class ChunkingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ChunkingError";
  }
}

export class ChunkFormatError extends ChunkingError {
  constructor(message: string) {
    super(message);
    this.name = "ChunkFormatError";
  }
}

export class ChunkValidationError extends ChunkingError {
  constructor(message: string) {
    super(message);
    this.name = "ChunkValidationError";
  }
}

export interface ChunkOptions {
  filename?: string | null;
  contentType?: string;
  encoding?: string | null;
}

export class UXSPChunk {
  public transferId: string;
  public chunkIndex: number;
  public totalChunks: number;
  public fileHashSha256: string;
  public chunkHashSha256: string;
  public kind: ChunkKind;
  public body: Uint8Array;
  public filename: string | null;
  public contentType: string;
  public encoding: string | null;

  constructor(
    transferId: string,
    chunkIndex: number,
    totalChunks: number,
    fileHashSha256: string,
    chunkHashSha256: string,
    kind: ChunkKind,
    body: Uint8Array,
    options?: ChunkOptions
  ) {
    this.transferId = transferId;
    this.chunkIndex = chunkIndex;
    this.totalChunks = totalChunks;
    this.fileHashSha256 = fileHashSha256.toLowerCase();
    this.chunkHashSha256 = chunkHashSha256.toLowerCase();
    this.kind = kind;
    this.body = body;
    this.filename = options?.filename || null;
    this.contentType = options?.contentType || "application/octet-stream";
    this.encoding = options?.encoding || null;
  }

  toBytes(): Uint8Array {
    const header = {
      transfer_id: this.transferId,
      chunk_index: this.chunkIndex,
      total_chunks: this.totalChunks,
      file_hash_sha256: this.fileHashSha256,
      chunk_hash_sha256: this.chunkHashSha256,
      kind: this.kind,
      filename: this.filename,
      content_type: this.contentType,
      encoding: this.encoding,
      body_len: this.body.length,
    };
    const headerRaw = encodeUTF8(JSON.stringify(header));
    const headerLen = headerRaw.length;
    if (headerLen > MAX_HEADER_LEN) {
      throw new ChunkValidationError(`Chunk header exceeds maximum size (${MAX_HEADER_LEN} bytes).`);
    }

    const totalLen = MAGIC.length + HEADER_LEN_BYTES + headerLen + this.body.length;
    const result = new Uint8Array(totalLen);

    result.set(MAGIC, 0);

    const view = new DataView(result.buffer);
    view.setUint32(MAGIC.length, headerLen, false); // big-endian

    result.set(headerRaw, MAGIC.length + HEADER_LEN_BYTES);
    result.set(this.body, MAGIC.length + HEADER_LEN_BYTES + headerLen);

    return result;
  }

  static async fromBytes(raw: Uint8Array): Promise<UXSPChunk> {
    if (!(raw instanceof Uint8Array)) {
      throw new ChunkFormatError("Packed chunk must be Uint8Array.");
    }
    const minLen = MAGIC.length + HEADER_LEN_BYTES;
    if (raw.length < minLen) {
      throw new ChunkFormatError("Packed chunk is too short.");
    }

    for (let i = 0; i < MAGIC.length; i++) {
      if (raw[i] !== MAGIC[i]) {
        throw new ChunkFormatError("Invalid chunk magic header.");
      }
    }

    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const headerLen = view.getUint32(MAGIC.length, false);

    const headerStart = MAGIC.length + HEADER_LEN_BYTES;
    const bodyStart = headerStart + headerLen;

    if (raw.length < bodyStart) {
      throw new ChunkFormatError("Chunk header length exceeds total buffer size.");
    }

    const headerRaw = raw.subarray(headerStart, bodyStart);
    let header: any;
    try {
      header = JSON.parse(decodeUTF8(headerRaw));
    } catch (e: any) {
      throw new ChunkFormatError(`Corrupted chunk header JSON: ${e.message}`);
    }

    const body = raw.subarray(bodyStart);
    if (body.length !== header.body_len) {
      throw new ChunkValidationError(
        `Body length mismatch: declared ${header.body_len}, actual ${body.length}`
      );
    }

    const calculatedChunkHash = await sha256Hex(body);
    if (calculatedChunkHash.toLowerCase() !== header.chunk_hash_sha256.toLowerCase()) {
      throw new ChunkValidationError("Chunk body SHA-256 hash mismatch: chunk corrupted or tampered.");
    }

    return new UXSPChunk(
      header.transfer_id,
      header.chunk_index,
      header.total_chunks,
      header.file_hash_sha256,
      header.chunk_hash_sha256,
      header.kind,
      body,
      {
        filename: header.filename,
        contentType: header.content_type,
        encoding: header.encoding,
      }
    );
  }
}

export interface ChunkTransferOptions {
  chunkSize?: number;
  kind?: ChunkKind;
  filename?: string | null;
  contentType?: string;
  encoding?: string | null;
  transferId?: string;
}

export async function createChunkedTransfer(
  data: Uint8Array,
  options?: ChunkTransferOptions
): Promise<UXSPChunk[]> {
  const chunkSize = options?.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (chunkSize <= 0) throw new ChunkValidationError("chunkSize must be positive");

  const totalLen = data.length;
  const totalChunks = Math.max(1, Math.ceil(totalLen / chunkSize));
  const transferId = options?.transferId || crypto.randomUUID();
  const fileHash = await sha256Hex(data);
  const kind = options?.kind || "binary";

  const chunks: UXSPChunk[] = [];
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, totalLen);
    const slice = data.subarray(start, end);
    const chunkHash = await sha256Hex(slice);

    chunks.push(
      new UXSPChunk(
        transferId,
        i,
        totalChunks,
        fileHash,
        chunkHash,
        kind,
        slice,
        {
          filename: options?.filename,
          contentType: options?.contentType,
          encoding: options?.encoding,
        }
      )
    );
  }

  return chunks;
}

export async function reassembleChunkedTransfer(chunks: UXSPChunk[]): Promise<Uint8Array> {
  if (!chunks || chunks.length === 0) {
    throw new ChunkValidationError("Cannot reassemble empty chunk array.");
  }

  const transferId = chunks[0].transferId;
  const totalChunks = chunks[0].totalChunks;
  const expectedFileHash = chunks[0].fileHashSha256;

  if (chunks.length !== totalChunks) {
    throw new ChunkValidationError(
      `Incomplete transfer: expected ${totalChunks} chunks, got ${chunks.length}`
    );
  }

  const sorted = [...chunks].sort((a, b) => a.chunkIndex - b.chunkIndex);

  let totalBytes = 0;
  for (let i = 0; i < totalChunks; i++) {
    const chunk = sorted[i];
    if (chunk.transferId !== transferId) {
      throw new ChunkValidationError("Chunk transfer_id mismatch within transfer.");
    }
    if (chunk.chunkIndex !== i) {
      throw new ChunkValidationError(`Missing chunk index ${i}.`);
    }
    if (chunk.fileHashSha256 !== expectedFileHash) {
      throw new ChunkValidationError("file_hash_sha256 mismatch between chunks.");
    }
    totalBytes += chunk.body.length;
  }

  const reassembled = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of sorted) {
    reassembled.set(chunk.body, offset);
    offset += chunk.body.length;
  }

  const actualFileHash = await sha256Hex(reassembled);
  if (actualFileHash.toLowerCase() !== expectedFileHash.toLowerCase()) {
    throw new ChunkValidationError("Reassembled file SHA-256 digest mismatch. File corrupted.");
  }

  return reassembled;
}

export async function createChunkedText(text: string, chunkSize?: number): Promise<UXSPChunk[]> {
  const bytes = encodeUTF8(text);
  return await createChunkedTransfer(bytes, {
    chunkSize,
    kind: "text",
    contentType: "text/plain",
    encoding: "utf-8",
  });
}

export async function decodeChunkedText(chunks: UXSPChunk[]): Promise<string> {
  const bytes = await reassembleChunkedTransfer(chunks);
  return decodeUTF8(bytes);
}
