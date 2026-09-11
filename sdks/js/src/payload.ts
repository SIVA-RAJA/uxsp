/**
 * UXSP Structured Payload Packing & Unpacking
 *
 * Implements envelope-within-the-envelope structured application messages
 * for text, binary, and files with content-type metadata.
 */

import { encodeUTF8, decodeUTF8 } from "./utils.js";

export type PayloadKind = "text" | "file" | "binary";

const MAGIC = encodeUTF8("UXSP-PAYLOAD-1");
const HEADER_LEN_BYTES = 4;
export const MAX_PACK_FILE_BYTES = 64 * 1024 * 1024; // 64 MB

export class PayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PayloadError";
  }
}

export class PayloadFormatError extends PayloadError {
  constructor(message: string) {
    super(message);
    this.name = "PayloadFormatError";
  }
}

export class PayloadValidationError extends PayloadError {
  constructor(message: string) {
    super(message);
    this.name = "PayloadValidationError";
  }
}

export interface PayloadOptions {
  filename?: string | null;
  contentType?: string;
  encoding?: string | null;
}

export class UXSPPayload {
  public kind: PayloadKind;
  public body: Uint8Array;
  public filename: string | null;
  public contentType: string;
  public encoding: string | null;

  constructor(
    kind: PayloadKind,
    body: Uint8Array,
    options?: PayloadOptions
  ) {
    this.kind = kind;
    this.body = body;
    this.filename = options?.filename || null;
    this.contentType = options?.contentType || "application/octet-stream";
    this.encoding = options?.encoding || null;
  }

  toBytes(): Uint8Array {
    const header = {
      kind: this.kind,
      filename: this.filename,
      content_type: this.contentType,
      encoding: this.encoding,
      body_len: this.body.length,
    };
    const headerRaw = encodeUTF8(JSON.stringify(header));
    const headerLen = headerRaw.length;

    const totalLen = MAGIC.length + HEADER_LEN_BYTES + headerLen + this.body.length;
    const result = new Uint8Array(totalLen);

    result.set(MAGIC, 0);

    const view = new DataView(result.buffer);
    view.setUint32(MAGIC.length, headerLen, false); // big-endian

    result.set(headerRaw, MAGIC.length + HEADER_LEN_BYTES);
    result.set(this.body, MAGIC.length + HEADER_LEN_BYTES + headerLen);

    return result;
  }

  static fromBytes(raw: Uint8Array): UXSPPayload {
    if (!(raw instanceof Uint8Array)) {
      throw new PayloadFormatError("Packed payload must be Uint8Array.");
    }
    const minLen = MAGIC.length + HEADER_LEN_BYTES;
    if (raw.length < minLen) {
      throw new PayloadFormatError("Packed payload is too short.");
    }

    for (let i = 0; i < MAGIC.length; i++) {
      if (raw[i] !== MAGIC[i]) {
        throw new PayloadFormatError("Invalid payload magic header.");
      }
    }

    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const headerLen = view.getUint32(MAGIC.length, false);

    const headerStart = MAGIC.length + HEADER_LEN_BYTES;
    const bodyStart = headerStart + headerLen;

    if (raw.length < bodyStart) {
      throw new PayloadFormatError("Payload header length exceeds total buffer size.");
    }

    const headerRaw = raw.subarray(headerStart, bodyStart);
    let header: any;
    try {
      header = JSON.parse(decodeUTF8(headerRaw));
    } catch (e: any) {
      throw new PayloadFormatError(`Corrupted payload header JSON: ${e.message}`);
    }

    const body = raw.subarray(bodyStart);
    if (body.length !== header.body_len) {
      throw new PayloadValidationError(
        `Body length mismatch: declared ${header.body_len}, actual ${body.length}`
      );
    }

    return new UXSPPayload(header.kind, body, {
      filename: header.filename,
      contentType: header.content_type,
      encoding: header.encoding,
    });
  }
}

export function packText(text: string, encoding: string = "utf-8"): Uint8Array {
  const body = encodeUTF8(text);
  return new UXSPPayload("text", body, {
    contentType: "text/plain",
    encoding: encoding,
  }).toBytes();
}

export function packBinary(
  data: Uint8Array,
  filename?: string,
  contentType: string = "application/octet-stream"
): Uint8Array {
  return new UXSPPayload("binary", data, {
    filename,
    contentType,
  }).toBytes();
}

export function packFile(
  data: Uint8Array,
  filename: string,
  contentType: string = "application/octet-stream"
): Uint8Array {
  if (data.length > MAX_PACK_FILE_BYTES) {
    throw new PayloadValidationError(`File size exceeds maximum ${MAX_PACK_FILE_BYTES} bytes.`);
  }
  return new UXSPPayload("file", data, {
    filename,
    contentType,
  }).toBytes();
}

export function unpackText(payloadBytes: Uint8Array): string {
  const payload = UXSPPayload.fromBytes(payloadBytes);
  if (payload.kind !== "text") {
    throw new PayloadValidationError(`Expected 'text' payload, got '${payload.kind}'`);
  }
  return decodeUTF8(payload.body);
}

export function unpackBinary(payloadBytes: Uint8Array): Uint8Array {
  const payload = UXSPPayload.fromBytes(payloadBytes);
  return payload.body;
}
