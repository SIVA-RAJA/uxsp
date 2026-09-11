/**
 * UXSP Drop-In Fetch Wrapper for Browser & Frontend Applications (React, Vue, Svelte)
 *
 * Provides automatic protocol negotiation, client-side request encryption,
 * response decryption, and transparent fallback to standard HTTPS.
 */

import { Identity } from "./identity.js";
import { PublicCard, SecurePackage } from "./types.js";
import { UXSPClient } from "./client.js";
import { getIdentity, getPeer } from "./dispatch.js";
import { encodeUTF8, decodeUTF8 } from "./utils.js";

export interface UXSPFetchConfig {
  identity?: Identity;
  peerRegistry?: Map<string, PublicCard> | Record<string, PublicCard>;
  allowFallback?: boolean;
  forceUXSP?: boolean;
  autoChunkThreshold?: number;
  secUxspSupport?: string;
}

export interface UXSPRequestInit extends RequestInit {
  identity?: Identity;
  peerCard?: PublicCard | string;
  uxspMode?: "auto" | "force-uxsp" | "force-plain";
  autoChunkThreshold?: number;
  chunkSize?: number;
  fetchFn?: typeof fetch;
}

export interface UXSPFetchResponse {
  status: number;
  statusText: string;
  headers: Headers;
  ok: boolean;
  url: string;
  isEncrypted: boolean;
  package?: SecurePackage;
  rawResponse: Response;
  text(): Promise<string>;
  json<T = any>(): Promise<T>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

interface CachedHostCapability {
  supportsUXSP: boolean;
  selectedVersion?: string;
  peerCard?: PublicCard;
  expiresAt: number;
}

const _CAPABILITY_CACHE = new Map<string, CachedHostCapability>();

function normalizeHostKey(urlStr: string): string {
  try {
    const parsed = new URL(urlStr, "https://localhost");
    return parsed.host.toLowerCase();
  } catch {
    return urlStr.toLowerCase();
  }
}

/**
 * Perform an HTTP request with automatic UXSP encryption and transparent fallback.
 */
export async function uxspFetch(
  input: string | URL | Request,
  init?: UXSPRequestInit
): Promise<UXSPFetchResponse> {
  const urlString = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
  const hostKey = normalizeHostKey(urlString);

  // Determine mode
  const mode = init?.uxspMode || "auto";
  const forceUXSP = mode === "force-uxsp";
  const forcePlain = mode === "force-plain";

  // Resolve sender Identity if possible
  let senderIdent: Identity | null = null;
  if (!forcePlain) {
    if (init?.identity) {
      senderIdent = init.identity;
    } else {
      try {
        senderIdent = getIdentity();
      } catch {
        // Ephemeral identity will be created if encryption is needed and none exists
      }
    }
  }

  // Resolve target peer card if specified or in cache
  let peerCard: PublicCard | null = null;
  if (!forcePlain) {
    if (init?.peerCard) {
      if (typeof init.peerCard === "string") {
        try {
          peerCard = await getPeer(init.peerCard);
        } catch {
          // not found in keystore
        }
      } else {
        peerCard = init.peerCard;
      }
    } else {
      const cached = _CAPABILITY_CACHE.get(hostKey);
      if (cached && cached.expiresAt > Date.now() && cached.peerCard) {
        peerCard = cached.peerCard;
      }
    }
  }

  const reqHeaders = new Headers(init?.headers || (input instanceof Request ? input.headers : undefined));
  let reqBody: any = init?.body !== undefined ? init.body : input instanceof Request ? input.body : undefined;

  let requestEncrypted = false;
  let sentPackage: SecurePackage | null = null;

  if (!forcePlain) {
    reqHeaders.set("Sec-UXSP-Support", "v1.2, ml-kem-768");
    if (senderIdent) {
      reqHeaders.set("X-UXSP-Sender", senderIdent.entity_id);
    }

    // Encrypt outgoing request body if peer card is known
    if (reqBody && peerCard) {
      if (!senderIdent) {
        senderIdent = await Identity.create("client", "CLIENT");
        reqHeaders.set("X-UXSP-Sender", senderIdent.entity_id);
      }

      let payloadBytes: Uint8Array;
      let detectedType = "TEXT";

      if (typeof reqBody === "string") {
        payloadBytes = encodeUTF8(reqBody);
        detectedType = "TEXT";
      } else if (reqBody instanceof Uint8Array) {
        payloadBytes = reqBody;
        detectedType = "BINARY";
      } else if (reqBody instanceof ArrayBuffer) {
        payloadBytes = new Uint8Array(reqBody);
        detectedType = "BINARY";
      } else if (typeof reqBody === "object") {
        payloadBytes = encodeUTF8(JSON.stringify(reqBody));
        detectedType = "JSON";
      } else {
        payloadBytes = encodeUTF8(String(reqBody));
      }

      const pkg = await UXSPClient.createEncryptedPackage(
        senderIdent,
        peerCard,
        payloadBytes,
        detectedType,
        {},
        {
          autoChunk: true,
          chunkThreshold: init?.autoChunkThreshold ?? (64 * 1024),
          chunkSize: init?.chunkSize,
        }
      );

      sentPackage = pkg;
      reqBody = UXSPClient.serializePackage(pkg);
      reqHeaders.set("Content-Type", "application/uxsp+json");
      reqHeaders.set("X-UXSP-Package", pkg.sender_id);
      requestEncrypted = true;
    } else if (forceUXSP && reqBody && !peerCard) {
      throw new Error(
        `Cannot force UXSP encryption for ${urlString}: peer PublicCard is required but not provided or resolved.`
      );
    }
  }

  // Execute standard fetch call
  const fetchFn = init?.fetchFn || (typeof globalThis.fetch === "function" ? globalThis.fetch : null);
  if (!fetchFn) {
    throw new Error("No fetch implementation available in current runtime.");
  }

  const response = await fetchFn(urlString, {
    ...init,
    headers: reqHeaders,
    body: reqBody,
  });

  // Inspect negotiation response
  const selectedHeader = response.headers.get("sec-uxsp-selected");
  const contentType = (response.headers.get("content-type") || "").toLowerCase();
  const pkgHeader = response.headers.get("x-uxsp-package");

  const isServerUXSP = Boolean(selectedHeader);
  const isResponseEncrypted =
    contentType.includes("application/uxsp+json") ||
    contentType.includes("application/uxsp") ||
    Boolean(pkgHeader);

  if (isServerUXSP) {
    _CAPABILITY_CACHE.set(hostKey, {
      supportsUXSP: true,
      selectedVersion: selectedHeader || undefined,
      peerCard: peerCard || undefined,
      expiresAt: Date.now() + 3600 * 1000,
    });
  }

  if (forceUXSP && !isResponseEncrypted && !isServerUXSP) {
    throw new Error(`UXSP encryption required, but server at ${urlString} responded with plain HTTP.`);
  }

  // Handle encrypted response
  let decryptedBytesCache: Uint8Array | null = null;
  let parsedPackageCache: SecurePackage | null = null;

  if (isResponseEncrypted) {
    try {
      const rawText = await response.text();
      parsedPackageCache = UXSPClient.parsePackage(rawText);
    } catch {
      // not a valid serialized package
    }
  }

  async function getDecryptedBytes(): Promise<Uint8Array> {
    if (decryptedBytesCache !== null) return decryptedBytesCache;

    if (!parsedPackageCache) {
      const rawText = await response.text();
      parsedPackageCache = UXSPClient.parsePackage(rawText);
    }
    const pkg = parsedPackageCache;
    const receiver = senderIdent || (await getIdentity());
    const senderCard = peerCard || (await getPeer(pkg.sender_id));

    decryptedBytesCache = await UXSPClient.openEncryptedPackage(receiver, senderCard, pkg);
    return decryptedBytesCache;
  }

  const customResponse: UXSPFetchResponse = {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    ok: response.ok,
    url: response.url || urlString,
    isEncrypted: isResponseEncrypted,
    rawResponse: response,

    get package(): SecurePackage | undefined {
      return parsedPackageCache || undefined;
    },

    async text(): Promise<string> {
      if (isResponseEncrypted) {
        const bytes = await getDecryptedBytes();
        return decodeUTF8(bytes);
      }
      return await response.text();
    },

    async json<T = any>(): Promise<T> {
      if (isResponseEncrypted) {
        const bytes = await getDecryptedBytes();
        const textStr = decodeUTF8(bytes);
        return JSON.parse(textStr) as T;
      }
      return await response.json();
    },

    async arrayBuffer(): Promise<ArrayBuffer> {
      if (isResponseEncrypted) {
        const bytes = await getDecryptedBytes();
        return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
      }
      return await response.arrayBuffer();
    },
  };

  return customResponse;
}

/**
 * Factory to create a scoped uxspFetch function with pre-configured defaults.
 */
export function createUXSPFetch(config: UXSPFetchConfig = {}): typeof uxspFetch {
  return async function scopedFetch(
    input: string | URL | Request,
    init?: UXSPRequestInit
  ): Promise<UXSPFetchResponse> {
    const mergedInit: UXSPRequestInit = {
      ...init,
      identity: init?.identity || config.identity,
      uxspMode:
        init?.uxspMode ||
        (config.forceUXSP ? "force-uxsp" : config.allowFallback === false ? "force-uxsp" : "auto"),
      autoChunkThreshold: init?.autoChunkThreshold ?? config.autoChunkThreshold,
    };
    return await uxspFetch(input, mergedInit);
  };
}

/**
 * Transparently intercept global window.fetch / globalThis.fetch for zero-config SPA encryption.
 * Returns an uninstallation callback that restores the original fetch.
 */
export function installFetchInterceptor(config?: UXSPFetchConfig): () => void {
  const originalFetch = globalThis.fetch;
  if (!originalFetch) {
    throw new Error("Cannot install fetch interceptor: globalThis.fetch is not defined.");
  }

  const customFetch = createUXSPFetch(config);

  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const uxspResp = await customFetch(input as any, {
      ...(init as any),
      fetchFn: originalFetch,
    });
    // Wrap UXSPFetchResponse into a standard Response-compliant object
    const respProxy = new Proxy(uxspResp.rawResponse, {
      get(target, prop) {
        if (prop === "text") return () => uxspResp.text();
        if (prop === "json") return () => uxspResp.json();
        if (prop === "arrayBuffer") return () => uxspResp.arrayBuffer();
        if (prop === "isEncrypted") return uxspResp.isEncrypted;
        if (prop === "package") return uxspResp.package;
        if (prop === "uxsp") return uxspResp;
        return (target as any)[prop];
      },
    });
    return respProxy as unknown as Response;
  };

  return function uninstall(): void {
    globalThis.fetch = originalFetch;
  };
}
