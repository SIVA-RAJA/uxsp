/**
 * Base64 Utilities
 */

export function encodeBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function decodeBase64(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

export function encodeUTF8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function decodeUTF8(buffer: ArrayBuffer | Uint8Array): string {
  return new TextDecoder().decode(buffer);
}
