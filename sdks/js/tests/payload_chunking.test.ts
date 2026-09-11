import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  UXSPClient,
  UXSPPayload,
  packText,
  packBinary,
  packFile,
  unpackText,
  unpackBinary,
  UXSPChunk,
  createChunkedTransfer,
  reassembleChunkedTransfer,
  createChunkedText,
  decodeChunkedText,
  ChunkValidationError,
} from "../dist/index.js";

test("Payload - Text, Binary, and File Packaging", () => {
  // 1. Text
  const textPacked = packText("Hello UXSP structured payload!");
  const textUnpacked = unpackText(textPacked);
  assert.strictEqual(textUnpacked, "Hello UXSP structured payload!");

  // 2. Binary
  const binData = new Uint8Array([1, 2, 3, 4, 5, 255]);
  const binPacked = packBinary(binData);
  const binUnpacked = unpackBinary(binPacked);
  assert.deepStrictEqual(binUnpacked, binData);

  // 3. File
  const fileData = new TextEncoder().encode("report-data-contents");
  const filePacked = packFile(fileData, "annual_report.pdf", "application/pdf");
  const parsedFile = UXSPPayload.fromBytes(filePacked);
  assert.strictEqual(parsedFile.kind, "file");
  assert.strictEqual(parsedFile.filename, "annual_report.pdf");
  assert.strictEqual(parsedFile.contentType, "application/pdf");
  assert.deepStrictEqual(parsedFile.body, fileData);
});

function fillRandom(buf: Uint8Array): Uint8Array {
  for (let offset = 0; offset < buf.length; offset += 65536) {
    const chunk = buf.subarray(offset, Math.min(offset + 65536, buf.length));
    crypto.getRandomValues(chunk);
  }
  return buf;
}

test("Chunking - Transfer, Integrity Verification & Reassembly", async () => {
  const originalData = fillRandom(new Uint8Array(150 * 1024)); // 150 KiB

  // Split into 32 KiB chunks
  const chunks = await createChunkedTransfer(originalData, { chunkSize: 32 * 1024 });
  assert.strictEqual(chunks.length, 5); // 150 / 32 = 4.6875 -> 5 chunks

  // Test individual chunk wire serialization
  const wireBytes = chunks[0].toBytes();
  const parsedChunk = await UXSPChunk.fromBytes(wireBytes);
  assert.strictEqual(parsedChunk.chunkIndex, 0);
  assert.strictEqual(parsedChunk.totalChunks, 5);

  // Reassemble in scrambled order
  const scrambled = [chunks[2], chunks[0], chunks[4], chunks[1], chunks[3]];
  const reassembled = await reassembleChunkedTransfer(scrambled);
  assert.deepStrictEqual(reassembled, originalData);

  // Text convenience
  const longText = "UXSP ".repeat(10000);
  const textChunks = await createChunkedText(longText, 1024);
  const decodedText = await decodeChunkedText(textChunks);
  assert.strictEqual(decodedText, longText);

  // Corrupted chunk rejection
  const tamperedChunkBytes = chunks[1].toBytes();
  tamperedChunkBytes[tamperedChunkBytes.length - 1] ^= 0xff; // flip last byte
  await assert.rejects(
    async () => {
      await UXSPChunk.fromBytes(tamperedChunkBytes);
    },
    ChunkValidationError
  );
});

test("UXSPClient - Auto-Chunking in createEncryptedPackage", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");

  const largeData = fillRandom(new Uint8Array(100 * 1024)); // 100 KB

  // Auto-chunk with 32KB chunkSize
  const pkg = await UXSPClient.createEncryptedPackage(
    alice,
    bob.publicCard(),
    largeData,
    "BINARY",
    {},
    { chunkSize: 32 * 1024 }
  );

  assert.strictEqual(pkg.is_chunked, true);
  assert.strictEqual(pkg.chunks.length, 4);

  // Open package and auto-reassemble
  const decrypted = await UXSPClient.openEncryptedPackage(bob, alice.publicCard(), pkg);
  assert.deepStrictEqual(decrypted, largeData);
});
