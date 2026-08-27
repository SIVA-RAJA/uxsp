import { test } from "node:test";
import * as assert from "node:assert";

import { LiveSession } from "../src/live.js";

test("LiveSession - Binary Frame Encryption & Decryption", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    
    const session = new LiveSession(key);
    
    const frame = new Uint8Array([0, 1, 2, 3, 255]);
    
    const encrypted = await session.encryptFrame(frame);
    
    // Check format: 2-byte len + 0-byte metadata + 12-byte nonce + ciphertext
    assert.ok(encrypted.byteLength > 2 + 12 + frame.byteLength);
    
    const { frame: decrypted, metadata } = await session.decryptFrame(encrypted);
    
    assert.deepEqual(decrypted, frame);
    assert.equal(metadata.byteLength, 0);
});

test("LiveSession - Frame with Metadata", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    
    const session = new LiveSession(key);
    
    const frame = new Uint8Array([99, 99, 99]);
    const meta = new TextEncoder().encode(JSON.stringify({ vol: 100 }));
    
    const encrypted = await session.encryptFrame(frame, meta);
    
    // length is at the front (2 bytes Big Endian)
    const view = new DataView(encrypted.buffer, encrypted.byteOffset, encrypted.byteLength);
    const metaLen = view.getUint16(0, false);
    
    assert.equal(metaLen, meta.byteLength);
    
    // Extract metadata without key!
    const unencryptedMeta = encrypted.slice(2, 2 + metaLen);
    assert.deepEqual(unencryptedMeta, meta);
    
    const { frame: decrypted, metadata } = await session.decryptFrame(encrypted);
    
    assert.deepEqual(decrypted, frame);
    assert.deepEqual(metadata, meta);
});

test("LiveSession - Frame tamper validation", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const session = new LiveSession(key);
    
    const frame = new Uint8Array([99, 99, 99]);
    const meta = new TextEncoder().encode("Hello Metadata");
    const encrypted = await session.encryptFrame(frame, meta);
    
    // Tamper with the metadata bytes (index 2+ are metadata bytes)
    const tampered = new Uint8Array(encrypted);
    tampered[3] = tampered[3] ^ 0xFF;
    
    await assert.rejects(
        async () => await session.decryptFrame(tampered),
        (err: Error) => {
            return err.message.includes("OperationError") || err.name === "OperationError";
        }
    );
});
