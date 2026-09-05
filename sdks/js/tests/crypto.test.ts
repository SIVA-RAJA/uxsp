import { test } from "node:test";
import * as assert from "node:assert";

import { aesGcmEncrypt, aesGcmDecrypt } from "../dist/crypto.js";

test("crypto - AES-GCM Encrypt and Decrypt Happy Path", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    const plaintext = new TextEncoder().encode("Secret message for UXSP");

    const ciphertext = await aesGcmEncrypt(key, nonce, plaintext);
    assert.ok(ciphertext.byteLength > plaintext.byteLength);

    const decrypted = await aesGcmDecrypt(key, nonce, ciphertext);
    assert.deepEqual(decrypted, plaintext);
});

test("crypto - AES-GCM with Associated Data", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    const plaintext = new TextEncoder().encode("Hello with associated data");
    const metadata = new TextEncoder().encode(JSON.stringify({ volume: 85 }));

    const ciphertext = await aesGcmEncrypt(key, nonce, plaintext, metadata);
    const decrypted = await aesGcmDecrypt(key, nonce, ciphertext, metadata);
    assert.deepEqual(decrypted, plaintext);
});

test("crypto - AES-GCM fails if Associated Data is tampered", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);

    const plaintext = new TextEncoder().encode("Hello with associated data");
    const metadata = new TextEncoder().encode(JSON.stringify({ volume: 85 }));

    const ciphertext = await aesGcmEncrypt(key, nonce, plaintext, metadata);
    
    const badMetadata = new TextEncoder().encode(JSON.stringify({ volume: 99 }));

    await assert.rejects(
        async () => await aesGcmDecrypt(key, nonce, ciphertext, badMetadata),
        (err: Error) => {
            return err.message.includes("OperationError") || err.name === "OperationError";
        }
    );
});
