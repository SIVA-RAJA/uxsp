"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const assert = __importStar(require("node:assert"));
const live_js_1 = require("../src/live.js");
(0, node_test_1.test)("LiveSession - Binary Frame Encryption & Decryption", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const session = new live_js_1.LiveSession(key);
    const frame = new Uint8Array([0, 1, 2, 3, 255]);
    const encrypted = await session.encryptFrame(frame);
    // Check format: 2-byte len + 0-byte metadata + 12-byte nonce + ciphertext
    assert.ok(encrypted.byteLength > 2 + 12 + frame.byteLength);
    const { frame: decrypted, metadata } = await session.decryptFrame(encrypted);
    assert.deepEqual(decrypted, frame);
    assert.equal(metadata.byteLength, 0);
});
(0, node_test_1.test)("LiveSession - Frame with Metadata", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const session = new live_js_1.LiveSession(key);
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
(0, node_test_1.test)("LiveSession - Frame tamper validation", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const session = new live_js_1.LiveSession(key);
    const frame = new Uint8Array([99, 99, 99]);
    const meta = new TextEncoder().encode("Hello Metadata");
    const encrypted = await session.encryptFrame(frame, meta);
    // Tamper with the metadata bytes (index 2+ are metadata bytes)
    const tampered = new Uint8Array(encrypted);
    tampered[3] = tampered[3] ^ 0xFF;
    await assert.rejects(async () => await session.decryptFrame(tampered), (err) => {
        return err.message.includes("OperationError") || err.name === "OperationError";
    });
});
