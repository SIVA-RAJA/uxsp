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
const crypto_js_1 = require("../src/crypto.js");
(0, node_test_1.test)("crypto - AES-GCM Encrypt and Decrypt Happy Path", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const plaintext = new TextEncoder().encode("Secret message for UXSP");
    const ciphertext = await (0, crypto_js_1.aesGcmEncrypt)(key, nonce, plaintext);
    assert.ok(ciphertext.byteLength > plaintext.byteLength);
    const decrypted = await (0, crypto_js_1.aesGcmDecrypt)(key, nonce, ciphertext);
    assert.deepEqual(decrypted, plaintext);
});
(0, node_test_1.test)("crypto - AES-GCM with Associated Data", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const plaintext = new TextEncoder().encode("Hello with associated data");
    const metadata = new TextEncoder().encode(JSON.stringify({ volume: 85 }));
    const ciphertext = await (0, crypto_js_1.aesGcmEncrypt)(key, nonce, plaintext, metadata);
    const decrypted = await (0, crypto_js_1.aesGcmDecrypt)(key, nonce, ciphertext, metadata);
    assert.deepEqual(decrypted, plaintext);
});
(0, node_test_1.test)("crypto - AES-GCM fails if Associated Data is tampered", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    const plaintext = new TextEncoder().encode("Hello with associated data");
    const metadata = new TextEncoder().encode(JSON.stringify({ volume: 85 }));
    const ciphertext = await (0, crypto_js_1.aesGcmEncrypt)(key, nonce, plaintext, metadata);
    const badMetadata = new TextEncoder().encode(JSON.stringify({ volume: 99 }));
    await assert.rejects(async () => await (0, crypto_js_1.aesGcmDecrypt)(key, nonce, ciphertext, badMetadata), (err) => {
        return err.message.includes("OperationError") || err.name === "OperationError";
    });
});
