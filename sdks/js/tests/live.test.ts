import { test } from "node:test";
import * as assert from "node:assert";

import { LiveSession } from "../dist/live.js";

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

test("LiveVoiceSession - Audio Frame Encryption & Decryption", async () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);

    const voiceSession = new (await import("../dist/live.js")).LiveVoiceSession(key, "opus", 48000, 2);
    assert.equal(voiceSession.codec, "opus");
    assert.equal(voiceSession.sampleRate, 48000);
    assert.equal(voiceSession.channels, 2);

    voiceSession.mute();
    assert.equal(voiceSession.isMuted, true);
    voiceSession.unmute();
    assert.equal(voiceSession.isMuted, false);

    const audioFrame = new Uint8Array([10, 20, 30, 40]);
    const encrypted = await voiceSession.encryptVoiceFrame(audioFrame, {
        metadata: new TextEncoder().encode("mic_input")
    });

    const { frame: decrypted, audioMetadata } = await voiceSession.decryptVoiceFrame(encrypted);

    assert.deepEqual(decrypted, audioFrame);
    assert.equal(audioMetadata.codec, "opus");
    assert.equal(audioMetadata.sampleRate, 48000);
    assert.equal(audioMetadata.channels, 2);
    assert.equal(audioMetadata.sequence, 1);
    assert.equal(audioMetadata.isMuted, false);
    assert.ok(audioMetadata.extraBytes);
    assert.equal(new TextDecoder().decode(audioMetadata.extraBytes!), "mic_input");
});

test("UXSPClient - Live Voice Package Negotiation", async () => {
    const { UXSPClient } = await import("../dist/client.js");
    const { Identity } = await import("../dist/identity.js");

    const sender = await Identity.create("Alice", "client");
    const receiver = await Identity.create("Bob", "server");

    const { pkg, session: senderSession } = await UXSPClient.createLiveVoicePackage(
        sender,
        receiver.publicCard(),
        { codec: "opus", sampleRate: 48000, channels: 1 }
    );

    assert.equal(pkg.data_type, "live_voice_session");
    assert.equal(pkg.sender_id, sender.entity_id);
    assert.equal(pkg.receiver_id, receiver.entity_id);

    const receiverSession = await UXSPClient.openLiveVoicePackage(
        receiver,
        sender.publicCard(),
        pkg
    );

    assert.deepEqual(senderSession.key, receiverSession.key);
    assert.equal(receiverSession.codec, "opus");

    const pcmData = new Uint8Array([100, 101, 102]);
    const encPcm = await senderSession.encryptVoiceFrame(pcmData);
    const { frame: decPcm, audioMetadata } = await receiverSession.decryptVoiceFrame(encPcm);

    assert.deepEqual(decPcm, pcmData);
    assert.equal(audioMetadata.codec, "opus");
});

