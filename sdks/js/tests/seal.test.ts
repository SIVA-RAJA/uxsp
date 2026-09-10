import { test } from "node:test";
import * as assert from "node:assert";
import { Identity } from "../dist/identity.js";
import { seal, openSeal } from "../dist/seal.js";
import { encodeHex, decodeHex } from "../dist/utils.js";

test("seal - Creates valid hybrid envelope when PQC is active", async () => {
    const sender = await Identity.create("Alice");
    const receiver = await Identity.create("Bob");
    
    const plaintext = new TextEncoder().encode("Hello world, from Alice to Bob!");
    
    // Create an envelope
    const envelope = await seal(sender, receiver.publicCard(), plaintext);
    
    // Check wire format rules are met
    assert.equal(envelope.version, "UXSP-1");
    assert.equal(envelope.sender_id, sender.entity_id);
    assert.equal(envelope.recipient_id, receiver.entity_id);
    assert.ok(envelope.envelope_nonce);
    assert.ok(envelope.ciphertext);
    assert.ok(envelope.nonce);
    assert.ok(envelope.ephemeral_pub);
    assert.ok(envelope.classical_sig);
    
    // Must be marked with active PQC fields
    assert.ok((envelope as any).pqc_sig);
    assert.ok((envelope as any).kem_ciphertext);
    assert.equal((envelope as any).pqc_mode, undefined);

    // Ensure we can open it successfully
    const decrypted = await openSeal(receiver, sender.publicCard(), envelope);
    const decryptedText = new TextDecoder().decode(decrypted);
    assert.equal(decryptedText, "Hello world, from Alice to Bob!");
});

test("seal - Generates 32-byte envelope nonce (64 hex chars)", async () => {
    const sender = await Identity.create("AliceNonce");
    const receiver = await Identity.create("BobNonce");
    const envelope = await seal(sender, receiver.publicCard(), new Uint8Array([1, 2, 3]));

    assert.equal(envelope.envelope_nonce.length, 64);
});

test("openSeal - Rejects expired envelopes (age > 300s)", async () => {
    const sender = await Identity.create("AliceOld");
    const receiver = await Identity.create("BobOld");
    const envelope = await seal(sender, receiver.publicCard(), new Uint8Array([1, 2, 3]));

    // Set timestamp to 301 seconds ago
    envelope.timestamp = Math.floor(Date.now() / 1000) - 301;

    await assert.rejects(
        async () => await openSeal(receiver, sender.publicCard(), envelope),
        /ReplayError: Envelope is \d+s old. Possible replay attack./
    );
});

test("openSeal - Rejects future envelopes (skew > 30s)", async () => {
    const sender = await Identity.create("AliceFuture");
    const receiver = await Identity.create("BobFuture");
    const envelope = await seal(sender, receiver.publicCard(), new Uint8Array([1, 2, 3]));

    // Set timestamp to 35 seconds in future
    envelope.timestamp = Math.floor(Date.now() / 1000) + 35;

    await assert.rejects(
        async () => await openSeal(receiver, sender.publicCard(), envelope),
        /TimestampError: Envelope timestamp is \d+s in the future. Clock skew too large./
    );
});

test("seal / openSeal - Supports custom associated data and fails on mismatch", async () => {
    const sender = await Identity.create("AliceAD");
    const receiver = await Identity.create("BobAD");
    const plaintext = new TextEncoder().encode("Associated Data Test");
    const ad = new TextEncoder().encode("custom-context-v1");

    const envelope = await seal(sender, receiver.publicCard(), plaintext, ad);

    // Opening with matching AD succeeds
    const decrypted = await openSeal(receiver, sender.publicCard(), envelope, ad);
    assert.equal(new TextDecoder().decode(decrypted), "Associated Data Test");

    // Opening another envelope with wrong AD fails decryption
    const envelope2 = await seal(sender, receiver.publicCard(), plaintext, ad);
    const wrongAd = new TextEncoder().encode("wrong-context");
    await assert.rejects(
        async () => await openSeal(receiver, sender.publicCard(), envelope2, wrongAd)
    );
});

test("openSeal - Forged signature envelope does not poison or commit the nonce", async () => {
    const sender = await Identity.create("AliceForged");
    const receiver = await Identity.create("BobForged");
    const plaintext = new TextEncoder().encode("Forged Test");

    const validEnvelope = await seal(sender, receiver.publicCard(), plaintext);
    
    // Create a copy with a tampered signature
    const forgedEnvelope = { ...validEnvelope };
    const badSig = decodeHex(validEnvelope.classical_sig);
    badSig[0] ^= 0xff;
    forgedEnvelope.classical_sig = encodeHex(badSig);

    // Forged envelope fails signature check
    await assert.rejects(
        async () => await openSeal(receiver, sender.publicCard(), forgedEnvelope),
        /Classical signature verification failed/
    );

    // The genuine envelope with the same nonce should now succeed (nonce was not consumed)
    const decrypted = await openSeal(receiver, sender.publicCard(), validEnvelope);
    assert.equal(new TextDecoder().decode(decrypted), "Forged Test");
});
