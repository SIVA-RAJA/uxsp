import { test } from "node:test";
import * as assert from "node:assert";
import { Identity } from "../src/identity.js";
import { seal, openSeal } from "../src/seal.js";
import { encodeHex, decodeHex } from "../src/utils.js";

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
