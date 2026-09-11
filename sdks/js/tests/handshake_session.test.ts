import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  Handshake,
  HandshakeAuthError,
  HandshakeExpiredError,
  HandshakeProofError,
  Session,
  SessionConfig,
  SessionExpiredError,
  SessionRevokedError,
  SessionReorderError,
  SessionState,
  MemoryNonceStore,
} from "../dist/index.js";

test("Handshake & Session - Complete 3-Way Handshake & Encrypted Chat", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const nonceStore = new MemoryNonceStore();

  // 1. Alice initiates
  const aliceHs = await Handshake.initiate(alice, bob.publicCard());
  assert.ok(aliceHs.helloMessage);
  assert.strictEqual(aliceHs.helloMessage.type, "UXSP-HELLO");
  assert.strictEqual(aliceHs.helloMessage.initiator_id, alice.entity_id);

  // 2. Bob responds
  const bobHs = await Handshake.respond(
    bob,
    aliceHs.helloMessage,
    alice.publicCard(),
    nonceStore
  );
  assert.ok(bobHs.ackMessage);
  assert.strictEqual(bobHs.ackMessage.type, "UXSP-ACK");
  assert.strictEqual(bobHs.ackMessage.responder_id, bob.entity_id);
  assert.ok(bobHs.session);
  assert.strictEqual(bobHs.session.isActive, true);

  // 3. Alice completes
  const aliceSession = await aliceHs.complete(
    bobHs.ackMessage,
    bob.publicCard(),
    nonceStore
  );
  assert.ok(aliceSession);
  assert.strictEqual(aliceSession.isActive, true);
  assert.strictEqual(aliceSession.sessionId, bobHs.session.sessionId);

  // Alice sends message to Bob
  const msg1 = new TextEncoder().encode("Hello Bob, post-quantum session established!");
  const encrypted1 = await aliceSession.encrypt(msg1);
  assert.strictEqual(encrypted1.seq, 0);

  const decrypted1 = await bobHs.session.decrypt(encrypted1);
  assert.strictEqual(new TextDecoder().decode(decrypted1), "Hello Bob, post-quantum session established!");

  // Bob replies to Alice
  const msg2 = new TextEncoder().encode("Hello Alice, quantum-safe communications active.");
  const encrypted2 = await bobHs.session.encrypt(msg2);
  assert.strictEqual(encrypted2.seq, 0);

  const decrypted2 = await aliceSession.decrypt(encrypted2);
  assert.strictEqual(new TextDecoder().decode(decrypted2), "Hello Alice, quantum-safe communications active.");
});

test("Handshake - Replay Attack Protection", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const nonceStore = new MemoryNonceStore();

  const aliceHs = await Handshake.initiate(alice, bob.publicCard());

  // First response succeeds
  await Handshake.respond(bob, aliceHs.helloMessage, alice.publicCard(), nonceStore);

  // Replaying the same HELLO message must fail
  await assert.rejects(
    async () => {
      await Handshake.respond(bob, aliceHs.helloMessage, alice.publicCard(), nonceStore);
    },
    HandshakeExpiredError
  );
});

test("Handshake - Identity and MITM Tampering Detection", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const eve = await Identity.create("Eve");
  const nonceStore = new MemoryNonceStore();

  const aliceHs = await Handshake.initiate(alice, bob.publicCard());

  // Tampered HELLO message initiator
  const tamperedHello = { ...aliceHs.helloMessage, initiator_id: eve.entity_id };
  await assert.rejects(
    async () => {
      await Handshake.respond(bob, tamperedHello, alice.publicCard(), nonceStore);
    },
    HandshakeAuthError
  );

  // Tampered ACK proof of possession (invalidates signature)
  const bobHs = await Handshake.respond(bob, aliceHs.helloMessage, alice.publicCard(), nonceStore);
  const tamperedAck = { ...bobHs.ackMessage, proof: "00".repeat(32) };
  await assert.rejects(
    async () => {
      await aliceHs.complete(tamperedAck, bob.publicCard(), nonceStore);
    },
    HandshakeAuthError
  );
});

test("Session - Sequence Reordering and Replay Protection", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const nonceStore = new MemoryNonceStore();

  const aliceHs = await Handshake.initiate(alice, bob.publicCard());
  const bobHs = await Handshake.respond(bob, aliceHs.helloMessage, alice.publicCard(), nonceStore);
  const aliceSession = await aliceHs.complete(bobHs.ackMessage, bob.publicCard(), nonceStore);
  const bobSession = bobHs.session;

  const enc0 = await aliceSession.encrypt(new TextEncoder().encode("msg0"));
  const enc1 = await aliceSession.encrypt(new TextEncoder().encode("msg1"));

  // Receiving seq=1 before seq=0 in strict order must fail
  await assert.rejects(
    async () => {
      await bobSession.decrypt(enc1);
    },
    SessionReorderError
  );

  // Decrypt seq=0 succeeds
  const dec0 = await bobSession.decrypt(enc0);
  assert.strictEqual(new TextDecoder().decode(dec0), "msg0");

  // Replaying seq=0 must fail
  await assert.rejects(
    async () => {
      await bobSession.decrypt(enc0);
    },
    SessionReorderError
  );

  // Now seq=1 succeeds
  const dec1 = await bobSession.decrypt(enc1);
  assert.strictEqual(new TextDecoder().decode(dec1), "msg1");
});

test("Session - Revocation and Message Expiry", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const nonceStore = new MemoryNonceStore();

  const cfg = new SessionConfig({ maxMessages: 2 });
  const aliceHs = await Handshake.initiate(alice, bob.publicCard(), cfg);
  const bobHs = await Handshake.respond(bob, aliceHs.helloMessage, alice.publicCard(), nonceStore, cfg);
  const aliceSession = await aliceHs.complete(bobHs.ackMessage, bob.publicCard(), nonceStore);

  await aliceSession.encrypt(new TextEncoder().encode("1"));
  await aliceSession.encrypt(new TextEncoder().encode("2"));

  // 3rd message exceeds maxMessages=2
  await assert.rejects(
    async () => {
      await aliceSession.encrypt(new TextEncoder().encode("3"));
    },
    SessionExpiredError
  );

  // Explicit revocation
  const bobSession = bobHs.session;
  bobSession.revoke();
  assert.strictEqual(bobSession.state, SessionState.REVOKED);
  await assert.rejects(
    async () => {
      await bobSession.encrypt(new TextEncoder().encode("revoked"));
    },
    SessionRevokedError
  );
});
