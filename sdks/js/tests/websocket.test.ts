import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  UXSPWebSocket,
  UXSPFrame,
  FrameType,
  FrameTooLargeError,
  SessionNotEstablishedError,
  UnexpectedFrameError,
} from "../dist/index.js";

test("UXSPWebSocket - Full Initiator & Responder Lifecycle", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");

  const aliceWs = UXSPWebSocket.asInitiator(alice, bob.publicCard());
  const bobWs = UXSPWebSocket.asResponder(bob);

  assert.strictEqual(aliceWs.isReady, false);
  assert.strictEqual(bobWs.isReady, false);

  // 1. Alice sends HELLO frame
  const helloFrame = await aliceWs.startHandshake();
  assert.strictEqual(helloFrame.type, FrameType.HANDSHAKE_HELLO);

  // Serialize and parse frame
  const wireHello = helloFrame.toJson();
  const parsedHello = UXSPFrame.fromJson(wireHello);
  assert.strictEqual(parsedHello.type, FrameType.HANDSHAKE_HELLO);

  // 2. Bob handles HELLO and produces ACK frame
  const ackFrame = await bobWs.handleHello(parsedHello, alice.publicCard());
  assert.strictEqual(ackFrame.type, FrameType.HANDSHAKE_ACK);

  // 3. Alice completes handshake and returns COMPLETE frame
  const completeFrame = await aliceWs.completeHandshake(ackFrame);
  assert.strictEqual(completeFrame.type, FrameType.HANDSHAKE_COMPLETE);
  assert.strictEqual(aliceWs.isReady, true);

  // 4. Bob processes COMPLETE frame
  await bobWs.handleComplete(completeFrame);
  assert.strictEqual(bobWs.isReady, true);

  // 5. Encrypted DATA frames
  const dataPayload = new TextEncoder().encode("Secure WebSocket telemetry frame");
  const encodedFrame = await aliceWs.encode(dataPayload);
  assert.strictEqual(encodedFrame.type, FrameType.DATA);

  const wireData = encodedFrame.toJson();
  const parsedData = UXSPFrame.fromJson(wireData);

  const decrypted = await bobWs.decode(parsedData);
  assert.strictEqual(new TextDecoder().decode(decrypted), "Secure WebSocket telemetry frame");

  // 6. Keepalive Ping / Pong
  const pingFrame = await aliceWs.ping();
  assert.strictEqual(pingFrame.type, FrameType.PING);

  const pongFrame = await bobWs.pong(pingFrame);
  assert.strictEqual(pongFrame.type, FrameType.PONG);

  // 7. Authenticated Close Teardown
  const closeFrame = await aliceWs.close("logout");
  assert.strictEqual(closeFrame.type, FrameType.CLOSE);
  assert.strictEqual(aliceWs.isReady, false);

  const closeReason = await bobWs.handleClose(closeFrame);
  assert.strictEqual(closeReason, "logout");
  assert.strictEqual(bobWs.isReady, false);
});

test("UXSPWebSocket - Error and Frame Validation", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");
  const ws = UXSPWebSocket.asInitiator(alice, bob.publicCard());

  // Cannot encode data before handshake
  await assert.rejects(
    async () => {
      await ws.encode(new Uint8Array(10));
    },
    SessionNotEstablishedError
  );

  // Oversized frame DOS rejection
  const hugeText = "A".repeat(1024 * 1024 + 50);
  assert.throws(() => {
    UXSPFrame.fromJson(hugeText);
  }, FrameTooLargeError);

  // Malformed frame rejection
  assert.throws(() => {
    UXSPFrame.fromJson("not-json");
  });

  // Missing frame type
  assert.throws(() => {
    UXSPFrame.fromJson(JSON.stringify({ payload: {} }));
  });
});

test("UXSPWebSocket - Session Resumption lifecycle", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");

  const aliceWs = UXSPWebSocket.asInitiator(alice, bob.publicCard());
  const bobWs = UXSPWebSocket.asResponder(bob);

  const hello = await aliceWs.startHandshake();
  const ack = await bobWs.handleHello(hello, alice.publicCard());
  const comp = await aliceWs.completeHandshake(ack);
  await bobWs.handleComplete(comp);

  // Send some data
  const d1 = await aliceWs.encode(new TextEncoder().encode("pre-disconnect 1"));
  assert.strictEqual(new TextDecoder().decode(await bobWs.decode(d1)), "pre-disconnect 1");

  // Reconnect: Alice initiates resumption
  const resumeFrame = await aliceWs.startResume();
  assert.strictEqual(resumeFrame.type, FrameType.RESUME);
  assert.strictEqual(resumeFrame.payload.session_id, aliceWs.session.sessionId);

  // Bob verifies and produces ACK
  const resumeAck = await bobWs.handleResume(resumeFrame);
  assert.strictEqual(resumeAck.type, FrameType.RESUME_ACK);

  // Alice completes resumption
  await aliceWs.completeResume(resumeAck);

  // Send more data post-resume
  const d2 = await aliceWs.encode(new TextEncoder().encode("post-disconnect 2"));
  assert.strictEqual(new TextDecoder().decode(await bobWs.decode(d2)), "post-disconnect 2");
});

test("UXSPWebSocket - Session Resumption tamper rejection", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");

  const aliceWs = UXSPWebSocket.asInitiator(alice, bob.publicCard());
  const bobWs = UXSPWebSocket.asResponder(bob);

  const hello = await aliceWs.startHandshake();
  const ack = await bobWs.handleHello(hello, alice.publicCard());
  const comp = await aliceWs.completeHandshake(ack);
  await bobWs.handleComplete(comp);

  const resumeFrame = await aliceWs.startResume();
  const tamperedPayload = { ...resumeFrame.payload, auth_tag: "00".repeat(32) };
  const tamperedFrame = UXSPFrame.build(FrameType.RESUME, tamperedPayload);

  await assert.rejects(async () => {
    await bobWs.handleResume(tamperedFrame);
  }, /Invalid resume authentication tag/);
});

