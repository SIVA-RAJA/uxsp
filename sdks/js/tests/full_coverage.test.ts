import { test } from "node:test";
import assert from "node:assert";

import { UXSPClient } from "../dist/client.js";
import { Identity } from "../dist/identity.js";
import type { PublicCard, SecurePackage, UXSPEnvelope } from "../dist/types.js";
import { LiveSession, LiveVoiceSession } from "../dist/live.js";
import { seal, openSeal } from "../dist/seal.js";
import {
  generateMLKEMKeyPair,
  generateMLDSAKeyPair,
  encapsulateMLKEM,
  decapsulateMLKEM,
  signMLDSA,
  verifyMLDSA
} from "../dist/pqc.js";
import {
  generateX25519KeyPair,
  deriveSharedSecret,
  signEd25519,
  aesGcmEncrypt,
  hkdf
} from "../dist/crypto.js";
import { encodeUTF8, decodeUTF8, decodeHex, encodeHex, decodeBase64 } from "../dist/utils.js";

test("Full Coverage - Identity validation edge cases", async () => {
  await assert.rejects(async () => {
    await Identity.create("");
  }, /Identity name must be a non-empty string/);

  await assert.rejects(async () => {
    await Identity.create("alice", "");
  }, /Identity role must be a non-empty string/);
});

test("Full Coverage - LiveSession & LiveVoiceSession edge cases", async () => {
  // Invalid key length
  assert.throws(() => {
    new LiveSession(new Uint8Array(16));
  }, /LiveSession key must be 32 bytes/);

  const validKey = new Uint8Array(32);
  crypto.getRandomValues(validKey);
  const session = new LiveSession(validKey);

  // Metadata too large (> 65535)
  const hugeMeta = new Uint8Array(65536);
  await assert.rejects(async () => {
    await session.encryptFrame(new Uint8Array([1, 2, 3]), hugeMeta);
  }, /Metadata too large/);

  // Frame too small for length header (< 2 bytes)
  await assert.rejects(async () => {
    await session.decryptFrame(new Uint8Array([1]));
  }, /Encrypted frame is too small to contain length header/);

  // Frame too small for metadata + nonce (< 2 + metaLen + NONCE_SIZE)
  const badFrame = new Uint8Array([0, 5, 1, 2]); // metaLen = 5, totalLen = 4 (< 2 + 5 + 12)
  await assert.rejects(async () => {
    await session.decryptFrame(badFrame);
  }, /Encrypted frame is too small to contain metadata and nonce/);

  // LiveSession.create and LiveSession.accept signaling flow
  const aliceLive = await Identity.create("aliceLive");
  const bobLive = await Identity.create("bobLive");
  const { envelope: liveEnv, session: aliceLiveSession } = await LiveSession.create(aliceLive, bobLive.publicCard());
  const bobLiveSession = await LiveSession.accept(bobLive, aliceLive.publicCard(), liveEnv);
  assert.deepStrictEqual(aliceLiveSession.key, bobLiveSession.key);

  const testLiveFrame = new Uint8Array([11, 22, 33]);
  const encLive = await aliceLiveSession.encryptFrame(testLiveFrame);
  const { frame: decLive } = await bobLiveSession.decryptFrame(encLive);
  assert.deepStrictEqual(decLive, testLiveFrame);

  // LiveVoiceSession non-JSON metadata fallback
  const voice = new LiveVoiceSession(validKey);
  const rawEncrypted = await session.encryptFrame(new Uint8Array([1, 2]), encodeUTF8("NON_JSON_METADATA"));
  const { audioMetadata } = await voice.decryptVoiceFrame(rawEncrypted);
  assert.strictEqual(audioMetadata.type, "raw");
  assert.strictEqual(audioMetadata.codec, "unknown");

  // Voice with extra metadata options
  const extraOptEncrypted = await voice.encryptVoiceFrame(new Uint8Array([5, 6]), {
    sequence: 42,
    isMuted: true,
    codec: "g711",
    sampleRate: 8000,
    channels: 1,
    metadata: new Uint8Array([0xde, 0xad, 0xbe, 0xef])
  });
  const decryptedVoice = await voice.decryptVoiceFrame(extraOptEncrypted);
  assert.strictEqual(decryptedVoice.audioMetadata.sequence, 42);
  assert.strictEqual(decryptedVoice.audioMetadata.isMuted, true);
  assert.strictEqual(decryptedVoice.audioMetadata.codec, "g711");
  assert.ok(decryptedVoice.audioMetadata.extraBytes);
  assert.strictEqual(encodeHex(decryptedVoice.audioMetadata.extraBytes!), "deadbeef");
});

test("Full Coverage - Seal & OpenSeal validation edge cases", async () => {
  const alice = await Identity.create("alice");
  const bob = await Identity.create("bob");
  const charlie = await Identity.create("charlie");

  const env = await seal(alice, bob.publicCard(), encodeUTF8("test message"));

  // 1. Recipient mismatch
  await assert.rejects(async () => {
    await openSeal(charlie, alice.publicCard(), env);
  }, /Envelope is not addressed to this receiver/);

  // 2. Sender mismatch
  await assert.rejects(async () => {
    await openSeal(bob, charlie.publicCard(), env);
  }, /Envelope sender_id does not match the provided senderCard/);

  // 3. Classical-only senderCard mismatch check (line 172-174)
  const classicalEnv: any = { ...env, envelope_nonce: "nonce_class_check_1", pqc_mode: "none" };
  const cardWithPqc: PublicCard = {
    ...alice.publicCard(),
    public_keys: {
      ...alice.publicCard().public_keys,
      pqc_sig_pub: "a".repeat(64)
    }
  };
  await assert.rejects(async () => {
    await openSeal(bob, cardWithPqc, classicalEnv);
  }, /Sender card advertises PQC capability but envelope specifies pqc_mode: 'none'/);

  // 4. Missing PQC sig in non-classical mode
  const freshEnv1 = await seal(alice, bob.publicCard(), encodeUTF8("msg1"));
  (freshEnv1 as any).pqc_sig = undefined;
  await assert.rejects(async () => {
    await openSeal(bob, alice.publicCard(), freshEnv1);
  }, /Envelope is missing PQC signature but is not in classical-only mode/);

  // 5. Missing kem_ciphertext in non-classical mode
  const freshEnv2 = await seal(alice, bob.publicCard(), encodeUTF8("msg2"));
  (freshEnv2 as any).kem_ciphertext = undefined;
  await assert.rejects(async () => {
    await openSeal(bob, alice.publicCard(), freshEnv2);
  }, /Envelope is missing kem_ciphertext but is not in classical-only mode/);

  // 6. Classical signature verification failure (tampered classical_sig)
  const freshEnv3 = await seal(alice, bob.publicCard(), encodeUTF8("msg3"));
  (freshEnv3 as any).classical_sig = "ff".repeat(64);
  await assert.rejects(async () => {
    await openSeal(bob, alice.publicCard(), freshEnv3);
  }, /Classical signature verification failed/);

  // 7. PQC signature verification failure (tampered pqc_sig)
  const freshEnv4 = await seal(alice, bob.publicCard(), encodeUTF8("msg4"));
  (freshEnv4 as any).pqc_sig = "ff".repeat(64);
  await assert.rejects(async () => {
    await openSeal(bob, alice.publicCard(), freshEnv4);
  }, /PQC signature verification failed/);

  // 8. Replay error
  const freshEnv5 = await seal(alice, bob.publicCard(), encodeUTF8("msg5"));
  await openSeal(bob, alice.publicCard(), freshEnv5);
  await assert.rejects(async () => {
    await openSeal(bob, alice.publicCard(), freshEnv5);
  }, /ReplayError: Envelope replay detected/);

  // 9. Classical-only mode openSeal test
  const classicalSenderCard: PublicCard = {
    ...alice.publicCard(),
    public_keys: {
      ...alice.publicCard().public_keys,
      pqc_sig_pub: "",
      pqc_kem_pub: ""
    }
  };
  const eph = await generateX25519KeyPair();
  const shX25519 = await deriveSharedSecret(
    eph.privateKey,
    bob.publicCard().public_keys.exchange_pub
  );
  const ephPubBytes = decodeBase64(eph.publicKey);
  const symmKey = await hkdf(shX25519, ephPubBytes, encodeUTF8("UXSP-hybrid-key-exchange-v1"), 32);
  const cNonce = new Uint8Array(12);
  crypto.getRandomValues(cNonce);
  const msgBytes = encodeUTF8("classical message");
  const cCiphertext = await aesGcmEncrypt(symmKey, cNonce, msgBytes, encodeUTF8(alice.entity_id + bob.entity_id));
  const cEnvNonce = "classical_nonce_test_999";
  const nowTs = Math.floor(Date.now() / 1000);
  
  let totalLen = 0;
  const f1 = encodeUTF8("UXSP-1");
  const f4 = encodeUTF8(alice.entity_id);
  const f5 = encodeUTF8(bob.entity_id);
  const f6 = encodeUTF8(nowTs.toString());
  const f7 = encodeUTF8(cEnvNonce);
  const f9 = new Uint8Array(0);
  const fields = [f1, cCiphertext, cNonce, f4, f5, f6, f7, ephPubBytes, f9];
  for (const f of fields) totalLen += 4 + f.length;
  const sigPayload = new Uint8Array(totalLen);
  let off = 0;
  for (const f of fields) {
    new DataView(sigPayload.buffer).setUint32(off, f.length, false);
    sigPayload.set(f, off + 4);
    off += 4 + f.length;
  }
  const cSig = await signEd25519(alice.keys.signing.privateKey, sigPayload);
  const validClassicalEnv: UXSPEnvelope = {
    version: "UXSP-1",
    sender_id: alice.entity_id,
    recipient_id: bob.entity_id,
    timestamp: nowTs,
    envelope_nonce: cEnvNonce,
    ciphertext: encodeHex(cCiphertext),
    nonce: encodeHex(cNonce),
    ephemeral_pub: encodeHex(ephPubBytes),
    classical_sig: encodeHex(cSig),
    pqc_mode: "none"
  };
  const openedClassical = await openSeal(bob, classicalSenderCard, validClassicalEnv);
  assert.deepEqual(openedClassical, msgBytes);
});

test("Full Coverage - Client package edge cases", async () => {
  const alice = await Identity.create("alice");
  const bob = await Identity.create("bob");

  // Missing envelope in live voice package
  const invalidVoicePkg: SecurePackage = {
    uxsp_package_version: "1.0",
    sender_id: "alice",
    receiver_id: "bob",
    data_type: "live_voice_session",
    is_chunked: false,
    envelope: null,
    chunks: [],
    metadata: {}
  };
  await assert.rejects(async () => {
    await UXSPClient.openLiveVoicePackage(bob, alice.publicCard(), invalidVoicePkg);
  }, /SecurePackage is missing its envelope/);

  // Missing envelope in standard package for openEncryptedPackage
  const missingEnvPkg: SecurePackage = {
    uxsp_package_version: "1.0",
    sender_id: "alice",
    receiver_id: "bob",
    data_type: "TEXT",
    is_chunked: false,
    envelope: null,
    chunks: [],
    metadata: {}
  };
  await assert.rejects(async () => {
    await UXSPClient.openEncryptedPackage(bob, alice.publicCard(), missingEnvPkg);
  }, /SecurePackage is missing its envelope/);

  // Chunked package with empty chunks
  const emptyChunksPkg: SecurePackage = {
    uxsp_package_version: "1.0",
    sender_id: "alice",
    receiver_id: "bob",
    data_type: "TEXT",
    is_chunked: true,
    envelope: null,
    chunks: [],
    metadata: {}
  };
  await assert.rejects(async () => {
    await UXSPClient.openEncryptedPackage(bob, alice.publicCard(), emptyChunksPkg);
  }, /Package is marked as chunked but contains no chunks/);

  // Invalid package creation schema validation error (corrupt envelope)
  assert.throws(() => {
    UXSPClient.createPackage({
      sender_id: "alice",
      receiver_id: "bob",
      envelope: { invalid: "envelope" } as any
    });
  }, /Failed to validate created UXSP SecurePackage against wire schema/);

  // Invalid package serialize
  assert.throws(() => {
    UXSPClient.serializePackage({} as any);
  }, /Cannot serialize invalid SecurePackage payload/);
});

test("Full Coverage - Utils edge cases", () => {
  const text = "Hello UTF-8!";
  const encoded = encodeUTF8(text);
  const decoded = decodeUTF8(encoded);
  assert.strictEqual(decoded, text);

  assert.throws(() => {
    decodeHex("abc"); // Odd length throws
  }, /Invalid hex string/);
});

test("Full Coverage - PQC stub branches", async () => {
  const kemKeys = await generateMLKEMKeyPair();
  assert.ok(kemKeys.publicKey);
  assert.ok(kemKeys.privateKey);

  const sigKeys = await generateMLDSAKeyPair();
  assert.ok(sigKeys.publicKey);
  assert.ok(sigKeys.privateKey);

  const encap = await encapsulateMLKEM("STUB_MLKEM_PUB");
  assert.strictEqual(encap.sharedSecret.length, 32);
  assert.strictEqual(encap.ciphertext.length, 32);

  const decap = await decapsulateMLKEM(new Uint8Array(32), "STUB_MLKEM_PRIV");
  assert.strictEqual(decap.length, 32);

  const sig = await signMLDSA("STUB_MLDSA_PRIV", new Uint8Array([1, 2, 3]));
  assert.strictEqual(sig.length, 64);

  const verified = await verifyMLDSA("STUB_MLDSA_PUB", sig, new Uint8Array([1, 2, 3]));
  assert.strictEqual(verified, true);
});
