import { test } from "node:test";
import assert from "node:assert";
import { UXSPClient } from "../src/client.js";
import { Identity } from "../src/identity.js";
import { PublicCard, SecurePackage } from "../src/types.js";
import { generateX25519KeyPair } from "../src/crypto.js";
import { seal } from "../src/seal.js";

test("UXSPClient - Full Coverage Test Suite", async () => {
  // 1. Setup Mock Identities
  const alice = await Identity.create("alice");
  const bob = await Identity.create("bob");
  const aliceCard = alice.publicCard();
  const bobCard: PublicCard = bob.publicCard();

  // 2. Encrypted Package & Open Encrypted Package
  const pkg = await UXSPClient.createEncryptedPackage(
    alice,
    bobCard,
    new TextEncoder().encode("Hello multi-language SDK!"),
    "TEXT",
    { foo: "bar" }
  );
  assert.strictEqual(pkg.sender_id, alice.entity_id);
  assert.strictEqual(pkg.receiver_id, bob.entity_id);

  const decrypted = await UXSPClient.openEncryptedPackage(bob, aliceCard, pkg);
  assert.strictEqual(new TextDecoder().decode(decrypted), "Hello multi-language SDK!");

  // 3. Serialize & Parse Package
  const jsonStr = UXSPClient.serializePackage(pkg);
  const parsedPkg = UXSPClient.parsePackage(jsonStr);
  assert.strictEqual(parsedPkg.sender_id, alice.entity_id);

  // 4. Parse Public Card
  const cardJson = JSON.stringify(bobCard);
  const parsedCard = UXSPClient.parsePublicCard(cardJson);
  assert.strictEqual(parsedCard.entity_id, bob.entity_id);

  // 5. Build Headers
  const headers = UXSPClient.buildHeaders("alice", pkg, { secUxspSupport: "v1.2" });
  assert.strictEqual(headers["X-UXSP-Sender"], "alice");
  assert.strictEqual(headers["Sec-UXSP-Support"], "v1.2");

  // 6. Inspect Response Negotiation
  const resSupport = UXSPClient.inspectResponseNegotiation({ "Sec-UXSP-Selected": "v1.2" });
  assert.strictEqual(resSupport.isUXSPSupported, true);
  assert.strictEqual(resSupport.selectedVersion, "v1.2");

  const resUnsupported = UXSPClient.inspectResponseNegotiation({});
  assert.strictEqual(resUnsupported.isUXSPSupported, false);

  // 7. Chunked Package Opening
  const chunk1 = await seal(alice, bobCard, new TextEncoder().encode("chunk1"));
  const chunk2 = await seal(alice, bobCard, new TextEncoder().encode("chunk2"));

  const chunkedPkg = UXSPClient.createPackage({
    sender_id: "alice",
    receiver_id: "bob",
    data_type: "TEXT",
    chunks: [chunk1, chunk2]
  });

  const chunkedDecrypted = await UXSPClient.openEncryptedPackage(bob, aliceCard, chunkedPkg);
  assert.strictEqual(new TextDecoder().decode(chunkedDecrypted), "chunk1chunk2");
});

test("UXSPClient - Error Validation Coverage", async () => {
  const alice = await Identity.create("alice");
  const bob = await Identity.create("bob");

  // Invalid package parse
  assert.throws(() => {
    UXSPClient.parsePackage({ invalid: "data" });
  });

  // Invalid card parse
  assert.throws(() => {
    UXSPClient.parsePublicCard({ invalid: "card" });
  });

  // Missing envelope in non-chunked package
  const emptyPkg: SecurePackage = {
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
    await UXSPClient.openEncryptedPackage(bob, alice.publicCard(), emptyPkg);
  });
});
