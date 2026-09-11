import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  TrustAnchor,
  TrustStore,
  PublicAnchor,
  SignedCard,
  CRL,
  UntrustedCardError,
  ExpiredCardError,
  RevokedCardError,
  CardNotYetValidError,
} from "../dist/index.js";

test("TrustAnchor - Card Issuance, TrustStore Verification & CRL Revocation", async () => {
  const rootCA = await TrustAnchor.create("UXSP-Root-CA");
  const publicAnchor = rootCA.publicAnchor();

  const alice = await Identity.create("Alice");
  const aliceCard = alice.publicCard();

  // 1. Issue signed card
  const signedCard = await rootCA.issue(aliceCard, 30);
  assert.strictEqual(signedCard.card.entity_id, alice.entity_id);
  assert.strictEqual(signedCard.issuer_id, rootCA.entity_id);
  assert.strictEqual(signedCard.isTimeValid(), true);

  // 2. TrustStore verification
  const store = new TrustStore();
  store.add(publicAnchor);

  const isValid = await store.verify(signedCard);
  assert.strictEqual(isValid, true);

  // 3. Reject untrusted issuer
  const untrustedStore = new TrustStore();
  await assert.rejects(
    async () => {
      await untrustedStore.verify(signedCard);
    },
    UntrustedCardError
  );

  // 4. Issue and verify CRL revocation
  const crl = await rootCA.issueCRL([
    { cert_id: signedCard.cert_id, reason: "key-compromise" },
  ]);
  assert.strictEqual(crl.isRevoked(signedCard.cert_id), true);

  // Verify CRL signature
  const crlValid = await crl.verify(publicAnchor.public_keys);
  assert.strictEqual(crlValid, true);

  // Add CRL to store
  store.addCRL(crl);

  // Verified card must now be rejected as revoked
  await assert.rejects(
    async () => {
      await store.verify(signedCard);
    },
    RevokedCardError
  );
});

test("TrustAnchor - Validity Window Checking", async () => {
  const rootCA = await TrustAnchor.create("Root-CA");
  const store = new TrustStore();
  store.add(rootCA.publicAnchor());

  const alice = await Identity.create("Alice");
  const now = Math.floor(Date.now() / 1000);

  // Card issued in the future
  const futureCard = await rootCA.issue(alice.publicCard(), 10, now + 500);
  await assert.rejects(
    async () => {
      await store.verify(futureCard, { now });
    },
    CardNotYetValidError
  );

  // Expired card
  const expiredCard = await rootCA.issue(alice.publicCard(), 1, now - 200000);
  await assert.rejects(
    async () => {
      await store.verify(expiredCard, { now });
    },
    ExpiredCardError
  );
});
