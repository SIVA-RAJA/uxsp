import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  configure,
  setIdentity,
  getIdentity,
  registerPeer,
  getPeer,
  Send,
  Receive,
  SendText,
  ReceiveText,
  SendJSON,
  ReceiveJSON,
  SendBinary,
  ReceiveBinary,
  SendFile,
  ReceiveFile,
  hashPassword,
  verifyPassword,
} from "../dist/index.js";

test("Identity - Key Rotation, Password Hashing & Encrypted Export/Import", async () => {
  const alice = await Identity.create("Alice", "DEVELOPER");
  assert.strictEqual(alice.key_version, 1);
  assert.strictEqual(alice.keys_rotated_at, null);

  const initialCard = alice.publicCard();

  // 1. Key Rotation
  await alice.rotateKeys();
  assert.strictEqual(alice.key_version, 2);
  assert.ok(alice.keys_rotated_at);

  const rotatedCard = alice.publicCard();
  assert.strictEqual(rotatedCard.key_version, 2);
  assert.notStrictEqual(rotatedCard.public_keys.exchange_pub, initialCard.public_keys.exchange_pub);

  // 2. Password Hashing
  const password = "SuperSecretPassword123!";
  const hash = await hashPassword(password);
  assert.ok(hash.startsWith("$pbkdf2-sha256$"));

  const validPw = await verifyPassword(hash, password);
  assert.strictEqual(validPw, true);

  const invalidPw = await verifyPassword(hash, "WrongPassword!");
  assert.strictEqual(invalidPw, false);

  // 3. Encrypted Export / Import
  const encryptedJson = await alice.exportEncrypted(password);
  assert.ok(encryptedJson.includes("UXSP-IDENTITY-1"));
  assert.ok(encryptedJson.includes("encrypted_private"));

  // Import with correct password
  const importedAlice = await Identity.importEncrypted(encryptedJson, password);
  assert.strictEqual(importedAlice.entity_id, alice.entity_id);
  assert.strictEqual(importedAlice.name, alice.name);
  assert.strictEqual(importedAlice.key_version, 2);
  assert.strictEqual(importedAlice.keys.signing.privateKey, alice.keys.signing.privateKey);

  // Import with incorrect password
  await assert.rejects(
    async () => {
      await Identity.importEncrypted(encryptedJson, "WrongPassword");
    },
    /Wrong password/
  );
});

test("Dispatchers - Simplified 1-Line Send / Receive Workflow", async () => {
  const alice = await Identity.create("Alice");
  const bob = await Identity.create("Bob");

  // Configure global security context
  setIdentity(alice);
  await registerPeer(bob.publicCard());

  assert.strictEqual(getIdentity().entity_id, alice.entity_id);
  assert.strictEqual((await getPeer(bob.entity_id)).name, "Bob");

  // 1. SendText / ReceiveText
  const textPkg = await SendText(bob.entity_id, "Quantum-resistant message!");
  const textRecv = await ReceiveText(textPkg, { receiver: bob, senderCard: alice.publicCard() });
  assert.strictEqual(textRecv, "Quantum-resistant message!");

  // 2. SendJSON / ReceiveJSON
  interface PayloadData {
    action: string;
    amount: number;
    tags: string[];
  }
  const jsonData: PayloadData = { action: "TRANSFER", amount: 5000, tags: ["urgent", "pqc"] };
  const jsonPkg = await SendJSON(bob.entity_id, jsonData);
  const jsonRecv = await ReceiveJSON<PayloadData>(jsonPkg, { receiver: bob, senderCard: alice.publicCard() });
  assert.deepStrictEqual(jsonRecv, jsonData);

  // 3. SendBinary / ReceiveBinary
  const binData = new Uint8Array([10, 20, 30, 40, 50]);
  const binPkg = await SendBinary(bob.entity_id, binData);
  const binRecv = await ReceiveBinary(binPkg, { receiver: bob, senderCard: alice.publicCard() });
  assert.deepStrictEqual(binRecv, binData);

  // 4. SendFile / ReceiveFile
  const fileContent = new TextEncoder().encode("Contract document signed.");
  const filePkg = await SendFile(bob.entity_id, fileContent, "contract.pdf", "application/pdf");
  const fileRecv = await ReceiveFile(filePkg, { receiver: bob, senderCard: alice.publicCard() });
  assert.deepStrictEqual(fileRecv.data, fileContent);
  assert.strictEqual(fileRecv.filename, "contract.pdf");
  assert.strictEqual(fileRecv.contentType, "application/pdf");

  // 5. Polymorphic Send & Receive
  const polyPkg = await Send(bob.entity_id, { status: "OK", code: 200 });
  const polyRecv = await Receive(polyPkg, { receiver: bob, senderCard: alice.publicCard() });
  assert.deepStrictEqual(polyRecv, { status: "OK", code: 200 });
});
