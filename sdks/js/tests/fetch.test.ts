import test from "node:test";
import assert from "node:assert";
import {
  Identity,
  UXSPClient,
  setIdentity,
  registerPeer,
  uxspFetch,
  createUXSPFetch,
  installFetchInterceptor,
} from "../dist/index.js";

test("uxspFetch - Plain HTTP fallback", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url: any, init: any) => {
      assert.strictEqual(init.headers.get("Sec-UXSP-Support"), "v1.2, ml-kem-768");
      return new Response(JSON.stringify({ status: "plain-ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const resp = await uxspFetch("https://api.example.com/hello");
    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.isEncrypted, false);
    const data = await resp.json();
    assert.deepStrictEqual(data, { status: "plain-ok" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("uxspFetch - Automatic encryption and decryption with UXSP server", async () => {
  const client = await Identity.create("client_user", "CLIENT");
  const server = await Identity.create("server_host", "SERVER");
  const serverCard = server.publicCard();
  const clientCard = client.publicCard();

  setIdentity(client);
  await registerPeer(serverCard);

  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url: any, init: any) => {
      // Verify outgoing request was encrypted into a SecurePackage
      const contentType = init.headers.get("Content-Type");
      assert.strictEqual(contentType, "application/uxsp+json");
      assert.strictEqual(init.headers.get("X-UXSP-Package"), client.entity_id);

      const parsedClientPkg = UXSPClient.parsePackage(init.body);
      const decryptedClientMsg = await UXSPClient.openEncryptedPackage(
        server,
        clientCard,
        parsedClientPkg
      );
      assert.strictEqual(new TextDecoder().decode(decryptedClientMsg), '{"msg":"secret message"}');

      // Server generates encrypted response package back to client
      const responseData = new TextEncoder().encode(JSON.stringify({ answer: 42 }));
      const serverPkg = await UXSPClient.createEncryptedPackage(
        server,
        clientCard,
        responseData,
        "JSON"
      );

      return new Response(UXSPClient.serializePackage(serverPkg), {
        status: 200,
        headers: {
          "Content-Type": "application/uxsp+json",
          "X-UXSP-Package": server.entity_id,
          "Sec-UXSP-Selected": "v1.2, ml-kem-768",
        },
      });
    };

    const resp = await uxspFetch("https://api.example.com/secure-calc", {
      method: "POST",
      body: { msg: "secret message" },
      peerCard: serverCard,
    });

    assert.strictEqual(resp.status, 200);
    assert.strictEqual(resp.isEncrypted, true);
    assert.ok(resp.package);
    assert.strictEqual(resp.package.sender_id, server.entity_id);

    const result = await resp.json();
    assert.deepStrictEqual(result, { answer: 42 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("uxspFetch - installFetchInterceptor transparently intercepts globalThis.fetch", async () => {
  const client = await Identity.create("app_client", "CLIENT");
  const server = await Identity.create("api_backend", "SERVER");
  const serverCard = server.publicCard();

  const originalFetch = globalThis.fetch;
  try {
    const mockServerFetch = async () => {
      return new Response(JSON.stringify({ interceptor: "active" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };
    globalThis.fetch = mockServerFetch as any;

    const uninstall = installFetchInterceptor({
      identity: client,
    });

    // Calling global fetch now uses UXSP interceptor
    const response = await globalThis.fetch("https://api.example.com/check");
    assert.strictEqual(response.status, 200);
    const data = await response.json();
    assert.deepStrictEqual(data, { interceptor: "active" });

    // Uninstall restores original
    uninstall();
    assert.strictEqual(globalThis.fetch, mockServerFetch);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
