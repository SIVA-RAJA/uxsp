import { test } from "node:test";
import * as assert from "node:assert";

import { UXSPClient } from "../src/client.js";

test("client - buildHeaders includes Sec-UXSP-Support by default", () => {
    const headers = UXSPClient.buildHeaders("sender_123");
    assert.strictEqual(headers["X-UXSP-Sender"], "sender_123");
    assert.strictEqual(headers["Content-Type"], "application/json");
    assert.strictEqual(headers["Sec-UXSP-Support"], "v1.2, ml-kem-768");
});

test("client - buildHeaders allows disabling or customizing negotiation header", () => {
    const headersCustom = UXSPClient.buildHeaders("sender_123", undefined, { secUxspSupport: "v1.2" });
    assert.strictEqual(headersCustom["Sec-UXSP-Support"], "v1.2");

    const headersDisabled = UXSPClient.buildHeaders("sender_123", undefined, { includeNegotiationHeader: false });
    assert.strictEqual(headersDisabled["Sec-UXSP-Support"], undefined);
});

test("client - inspectResponseNegotiation detects server support", () => {
    const resSupported = UXSPClient.inspectResponseNegotiation({ "Sec-UXSP-Selected": "v1.2" });
    assert.strictEqual(resSupported.isUXSPSupported, true);
    assert.strictEqual(resSupported.selectedVersion, "v1.2");

    const resUnsupported = UXSPClient.inspectResponseNegotiation({ "content-type": "application/json" });
    assert.strictEqual(resUnsupported.isUXSPSupported, false);
    assert.strictEqual(resUnsupported.selectedVersion, undefined);
});
