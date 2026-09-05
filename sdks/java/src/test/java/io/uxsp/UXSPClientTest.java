package io.uxsp;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class UXSPClientTest {

    public static void main(String[] args) throws Exception {
        testBindFields();
        testIdentityAndPublicCard();
        testSealAndOpenSeal();
        testEncryptedPackageWorkflow();
        testHeadersAndNegotiation();
        testReplayDetection();
        System.out.println("All Java UXSPClient tests passed successfully!");
    }

    public static void testBindFields() {
        byte[] field1 = "UXSP-1".getBytes(StandardCharsets.UTF_8);
        byte[] field2 = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] bound = UXSPClient.bindFields(field1, field2);

        if (bound.length != (4 + field1.length + 4 + field2.length)) {
            throw new RuntimeException("Length-prefixed field binding length mismatch");
        }
    }

    public static void testIdentityAndPublicCard() {
        UXSPClient.Identity alice = UXSPClient.Identity.create("alice", "CLIENT");
        if (alice.entityId == null || alice.entityId.isEmpty() || !"alice".equals(alice.name)) {
            throw new RuntimeException("Identity creation validation failed");
        }

        UXSPClient.PublicCard card = alice.getPublicCard();
        if (!alice.entityId.equals(card.entityId) || card.exchangePub.isEmpty()) {
            throw new RuntimeException("PublicCard generation failed");
        }
    }

    public static void testSealAndOpenSeal() throws Exception {
        UXSPClient.Identity alice = UXSPClient.Identity.create("alice", "CLIENT");
        UXSPClient.Identity bob = UXSPClient.Identity.create("bob", "SERVER");

        byte[] plaintext = "Hello Java UXSP Engine!".getBytes(StandardCharsets.UTF_8);
        UXSPClient.Envelope env = UXSPClient.seal(plaintext, alice, bob.getPublicCard());

        if (!alice.entityId.equals(env.senderId) || !bob.entityId.equals(env.recipientId)) {
            throw new RuntimeException("Envelope metadata mismatch");
        }

        byte[] decrypted = UXSPClient.openSeal(env, bob, alice.getPublicCard());
        if (decrypted == null || decrypted.length == 0) {
            throw new RuntimeException("Decryption returned empty bytes");
        }
    }

    public static void testEncryptedPackageWorkflow() throws Exception {
        UXSPClient.Identity alice = UXSPClient.Identity.create("alice", "CLIENT");
        UXSPClient.Identity bob = UXSPClient.Identity.create("bob", "SERVER");

        byte[] plaintext = "Cross-platform payload test".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> meta = new HashMap<>();
        meta.put("sender_app", "android");

        UXSPClient.SecurePackage pkg = UXSPClient.createEncryptedPackage(alice, bob.getPublicCard(), plaintext, "TEXT", meta);
        if (!alice.entityId.equals(pkg.sender_id) || !"TEXT".equals(pkg.data_type)) {
            throw new RuntimeException("Package metadata mismatch");
        }

        byte[] opened = UXSPClient.openEncryptedPackage(bob, alice.getPublicCard(), pkg);
        if (opened == null || opened.length == 0) {
            throw new RuntimeException("Opened package payload was empty");
        }
    }

    public static void testHeadersAndNegotiation() {
        Map<String, String> headers = UXSPClient.buildHeaders("alice", null, "v1.2, ml-kem-768", true);
        if (!"alice".equals(headers.get(UXSPClient.HEADER_UXSP_SENDER)) ||
            !"v1.2, ml-kem-768".equals(headers.get(UXSPClient.HEADER_SEC_UXSP_SUPPORT))) {
            throw new RuntimeException("Header creation mismatch");
        }

        Map<String, String> serverHeaders = new HashMap<>();
        serverHeaders.put("Sec-UXSP-Selected", "v1.2");
        UXSPClient.NegotiationResult res = UXSPClient.inspectResponseNegotiation(serverHeaders);
        if (!res.isUXSPSupported || !"v1.2".equals(res.selectedVersion)) {
            throw new RuntimeException("Negotiation inspection failed");
        }
    }

    public static void testReplayDetection() throws Exception {
        String nonce = "java_replay_nonce_test_999";
        long now = java.time.Instant.now().getEpochSecond();

        UXSPClient.verifyFreshnessAndNonce(nonce, now, 300);

        try {
            UXSPClient.verifyFreshnessAndNonce(nonce, now, 300);
            throw new RuntimeException("Expected replay detection exception");
        } catch (IllegalStateException e) {
            // Expected
        }
    }
}
