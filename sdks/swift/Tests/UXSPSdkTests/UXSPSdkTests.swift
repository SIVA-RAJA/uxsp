import Foundation
import UXSPSdk

public class UXSPSdkTests {
    public static func runAllTests() {
        testBindFields()
        testIdentityAndPublicCard()
        testSealAndOpenSeal()
        testHeadersAndNegotiation()
        testReplayDetection()
        print("All Swift UXSPSdk tests passed successfully!")
    }

    public static func testBindFields() {
        let field1 = "UXSP-1".data(using: .utf8)!
        let field2 = "swift".data(using: .utf8)!
        let bound = UXSPClient.bindFields([field1, field2])
        assert(bound.count == (4 + field1.count + 4 + field2.count), "Bind fields length error")
    }

    public static func testIdentityAndPublicCard() {
        let alice = Identity.create(name: "alice", role: "CLIENT")
        assert(!alice.entityId.isEmpty, "Alice entity ID empty")
        assert(alice.name == "alice", "Alice name mismatch")

        let card = alice.publicCard()
        assert(card.entityId == alice.entityId, "Card entity ID mismatch")
        assert(!card.exchangePub.isEmpty, "Card exchangePub empty")
    }

    public static func testSealAndOpenSeal() {
        let alice = Identity.create(name: "alice")
        let bob = Identity.create(name: "bob")

        let plaintext = "Hello Swift UXSP Engine!".data(using: .utf8)!
        do {
            let env = try UXSPClient.seal(plaintext: plaintext, sender: alice, recipientCard: bob.publicCard())
            assert(env.senderId == alice.entityId, "Sender ID mismatch")
            assert(env.recipientId == bob.entityId, "Recipient ID mismatch")

            let decrypted = try UXSPClient.openSeal(envelope: env, recipient: bob, senderCard: alice.publicCard())
            assert(decrypted == plaintext, "Decrypted plaintext mismatch")
        } catch {
            assertionFailure("Seal or OpenSeal failed with error: \(error)")
        }
    }

    public static func testHeadersAndNegotiation() {
        let headers = UXSPClient.buildHeaders(senderId: "alice")
        assert(headers[UXSPConstants.headerUXSPSender] == "alice", "Sender header mismatch")
        assert(headers[UXSPConstants.headerSecUXSPSupport] == UXSPConstants.defaultSecUXSPSupport, "Negotiation header mismatch")

        let supportedRes = UXSPClient.inspectResponseNegotiation(headers: ["Sec-UXSP-Selected": "v1.2"])
        assert(supportedRes.isUXSPSupported && supportedRes.selectedVersion == "v1.2", "Negotiation inspection failed for supported")

        let unsupportedRes = UXSPClient.inspectResponseNegotiation(headers: ["Content-Type": "application/json"])
        assert(!unsupportedRes.isUXSPSupported, "Negotiation inspection failed for unsupported")
    }

    public static func testReplayDetection() {
        let nonce = "swift_replay_nonce_test_777"
        let ts = UInt64(Date().timeIntervalSince1970)

        do {
            try UXSPClient.verifyFreshnessAndNonce(nonce, timestamp: ts)
        } catch {
            assertionFailure("First nonce check failed: \(error)")
        }

        var caughtReplay = false
        do {
            try UXSPClient.verifyFreshnessAndNonce(nonce, timestamp: ts)
        } catch UXSPError.replayDetected {
            caughtReplay = true
        } catch {
            assertionFailure("Unexpected error on replay check: \(error)")
        }
        assert(caughtReplay, "Failed to catch duplicate nonce replay attack")
    }
}
