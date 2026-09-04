import Foundation

/// UXSP Swift iOS/macOS Client SDK.
public struct UXSPEnvelope: Codable {
    public let version: String
    public let senderId: String
    public let recipientId: String
    public let timestamp: UInt64
    public let envelopeNonce: String
    public let ciphertext: String
    public let nonce: String
    public let ephemeralPub: String
    public let kemCiphertext: String
    public let classicalSig: String
    public let pqcSig: String

    enum CodingKeys: String, CodingKey {
        case version
        case senderId = "sender_id"
        case recipientId = "recipient_id"
        case timestamp
        case envelopeNonce = "envelope_nonce"
        case ciphertext
        case nonce
        case ephemeralPub = "ephemeral_pub"
        case kemCiphertext = "kem_ciphertext"
        case classicalSig = "classical_sig"
        case pqcSig = "pqc_sig"
    }
}

public class UXSPClient {
    public static func bindFields(_ fields: [Data]) -> Data {
        var result = Data()
        for field in fields {
            var len = UInt32(field.count).bigEndian
            result.append(Data(bytes: &len, count: 4))
            result.append(field)
        }
        return result
    }
}
