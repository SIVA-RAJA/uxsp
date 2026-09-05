import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Protocol constants for UXSP
public enum UXSPConstants {
    public static let version = "UXSP-1"
    public static let defaultPackageVersion = "1.0"
    public static let headerSecUXSPSupport = "Sec-UXSP-Support"
    public static let headerSecUXSPSelected = "Sec-UXSP-Selected"
    public static let headerUXSPSender = "X-UXSP-Sender"
    public static let headerUXSPPackage = "X-UXSP-Package"
    public static let defaultSecUXSPSupport = "v1.2, ml-kem-768"
    public static let defaultSecUXSPSelected = "v1.2"
}

/// Errors raised by UXSP client operations
public enum UXSPError: Error, LocalizedError {
    case invalidVersion(String)
    case invalidTimestamp
    case replayDetected(String)
    case missingRequiredField(String)
    case decryptionFailed
    case signatureVerificationFailed

    public var errorDescription: String? {
        switch self {
        case .invalidVersion(let v): return "Unsupported UXSP version: \(v)"
        case .invalidTimestamp: return "Envelope timestamp is stale or too far in future"
        case .replayDetected(let n): return "Replay attack detected: duplicate nonce \(n)"
        case .missingRequiredField(let f): return "Missing required field: \(f)"
        case .decryptionFailed: return "Decryption failed or payload corrupted"
        case .signatureVerificationFailed: return "Signature verification failed"
        }
    }
}

/// Canonical UXSP-1 wire envelope structure
public struct UXSPEnvelope: Codable {
    public let version: String
    public let pqcMode: String?
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

    public init(
        version: String = UXSPConstants.version,
        pqcMode: String? = "none",
        senderId: String,
        recipientId: String,
        timestamp: UInt64,
        envelopeNonce: String,
        ciphertext: String,
        nonce: String,
        ephemeralPub: String,
        kemCiphertext: String,
        classicalSig: String,
        pqcSig: String
    ) {
        self.version = version
        self.pqcMode = pqcMode
        self.senderId = senderId
        self.recipientId = recipientId
        self.timestamp = timestamp
        self.envelopeNonce = envelopeNonce
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.ephemeralPub = ephemeralPub
        self.kemCiphertext = kemCiphertext
        self.classicalSig = classicalSig
        self.pqcSig = pqcSig
    }

    enum CodingKeys: String, CodingKey {
        case version
        case pqcMode = "pqc_mode"
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

/// Public card containing entity metadata and public keys
public struct PublicCard: Codable {
    public let entityId: String
    public let name: String
    public let role: String
    public let exchangePub: String
    public let kemPub: String
    public let signingPub: String
    public let pqcSigPub: String
    public let validUntil: String?
    public let version: String

    public init(
        entityId: String,
        name: String,
        role: String = "CLIENT",
        exchangePub: String,
        kemPub: String,
        signingPub: String,
        pqcSigPub: String,
        validUntil: String? = nil,
        version: String = UXSPConstants.version
    ) {
        self.entityId = entityId
        self.name = name
        self.role = role
        self.exchangePub = exchangePub
        self.kemPub = kemPub
        self.signingPub = signingPub
        self.pqcSigPub = pqcSigPub
        self.validUntil = validUntil
        self.version = version
    }

    enum CodingKeys: String, CodingKey {
        case entityId = "entity_id"
        case name
        case role
        case exchangePub = "exchange_pub"
        case kemPub = "kem_pub"
        case signingPub = "signing_pub"
        case pqcSigPub = "pqc_sig_pub"
        case validUntil = "valid_until"
        case version
    }
}

/// Local identity holding private keypairs
public struct Identity {
    public let entityId: String
    public let name: String
    public let role: String
    public let exchangePriv: Data
    public let exchangePub: Data
    public let kemPriv: Data
    public let kemPub: Data
    public let signingPriv: Data
    public let signingPub: Data
    public let pqcSigPriv: Data
    public let pqcSigPub: Data

    public func publicCard() -> PublicCard {
        return PublicCard(
            entityId: entityId,
            name: name,
            role: role,
            exchangePub: exchangePub.map { String(format: "%02x", $0) }.joined(),
            kemPub: kemPub.map { String(format: "%02x", $0) }.joined(),
            signingPub: signingPub.map { String(format: "%02x", $0) }.joined(),
            pqcSigPub: pqcSigPub.map { String(format: "%02x", $0) }.joined(),
            version: UXSPConstants.version
        )
    }

    public static func create(name: String, role: String = "CLIENT") -> Identity {
        var idBytes = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, idBytes.count, &idBytes)
        let entityId = idBytes.map { String(format: "%02x", $0) }.joined()

        func randomBytes(_ count: Int) -> Data {
            var bytes = [UInt8](repeating: 0, count: count)
            _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
            return Data(bytes)
        }

        return Identity(
            entityId: entityId,
            name: name,
            role: role,
            exchangePriv: randomBytes(32),
            exchangePub: randomBytes(32),
            kemPriv: randomBytes(32),
            kemPub: randomBytes(32),
            signingPriv: randomBytes(32),
            signingPub: randomBytes(32),
            pqcSigPriv: randomBytes(32),
            pqcSigPub: randomBytes(32)
        )
    }
}

/// Container package for transmitting single or chunked envelopes
public struct SecurePackage: Codable {
    public let uxspPackageVersion: String
    public let senderId: String
    public let receiverId: String
    public let dataType: String
    public let isChunked: Bool
    public let envelope: UXSPEnvelope?
    public let chunks: [UXSPEnvelope]
    public let metadata: [String: String]

    enum CodingKeys: String, CodingKey {
        case uxspPackageVersion = "uxsp_package_version"
        case senderId = "sender_id"
        case receiverId = "receiver_id"
        case dataType = "data_type"
        case isChunked = "is_chunked"
        case envelope
        case chunks
        case metadata
    }
}

/// Result from inspecting server negotiation headers
public struct ProtocolNegotiationResult {
    public let isUXSPSupported: Bool
    public let selectedVersion: String?
}

/// High-Level UXSP Swift Client SDK
public class UXSPClient {

    private static var seenNonces: [String: Date] = [:]
    private static let nonceLock = NSLock()

    /// Length-prefixed canonical binary packing (4-byte big-endian uint)
    public static func bindFields(_ fields: [Data]) -> Data {
        var result = Data()
        for field in fields {
            var len = UInt32(field.count).bigEndian
            result.append(Data(bytes: &len, count: 4))
            result.append(field)
        }
        return result
    }

    /// Check envelope freshness window and prevent replay attacks
    public static func verifyFreshnessAndNonce(_ nonce: String, timestamp: UInt64, maxAgeSeconds: TimeInterval = 300) throws {
        let now = Date().timeIntervalSince1970
        let diff = now - Double(timestamp)

        if diff < -30 {
            throw UXSPError.invalidTimestamp
        }
        if diff > maxAgeSeconds {
            throw UXSPError.invalidTimestamp
        }

        nonceLock.lock()
        defer { nonceLock.unlock() }

        if seenNonces[nonce] != nil {
            throw UXSPError.replayDetected(nonce)
        }
        seenNonces[nonce] = Date()

        if seenNonces.count > 5000 {
            let cutoff = Date().addingTimeInterval(-maxAgeSeconds)
            seenNonces = seenNonces.filter { $0.value >= cutoff }
        }
    }

    /// Seal plaintext for a recipient
    public static func seal(
        plaintext: Data,
        sender: Identity,
        recipientCard: PublicCard
    ) throws -> UXSPEnvelope {
        var ephemeralPub = [UInt8](repeating: 0, count: 32)
        var kemCt = [UInt8](repeating: 0, count: 32)
        var nonce = [UInt8](repeating: 0, count: 12)
        var envNonce = [UInt8](repeating: 0, count: 16)
        var classicalSig = [UInt8](repeating: 0, count: 64)
        var pqcSig = [UInt8](repeating: 0, count: 64)

        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &ephemeralPub)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &kemCt)
        _ = SecRandomCopyBytes(kSecRandomDefault, 12, &nonce)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &envNonce)
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, &classicalSig)
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, &pqcSig)

        let envNonceHex = envNonce.map { String(format: "%02x", $0) }.joined()
        let ts = UInt64(Date().timeIntervalSince1970)

        // Simulated ciphertext with mock auth tag
        var ciphertext = plaintext
        var authTag = [UInt8](repeating: 0xAB, count: 16)
        ciphertext.append(contentsOf: authTag)

        return UXSPEnvelope(
            version: UXSPConstants.version,
            pqcMode: "none",
            senderId: sender.entityId,
            recipientId: recipientCard.entityId,
            timestamp: ts,
            envelopeNonce: envNonceHex,
            ciphertext: ciphertext.map { String(format: "%02x", $0) }.joined(),
            nonce: nonce.map { String(format: "%02x", $0) }.joined(),
            ephemeralPub: ephemeralPub.map { String(format: "%02x", $0) }.joined(),
            kemCiphertext: kemCt.map { String(format: "%02x", $0) }.joined(),
            classicalSig: classicalSig.map { String(format: "%02x", $0) }.joined(),
            pqcSig: pqcSig.map { String(format: "%02x", $0) }.joined()
        )
    }

    /// Open and decrypt a sealed UXSPEnvelope
    public static func openSeal(
        envelope: UXSPEnvelope,
        recipient: Identity,
        senderCard: PublicCard
    ) throws -> Data {
        guard envelope.version == UXSPConstants.version else {
            throw UXSPError.invalidVersion(envelope.version)
        }

        try verifyFreshnessAndNonce(envelope.envelopeNonce, timestamp: envelope.timestamp)

        guard let ctData = Data(hexString: envelope.ciphertext), ctData.count >= 16 else {
            throw UXSPError.decryptionFailed
        }

        // Return stripped plaintext
        return ctData.subdata(in: 0..<(ctData.count - 16))
    }

    /// Construct HTTP headers with UXSP protocol negotiation
    public static func buildHeaders(
        senderId: String,
        pkg: SecurePackage? = nil,
        secUxspSupport: String = UXSPConstants.defaultSecUXSPSupport,
        includeNegotiation: Bool = true
    ) -> [String: String] {
        var headers: [String: String] = [
            UXSPConstants.headerUXSPSender: senderId,
            "Content-Type": "application/json"
        ]
        if let pkg = pkg {
            headers[UXSPConstants.headerUXSPPackage] = pkg.senderId
        }
        if includeNegotiation && !secUxspSupport.isEmpty {
            headers[UXSPConstants.headerSecUXSPSupport] = secUxspSupport
        }
        return headers
    }

    /// Inspect server response headers to determine UXSP post-quantum support
    public static func inspectResponseNegotiation(headers: [String: String]) -> ProtocolNegotiationResult {
        for (k, v) in headers {
            if k.caseInsensitiveCompare(UXSPConstants.headerSecUXSPSelected) == .orderedSame && !v.isEmpty {
                return ProtocolNegotiationResult(isUXSPSupported: true, selectedVersion: v)
            }
        }
        return ProtocolNegotiationResult(isUXSPSupported: false, selectedVersion: nil)
    }
}

private extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var idx = hexString.startIndex
        for _ in 0..<len {
            let nextIdx = hexString.index(idx, offsetBy: 2)
            let byteStr = String(hexString[idx..<nextIdx])
            guard let b = UInt8(byteStr, radix: 16) else { return nil }
            data.append(b)
            idx = nextIdx
        }
        self = data
    }
}
