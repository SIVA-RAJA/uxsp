"""
UXSP — Universal Exchange Security Protocol

This is the main public API entry point for the UXSP library.

What this file does:
    - Collects and re-exports all public classes, functions, and errors from every
      sub-module (core, crypto, storage, transport) so that users only need to
      import from 'uxsp' directly (e.g. 'from uxsp import Identity, Envelope').
    - Sets package-level metadata: __version__, __author__, __license__.
    - Defines __all__ to control what 'from uxsp import *' exposes.

Sub-module overview:
    uxsp.core.identity      — Identity and PublicCard (keys + metadata per entity)
    uxsp.core.envelope      — Envelope wrapper around a sealed message
    uxsp.core.handshake     — Mutual-auth handshake to establish a shared session
    uxsp.core.session       — Encrypted, sequenced session for ongoing communication
    uxsp.core.signing       — Trust anchors and certificate-chain signing/verification
    uxsp.core.payload       — Structured text/file/binary payload packing
    uxsp.core.chunking      — Large-payload chunked transfer with integrity hashes
    uxsp.core.nonce         — In-memory nonce store and generator (lightweight)
    uxsp.core.replay        — Replay-attack guard backed by a NonceStore
    uxsp.core.rate_limit    — Fixed and sliding-window rate limiters (memory + Redis)
    uxsp.crypto.hybrid      — Hybrid (classical + PQC) seal/open and signing
    uxsp.crypto.kdf         — HKDF key derivation and Argon2id password hashing
    uxsp.storage.keystore   — Card registries (memory, file, Redis, Postgres, caching)
    uxsp.storage.noncestore — Heavier nonce stores (Redis, Postgres, tiered)
    uxsp.transport.http     — HTTP request/response helpers that carry UXSP envelopes
    uxsp.transport.websocket — WebSocket frame manager for full UXSP sessions
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("uxsp")
except PackageNotFoundError:
    __version__ = "1.0.0"
__author__ = "SIVA RAJA S"
__license__ = "MIT"

# ─────────────────────────────────────────────
# IDENTITY
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# ENVELOPE
# ─────────────────────────────────────────────
from uxsp.core.chunking import (
    ChunkFormatError,
    ChunkingError,
    ChunkValidationError,
    UXSPChunk,
    create_chunked_text,
    create_chunked_transfer,
    decode_chunked_text,
    reassemble_chunked_transfer,
)
from uxsp.core.envelope import (
    Envelope,
    EnvelopeError,
    EnvelopeExpiredError,
    EnvelopeTooLargeError,
    EnvelopeValidationError,
)

# ─────────────────────────────────────────────
# SESSION MANAGEMENT
# ─────────────────────────────────────────────
from uxsp.core.handshake import (
    Handshake,
    HandshakeAuthError,
    HandshakeError,
    HandshakeExpiredError,
    HandshakeProofError,
)
from uxsp.core.identity import (
    Identity,
    PublicCard,
    validate_role,
)
from uxsp.core.nonce import (
    MemoryNonceStore,
    NonceStore,
    UXSPStoreError,
    generate_nonce,
)
from uxsp.core.payload import (
    PayloadError,
    PayloadFormatError,
    PayloadValidationError,
    UXSPPayload,
    pack_binary,
    pack_file,
    pack_text,
    unpack_text,
    unpack_to_file,
)

# ─────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────
from uxsp.core.rate_limit import (
    GuardedHandshake,
    RateLimiter,
    RateLimiterBase,
    RateLimitExceededError,
    RedisRateLimiter,
    RedisSlidingRateLimiter,
    SlidingRateLimiter,
)

# ─────────────────────────────────────────────
# REPLAY PROTECTION
# ─────────────────────────────────────────────
from uxsp.core.replay import (
    DefaultReplayGuard,
    DuplicateNonceError,
    FutureEnvelopeError,
    ReplayError,
    ReplayGuard,
    StaleEnvelopeError,
)
from uxsp.core.session import (
    Session,
    SessionConfig,
    SessionError,
    SessionExpiredError,
    SessionNotActiveError,
    SessionReorderError,
    SessionRevokedError,
    SessionState,
)

# ─────────────────────────────────────────────
# SIGNING — trust anchors and certificate chains
# ─────────────────────────────────────────────
from uxsp.core.signing import (
    CardNotYetValidError,
    ExpiredCardError,
    InvalidCardSignatureError,
    PublicAnchor,
    SignedCard,
    SigningError,
    TrustAnchor,
    TrustStore,
    UntrustedCardError,
)

# ─────────────────────────────────────────────
# LOW-LEVEL CRYPTO (advanced use only)
# ─────────────────────────────────────────────
from uxsp.crypto.hybrid import open_seal, seal
from uxsp.crypto.kdf import (
    argon2id_hash,
    argon2id_needs_rehash,
    argon2id_verify,
    derive_key,
)

# ─────────────────────────────────────────────
# KEY STORE
# ─────────────────────────────────────────────
from uxsp.storage.keystore import (
    CachingKeyStore,
    CardNotFoundError,
    DuplicateCardError,
    FileKeyStore,
    KeyStore,
    KeyStoreBackendError,
    KeyStoreError,
    MemoryKeyStore,
    PostgresKeyStore,
    RedisKeyStore,
)

# ─────────────────────────────────────────────
# NONCE STORES (storage layer — heavier backends)
# ─────────────────────────────────────────────
from uxsp.storage.noncestore import (
    PostgresNonceStore,
    RedisNonceStore,
    SlidingWindowNonceStore,
    TieredNonceStore,
)

# ─────────────────────────────────────────────
# TRANSPORT
# ─────────────────────────────────────────────
from uxsp.transport.http import (
    MissingUXSPHeaderError,
    UXSPHTTPError,
    UXSPHTTPRequest,
    UXSPHTTPResponse,
    UXSPVersionMismatchError,
    WrongRecipientError,
)
from uxsp.transport.websocket import (
    FrameTooLargeError,
    FrameType,
    SessionNotEstablishedError,
    UnexpectedFrameError,
    UXSPFrame,
    UXSPWebSocket,
    UXSPWebSocketError,
)

# ─────────────────────────────────────────────
# SIMPLIFIED DEVELOPER WORKFLOW
# ─────────────────────────────────────────────
from uxsp import secure
from uxsp.secure import (
    PeerNotFoundError,
    Receive,
    ReceiveArchive,
    ReceiveAudio,
    ReceiveBinary,
    ReceiveContact,
    ReceiveDoc,
    ReceiveDocument,
    ReceiveFile,
    ReceiveHTML,
    ReceiveImage,
    ReceiveJSON,
    ReceiveLocation,
    ReceivePDF,
    ReceivePhoto,
    ReceiveText,
    ReceiveVideo,
    ReceiveVoice,
    ReceiveZip,
    SecureContext,
    SecureError,
    SecurePackage,
    SecureReceiveError,
    SecureSendError,
    Send,
    SendArchive,
    SendAudio,
    SendBinary,
    SendContact,
    SendDoc,
    SendDocument,
    SendFile,
    SendHTML,
    SendImage,
    SendJSON,
    SendLocation,
    SendPDF,
    SendPhoto,
    SendText,
    SendVideo,
    SendVoice,
    SendZip,
    TypeMismatchError,
    create_identity,
    export_identity_encrypted,
    hash_password,
    import_identity_encrypted,
    verify_password,
)

# ─────────────────────────────────────────────
# __all__ — what `from uxsp import *` exports
# ─────────────────────────────────────────────
__all__ = [
    # simplified workflow (secure)
    "secure",
    "create_identity",
    "hash_password",
    "verify_password",
    "export_identity_encrypted",
    "import_identity_encrypted",
    "SecurePackage",
    "SecureContext",
    "SecureError",
    "SecureSendError",
    "SecureReceiveError",
    "PeerNotFoundError",
    "TypeMismatchError",
    "SendVideo",
    "ReceiveVideo",
    "SendAudio",
    "ReceiveAudio",
    "SendPhoto",
    "ReceivePhoto",
    "SendImage",
    "ReceiveImage",
    "SendText",
    "ReceiveText",
    "SendDocument",
    "ReceiveDocument",
    "SendDoc",
    "ReceiveDoc",
    "SendPDF",
    "ReceivePDF",
    "SendFile",
    "ReceiveFile",
    "SendBinary",
    "ReceiveBinary",
    "SendJSON",
    "ReceiveJSON",
    "SendHTML",
    "ReceiveHTML",
    "SendArchive",
    "ReceiveArchive",
    "SendZip",
    "ReceiveZip",
    "SendVoice",
    "ReceiveVoice",
    "SendLocation",
    "ReceiveLocation",
    "SendContact",
    "ReceiveContact",
    "Send",
    "Receive",
    # identity
    "Identity",
    "PublicCard",
    "validate_role",
    # envelope
    "Envelope",
    "EnvelopeError",
    "EnvelopeValidationError",
    "EnvelopeTooLargeError",
    "EnvelopeExpiredError",
    # signing
    "TrustAnchor",
    "PublicAnchor",
    "SignedCard",
    "TrustStore",
    "SigningError",
    "UntrustedCardError",
    "InvalidCardSignatureError",
    "ExpiredCardError",
    "CardNotYetValidError",
    # handshake
    "Handshake",
    "HandshakeError",
    "HandshakeAuthError",
    "HandshakeProofError",
    "HandshakeExpiredError",
    # session
    "Session",
    "SessionConfig",
    "SessionState",
    "SessionError",
    "SessionExpiredError",
    "SessionRevokedError",
    "SessionNotActiveError",
    "SessionReorderError",
    # replay
    "ReplayGuard",
    "DefaultReplayGuard",
    "ReplayError",
    "StaleEnvelopeError",
    "DuplicateNonceError",
    "FutureEnvelopeError",
    # payload
    "UXSPPayload",
    "PayloadError",
    "PayloadFormatError",
    "PayloadValidationError",
    "pack_text",
    "unpack_text",
    "pack_file",
    "unpack_to_file",
    "pack_binary",
    # chunking
    "UXSPChunk",
    "ChunkingError",
    "ChunkFormatError",
    "ChunkValidationError",
    "create_chunked_transfer",
    "reassemble_chunked_transfer",
    "create_chunked_text",
    "decode_chunked_text",
    # nonce (core)
    "NonceStore",
    "MemoryNonceStore",
    "UXSPStoreError",
    "generate_nonce",
    # nonce (storage layer)
    "RedisNonceStore",
    "SlidingWindowNonceStore",
    "PostgresNonceStore",
    "TieredNonceStore",
    # rate limit
    "RateLimiter",
    "SlidingRateLimiter",
    "RedisRateLimiter",
    "RedisSlidingRateLimiter",
    "RateLimiterBase",
    "RateLimitExceededError",
    "GuardedHandshake",
    # keystore
    "KeyStore",
    "MemoryKeyStore",
    "FileKeyStore",
    "RedisKeyStore",
    "PostgresKeyStore",
    "CachingKeyStore",
    "KeyStoreError",
    "CardNotFoundError",
    "KeyStoreBackendError",
    "DuplicateCardError",
    # transport
    "UXSPHTTPRequest",
    "UXSPHTTPResponse",
    "UXSPHTTPError",
    "MissingUXSPHeaderError",
    "WrongRecipientError",
    "UXSPVersionMismatchError",
    "UXSPWebSocket",
    "UXSPFrame",
    "FrameType",
    "UXSPWebSocketError",
    "UnexpectedFrameError",
    "SessionNotEstablishedError",
    "FrameTooLargeError",
    # low-level crypto
    "seal",
    "open_seal",
    "derive_key",
    "argon2id_hash",
    "argon2id_verify",
    "argon2id_needs_rehash",
    # meta
    "__version__",
]
