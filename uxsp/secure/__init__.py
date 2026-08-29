"""
uxsp.secure — Simple Developer Workflow for UXSP

Provides a Simple high-level API for developers.
All underlying complexities (PQC hybrid encryption, chunking, replay guards,
and envelope serialization) are handled automatically behind 1-line functions.
"""

from uxsp.secure._context import (
    _GLOBAL_CONTEXT as _GLOBAL_CONTEXT,
)
from uxsp.secure._context import (
    SecureContext,
    configure,
    get_context,
    get_identity,
    get_peer,
    register_peer,
    reset_context,
    set_identity,
)
from uxsp.secure._dispatch import Receive, Send
from uxsp.secure._engine import (
    _resolve_package_input as _resolve_package_input,
)
from uxsp.secure._engine import (
    _secure_receive_payload as _secure_receive_payload,
)
from uxsp.secure._engine import (
    _secure_send_payload as _secure_send_payload,
)
from uxsp.secure._errors import (
    PeerNotFoundError,
    SecureError,
    SecureReceiveError,
    SecureSendError,
    TypeMismatchError,
)
from uxsp.secure._identity_helpers import (
    create_identity,
    export_identity_encrypted,
    hash_password,
    import_identity_encrypted,
    revoke_peer,
    rotate_keys,
    verify_password,
    verify_peer_validity,
)
from uxsp.secure._live import (
    ReceiveLiveSession,
    ReceiveLiveVoice,
    ReceiveLiveVoiceCall,
    ReceiveVoiceCall,
    SendLiveSession,
    SendLiveVoice,
    SendLiveVoiceCall,
    SendVoiceCall,
)
from uxsp.secure._package import SecurePackage
from uxsp.secure._stream import ReceiveStream, SendStream
from uxsp.secure._utils import _normalize_id as _normalize_id
from uxsp.secure._utils import _safe_is_file as _safe_is_file
from uxsp.secure.types import (
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
)

__all__ = [
    "SecureError",
    "SecureSendError",
    "SecureReceiveError",
    "PeerNotFoundError",
    "TypeMismatchError",
    "SecurePackage",
    "SecureContext",
    "configure",
    "get_context",
    "set_identity",
    "get_identity",
    "register_peer",
    "get_peer",
    "reset_context",
    "create_identity",
    "rotate_keys",
    "revoke_peer",
    "verify_peer_validity",
    "hash_password",
    "verify_password",
    "export_identity_encrypted",
    "import_identity_encrypted",
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
    "SendStream",
    "ReceiveStream",
    "SendLiveSession",
    "ReceiveLiveSession",
    "SendLiveVoiceCall",
    "ReceiveLiveVoiceCall",
    "SendLiveVoice",
    "ReceiveLiveVoice",
    "SendVoiceCall",
    "ReceiveVoiceCall",
]
