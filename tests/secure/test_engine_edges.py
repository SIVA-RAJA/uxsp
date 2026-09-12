from __future__ import annotations

import pytest

from uxsp.core.identity import Identity
from uxsp.secure._context import _GLOBAL_CONTEXT
from uxsp.secure._engine import _secure_receive_payload, _secure_send_payload
from uxsp.secure._errors import SecureReceiveError


def test_engine_chunked_missing_envelope():
    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")

    # Send large payload to force chunking
    large_payload = b"A" * 40000
    pkg = _secure_send_payload(receiver=receiver, payload_bytes=large_payload, sender=sender)

    assert pkg.is_chunked is True

    # Intentionally corrupt the package
    pkg.envelope = None

    _GLOBAL_CONTEXT.set_identity(receiver)
    with pytest.raises(SecureReceiveError, match="Package is marked chunked but missing session key envelope"):
        _secure_receive_payload(sender=sender, package_input=pkg)


def test_engine_receive_exceptions_mapping():
    from unittest.mock import patch

    from uxsp.core.envelope import EnvelopeExpiredError
    from uxsp.core.replay import DuplicateNonceError
    from uxsp.crypto.hybrid import EnvelopeValidationError
    from uxsp.secure._errors import DuplicateMessageError, InvalidSenderError, MessageExpiredError

    sender = Identity.create("test", "USER")
    receiver = Identity.create("test", "USER")
    _GLOBAL_CONTEXT.set_identity(receiver)
    pkg = _secure_send_payload(receiver=receiver, payload_bytes=b"hello", sender=sender)

    with patch.object(receiver, "open_from", side_effect=EnvelopeExpiredError("expired")):
        with pytest.raises(MessageExpiredError, match="Message expired"):
            _secure_receive_payload(sender=sender, package_input=pkg)

    with patch.object(receiver, "open_from", side_effect=EnvelopeValidationError("invalid")):
        with pytest.raises(InvalidSenderError, match="Invalid sender"):
            _secure_receive_payload(sender=sender, package_input=pkg)

    with patch.object(receiver, "open_from", side_effect=DuplicateNonceError("dup")):
        with pytest.raises(DuplicateMessageError, match="Message already processed"):
            _secure_receive_payload(sender=sender, package_input=pkg)

