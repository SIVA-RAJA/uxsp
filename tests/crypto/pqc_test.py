"""
Full-coverage pytest suite for pqc.py
======================================
Strategy
--------
* The real `oqs` C-extension is never required.  Every test patches `oqs` with
  carefully crafted fakes so the suite runs in any environment.
* Module-level code (import block, _detect_kem/_detect_sig, the try/except that
  sets _KEM_ALGORITHM/_SIG_ALGORITHM) is re-executed by reimporting the module
  inside each test that needs a different module-init scenario.
* All public functions are exercised on the happy path AND on every guard branch
  (empty algorithm strings, wrong argument types).
"""

from __future__ import annotations

import importlib
import sys
import types
import warnings

import pytest

# ──────────────────────────────────────────────────────────────────────────────
# Helpers — build fake `oqs` modules
# ──────────────────────────────────────────────────────────────────────────────

def _make_oqs_module(
    *,
    kem_algorithms: list[str] | None = None,
    sig_algorithms: list[str] | None = None,
    raise_import: bool = False,
    include_mech_error: bool = True,
):
    """Return a fake `oqs` module object."""
    if raise_import:
        return None  # caller will raise ImportError instead

    if kem_algorithms is None:
        kem_algorithms = ["ML-KEM-768"]
    if sig_algorithms is None:
        sig_algorithms = ["ML-DSA-65"]

    fake = types.ModuleType("oqs")

    # ── MechanismNotEnabledError ──────────────────────────────────────────────
    class MechanismNotEnabledError(RuntimeError):
        pass

    if include_mech_error:
        fake.MechanismNotEnabledError = MechanismNotEnabledError

    # ── algorithm lists ───────────────────────────────────────────────────────
    fake.get_enabled_kem_mechanisms = lambda: list(kem_algorithms)
    fake.get_enabled_sig_mechanisms = lambda: list(sig_algorithms)

    # ── KeyEncapsulation context-manager ──────────────────────────────────────
    class FakeKem:
        def __init__(self, algorithm, secret_key=None):
            self.algorithm = algorithm
            self._secret_key = secret_key or b"private_key_bytes"

        # generate_keypair returns the *public* key; secret key exported separately
        def generate_keypair(self):
            return b"public_key_bytes"

        def export_secret_key(self):
            return self._secret_key

        def encap_secret(self, public_key):
            # returns (ciphertext, shared_secret)
            return b"ciphertext_bytes", b"shared_secret_bytes"

        def decap_secret(self, ciphertext):
            return bytearray(b"shared_secret_bytes")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    # ── Signature context-manager ─────────────────────────────────────────────
    class FakeSig:
        def __init__(self, algorithm, secret_key=None):
            self.algorithm = algorithm
            self._secret_key = secret_key or b"sig_private_key"

        def generate_keypair(self):
            return b"sig_public_key_bytes"

        def export_secret_key(self):
            return self._secret_key

        def sign(self, message):
            return bytearray(b"signature_bytes")

        def verify(self, message, signature, public_key):
            # Return True only for matching test vectors
            return (
                message == b"hello"
                and signature == b"signature_bytes"
                and public_key == b"sig_public_key_bytes"
            )

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    fake.KeyEncapsulation = FakeKem
    fake.Signature = FakeSig

    return fake


def _reimport_pqc(fake_oqs):
    """
    Remove pqc from sys.modules and reimport it with fake_oqs injected.
    Returns the freshly imported module.
    """
    sys.modules.pop("pqc", None)

    if fake_oqs is None:
        # Simulate `import oqs` raising ImportError
        sys.modules["oqs"] = None  # type: ignore[assignment]
        with pytest.raises(ImportError, match="liboqs"):
            importlib.import_module("uxsp.crypto.pqc")
        sys.modules.pop("oqs", None)
        return None

    sys.modules["oqs"] = fake_oqs
    mod = importlib.import_module("uxsp.crypto.pqc")
    return mod


def _clean():
    sys.modules.pop("uxsp.crypto.pqc", None)
    sys.modules.pop("oqs", None)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Import / module-init paths
# ──────────────────────────────────────────────────────────────────────────────

class TestModuleInit:

    def teardown_method(self):
        _clean()

    # ── 1a. Happy path: both algorithms detected ──────────────────────────────
    def test_normal_import_sets_algorithms(self):
        mod = _reimport_pqc(_make_oqs_module())
        assert mod._KEM_ALGORITHM == "ML-KEM-768"
        assert mod._SIG_ALGORITHM == "ML-DSA-65"

    # ── 1b. Fallback algorithm names ─────────────────────────────────────────
    def test_fallback_kyber_dilithium(self):
        fake = _make_oqs_module(
            kem_algorithms=["Kyber768"],
            sig_algorithms=["Dilithium3"],
        )
        mod = _reimport_pqc(fake)
        assert mod._KEM_ALGORITHM == "Kyber768"
        assert mod._SIG_ALGORITHM == "Dilithium3"

    # ── 1c. oqs import raises ImportError → pqc raises ImportError ────────────
    def test_missing_oqs_raises_import_error(self):
        # _reimport_pqc(None) handles this case internally
        _reimport_pqc(None)

    # ── 1d. No supported KEM → warning, _KEM_ALGORITHM == "" ─────────────────
    def test_no_kem_algorithm_warns(self):
        fake = _make_oqs_module(
            kem_algorithms=["UNSUPPORTED-KEM"],
            sig_algorithms=["ML-DSA-65"],
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            mod = _reimport_pqc(fake)
        assert mod._KEM_ALGORITHM == ""
        assert any("PQC algorithms unavailable" in str(w.message) for w in caught)

    # ── 1e. No supported SIG → warning, _SIG_ALGORITHM == "" ─────────────────
    def test_no_sig_algorithm_warns(self):
        fake = _make_oqs_module(
            kem_algorithms=["ML-KEM-768"],
            sig_algorithms=["UNSUPPORTED-SIG"],
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            mod = _reimport_pqc(fake)
        assert mod._SIG_ALGORITHM == ""
        assert any("PQC algorithms unavailable" in str(w.message) for w in caught)

    # ── 1f. oqs module without MechanismNotEnabledError attribute ────────────
    def test_no_mech_error_attribute_falls_back_to_runtime_error(self):
        fake = _make_oqs_module(include_mech_error=False)
        mod = _reimport_pqc(fake)
        # When the attribute is absent getattr falls back to RuntimeError
        assert mod._OQS_MECH_ERROR is RuntimeError


# ──────────────────────────────────────────────────────────────────────────────
# 2. _detect_kem  /  _detect_sig  (called indirectly via reimport)
# ──────────────────────────────────────────────────────────────────────────────

class TestDetectFunctions:

    def teardown_method(self):
        _clean()

    def test_detect_kem_prefers_ml_kem_over_kyber(self):
        fake = _make_oqs_module(kem_algorithms=["ML-KEM-768", "Kyber768"])
        mod = _reimport_pqc(fake)
        assert mod._KEM_ALGORITHM == "ML-KEM-768"

    def test_detect_sig_prefers_ml_dsa_over_dilithium(self):
        fake = _make_oqs_module(sig_algorithms=["ML-DSA-65", "Dilithium3"])
        mod = _reimport_pqc(fake)
        assert mod._SIG_ALGORITHM == "ML-DSA-65"

    def test_detect_kem_no_match_runtime_error_causes_empty_string(self):
        fake = _make_oqs_module(kem_algorithms=[])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            mod = _reimport_pqc(fake)
        assert mod._KEM_ALGORITHM == ""

    def test_detect_sig_no_match_runtime_error_causes_empty_string(self):
        fake = _make_oqs_module(sig_algorithms=[])
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            mod = _reimport_pqc(fake)
        assert mod._SIG_ALGORITHM == ""


# ──────────────────────────────────────────────────────────────────────────────
# Fixture: a normally-imported pqc module (used by most functional tests)
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def pqc():
    fake = _make_oqs_module()
    sys.modules.pop("uxsp.crypto.pqc", None)
    sys.modules["oqs"] = fake
    mod = importlib.import_module("uxsp.crypto.pqc")
    yield mod
    _clean()


@pytest.fixture()
def pqc_no_alg():
    """pqc module where both algorithm strings are empty (simulates failed detection)."""
    fake = _make_oqs_module()
    sys.modules.pop("uxsp.crypto.pqc", None)
    sys.modules["oqs"] = fake
    mod = importlib.import_module("uxsp.crypto.pqc")
    mod._KEM_ALGORITHM = ""
    mod._SIG_ALGORITHM = ""
    yield mod
    _clean()


# ──────────────────────────────────────────────────────────────────────────────
# 3. generate_kem_keypair
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerateKemKeypair:

    def test_returns_correct_keys(self, pqc):
        result = pqc.generate_kem_keypair()
        assert result["public_key"] == b"public_key_bytes"
        assert result["private_key"] == b"private_key_bytes"
        assert result["algorithm"] == "ML-KEM-768"

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No KEM algorithm available"):
            pqc_no_alg.generate_kem_keypair()


# ──────────────────────────────────────────────────────────────────────────────
# 4. encapsulate
# ──────────────────────────────────────────────────────────────────────────────

class TestEncapsulate:

    def test_happy_path(self, pqc):
        result = pqc.encapsulate(b"recipient_public_key")
        assert result["shared_secret"] == b"shared_secret_bytes"
        assert result["ciphertext"] == b"ciphertext_bytes"
        assert result["algorithm"] == "ML-KEM-768"

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No KEM algorithm available"):
            pqc_no_alg.encapsulate(b"some_key")

    def test_raises_type_error_on_non_bytes(self, pqc):
        with pytest.raises(TypeError, match="recipient_public_key must be bytes"):
            pqc.encapsulate("not bytes")  # type: ignore[arg-type]

    def test_raises_type_error_on_int(self, pqc):
        with pytest.raises(TypeError):
            pqc.encapsulate(12345)  # type: ignore[arg-type]


# ──────────────────────────────────────────────────────────────────────────────
# 5. decapsulate
# ──────────────────────────────────────────────────────────────────────────────

class TestDecapsulate:

    def test_happy_path(self, pqc):
        result = pqc.decapsulate(b"ciphertext", b"private_key")
        assert isinstance(result, bytes)
        assert result == b"shared_secret_bytes"

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No KEM algorithm available"):
            pqc_no_alg.decapsulate(b"ct", b"sk")

    def test_raises_type_error_ciphertext(self, pqc):
        with pytest.raises(TypeError, match="ciphertext must be bytes"):
            pqc.decapsulate("not bytes", b"key")  # type: ignore[arg-type]

    def test_raises_type_error_private_key(self, pqc):
        with pytest.raises(TypeError, match="private_key must be bytes"):
            pqc.decapsulate(b"ciphertext", "not bytes")  # type: ignore[arg-type]

    def test_returns_plain_bytes_not_bytearray(self, pqc):
        result = pqc.decapsulate(b"ct", b"sk")
        assert type(result) is bytes


# ──────────────────────────────────────────────────────────────────────────────
# 6. generate_sig_keypair
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerateSigKeypair:

    def test_returns_correct_keys(self, pqc):
        result = pqc.generate_sig_keypair()
        assert result["public_key"] == b"sig_public_key_bytes"
        assert result["private_key"] == b"sig_private_key"
        assert result["algorithm"] == "ML-DSA-65"

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No signature algorithm available"):
            pqc_no_alg.generate_sig_keypair()


# ──────────────────────────────────────────────────────────────────────────────
# 7. pqc_sign
# ──────────────────────────────────────────────────────────────────────────────

class TestPqcSign:

    def test_happy_path(self, pqc):
        sig = pqc.pqc_sign(b"hello", b"sig_private_key")
        assert isinstance(sig, bytes)
        assert sig == b"signature_bytes"

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No signature algorithm available"):
            pqc_no_alg.pqc_sign(b"msg", b"key")

    def test_raises_type_error_message(self, pqc):
        with pytest.raises(TypeError, match="message must be bytes"):
            pqc.pqc_sign("not bytes", b"key")  # type: ignore[arg-type]

    def test_raises_type_error_private_key(self, pqc):
        with pytest.raises(TypeError, match="private_key must be bytes"):
            pqc.pqc_sign(b"msg", "not bytes")  # type: ignore[arg-type]

    def test_returns_plain_bytes_not_bytearray(self, pqc):
        result = pqc.pqc_sign(b"hello", b"key")
        assert type(result) is bytes


# ──────────────────────────────────────────────────────────────────────────────
# 8. pqc_verify
# ──────────────────────────────────────────────────────────────────────────────

class TestPqcVerify:

    def test_valid_signature_returns_true(self, pqc):
        assert pqc.pqc_verify(b"hello", b"signature_bytes", b"sig_public_key_bytes") is True

    def test_wrong_message_returns_false(self, pqc):
        assert pqc.pqc_verify(b"wrong", b"signature_bytes", b"sig_public_key_bytes") is False

    def test_wrong_signature_returns_false(self, pqc):
        assert pqc.pqc_verify(b"hello", b"bad_sig", b"sig_public_key_bytes") is False

    def test_raises_when_no_algorithm(self, pqc_no_alg):
        with pytest.raises(RuntimeError, match="No signature algorithm available"):
            pqc_no_alg.pqc_verify(b"msg", b"sig", b"pk")

    def test_raises_type_error_message(self, pqc):
        with pytest.raises(TypeError, match="message must be bytes"):
            pqc.pqc_verify("msg", b"sig", b"pk")  # type: ignore[arg-type]

    def test_raises_type_error_signature(self, pqc):
        with pytest.raises(TypeError, match="signature must be bytes"):
            pqc.pqc_verify(b"msg", "sig", b"pk")  # type: ignore[arg-type]

    def test_raises_type_error_public_key(self, pqc):
        with pytest.raises(TypeError, match="public_key must be bytes"):
            pqc.pqc_verify(b"msg", b"sig", "pk")  # type: ignore[arg-type]

    def test_oqs_exception_returns_false(self, pqc):
        """
        If the underlying oqs.Signature.verify() raises any of the caught
        exception types, pqc_verify must return False (not propagate).
        """
        # Patch the FakeSig.verify to raise RuntimeError
        original_sig = sys.modules["oqs"].Signature

        class RaisingSig(original_sig):
            def verify(self, message, signature, public_key):
                raise RuntimeError("internal oqs error")

        sys.modules["oqs"].Signature = RaisingSig
        result = pqc.pqc_verify(b"hello", b"signature_bytes", b"sig_public_key_bytes")
        sys.modules["oqs"].Signature = original_sig
        assert result is False

    def test_value_error_from_verify_returns_false(self, pqc):
        original_sig = sys.modules["oqs"].Signature

        class RaisingSig(original_sig):
            def verify(self, message, signature, public_key):
                raise ValueError("bad value")

        sys.modules["oqs"].Signature = RaisingSig
        result = pqc.pqc_verify(b"hello", b"signature_bytes", b"sig_public_key_bytes")
        sys.modules["oqs"].Signature = original_sig
        assert result is False

    def test_type_error_from_verify_returns_false(self, pqc):
        original_sig = sys.modules["oqs"].Signature

        class RaisingSig(original_sig):
            def verify(self, message, signature, public_key):
                raise TypeError("bad type from oqs")

        sys.modules["oqs"].Signature = RaisingSig
        result = pqc.pqc_verify(b"hello", b"signature_bytes", b"sig_public_key_bytes")
        sys.modules["oqs"].Signature = original_sig
        assert result is False

    def test_mech_error_from_verify_returns_false(self, pqc):
        """_OQS_MECH_ERROR (MechanismNotEnabledError) is also caught."""
        original_sig = sys.modules["oqs"].Signature
        MechError = pqc._OQS_MECH_ERROR

        class RaisingSig(original_sig):
            def verify(self, message, signature, public_key):
                raise MechError("mech not enabled")

        sys.modules["oqs"].Signature = RaisingSig
        result = pqc.pqc_verify(b"hello", b"signature_bytes", b"sig_public_key_bytes")
        sys.modules["oqs"].Signature = original_sig
        assert result is False


# ──────────────────────────────────────────────────────────────────────────────
# 9. active_algorithms
# ──────────────────────────────────────────────────────────────────────────────

class TestActiveAlgorithms:

    def test_returns_algorithm_names(self, pqc):
        result = pqc.active_algorithms()
        assert result == {"kem": "ML-KEM-768", "sig": "ML-DSA-65"}

    def test_returns_unavailable_when_empty(self, pqc_no_alg):
        result = pqc_no_alg.active_algorithms()
        assert result == {"kem": "unavailable", "sig": "unavailable"}

    def test_partial_unavailable_kem(self, pqc):
        pqc._KEM_ALGORITHM = ""
        result = pqc.active_algorithms()
        assert result["kem"] == "unavailable"
        assert result["sig"] == "ML-DSA-65"

    def test_partial_unavailable_sig(self, pqc):
        pqc._SIG_ALGORITHM = ""
        result = pqc.active_algorithms()
        assert result["kem"] == "ML-KEM-768"
        assert result["sig"] == "unavailable"


# ──────────────────────────────────────────────────────────────────────────────
# 10. TypedDict shapes (structural integrity)
# ──────────────────────────────────────────────────────────────────────────────

class TestTypedDictShapes:

    def test_kem_keypair_keys(self, pqc):
        kp = pqc.generate_kem_keypair()
        assert set(kp.keys()) == {"public_key", "private_key", "algorithm"}

    def test_encapsulate_result_keys(self, pqc):
        res = pqc.encapsulate(b"pk")
        assert set(res.keys()) == {"shared_secret", "ciphertext", "algorithm"}

    def test_sig_keypair_keys(self, pqc):
        kp = pqc.generate_sig_keypair()
        assert set(kp.keys()) == {"public_key", "private_key", "algorithm"}
