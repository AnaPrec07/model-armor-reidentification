"""
dlp_reidentify.py — Re-identify DLP `CryptoDeterministicConfig` surrogates
without calling dlp.googleapis.com.

Model Armor (via a DLP de-identification template) already produced surrogates
of the form:

    SURROGATE_NAME(LEN):BASE64_CIPHERTEXT     e.g.  EMAIL_TOKEN(28):o7Hk...==

DLP's deterministic transform is AES-SIV (RFC 5297) via Tink DeterministicAead.
To reverse it ourselves we need three things to match DLP EXACTLY:
  1. the raw AES-SIV key (unwrap the same KMS-wrapped key DLP used),
  2. the base64 ciphertext (parsed out of the surrogate),
  3. the associated data ("context") fed into S2V.

Item 3 is the only fiddly part. Instead of guessing, calibrate() finds it from
ONE known (plaintext -> surrogate) pair, then reuse that AAD forever.

Requires: cryptography>=38 (AES-SIV), google-cloud-kms for the real KMS path.
Python 3.12.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESSIV

# DLP surrogate wire format: NAME(LEN):BASE64  — LEN is the base64 string length.
_SURROGATE_RE = re.compile(r"([A-Z0-9_]+)\((\d+)\):([A-Za-z0-9+/=]+)")


# ---------------------------------------------------------------------------
# 1. Surrogate parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Surrogate:
    info_type: str
    declared_len: int
    b64: str

    @property
    def ciphertext(self) -> bytes:
        return base64.b64decode(self.b64)


def parse_surrogate(token: str) -> Surrogate | None:
    m = _SURROGATE_RE.fullmatch(token.strip())
    if not m:
        return None
    name, length, b64 = m.group(1), int(m.group(2)), m.group(3)
    return Surrogate(name, length, b64)


# ---------------------------------------------------------------------------
# 2. Key acquisition — unwrap the SAME key DLP's template used.
# ---------------------------------------------------------------------------


def unwrap_kms_key(wrapped_key: bytes, kms_key_name: str, client=None) -> bytes:
    """Unwrap a DLP `kmsWrapped` crypto key with Cloud KMS -> raw AES-SIV key.

    kms_key_name is the SAME cryptoKey referenced in the de-id template's
    cryptoKeyName. The unwrapped bytes are the exact key DLP encrypts with.
    """
    from google.cloud import kms

    client = client or kms.KeyManagementServiceClient()
    resp = client.decrypt(
        request={"name": kms_key_name, "ciphertext": wrapped_key}
    )
    return resp.plaintext  # 32 / 48 / 64 bytes for AES-128/192/256-SIV


# ---------------------------------------------------------------------------
# 3. The re-identifier
# ---------------------------------------------------------------------------

# Tink/DLP always feed S2V exactly ONE associated-data component (possibly
# empty). In `cryptography` that's a single-element list. NOTE: [b""] (one
# empty component) is NOT the same as [] (zero components) under SIV.
AadFactory = "Callable[[Surrogate], list[bytes]]"


def aad_surrogate_name(s: Surrogate) -> list[bytes]:
    return [s.info_type.encode("utf-8")]


def aad_empty(_s: Surrogate) -> list[bytes]:
    return [b""]


def aad_const(value: bytes):
    def _f(_s: Surrogate) -> list[bytes]:
        return [value]

    return _f


# Ordered candidates tried during calibration. Add your template's `context`
# string here if your de-id used record transformations.
DEFAULT_AAD_CANDIDATES = [
    ("surrogate_name", aad_surrogate_name),
    ("empty", aad_empty),
]


class DeterministicReidentifier:
    """Reverses DLP AES-SIV surrogates. Pin the AAD via calibrate() first."""

    def __init__(self, raw_key: bytes, aad_factory=aad_surrogate_name) -> None:
        self._siv = AESSIV(raw_key)
        self._aad = aad_factory

    def decrypt(self, token: str) -> str | None:
        s = parse_surrogate(token)
        if s is None:
            return None
        try:
            pt = self._siv.decrypt(s.ciphertext, self._aad(s))
            return pt.decode("utf-8")
        except Exception:
            return None  # wrong key / wrong AAD / tampered -> fail closed

    def calibrate(self, known_plaintext: str, known_surrogate: str,
                  candidates=DEFAULT_AAD_CANDIDATES) -> str:
        """Find which AAD construction DLP used, from one known pair.

        Run ONE value of each info_type through Model Armor, capture the
        surrogate, and pass the pair here. The returned name (and the bound
        self._aad) then works for every surrogate of that template.
        """
        s = parse_surrogate(known_surrogate)
        if s is None:
            raise ValueError(f"not a surrogate: {known_surrogate!r}")
        target = known_plaintext.encode("utf-8")
        for name, factory in candidates:
            try:
                if self._siv.decrypt(s.ciphertext, factory(s)) == target:
                    self._aad = factory
                    return name
            except Exception:
                continue
        raise RuntimeError(
            "no candidate AAD reproduced the plaintext — check that the key, "
            "transform (must be cryptoDeterministicConfig, not FPE/hash), and "
            "surrogateInfoType match the de-id template."
        )

    def reidentify_text(self, text: str, *, leave_unknown: bool = True) -> str:
        """Scan a full document/LLM response and restore every surrogate."""

        def _sub(m: re.Match[str]) -> str:
            original = self.decrypt(m.group(0))
            if original is None:
                return m.group(0) if leave_unknown else ""
            return original

        return _SURROGATE_RE.sub(_sub, text)


# ---------------------------------------------------------------------------
# 4. Tests — simulate DLP's output, then prove we reverse it.
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import unittest

    def fake_dlp_deidentify(plaintext: str, info_type: str, key: bytes,
                            aad_mode: str = "surrogate_name") -> str:
        """Stand-in for what Model Armor+DLP emit, so tests are hermetic.

        Mirrors DLP: AES-SIV encrypt with single-component AAD, base64, wrap as
        NAME(LEN):B64. We test both the 'surrogate name as AAD' and 'empty AAD'
        conventions so calibrate() is exercised against both.
        """
        siv = AESSIV(key)
        aad = [info_type.encode()] if aad_mode == "surrogate_name" else [b""]
        ct = siv.encrypt(plaintext.encode("utf-8"), aad)
        b64 = base64.b64encode(ct).decode()
        return f"{info_type}({len(b64)}):{b64}"

    class Tests(unittest.TestCase):
        def setUp(self) -> None:
            self.key = os.urandom(64)  # AES-256-SIV

        def test_parse(self) -> None:
            s = parse_surrogate("EMAIL_TOKEN(24):YWJjZGVmZ2hpamtsbW4=")
            self.assertEqual(s.info_type, "EMAIL_TOKEN")
            self.assertEqual(s.declared_len, 24)

        def test_roundtrip_surrogate_name_aad(self) -> None:
            sur = fake_dlp_deidentify("ana@banesco.com", "EMAIL_ADDRESS",
                                      self.key, "surrogate_name")
            r = DeterministicReidentifier(self.key, aad_surrogate_name)
            self.assertEqual(r.decrypt(sur), "ana@banesco.com")

        def test_calibrate_finds_empty_aad(self) -> None:
            sur = fake_dlp_deidentify("5551234", "PHONE", self.key, "empty")
            r = DeterministicReidentifier(self.key, aad_surrogate_name)  # wrong guess
            self.assertIsNone(r.decrypt(sur))                            # fails first
            mode = r.calibrate("5551234", sur)                           # discovers it
            self.assertEqual(mode, "empty")
            self.assertEqual(r.decrypt(sur), "5551234")                 # now works

        def test_determinism(self) -> None:
            a = fake_dlp_deidentify("dup", "X", self.key)
            b = fake_dlp_deidentify("dup", "X", self.key)
            self.assertEqual(a, b)  # same value -> same surrogate

        def test_full_document(self) -> None:
            key = self.key
            name = fake_dlp_deidentify("Ana", "PERSON_NAME", key)
            mail = fake_dlp_deidentify("ana@x.com", "EMAIL_ADDRESS", key)
            doc = f"Agent {name} can be reached at {mail} today."
            r = DeterministicReidentifier(key, aad_surrogate_name)
            restored = r.reidentify_text(doc)
            self.assertEqual(restored, "Agent Ana can be reached at ana@x.com today.")

        def test_unicode(self) -> None:
            sur = fake_dlp_deidentify("José Ñandú", "PERSON_NAME", self.key)
            r = DeterministicReidentifier(self.key, aad_surrogate_name)
            self.assertEqual(r.decrypt(sur), "José Ñandú")

        def test_wrong_key_fails_closed(self) -> None:
            sur = fake_dlp_deidentify("secret", "X", self.key)
            r = DeterministicReidentifier(os.urandom(64))  # different key
            self.assertIsNone(r.decrypt(sur))

        def test_unknown_token_left_intact(self) -> None:
            r = DeterministicReidentifier(self.key)
            out = r.reidentify_text("keep PLAIN(4):bm90Yg== as-is",
                                    leave_unknown=True)
            self.assertIn("PLAIN(4):bm90Yg==", out)

    unittest.main(verbosity=2)
