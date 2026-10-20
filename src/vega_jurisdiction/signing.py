"""signing.py - domain-separated Ed25519 messages for jurisdiction actions.

A signature made for one kind of action can never verify as another kind (the kind is inside the signed bytes), and the payload is
canonical JSON of plain data only. Holders sign on their own devices; this module only gives them the same bytes the verifier checks.
(The earlier VEGA_CORE jurisdiction_protocol.py signed with a fixed public constant, so anyone could forge a branch approval; this replaces that with each
holder's own private key.)"""
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

KINDS = ("position", "veto_open", "ballot", "override", "consent")


class SigningRefused(ValueError):
    pass


def canonical(obj) -> bytes:
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SigningRefused("payload is not plain data: %s" % exc) from exc


def message(kind: str, payload) -> bytes:
    if kind not in KINDS:
        raise SigningRefused("unknown kind %r" % (kind,))
    return b"VEGA-JURIS-1|" + kind.encode("ascii") + b"|" + canonical(payload)


class Holder:
    """A key holder (a branch of government, or a voter). The private key stays in this object."""

    def __init__(self):
        self._sk = Ed25519PrivateKey.generate()
        self.public = self._sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, kind: str, payload) -> str:
        return self._sk.sign(message(kind, payload)).hex()


def verify(public_hex, kind: str, payload, sig_hex) -> bool:
    """True only for a valid signature by that key over exactly this kind and payload. Never raises."""
    try:
        if not isinstance(public_hex, str) or not isinstance(sig_hex, str) or len(public_hex) != 64 or len(sig_hex) != 128:
            return False
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(sig_hex), message(kind, payload))
        return True
    except (InvalidSignature, ValueError, TypeError, SigningRefused):
        return False
