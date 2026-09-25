"""Key material. One master key; purpose-specific keys are derived from it with HMAC."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Keys:
    fingerprint: bytes  # registry lookups: we store HMAC fingerprints, never decoy secrets
    tag: bytes          # HMAC tag inside internal API keys, so forged keys are rejected cheaply
    ingest: bytes       # sensors sign every event they forward to control

    @classmethod
    def from_master(cls, master: bytes) -> "Keys":
        def derive(label: bytes) -> bytes:
            return hmac.new(master, label, hashlib.sha256).digest()

        return cls(fingerprint=derive(b"fingerprint"), tag=derive(b"api-key-tag"), ingest=derive(b"sensor-ingest"))


def create_master(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(secrets.token_hex(32), encoding="ascii")


def load_keys(path: Path) -> Keys:
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. Run `python -m mirage init` first.")
    return Keys.from_master(bytes.fromhex(path.read_text(encoding="ascii").strip()))


def sign(key: bytes, body: bytes) -> str:
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def verify(key: bytes, body: bytes, signature: str | None) -> bool:
    return bool(signature) and hmac.compare_digest(sign(key, body), signature)
