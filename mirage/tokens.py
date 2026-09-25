"""Decoy credential generators. Everything random comes from `secrets` (a CSPRNG)."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string

BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE62 = string.digits + string.ascii_letters
AWS_SECRET_ALPHABET = string.ascii_letters + string.digits + "+/"

AWS_PURPOSES = ("backup-legacy", "reporting-etl", "s3-archive", "billing-export", "ci-deploy-old", "data-sync")
API_SERVICES = ("payments-api", "reporting-api", "billing-api", "hr-sync-api", "inventory-api", "ledger-api")

TAG_LEN = 6


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _base62(data: bytes, length: int) -> str:
    n = int.from_bytes(data, "big")
    out = []
    for _ in range(length):
        n, r = divmod(n, 62)
        out.append(BASE62[r])
    return "".join(out)


def aws_key_pair() -> tuple[str, str]:
    """AWS-format access key pair (AKIA + 16 base32 chars, 40-char secret).

    In production these come from a real zero-permission IAM user in a dedicated
    account (see docs); the demo sends them to a local AWS emulator instead.
    """
    return "AKIA" + _random(BASE32, 16), _random(AWS_SECRET_ALPHABET, 40)


def api_key(prefix: str, tag_key: bytes) -> str:
    """Internal-style API key whose last characters are an HMAC tag over the rest."""
    body = f"{prefix}_{_random(BASE62, 28)}"
    return body + _tag(body, tag_key)


def api_key_tag_ok(token: str, tag_key: bytes) -> bool:
    if len(token) <= TAG_LEN:
        return False
    body, tag = token[:-TAG_LEN], token[-TAG_LEN:]
    return hmac.compare_digest(tag, _tag(body, tag_key))


def _tag(body: str, tag_key: bytes) -> str:
    return _base62(hmac.new(tag_key, body.encode(), hashlib.sha256).digest(), TAG_LEN)


def fingerprint(value: str, key: bytes) -> str:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()


def mask(value: str) -> str:
    return f"{value[:4]}...{value[-4:]}" if len(value) > 12 else "****"


def aws_account_id() -> str:
    return str(10**11 + secrets.randbelow(9 * 10**11))


def iam_user_id() -> str:
    return "AIDA" + _random(string.ascii_uppercase + string.digits, 17)


def token_id() -> str:
    return "tok_" + secrets.token_hex(8)


def placement_id() -> str:
    return "plc_" + secrets.token_hex(8)


def incident_id() -> str:
    return "inc_" + secrets.token_hex(6)


def choose(options):
    return secrets.choice(list(options))
