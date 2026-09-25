import re

from mirage import tokens

KEY = b"k" * 32


def test_aws_pair_has_the_real_format():
    for _ in range(200):
        key_id, secret = tokens.aws_key_pair()
        assert re.fullmatch(r"AKIA[A-Z2-7]{16}", key_id)
        assert re.fullmatch(r"[A-Za-z0-9+/]{40}", secret)


def test_api_key_tag_accepts_ours_and_rejects_forgeries():
    key = tokens.api_key("acme_live", KEY)
    assert tokens.api_key_tag_ok(key, KEY)
    tampered = key[:-7] + ("A" if key[-7] != "A" else "B") + key[-6:]
    assert not tokens.api_key_tag_ok(tampered, KEY)
    assert not tokens.api_key_tag_ok(key, b"x" * 32)
    assert not tokens.api_key_tag_ok("short", KEY)


def test_generated_values_are_unique():
    assert len({tokens.aws_key_pair()[0] for _ in range(5000)}) == 5000
    assert len({tokens.api_key("acme_live", KEY) for _ in range(5000)}) == 5000


def test_fingerprint_is_keyed_and_stable():
    assert tokens.fingerprint("value", KEY) == tokens.fingerprint("value", KEY)
    assert tokens.fingerprint("value", KEY) != tokens.fingerprint("value", b"y" * 32)
    assert "value" not in tokens.fingerprint("value", KEY)


def test_mask_hides_the_middle():
    assert tokens.mask("ABCDEFGHIJKLMNOPQRST") == "ABCD...QRST"
