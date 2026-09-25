import hashlib
import os
import sys
import time

import pytest

from mirage.placer import Placer, secret_labels

DEV_CREDS = "laptop-dev-07/Users/r.iyer/.aws/credentials"


def snapshot(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_dry_run_writes_nothing(settings, registry, keys, estate):
    before = snapshot(estate)
    results = Placer(settings, registry, keys).deploy(dry_run=True)
    assert {r["status"] for r in results} == {"would deploy"}
    assert snapshot(estate) == before
    assert registry.list_placements() == []


def test_append_keeps_existing_profiles_and_timestamps(settings, registry, keys, estate):
    creds = estate / DEV_CREDS
    original, stat = creds.read_bytes(), creds.stat()
    Placer(settings, registry, keys).deploy()
    updated = creds.read_bytes()
    assert updated.startswith(original), "existing content must be untouched"
    assert b"[default]" in original and updated.count(b"[default]") == 1, "no new default profile"
    assert creds.stat().st_mtime_ns == stat.st_mtime_ns, "appending must not make the file look recent"
    placement = registry.find_placement("laptop-dev-07", "Users/r.iyer/.aws/credentials", "aws_credentials_profile")
    backup = placement["meta"]["backup"]
    assert backup and open(backup, "rb").read() == original


def test_redeploy_is_idempotent(settings, registry, keys, deployed, estate):
    before = snapshot(estate)
    results = Placer(settings, registry, keys).deploy()
    assert {r["status"] for r in results} == {"already deployed"}
    assert snapshot(estate) == before


def test_never_overwrites_an_existing_file(settings, registry, keys, estate):
    target = estate / "laptop-hr-05/Users/s.lindqvist/scripts/sync_reports.ps1"
    target.write_text("real script", encoding="utf-8")
    results = Placer(settings, registry, keys).deploy()
    hr = next(r for r in results if r["host"] == "laptop-hr-05")
    assert hr["status"] == "skipped: file already exists"
    assert target.read_text(encoding="utf-8") == "real script"


@pytest.mark.parametrize("bad", ["../escape.txt", "Users/../../escape.txt", "C:/Windows/evil.txt", "/etc/passwd"])
def test_refuses_paths_outside_the_estate(settings, registry, keys, estate, bad):
    with pytest.raises(ValueError):
        Placer(settings, registry, keys).safe_target("laptop-dev-07", bad)


def test_new_decoys_are_backdated(settings, registry, keys, deployed):
    ninety_days = 90 * 86400
    for placement in deployed.values():
        if placement["created_file"]:
            stat = os.stat(placement["abs_path"])
            assert time.time() - stat.st_mtime >= ninety_days
            if sys.platform == "win32":
                created = getattr(stat, "st_birthtime", stat.st_ctime)  # st_ctime is creation time on Windows < 3.12
                assert time.time() - created >= ninety_days
                assert created <= stat.st_mtime


def test_records_real_secrets_next_to_each_decoy(deployed):
    creds = deployed["laptop-dev-07:Users/r.iyer/.aws/credentials"]["colocated"]
    env = deployed["laptop-dev-07:Users/r.iyer/projects/billing-service/deploy/.env.prod.bak"]["colocated"]
    assert creds == ["AWS profile [default] (same file)"]
    assert env == [".env: STRIPE_SECRET_KEY, DATABASE_URL, JWT_SIGNING_SECRET"]
    assert deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]["colocated"] == []


def test_registry_holds_no_decoy_values(settings, registry, deployed):
    registry.close()  # flush WAL into the main database file
    blob = b"".join(p.read_bytes() for p in settings.data_dir.glob("mirage.db*"))
    for placement in deployed.values():
        text = open(placement["abs_path"], encoding="utf-8").read()
        for line in text.splitlines():
            for value in line.replace('"', " ").replace("=", " ").split():
                if value.startswith(("AKIA", "acme_live_")) and "EXAMPLE" not in value:
                    assert value.encode() not in blob, f"plaintext decoy value in registry: {value[:8]}..."


def test_retire_restores_the_estate(settings, registry, keys, estate):
    creds = estate / DEV_CREDS
    original = creds.read_bytes()
    placer = Placer(settings, registry, keys)
    placer.deploy()
    placer.retire_all()
    assert creds.read_bytes() == original
    assert not (estate / "laptop-hr-05/Users/s.lindqvist/scripts/sync_reports.ps1").exists()
    assert registry.list_placements() == []


def test_secret_labels_reports_names_not_values():
    assert secret_labels("[default]\naws_access_key_id = AKIAX\n[other]\nregion = x\n") == ["AWS profile [default]"]
    assert secret_labels("API_TOKEN=abc\nPORT=3000\nEMPTY_SECRET=\n$ApiKey = \"x\"\n") == ["API_TOKEN", "ApiKey"]
