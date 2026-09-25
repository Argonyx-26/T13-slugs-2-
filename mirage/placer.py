"""Decoy placement: one unique decoy per location, written safely and made to look real.

Rules (flaws #4, #18, #21):
- never overwrite a file, never touch an existing profile, never write a default profile
- append-only for shared credential files, with a backup and the original timestamps kept
- refuse any path outside the estate root
- backdate new decoys so they don't all carry today's timestamp
- record which real secrets sit next to each decoy, so an incident can say what to rotate
"""

from __future__ import annotations

import os
import re
import secrets
import shutil
import sys
import time
from pathlib import Path

from . import tokens
from .config import Settings
from .keys import Keys
from .registry import Registry

TEMPLATES: dict[str, dict] = {
    "aws_credentials_profile": {
        "kind": "aws", "mode": "append", "technique": "T1552.001", "scope": "host-local",
        "label": "AWS credentials profile",
    },
    "backup_script_aws": {
        "kind": "aws", "mode": "create", "technique": "T1552.001", "scope": "shared",
        "label": "Legacy backup script with AWS keys",
    },
    "env_backup": {
        "kind": "api", "mode": "create", "technique": "T1552.001", "scope": "host-local",
        "label": ".env backup with API key and URL",
    },
    "onboarding_doc": {
        "kind": "api", "mode": "create", "technique": "T1552.001", "scope": "host-local",
        "label": "IT onboarding doc with API key",
    },
    "ps_script": {
        "kind": "api", "mode": "create", "technique": "T1552.001", "scope": "host-local",
        "label": "Script with hard-coded API key",
    },
}

_SECTION = re.compile(r"^[ \t]*\[([^\]\r\n]+)\][ \t]*$", re.M)
_AWS_KEY_LINE = re.compile(r"(?im)^[ \t]*aws_access_key_id[ \t]*=[ \t]*\S")
_ENV_SECRET = re.compile(
    r"^[ \t]*(?:export[ \t]+|\$env:|\$)?"
    r"([A-Za-z0-9_]*?(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|DSN|DATABASE_URL|CONNECTION_STRING))"
    r"[ \t]*[=:][ \t]*[^\s#]",
    re.I | re.M,
)


def norm(path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def secret_labels(text: str) -> list[str]:
    """Names of real-looking secrets in a file (never the values)."""
    if _AWS_KEY_LINE.search(text):
        parts = _SECTION.split(text)
        return [f"AWS profile [{name.strip()}]" for name, body in zip(parts[1::2], parts[2::2]) if _AWS_KEY_LINE.search(body)]
    names: list[str] = []
    for match in _ENV_SECRET.finditer(text):
        if match.group(1) not in names:
            names.append(match.group(1))
    return names


def aws_profiles(text: str) -> set[str]:
    return {m.strip() for m in _SECTION.findall(text)}


# -- timestamps ------------------------------------------------------------------------

def backdate(path: Path, min_days: int = 90, max_days: int = 400) -> float:
    """Give a new decoy a believable history: created and modified months ago."""
    now = time.time()
    age = (min_days + secrets.randbelow(max_days - min_days + 1)) * 86400 + secrets.randbelow(86400)
    mtime = now - age
    atime = min(now - 3600, mtime + secrets.randbelow(int(age // 2) + 1))
    if sys.platform == "win32":
        _set_creation_time(path, mtime - secrets.randbelow(7 * 86400))
    os.utime(path, (atime, mtime))
    return mtime


def _set_creation_time(path: Path, timestamp: float) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create_file.restype = wintypes.HANDLE
    set_file_time = kernel32.SetFileTime
    set_file_time.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME),
                              ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
    set_file_time.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    file_write_attributes, share_all, open_existing, backup_semantics = 0x100, 0x7, 3, 0x02000000
    handle = create_file(str(path), file_write_attributes, share_all, None, open_existing, backup_semantics, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ticks = int((timestamp + 11644473600) * 10_000_000)  # FILETIME: 100ns since 1601-01-01
        created = wintypes.FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)
        if not set_file_time(handle, ctypes.byref(created), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel32.CloseHandle(handle)


# -- content templates -------------------------------------------------------------------

def _render(template: str, ctx: dict) -> str:
    if template == "aws_credentials_profile":
        return (f"[{ctx['profile']}]\naws_access_key_id = {ctx['key_id']}\n"
                f"aws_secret_access_key = {ctx['secret']}\nregion = {ctx['region']}\n")
    if template == "backup_script_aws":
        return "\n".join([
            "# s3_backup.ps1 - nightly backup of finance exports to S3.",
            "# Superseded by the Veeam job; kept for reference.",
            f'$env:AWS_ACCESS_KEY_ID     = "{ctx["key_id"]}"',
            f'$env:AWS_SECRET_ACCESS_KEY = "{ctx["secret"]}"',
            f'$env:AWS_DEFAULT_REGION    = "{ctx["region"]}"',
            "",
            f'aws s3 sync "D:\\Exports\\finance" "s3://{ctx["bucket"]}/nightly/" --storage-class STANDARD_IA --only-show-errors',
            "",
        ])
    if template == "env_backup":
        header = tokens.choose([
            f"# {ctx['service']} - production settings (superseded by Vault, kept for rollback)",
            f"# {ctx['service']} - old prod config, do not use",
            f"# {ctx['service']} - production .env backup before the secrets migration",
        ])
        var = ctx["service"].upper().replace("-", "_")
        return "\n".join([
            header,
            "NODE_ENV=production",
            "PORT=3000",
            "LOG_LEVEL=warn",
            f"{var}_URL={ctx['url']}",
            f"{var}_KEY={ctx['api_key']}",
            f"REDIS_URL=redis://cache-01.{ctx['domain']}:6379/2",
            "FEATURE_FLAGS=checkout_v2,async_refunds",
            "",
        ])
    if template == "onboarding_doc":
        return "\n".join([
            "# New starter checklist: VPN and internal API access",
            "",
            "Maintained by the IT Service Desk.",
            "",
            "1. Install the VPN client from the self-service portal and sign in with your SSO account.",
            "2. Request access to the Finance share (\\\\fs-01\\Finance) through the access-request form.",
            "3. Until your personal API key is issued, use the team's shared read-only key for the reporting API:",
            "",
            f"   - Base URL: {ctx['url']}",
            f"   - API key: {ctx['api_key']}",
            "",
            "4. Please don't share this document outside the Finance team.",
            "",
        ])
    if template == "ps_script":
        return "\n".join([
            "# sync_reports.ps1 - nightly HR report export (legacy; replaced by the HRIS connector)",
            "# Runs as a scheduled task on this machine.",
            f'$ApiBase = "{ctx["url"]}"',
            f'$ApiKey  = "{ctx["api_key"]}"',
            '$OutDir  = "C:\\Reports\\HR"',
            "",
            "New-Item -ItemType Directory -Force -Path $OutDir | Out-Null",
            '$headers = @{ Authorization = "Bearer $ApiKey" }',
            'Invoke-RestMethod -Uri "$ApiBase/reports/headcount?format=csv" -Headers $headers -OutFile (Join-Path $OutDir "headcount.csv")',
            "",
        ])
    raise KeyError(template)


# -- placer ------------------------------------------------------------------------------

class Placer:
    def __init__(self, settings: Settings, registry: Registry, keys: Keys):
        self.settings = settings
        self.registry = registry
        self.keys = keys
        self.root = settings.estate_root.resolve()

    def safe_target(self, host: str, rel: str) -> Path:
        rel_path = Path(rel)
        if rel_path.is_absolute() or rel_path.drive or ".." in rel_path.parts:
            raise ValueError(f"refusing unsafe decoy path: {rel!r}")
        target = (self.root / host / rel_path).resolve()
        if not target.is_relative_to(self.root):
            raise ValueError(f"refusing path outside the estate: {target}")
        return target

    def deploy(self, dry_run: bool = False) -> list[dict]:
        manifest = self.settings.load_manifest()
        org = manifest["org"]
        if not dry_run and self.registry.get_meta("decoy_aws_account") is None:
            self.registry.set_meta("decoy_aws_account", tokens.aws_account_id())
            self.registry.set_meta("org", org)
        planned = {
            norm(self.safe_target(h["name"], d["path"])) for h in manifest["hosts"] for d in h.get("decoys", [])
        }
        results = []
        for host in manifest["hosts"]:
            if not dry_run:
                self.registry.upsert_host(host["name"], host["role"], host["owner"], host.get("team", ""), host.get("os", ""))
            for spec in host.get("decoys", []):
                results.append(self._deploy_one(host, spec, org, planned, dry_run))
        if not dry_run:
            self.write_decoy_paths()
        return results

    def _deploy_one(self, host: dict, spec: dict, org: dict, planned: set[str], dry_run: bool) -> dict:
        template = TEMPLATES[spec["template"]]
        target = self.safe_target(host["name"], spec["path"])
        base = {"host": host["name"], "path": spec["path"], "template": spec["template"], "kind": template["kind"]}
        if self.registry.find_placement(host["name"], spec["path"], spec["template"]):
            return {**base, "status": "already deployed"}
        if template["mode"] == "create" and target.exists():
            return {**base, "status": "skipped: file already exists"}
        if dry_run:
            return {**base, "status": "would deploy"}
        return {**base, **self._place(host, spec, template, target, org, planned)}

    def _place(self, host: dict, spec: dict, template: dict, target: Path, org: dict, planned: set[str]) -> dict:
        slug, domain = org["slug"], org["internal_domain"]
        tid, pid = tokens.token_id(), tokens.placement_id()
        ctx: dict = {"domain": domain}
        if template["kind"] == "aws":
            key_id, secret = tokens.aws_key_pair()
            existing = aws_profiles(target.read_text(encoding="utf-8", errors="replace")) if target.exists() else set()
            identity, profile = self._aws_names(slug, existing)
            account = self.registry.get_meta("decoy_aws_account")
            ctx.update(key_id=key_id, secret=secret, profile=profile, region=org.get("aws_region", "eu-west-1"),
                       bucket=f"{slug}-finance-backup-legacy")
            meta = {"profile": profile, "account": account, "user_id": tokens.iam_user_id(),
                    "arn": f"arn:aws:iam::{account}:user/{identity}", "region": ctx["region"]}
            lookup, display = key_id, tokens.mask(key_id)
        else:
            service = spec.get("service") or tokens.choose(tokens.API_SERVICES)
            url = f"http://{service}.{domain}:{self.settings.sensor_port}/{spec.get('api_version', 'v2')}"
            api_key = tokens.api_key(f"{slug}_live", self.keys.tag)
            ctx.update(service=service, url=url, api_key=api_key)
            identity, meta = service, {"service": service, "url": url}
            lookup, display = api_key, tokens.mask(api_key)
            spec = {**spec, "service": service}

        colocated = self._colocated(target, template["mode"], planned)
        content = _render(spec["template"], ctx)
        created_file, backup = self._write(target, template["mode"], content, pid)

        self.registry.add_token(tid, template["kind"], tokens.fingerprint(lookup, self.keys.fingerprint), display, identity, meta)
        self.registry.add_placement({
            "id": pid, "token_id": tid, "host": host["name"], "rel_path": spec["path"],
            "abs_path": str(target), "norm_path": norm(target), "template": spec["template"],
            "label": template["label"], "scope": spec.get("scope", template["scope"]),
            "technique": template["technique"], "mode": template["mode"], "created_file": int(created_file),
            "colocated": colocated, "meta": {**meta, "backup": str(backup) if backup else None, "spec": spec},
            "deployed_at": time.time(),
        })
        return {"status": "deployed", "placement_id": pid, "display": display, "identity": identity,
                "scope": spec.get("scope", template["scope"]), "colocated": colocated}

    def _write(self, target: Path, mode: str, content: str, pid: str) -> tuple[bool, Path | None]:
        target.parent.mkdir(parents=True, exist_ok=True)
        if mode == "append" and target.exists():
            before = target.stat()
            backup = self.settings.backup_dir / f"{pid}.orig"
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup)
            original = target.read_bytes()
            separator = b"\n" if original and not original.endswith(b"\n") else b""
            with open(target, "ab") as fh:
                fh.write(separator + b"\n" + content.encode("utf-8"))
            os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))  # appending must not look recent
            return False, backup
        with open(target, "x", encoding="utf-8", newline="\n") as fh:  # "x": never overwrite
            fh.write(content)
        backdate(target)
        return True, None

    def _aws_names(self, slug: str, existing: set[str]) -> tuple[str, str]:
        for _ in range(20):
            purpose = tokens.choose(tokens.AWS_PURPOSES)
            profile = f"{slug}-{purpose}"
            if profile not in existing and profile != "default":
                return f"svc-{slug}-{purpose}", profile
        suffix = secrets.token_hex(2)
        return f"svc-{slug}-ops-{suffix}", f"{slug}-ops-{suffix}"

    def _colocated(self, target: Path, mode: str, planned: set[str]) -> list[str]:
        labels: list[str] = []
        if mode == "append" and target.exists():
            labels += [f"{label} (same file)" for label in secret_labels(target.read_text(encoding="utf-8", errors="replace"))]
        if target.parent.exists():
            for sibling in sorted(target.parent.iterdir()):
                if not sibling.is_file() or norm(sibling) == norm(target) or norm(sibling) in planned:
                    continue
                if self.registry.find_placement_by_path(norm(sibling)) or sibling.stat().st_size > 256 * 1024:
                    continue
                names = secret_labels(sibling.read_text(encoding="utf-8", errors="replace"))
                if names:
                    labels.append(f"{sibling.name}: {', '.join(names)}")
        return labels

    def replace(self, placement_id: str) -> dict:
        """Swap a burned decoy for a fresh one at the same path.

        The attacker knows the old key, so it must not stay in the file. Its token stays
        active in the registry, though: if the attacker tries the old key again, it still
        alerts and still points to this placement.
        """
        old = self.registry.get_placement(placement_id)
        if old is None or old["status"] != "deployed":
            raise ValueError("only a deployed decoy can be replaced")
        host = self.registry.get_host(old["host"])
        spec = old["meta"].get("spec") or {"template": old["template"], "path": old["rel_path"], "scope": old["scope"]}
        target = Path(old["abs_path"])
        if old["created_file"]:
            target.unlink(missing_ok=True)
        elif target.exists():
            _remove_profile(target, old["meta"]["profile"])
        self.registry.set_placement_status(placement_id, "burned")
        result = self._place(host, spec, TEMPLATES[spec["template"]], target, self.registry.get_meta("org"), {norm(target)})
        self.write_decoy_paths()
        return result

    def write_decoy_paths(self) -> None:
        paths = [p["abs_path"] for p in self.registry.list_placements()]
        self.settings.decoy_paths_file.parent.mkdir(parents=True, exist_ok=True)
        self.settings.decoy_paths_file.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")

    def retire_all(self) -> list[dict]:
        results = []
        for placement in self.registry.list_placements():
            target = Path(placement["abs_path"])
            if placement["created_file"]:
                target.unlink(missing_ok=True)
            elif target.exists():
                _remove_profile(target, placement["meta"]["profile"])
            self.registry.set_placement_status(placement["id"], "retired")
            self.registry.set_token_status(placement["token_id"], "retired")
            results.append({"host": placement["host"], "path": placement["rel_path"], "status": "retired"})
        self.write_decoy_paths()
        return results


def _remove_profile(target: Path, profile: str) -> None:
    before = target.stat()
    lines = target.read_text(encoding="utf-8").splitlines(keepends=True)
    out: list[str] = []
    skipping = False
    for line in lines:
        stripped = line.strip()
        if stripped == f"[{profile}]":
            skipping = True
            if out and out[-1].strip() == "":
                out.pop()  # the blank separator line we added
            continue
        if skipping and stripped.startswith("["):
            skipping = False
        if not skipping:
            out.append(line)
    target.write_text("".join(out), encoding="utf-8", newline="")
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
