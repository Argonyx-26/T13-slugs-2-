"""Attacker and scanner simulator for the demo.

It behaves like a credential-harvesting tool: read every file on the target hosts, pull
out anything that looks like a credential with generic patterns, then try each one.

Demo shortcuts (stated in the README):
- "*.acme.internal" resolves to the local decoy sensor (a stand-in for internal DNS).
- AWS calls go to the local AWS emulator, like pointing a tool at LocalStack, because real
  CloudTrail alerts take 2-30 minutes.
- Source addresses are loopback aliases (127.0.0.x) standing in for real networks.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirage.config import Settings, load_settings  # noqa: E402

AWS_ID = re.compile(r"(?i)aws_access_key_id[ \t\"']*[=:][ \t\"']*(AKIA[A-Z2-7]{16})")
AWS_SECRET = re.compile(r"(?i)aws_secret_access_key[ \t\"']*[=:][ \t\"']*([A-Za-z0-9/+]{40})")
API_KEY = re.compile(r"(?i)(?:api[_ -]?key|_key|token)[ \t\"']*[=:][ \t\"']*([A-Za-z0-9_\-]{24,})")
URL = re.compile(r"https?://[^\s\"'<>)]+")

MODES = {
    "attacker": {"hosts": ["laptop-dev-07", "fs-01"], "src": "127.0.0.66", "profile": "attacker"},
    "crown-jewel": {"hosts": ["db-prod-01"], "src": "127.0.0.66", "profile": "attacker"},
    "scanner": {"hosts": ["fs-01"], "src": "127.0.0.10", "profile": "scanner"},
    "spoofed-scanner": {"hosts": ["laptop-fin-02"], "src": "127.0.0.20", "profile": "scanner"},
    "flood": {"hosts": ["laptop-hr-05", "laptop-fin-02", "laptop-ops-03"], "src": "127.0.0.66", "profile": "attacker"},
}
USER_AGENTS = {
    "attacker": {"aws": "aws-cli/2.17.20 Python/3.11.9 Linux/6.8.0-45-generic exe/x86_64.ubuntu.24",
                 "api": "python-requests/2.32.3"},
    "scanner": {"aws": "TruffleHog", "api": "TruffleHog"},
}


@dataclass
class Finding:
    host: str
    path: str
    kind: str  # "aws" or "api"
    key: str
    secret: str = ""
    url: str = ""

    @property
    def masked(self) -> str:
        return f"{self.key[:4]}...{self.key[-4:]}"


def harvest(estate_root: Path, hosts: list[str]) -> tuple[list[Finding], int]:
    findings, files_read = [], 0
    for host in hosts:
        host_root = estate_root / host
        for path in sorted(p for p in host_root.rglob("*") if p.is_file()):
            text = path.read_text(encoding="utf-8", errors="replace")
            files_read += 1
            rel = path.relative_to(host_root).as_posix()
            for key_id, secret in zip(AWS_ID.findall(text), AWS_SECRET.findall(text)):
                findings.append(Finding(host, rel, "aws", key_id, secret))
            lines = text.splitlines()
            urls = [(i, m.group(0)) for i, line in enumerate(lines) for m in URL.finditer(line)]
            for i, line in enumerate(lines):
                if "aws_" in line.lower():  # already handled as an AWS key pair
                    continue
                for match in API_KEY.finditer(line):
                    nearest = min(urls, key=lambda u: (abs(u[0] - i), u[0]), default=(0, ""))[1]
                    findings.append(Finding(host, rel, "api", match.group(1), url=nearest))
    return findings, files_read


def sigv4_headers(method: str, url: str, body: bytes, key_id: str, secret: str, region: str, service: str) -> dict:
    parts = urlsplit(url)
    now = datetime.now(timezone.utc)
    amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    headers = {"host": parts.netloc, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash}
    if body:
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
    signed = ";".join(sorted(headers))
    canonical = "\n".join([method, parts.path or "/", parts.query,
                           "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)), signed, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])

    def h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = h(h(h(h(("AWS4" + secret).encode(), date), region), service), "aws4_request")
    signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, Signature={signature}"
    return headers


def _xml_value(text: str, tag: str) -> str:
    match = re.search(fr"<{tag}>([^<]*)</{tag}>", text)
    return match.group(1) if match else ""


class Tester:
    def __init__(self, settings: Settings, src_ip: str, profile: str, internal_domain: str, out=print):
        self.settings = settings
        self.profile = profile
        self.internal_domain = internal_domain
        self.out = out
        self.client = httpx.Client(transport=httpx.HTTPTransport(local_address=src_ip), timeout=5.0)
        self.results: list[dict] = []

    def aws(self, finding: Finding, service: str, method: str, body: bytes = b"") -> None:
        url = self.settings.sensor_url + "/"
        headers = sigv4_headers(method, url, body, finding.key, finding.secret, "us-east-1", service)
        headers["user-agent"] = USER_AGENTS[self.profile]["aws"]
        response = self.client.request(method, url, content=body, headers=headers)
        detail = _xml_value(response.text, "Arn") or _xml_value(response.text, "Code")
        what = "sts:GetCallerIdentity" if service == "sts" else "s3:ListBuckets"
        self._log("aws", finding, what, response.status_code, detail)

    def api(self, finding: Finding, suffix: str) -> None:
        parts = urlsplit(finding.url)
        if not finding.url or not (parts.hostname or "").endswith(self.internal_domain):
            self._log("api", finding, "skipped", 0, "no internal endpoint next to this key")
            return
        # Simulated internal DNS: *.acme.internal -> the decoy sensor.
        target = f"http://{self.settings.sensor_host}:{parts.port or 80}{parts.path.rstrip('/')}{suffix}"
        response = self.client.get(target, headers={
            "host": parts.netloc, "authorization": f"Bearer {finding.key}",
            "user-agent": USER_AGENTS[self.profile]["api"],
        })
        try:
            detail = response.json().get("error", "")
        except ValueError:
            detail = ""
        self._log("api", finding, f"GET {finding.url.rstrip('/')}{suffix}", response.status_code, detail)

    def try_all(self, finding: Finding) -> None:
        if finding.kind == "aws":
            self.aws(finding, "sts", "POST", b"Action=GetCallerIdentity&Version=2011-06-15")
            if self.profile == "attacker":
                self.aws(finding, "s3", "GET")
        else:
            self.api(finding, "/accounts?limit=50")

    def _log(self, kind: str, finding: Finding, what: str, status: int, detail: str) -> None:
        self.results.append({"host": finding.host, "kind": kind, "what": what, "status": status, "detail": detail})
        if self.out:
            code = "--" if status == 0 else status
            self.out(f"  {kind.upper():<4}{finding.masked:<13}{what:<58} -> {code} {detail}")

    def close(self) -> None:
        self.client.close()


def run(mode: str, settings: Settings | None = None, pause: float = 2.5, repeat: int = 50, out=print) -> dict:
    settings = settings or load_settings()
    config = MODES[mode]
    org = settings.load_manifest()["org"]
    say = out or (lambda *_: None)
    say(f"[{mode}] harvesting credentials from {', '.join(config['hosts'])} (source {config['src']})")
    findings, files_read = harvest(settings.estate_root, config["hosts"])
    for f in findings:
        say(f"  found {f.kind.upper():<4}{f.masked:<13}on {f.host}: {f.path}")
    say(f"  {len(findings)} credentials in {files_read} files")
    if pause:
        time.sleep(pause)
    say(f"[{mode}] trying them...")
    tester = Tester(settings, config["src"], config["profile"], org["internal_domain"], out=out)
    try:
        for index, finding in enumerate(findings):
            tester.try_all(finding)
            if mode == "flood" and index == 0:
                tester.out, shown = None, tester.out
                for _ in range(repeat - 1):  # a bot hammering the first key it found
                    tester.try_all(finding)
                tester.out = shown
                say(f"  ... and {repeat - 1} more times, as fast as possible")
    finally:
        tester.close()
    return {"mode": mode, "findings": len(findings), "files_read": files_read, "results": tester.results}


def main() -> int:
    parser = argparse.ArgumentParser(description="Simulate an attacker or a secret scanner against the demo estate.")
    parser.add_argument("mode", choices=sorted(MODES))
    parser.add_argument("--pause", type=float, default=2.5, help="seconds between harvesting and using (default 2.5)")
    parser.add_argument("--repeat", type=int, default=50, help="flood mode: how often to retry the first key")
    args = parser.parse_args()
    run(args.mode, pause=args.pause, repeat=args.repeat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
