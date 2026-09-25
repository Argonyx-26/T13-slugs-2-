"""Runtime settings. Most values can be overridden with MIRAGE_* environment variables."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default, cast=str):
    raw = os.environ.get(f"MIRAGE_{name}")
    if raw is None or raw == "":
        return default
    return cast(raw)


@dataclass
class Settings:
    data_dir: Path
    estate_root: Path
    estate_manifest: Path
    control_host: str = "127.0.0.1"
    control_port: int = 7000
    sensor_host: str = "127.0.0.1"
    sensor_port: int = 8080

    # Self-test: control sends a reserved token through the sensor and back.
    selftest_interval: float = 10.0
    selftest_stale_after: float = 30.0
    # Read-audit sensor heartbeat.
    heartbeat_interval: float = 10.0
    heartbeat_stale_after: float = 30.0
    readaudit_poll_interval: float = 1.0
    spool_flush_interval: float = 5.0

    # Triage and response.
    group_window: float = 30 * 60
    attribution_lookback: float = 24 * 3600
    breaker_limit: int = 2
    breaker_window: float = 10 * 60
    breaker_cooldown: float = 30 * 60
    webhook_url: str | None = None

    # A scanner is only "known" when BOTH its source IP and its user-agent match.
    scanner_allowlist: list[dict] = field(default_factory=lambda: [
        {"ip": "127.0.0.10", "ua_contains": "trufflehog", "label": "AppSec secret scanner (appsec-scan-01)"},
    ])
    scanner_ua_markers: tuple[str, ...] = (
        "trufflehog", "gitleaks", "gitguardian", "ggshield", "detect-secrets", "noseyparker", "kingfisher",
    )
    # Demo network map: loopback aliases stand in for real networks.
    network_map: dict[str, dict] = field(default_factory=lambda: {
        "127.0.0.1": {"zone": "internal", "name": "localhost"},
        "127.0.0.10": {"zone": "internal", "name": "appsec-scan-01"},
        "127.0.0.20": {"zone": "internal", "name": "unrecognised internal host"},
        "127.0.0.66": {"zone": "external", "name": "VPS 185.220.101.66 (simulated)"},
    })
    # Processes that read files for harmless reasons (antivirus, indexing, sync).
    benign_readers: tuple[str, ...] = (
        "msmpeng.exe", "mpdefendercoreservice.exe", "mssense.exe", "searchindexer.exe",
        "searchprotocolhost.exe", "searchfilterhost.exe", "onedrive.exe",
    )

    @property
    def db_path(self) -> Path:
        return self.data_dir / "mirage.db"

    @property
    def key_path(self) -> Path:
        return self.data_dir / "master.key"

    @property
    def selftest_token_path(self) -> Path:
        return self.data_dir / "selftest.token"

    @property
    def spool_dir(self) -> Path:
        return self.data_dir / "spool"

    @property
    def pid_dir(self) -> Path:
        return self.data_dir / "pids"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def decoy_paths_file(self) -> Path:
        return self.data_dir / "decoy_paths.txt"

    @property
    def control_url(self) -> str:
        return f"http://{self.control_host}:{self.control_port}"

    @property
    def sensor_url(self) -> str:
        return f"http://{self.sensor_host}:{self.sensor_port}"

    def load_manifest(self) -> dict:
        return json.loads(self.estate_manifest.read_text(encoding="utf-8"))


def load_settings(**overrides) -> Settings:
    settings = Settings(
        data_dir=Path(_env("DATA_DIR", PROJECT_ROOT / "data", Path)),
        estate_root=Path(_env("ESTATE_ROOT", PROJECT_ROOT / "demo" / "estate", Path)),
        estate_manifest=Path(_env("ESTATE_MANIFEST", PROJECT_ROOT / "demo" / "estate.json", Path)),
        control_port=_env("CONTROL_PORT", 7000, int),
        sensor_port=_env("SENSOR_PORT", 8080, int),
        selftest_interval=_env("SELFTEST_INTERVAL", 10.0, float),
        selftest_stale_after=_env("SELFTEST_STALE_AFTER", 30.0, float),
        breaker_limit=_env("BREAKER_LIMIT", 2, int),
        breaker_window=_env("BREAKER_WINDOW", 600.0, float),
        webhook_url=_env("WEBHOOK_URL", None),
    )
    for key, value in overrides.items():
        if not hasattr(settings, key):
            raise AttributeError(f"unknown setting: {key}")
        setattr(settings, key, value)
    return settings
