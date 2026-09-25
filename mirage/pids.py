"""PID files for Mirage's own processes, so its own reads of decoy files aren't reported."""

from __future__ import annotations

import atexit
import os

from .config import Settings


def register(settings: Settings, role: str) -> None:
    settings.pid_dir.mkdir(parents=True, exist_ok=True)
    pid_file = settings.pid_dir / f"{role}-{os.getpid()}.pid"
    pid_file.write_text(str(os.getpid()), encoding="ascii")
    atexit.register(lambda: pid_file.unlink(missing_ok=True))


def own_pids(settings: Settings) -> set[int]:
    found = set()
    if settings.pid_dir.exists():
        for pid_file in settings.pid_dir.glob("*.pid"):
            try:
                found.add(int(pid_file.read_text(encoding="ascii").strip()))
            except (OSError, ValueError):
                continue
    return found
