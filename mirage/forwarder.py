"""Sensor -> control delivery. Events are HMAC-signed and spooled to disk if control is down (flaw #6)."""

from __future__ import annotations

import json
import threading

import httpx

from .config import Settings
from .keys import Keys, sign


class Forwarder:
    def __init__(self, settings: Settings, keys: Keys, name: str):
        self.url = settings.control_url + "/ingest"
        self.key = keys.ingest
        self.spool = settings.spool_dir / f"{name}.jsonl"
        self.flush_interval = settings.spool_flush_interval
        self._client = httpx.Client(timeout=2.0)
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def _post(self, event: dict) -> dict:
        body = json.dumps(event, separators=(",", ":")).encode()
        response = self._client.post(self.url, content=body, headers={
            "content-type": "application/json",
            "x-mirage-signature": sign(self.key, body),
        })
        response.raise_for_status()
        return response.json()

    def send(self, event: dict) -> dict | None:
        """Deliver an event and return control's reply, or spool it and return None."""
        try:
            return self._post(event)
        except (httpx.HTTPError, ValueError):
            with self._lock:
                self.spool.parent.mkdir(parents=True, exist_ok=True)
                with open(self.spool, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event) + "\n")
            return None

    def flush(self) -> int:
        """Retry spooled events in order; stop at the first failure. Returns how many were delivered."""
        with self._lock:
            if not self.spool.exists():
                return 0
            pending = [line for line in self.spool.read_text(encoding="utf-8").splitlines() if line.strip()]
            delivered = 0
            for line in pending:
                event = json.loads(line)
                event["spooled"] = True
                try:
                    self._post(event)
                except (httpx.HTTPError, ValueError):
                    break
                delivered += 1
            remaining = pending[delivered:]
            if remaining:
                self.spool.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                self.spool.unlink(missing_ok=True)
            return delivered

    def start_flusher(self) -> threading.Thread:
        def loop():
            while not self._stop.wait(self.flush_interval):
                self.flush()

        thread = threading.Thread(target=loop, name="spool-flusher", daemon=True)
        thread.start()
        return thread

    def close(self) -> None:
        self._stop.set()
        self._client.close()
