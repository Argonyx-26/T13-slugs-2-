"""Alerts (console pages, optional Slack-compatible webhook) and the dashboard's live feed.

In production, HIGH alerts should also page through a channel the attacker can't read,
such as PagerDuty or SMS (flaw #30). The webhook here is the integration point.
"""

from __future__ import annotations

import asyncio
import threading
import time

import httpx

from .config import Settings


class Broadcaster:
    """Fans events out to dashboard connections (server-sent events)."""

    def __init__(self):
        self._loop: asyncio.AbstractEventLoop | None = None
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = threading.Lock()

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        with self._lock:
            self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.discard(queue)

    def publish(self, kind: str, data: dict | None = None) -> None:
        if self._loop is None:
            return
        message = {"type": kind, "data": data or {}}
        with self._lock:
            subscribers = list(self._subscribers)
        for queue in subscribers:
            try:
                self._loop.call_soon_threadsafe(self._offer, queue, message)
            except RuntimeError:  # loop closed during shutdown
                return

    @staticmethod
    def _offer(queue: asyncio.Queue, message: dict) -> None:
        if not queue.full():
            queue.put_nowait(message)


class Alerter:
    def __init__(self, settings: Settings, broadcaster: Broadcaster, out=print):
        self.settings = settings
        self.broadcaster = broadcaster
        self.out = out

    def _emit(self, level: str, text: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {level:<7}{text}"
        self.out(line.encode("ascii", "replace").decode("ascii"))

    def _webhook(self, text: str) -> None:
        if not self.settings.webhook_url:
            return

        def post():
            try:
                httpx.post(self.settings.webhook_url, json={"text": text}, timeout=5)
            except httpx.HTTPError:
                pass

        threading.Thread(target=post, daemon=True).start()

    def incident(self, incident: dict, new: bool) -> None:
        verb = "NEW" if new else "ESCALATED"
        text = (f"[{incident['severity']}] {verb} {incident['host']} {incident['summary']['path']} | "
                f"{incident['label']} | action: {incident['action']}")
        level = "TICKET" if incident["severity"] == "LOW" else "PAGE"
        self._emit(level, text)
        if incident["severity"] == "HIGH":
            self._webhook("Mirage: " + text)
        self.broadcaster.publish("incident", {"id": incident["id"], "severity": incident["severity"],
                                              "stage": incident["stage"], "new": new})

    def page(self, title: str, detail: str) -> None:
        self._emit("PAGE", f"{title}. {detail}")
        self._webhook(f"Mirage: {title}. {detail}")
        self.broadcaster.publish("alert", {"title": title, "detail": detail})

    def changed(self) -> None:
        self.broadcaster.publish("changed")
