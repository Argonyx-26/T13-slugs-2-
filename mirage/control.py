"""Control plane: event intake, triage, response, registry, dashboard, self-test."""

from __future__ import annotations

import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse

from . import pids
from .alerting import Alerter, Broadcaster
from .config import Settings
from .keys import load_keys, verify
from .placer import Placer
from .registry import Registry
from .response import EDRConnector, MockEDR, Responder, render_report
from .triage import Engine

STATIC = Path(__file__).parent / "static"

BUILT_TECHNIQUES = {
    "T1552.001": "Credentials in files",
    "T1078.004": "Cloud accounts (decoy AWS keys)",
    "T1005": "Decoy file reads (Windows Event 4663)",
}
ROADMAP_TECHNIQUES = [
    ("T1003.001", "LSASS memory (honey hash)"),
    ("T1558.003", "Kerberoasting (honey SPN)"),
    ("T1087.002", "AD enumeration (honey user)"),
    ("T1555.003", "Browser credential stores"),
    ("T1552.004", "Private keys (decoy SSH key)"),
    ("T1530", "Cloud storage (decoy bucket)"),
]


class Health:
    """End-to-end pipeline health: a silent failure is itself an alert (flaw #6)."""

    def __init__(self, settings: Settings, alerter: Alerter, clock=time.time):
        self.settings = settings
        self.alerter = alerter
        self.clock = clock
        self.started = clock()
        self.last_selftest: float | None = None
        self.beats: dict[str, float] = {}
        self._down_alerted: set[str] = set()
        self._lock = threading.Lock()

    def selftest_ok(self) -> None:
        with self._lock:
            self.last_selftest = self.clock()
        self._recovered("pipeline", "Detection pipeline recovered: self-test token delivered again")

    def beat(self, sensor: str) -> None:
        with self._lock:
            self.beats[sensor] = self.clock()
        self._recovered(sensor, f"Sensor {sensor} is sending heartbeats again")

    def _recovered(self, name: str, message: str) -> None:
        with self._lock:
            was_down = name in self._down_alerted
            self._down_alerted.discard(name)
        if was_down:
            self.alerter.page(message, "")
        self.alerter.changed()

    def snapshot(self) -> dict:
        now = self.clock()
        with self._lock:
            last, beats = self.last_selftest, dict(self.beats)
        pipeline_ok = last is not None and now - last < self.settings.selftest_stale_after
        starting = last is None and now - self.started < self.settings.selftest_stale_after
        sensors = {name: {"last": ts, "ok": now - ts < self.settings.heartbeat_stale_after} for name, ts in beats.items()}
        return {"pipeline_ok": pipeline_ok, "starting": starting, "last_selftest": last,
                "stale_after": self.settings.selftest_stale_after, "sensors": sensors, "now": now}

    def _first_alert(self, name: str) -> bool:
        with self._lock:
            if name in self._down_alerted:
                return False
            self._down_alerted.add(name)
            return True

    def evaluate(self) -> dict:
        """Check staleness and page once per outage. Called by the self-test loop and by every health read,
        so anyone who can see the outage has also triggered the page."""
        snap = self.snapshot()
        if not snap["pipeline_ok"] and not snap["starting"] and self._first_alert("pipeline"):
            since = "never" if snap["last_selftest"] is None else f"{int(snap['now'] - snap['last_selftest'])}s ago"
            self.alerter.page("Detection pipeline DOWN", f"The self-test token has not come back (last success: {since}). "
                              "Decoys may be firing without alerts.")
        for name, sensor in snap["sensors"].items():
            if not sensor["ok"] and self._first_alert(name):
                self.alerter.page(f"Sensor {name} is silent", "No heartbeat received; its decoys are unmonitored.")
        return snap


def selftest_loop(settings: Settings, health: Health, stop: threading.Event) -> None:
    token = settings.selftest_token_path.read_text(encoding="ascii").strip()
    with httpx.Client(timeout=3.0) as client:
        while True:
            try:
                client.get(f"{settings.sensor_url}/v1/status",
                           headers={"authorization": f"Bearer {token}", "user-agent": "mirage-selftest/1.0"})
            except httpx.HTTPError:
                pass
            health.evaluate()
            if stop.wait(settings.selftest_interval):
                return


def coverage(placements: list[dict]) -> dict:
    built = {p["technique"] for p in placements}
    if any(p["template"] in ("aws_credentials_profile", "backup_script_aws") for p in placements):
        built.add("T1078.004")
    built.add("T1005")
    return {"built": [{"id": t, "label": BUILT_TECHNIQUES.get(t, t)} for t in sorted(built)],
            "roadmap": [{"id": t, "label": label} for t, label in ROADMAP_TECHNIQUES]}


def _print_flush(line: str) -> None:
    print(line, flush=True)  # stdout is often a log file; don't lose pages to buffering


def create_control_app(settings: Settings, *, registry: Registry | None = None, edr: EDRConnector | None = None,
                       out=_print_flush) -> FastAPI:
    registry = registry or Registry(settings.db_path)
    keys = load_keys(settings.key_path)
    broadcaster = Broadcaster()
    alerter = Alerter(settings, broadcaster, out=out)
    placer = Placer(settings, registry, keys)
    responder = Responder(settings, registry, edr or MockEDR(registry, settings.evidence_dir), alerter,
                          replace_decoy=placer.replace)
    health = Health(settings, alerter)
    engine = Engine(settings, registry, keys, responder, alerter, health, own_pids=lambda: pids.own_pids(settings))

    @asynccontextmanager
    async def lifespan(_app):
        broadcaster.bind(asyncio.get_running_loop())
        stop = threading.Event()
        thread = threading.Thread(target=selftest_loop, args=(settings, health, stop), name="selftest", daemon=True)
        thread.start()
        yield
        stop.set()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.registry = registry
    app.state.health = health
    app.state.responder = responder

    def mutation_allowed(request: Request) -> bool:
        # Custom header forces a CORS preflight, so other web pages can't click our buttons.
        return request.headers.get("x-mirage-action") == "1"

    @app.post("/ingest")
    async def ingest(request: Request):
        body = await request.body()
        if not verify(keys.ingest, body, request.headers.get("x-mirage-signature")):
            return JSONResponse({"ok": False, "error": "bad signature"}, status_code=401)
        try:
            event = json.loads(body)
        except ValueError:
            return JSONResponse({"ok": False, "error": "bad json"}, status_code=400)
        return await run_in_threadpool(engine.handle, event)

    @app.get("/")
    async def dashboard():
        return FileResponse(STATIC / "dashboard.html", headers={"cache-control": "no-store"})

    def state() -> dict:
        placements = registry.list_placements()
        tokens_by_id = {p["token_id"]: registry.get_token(p["token_id"]) for p in placements}
        decoys = [{
            "id": p["id"], "host": p["host"], "path": p["rel_path"], "label": p["label"], "scope": p["scope"],
            "technique": p["technique"], "kind": tokens_by_id[p["token_id"]]["kind"],
            "display": tokens_by_id[p["token_id"]]["display"], "identity": tokens_by_id[p["token_id"]]["identity"],
            "colocated": p["colocated"], "deployed_at": p["deployed_at"],
        } for p in placements]
        return {
            "org": registry.get_meta("org", {}),
            "health": health.evaluate(),
            "breaker": responder.breaker_state(),
            "hosts": [{**h, "release_blockers": len(responder.release_blockers(h["name"]))} for h in registry.list_hosts()],
            "campaigns": responder.campaigns(),
            "incidents": registry.list_incidents(60),
            "decoys": decoys,
            "stats": registry.stats(),
            "coverage": coverage(placements),
        }

    @app.get("/api/state")
    async def api_state():
        return await run_in_threadpool(state)

    @app.get("/api/incidents")
    async def api_incidents():
        return await run_in_threadpool(registry.list_incidents, 200)

    @app.get("/api/hosts")
    async def api_hosts():
        return await run_in_threadpool(registry.list_hosts)

    @app.get("/api/health")
    async def api_health():
        snap = await run_in_threadpool(health.evaluate)
        return {**snap, "breaker": await run_in_threadpool(responder.breaker_state)}

    @app.post("/api/incidents/{incident_id}/approve")
    async def approve(incident_id: str, request: Request):
        if not mutation_allowed(request):
            return JSONResponse({"error": "missing x-mirage-action header"}, status_code=403)
        incident = await run_in_threadpool(responder.approve, incident_id, "analyst (dashboard)")
        return incident or JSONResponse({"error": "not found"}, status_code=404)

    async def _body(request: Request) -> dict:
        try:
            data = await request.json()
            return data if isinstance(data, dict) else {}
        except ValueError:
            return {}

    def _outcome(result: dict | None) -> JSONResponse:
        if result is None:
            return JSONResponse({"ok": False, "error": "not found"}, status_code=404)
        return JSONResponse(result, status_code=200 if result.get("ok") else 409)

    @app.post("/api/hosts/{host}/release")
    async def release(host: str, request: Request):
        if not mutation_allowed(request):
            return JSONResponse({"error": "missing x-mirage-action header"}, status_code=403)
        body = await _body(request)
        actor = str(body.get("actor") or "analyst (dashboard)")
        result = await run_in_threadpool(responder.release, host, actor, bool(body.get("force")), str(body.get("reason") or ""))
        return _outcome(result)

    @app.post("/api/incidents/{incident_id}/steps/{step_id}/done")
    async def step_done(incident_id: str, step_id: str, request: Request):
        if not mutation_allowed(request):
            return JSONResponse({"error": "missing x-mirage-action header"}, status_code=403)
        body = await _body(request)
        actor = str(body.get("actor") or "analyst (dashboard)")
        return _outcome(await run_in_threadpool(responder.complete_step, incident_id, step_id, actor, str(body.get("note") or "")))

    @app.post("/api/incidents/{incident_id}/steps/{step_id}/run")
    async def step_run(incident_id: str, step_id: str, request: Request):
        if not mutation_allowed(request):
            return JSONResponse({"error": "missing x-mirage-action header"}, status_code=403)
        body = await _body(request)
        actor = str(body.get("actor") or "analyst (dashboard)")
        return _outcome(await run_in_threadpool(responder.run_step, incident_id, step_id, actor))

    @app.get("/api/incidents/{incident_id}/report")
    async def report(incident_id: str):
        def build():
            incident = registry.get_incident(incident_id)
            if incident is None:
                return None
            placement = registry.get_placement(incident["placement_id"])
            host = registry.get_host(incident["host"])
            return render_report(incident, placement, host, registry.actions_for_incident(incident_id, incident["host"]))

        text = await run_in_threadpool(build)
        if text is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return PlainTextResponse(text, media_type="text/markdown; charset=utf-8",
                                 headers={"content-disposition": f'inline; filename="{incident_id}.md"'})

    @app.post("/api/breaker/reset")
    async def reset_breaker(request: Request):
        if not mutation_allowed(request):
            return JSONResponse({"error": "missing x-mirage-action header"}, status_code=403)
        await run_in_threadpool(responder.reset_breaker, "analyst (dashboard)")
        return responder.breaker_state()

    @app.get("/events")
    async def events(request: Request):
        queue = broadcaster.subscribe()

        async def stream():
            try:
                yield "retry: 2000\n\n"
                while not await request.is_disconnected():
                    try:
                        message = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"event: {message['type']}\ndata: {json.dumps(message['data'])}\n\n"
            finally:
                broadcaster.unsubscribe(queue)

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"cache-control": "no-cache"})

    return app
