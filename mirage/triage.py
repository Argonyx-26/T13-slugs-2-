"""Triage: classify each trigger, attribute it, group it into incidents, escalate stolen -> used.

Harmless triggers are labelled and kept, never deleted (flaw #7): an attacker can copy a
scanner's user-agent, so a label only lowers severity and blocks automatic response.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from . import tokens
from .alerting import Alerter
from .config import Settings
from .keys import Keys
from .registry import Registry
from .response import Responder

SEVERITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
MAX_ATTEMPTS = 12
MAX_TIMELINE = 12


@dataclass
class Verdict:
    severity: str
    classification: str
    label: str
    bucket: str  # "benign" or "threat": harmless triggers never merge into real incidents
    source: dict | None = None


def source_info(settings: Settings, ip: str | None) -> dict:
    known = settings.network_map.get(ip or "")
    if known:
        return {"ip": ip, **known}
    return {"ip": ip, "zone": "unknown", "name": "unmapped address"}


def classify_use(settings: Settings, ip: str | None, user_agent: str | None) -> Verdict:
    ua = (user_agent or "").lower()
    source = source_info(settings, ip)
    for entry in settings.scanner_allowlist:
        if entry["ip"] == ip and entry["ua_contains"] in ua:
            label = f"{entry['label']}: source IP and user-agent both match the allowlist"
            return Verdict("LOW", "benign:scanner", label, "benign", source)
    if any(marker in ua for marker in settings.scanner_ua_markers):
        label = f"Scanner user-agent from unexpected source {ip} ({source['name']}): possible spoofing"
        return Verdict("HIGH", "suspicious:spoofed-scanner", label, "threat", source)
    label = f"Decoy credential used from {source['zone']} source {ip} ({source['name']})"
    return Verdict("HIGH", "malicious:credential-use", label, "threat", source)


def classify_read(settings: Settings, process_name: str, process_id: int, own_pids: set[int]) -> Verdict | None:
    """None means "ignore": Mirage reading its own decoys."""
    if process_id in own_pids:
        return None
    exe = os.path.basename(process_name.replace("\\", "/")).lower()
    if exe in settings.benign_readers:
        return Verdict("LOW", "benign:system-reader", f"Routine read by {exe}", "benign")
    return Verdict("MEDIUM", "suspicious:file-read", f"Decoy file read by {exe or 'unknown process'} (PID {process_id})", "threat")


class Engine:
    def __init__(self, settings: Settings, registry: Registry, keys: Keys, responder: Responder,
                 alerter: Alerter, health, own_pids=lambda: set(), clock=time.time):
        self.settings = settings
        self.registry = registry
        self.keys = keys
        self.responder = responder
        self.alerter = alerter
        self.health = health
        self.own_pids = own_pids
        self.clock = clock

    def handle(self, event: dict) -> dict:
        kind = event.get("kind")
        if kind == "heartbeat":
            self.health.beat(event.get("sensor", "unknown"))
            return {"ok": True}
        if kind == "token_use":
            return self._token_use(event)
        if kind == "file_read":
            return self._file_read(event)
        return {"ok": False, "error": "unknown event kind"}

    # -- decoy credential used -------------------------------------------------------
    def _lookup(self, cred: dict) -> dict | None:
        if cred.get("type") == "aws":
            value = cred.get("key_id") or ""
        elif cred.get("type") == "api":
            value = cred.get("key") or ""
            if not tokens.api_key_tag_ok(value, self.keys.tag):
                return None  # not one of ours: rejected without touching the registry
        else:
            return None
        return self.registry.find_token(tokens.fingerprint(value, self.keys.fingerprint)) if value else None

    def _token_use(self, event: dict) -> dict:
        cred = event.get("credential") or {}
        token = self._lookup(cred)
        if token is None:
            self.registry.bump("unknown_credentials")
            return {"ok": True, "known": False}
        if token["kind"] == "selftest":
            self.health.selftest_ok()
            return {"ok": True, "known": True, "kind": "selftest"}

        placement = self.registry.placement_for_token(token["id"])
        verdict = classify_use(self.settings, event.get("src_ip"), event.get("user_agent"))
        ts = event.get("ts") or self.clock()
        attempt = {
            "ts": ts, "what": cred.get("action") or f"{event.get('method')} {event.get('path')}",
            "ip": event.get("src_ip"), "ua": event.get("user_agent", ""), "late": bool(event.get("spooled")),
        }
        event_id = self.registry.add_event(
            ts, event.get("sensor", "http-decoy"), "token_use", token_id=token["id"], placement_id=placement["id"],
            src_ip=event.get("src_ip"), user_agent=event.get("user_agent"), classification=verdict.classification,
            detail={"action": attempt["what"], "host_header": event.get("host_header"), "spooled": attempt["late"]},
        )
        incident = self._group(placement, token, verdict, "used", attempt=attempt)
        self.registry.set_event_incident(event_id, incident["id"])
        identity = token["meta"] if token["kind"] == "aws" else {}
        return {"ok": True, "known": True, "kind": token["kind"],
                "identity": {k: identity.get(k) for k in ("arn", "account", "user_id")}}

    # -- decoy file read -------------------------------------------------------------
    def _file_read(self, event: dict) -> dict:
        placement = self.registry.find_placement_by_path(os.path.normcase(os.path.abspath(event.get("path", ""))))
        if placement is None:
            return {"ok": True, "decoy": False}
        verdict = classify_read(self.settings, event.get("process_name", ""), int(event.get("process_id") or 0), self.own_pids())
        if verdict is None:
            return {"ok": True, "ignored": "self"}
        ts = event.get("ts") or self.clock()
        reader = {"process": event.get("process_name"), "pid": event.get("process_id"), "user": event.get("user"),
                  "computer": event.get("computer"), "ts": ts}
        event_id = self.registry.add_event(
            ts, event.get("sensor", "readaudit"), "file_read", token_id=placement["token_id"], placement_id=placement["id"],
            classification=verdict.classification, detail=reader,
        )
        if verdict.bucket == "benign":
            self.registry.bump("benign_reads")
            return {"ok": True, "benign": True}
        token = self.registry.get_token(placement["token_id"])
        incident = self._group(placement, token, verdict, "stolen", reader=reader)
        self.registry.set_event_incident(event_id, incident["id"])
        return {"ok": True, "incident": incident["id"]}

    # -- grouping and escalation -------------------------------------------------------
    def _attribution(self, placement: dict, now: float) -> tuple[str, dict | None]:
        reads = self.registry.suspicious_reads(placement["id"], now - self.settings.attribution_lookback)
        if reads:
            return "confirmed", reads[0]["detail"]
        return "planted-location", None

    def _group(self, placement: dict, token: dict, verdict: Verdict, stage: str, *, attempt=None, reader=None) -> dict:
        now = self.clock()
        host = self.registry.get_host(placement["host"])
        incident = self.registry.find_open_incident(placement["id"], verdict.bucket, now - self.settings.group_window)
        attribution, first_reader = self._attribution(placement, now)
        reader = reader or first_reader

        if incident is None:
            incident = {
                "id": tokens.incident_id(), "placement_id": placement["id"], "host": placement["host"],
                "bucket": verdict.bucket, "opened_at": now, "updated_at": now, "stage": stage,
                "severity": verdict.severity, "classification": verdict.classification, "label": verdict.label,
                "attribution": attribution, "action": "none", "status": "open", "event_count": 1,
                "breaker_tripped": 0, "tasks": [],
                "summary": {
                    "token_kind": token["kind"], "display": token["display"], "identity": token["identity"],
                    "path": placement["rel_path"], "template_label": placement["label"], "scope": placement["scope"],
                    "technique": placement["technique"], "owner": host["owner"], "role": host["role"],
                    "source": verdict.source, "reader": reader, "attempts": [], "timeline": [],
                },
            }
            self._record(incident, stage, verdict, attempt, reader, now)
            self.responder.apply(incident, placement, host)
            self.registry.insert_incident(incident)
            self.alerter.incident(incident, new=True)
            return incident

        escalated = False
        if SEVERITY[verdict.severity] > SEVERITY[incident["severity"]]:
            incident.update(severity=verdict.severity, classification=verdict.classification, label=verdict.label)
            escalated = True
        if stage == "used" and incident["stage"] == "stolen":
            incident["stage"] = "used"
            escalated = True
        if verdict.source and (stage == "used" or not incident["summary"].get("source")):
            incident["summary"]["source"] = verdict.source
        newly_confirmed = attribution == "confirmed" and incident["attribution"] != "confirmed"
        incident["attribution"] = attribution
        if reader:
            incident["summary"]["reader"] = reader
        incident["event_count"] += 1
        incident["updated_at"] = now
        self._record(incident, stage, verdict, attempt, reader, now)
        if escalated or newly_confirmed:
            self.responder.apply(incident, placement, host)
        self.registry.update_incident(incident)
        if escalated:
            self.alerter.incident(incident, new=False)
        else:
            self.alerter.changed()
        return incident

    def _record(self, incident: dict, stage: str, verdict: Verdict, attempt, reader, now: float) -> None:
        summary = incident["summary"]
        if attempt:
            summary["attempts"] = (summary["attempts"] + [attempt])[-MAX_ATTEMPTS:]
        timeline = summary["timeline"]
        entry = {"ts": now, "stage": stage, "severity": verdict.severity, "text": verdict.label}
        if reader and stage == "stolen":
            entry["text"] = f"{verdict.label} as {reader.get('user')}"
        # Collapse repeats of the same step so a flood stays readable.
        if timeline and timeline[-1]["stage"] == stage and timeline[-1]["text"] == entry["text"]:
            timeline[-1]["count"] = timeline[-1].get("count", 1) + 1
            timeline[-1]["last_ts"] = now
        else:
            timeline.append(entry)
        summary["timeline"] = timeline[-MAX_TIMELINE:]
