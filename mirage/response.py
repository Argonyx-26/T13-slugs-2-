"""Response: decision table, circuit breaker, containment and follow-up tasks.

Covers flaws #9 (contain only confirmed hosts), #26 (never auto-isolate critical assets;
circuit breaker against decoy abuse) and #28 (rotate the real secrets next to the decoy).
"""

from __future__ import annotations

import time
from typing import Protocol

from .alerting import Alerter
from .config import Settings
from .registry import Registry

ROLE_LABEL = {"workstation": "workstation", "server": "server", "crown_jewel": "crown-jewel asset"}


def decide(severity: str, role: str, scope: str, attribution: str, breaker_open: bool, host_status: str) -> str:
    """Pure decision table: confidence x asset criticality x attribution."""
    if severity == "LOW":
        return "ticket"
    if severity == "MEDIUM":
        return "page"
    if host_status == "isolated":
        return "already_contained"
    if role in ("server", "crown_jewel"):
        return "approval_required"
    if scope == "host-local" or attribution == "confirmed":
        return "approval_required" if breaker_open else "auto_contain"
    return "approval_required"  # shared location and no confirmed reader: the planted host may be innocent


def explain(action: str, role: str, scope: str, breaker_open: bool) -> str:
    """One sentence a presenter (or an on-call analyst) can read out: why this action and not another."""
    if action == "ticket":
        return "Known scanner or routine reader: recorded for audit, nothing contained."
    if action == "page":
        return "The decoy file was read but the key hasn't been used yet: early warning, no containment."
    if action == "already_contained":
        return "The host was already contained by an earlier incident."
    if action == "auto_contain":
        if scope == "host-local":
            return "Workstation, and the decoy existed only on this host, so attribution is solid: contained automatically."
        return "Workstation, and read telemetry confirms who took the decoy: contained automatically."
    if action == "approval_required":
        if breaker_open:
            return "Circuit breaker is open (possible decoy abuse): automatic response is paused, so a person decides."
        if role in ("server", "crown_jewel"):
            return f"This is a {ROLE_LABEL[role]}: it is never isolated automatically, so a person decides."
        return "The decoy sits in a shared location with no confirmed reader, so the planted host may be innocent: a person decides."
    return ""


class EDRConnector(Protocol):
    name: str

    def isolate(self, host: str, reason: str) -> dict: ...

    def release(self, host: str) -> dict: ...


class MockEDR:
    """Stands in for Defender for Endpoint / CrowdStrike / SentinelOne network containment."""

    name = "mock-edr"

    def __init__(self, registry: Registry):
        self.registry = registry

    def isolate(self, host: str, reason: str) -> dict:
        self.registry.set_host_status(host, "isolated")
        return {"connector": self.name, "result": "network containment applied (simulated)", "reason": reason}

    def release(self, host: str) -> dict:
        self.registry.set_host_status(host, "online")
        return {"connector": self.name, "result": "network containment lifted (simulated)"}


class Responder:
    def __init__(self, settings: Settings, registry: Registry, edr: EDRConnector, alerter: Alerter, clock=time.time):
        self.settings = settings
        self.registry = registry
        self.edr = edr
        self.alerter = alerter
        self.clock = clock

    # -- circuit breaker -------------------------------------------------------------
    def _recent_auto(self) -> int:
        return self.registry.count_actions("auto_contain", self.clock() - self.settings.breaker_window)

    def breaker_open(self) -> bool:
        tripped = self.registry.get_meta("breaker_tripped_at")
        return tripped is not None and self.clock() - tripped < self.settings.breaker_cooldown

    def breaker_state(self) -> dict:
        return {"open": self.breaker_open(), "tripped_at": self.registry.get_meta("breaker_tripped_at"),
                "recent_auto": self._recent_auto(), "limit": self.settings.breaker_limit,
                "window_minutes": round(self.settings.breaker_window / 60)}

    def reset_breaker(self, actor: str) -> None:
        self.registry.del_meta("breaker_tripped_at")
        self.registry.add_action("breaker_reset", actor=actor)
        self.alerter.changed()

    # -- decisions -------------------------------------------------------------------
    def apply(self, incident: dict, placement: dict, host: dict) -> dict:
        """Decide and act. Safe to call again when an incident escalates: it never contains twice."""
        if incident["status"] in ("contained", "closed"):
            incident["tasks"] = self.tasks(incident, placement, host)
            return incident
        action = decide(incident["severity"], host["role"], placement["scope"], incident["attribution"],
                        self.breaker_open(), host["status"])
        if action == "auto_contain":
            if self._recent_auto() >= self.settings.breaker_limit:
                self.registry.set_meta("breaker_tripped_at", self.clock())
                self.registry.add_action("breaker_trip", host=host["name"], incident_id=incident["id"], actor="mirage")
                incident["breaker_tripped"] = 1
                action = "approval_required"
                self.alerter.page(
                    "Circuit breaker tripped: possible decoy abuse",
                    f"{self.settings.breaker_limit} automatic containments already happened in the last "
                    f"{round(self.settings.breaker_window / 60)} minutes, and a burst like this is what an attacker "
                    f"firing decoys on purpose looks like. Automatic response is paused; containing "
                    f"{host['name']} now needs approval.",
                )
            else:
                self._contain(incident, host, actor="mirage:auto", kind="auto_contain")
        incident["action"] = action
        if action == "already_contained":
            incident["status"] = "contained"
        incident["summary"]["why"] = explain(action, host["role"], placement["scope"], self.breaker_open())
        incident["tasks"] = self.tasks(incident, placement, host)
        return incident

    def _contain(self, incident: dict, host: dict, *, actor: str, kind: str) -> None:
        result = self.edr.isolate(host["name"], reason=f"{incident['id']}: {incident['label']}")
        self.registry.add_action(kind, host=host["name"], incident_id=incident["id"], actor=actor, detail=result)
        host["status"] = "isolated"
        incident["status"] = "contained"
        incident["summary"]["contained"] = {"ts": self.clock(), "by": actor, **result}

    def approve(self, incident_id: str, actor: str) -> dict | None:
        incident = self.registry.get_incident(incident_id)
        if incident is None:
            return None
        if incident["action"] != "approval_required" or incident["status"] != "open":
            return incident
        host = self.registry.get_host(incident["host"])
        if host["status"] != "isolated":
            self._contain(incident, host, actor=actor, kind="manual_contain")
        incident["status"] = "contained"
        incident["action"] = "approved_contained"
        incident["summary"]["why"] = f"Containment approved by {actor}."
        placement = self.registry.get_placement(incident["placement_id"])
        incident["tasks"] = self.tasks(incident, placement, host)
        incident["updated_at"] = self.clock()
        self.registry.update_incident(incident)
        self.alerter.changed()
        return incident

    def release(self, host_name: str, actor: str) -> dict | None:
        host = self.registry.get_host(host_name)
        if host is None:
            return None
        result = self.edr.release(host_name)
        self.registry.add_action("release", host=host_name, actor=actor, detail=result)
        for incident in self.registry.open_incidents_for_host(host_name):
            incident["status"] = "closed"
            incident["updated_at"] = self.clock()
            self.registry.update_incident(incident)
        self.alerter.changed()
        return self.registry.get_host(host_name)

    # -- follow-up work --------------------------------------------------------------
    def tasks(self, incident: dict, placement: dict, host: dict) -> list[str]:
        summary = incident["summary"]
        if incident["severity"] == "LOW":
            source = summary.get("source") or {}
            return [f"Confirm with the owner of {source.get('name', 'the scanner')} ({source.get('ip')}) "
                    "that this scan was expected. No containment needed."]
        tasks = []
        if incident["action"] == "approval_required" and incident["status"] == "open":
            tasks.append(f"Decide: approve network containment of {host['name']} ({ROLE_LABEL.get(host['role'], host['role'])})")
        if placement["colocated"]:
            tasks.append(f"Rotate the real secrets stored next to the decoy on {host['name']}: " + "; ".join(placement["colocated"]))
        tasks.append(f"Revoke sessions and reset credentials for {host['owner']} ({host['name']})")
        if incident["severity"] == "HIGH":
            source = summary.get("source") or {}
            if source.get("zone") == "external":
                tasks.append(f"Block {source.get('ip')} ({source.get('name')}) at the egress firewall and WAF")
            elif source.get("ip"):
                tasks.append(f"Investigate the internal source {source.get('ip')} ({source.get('name')})")
        tasks.append(f"Preserve evidence on {host['name']}: memory image and process list before clean-up")
        return tasks
