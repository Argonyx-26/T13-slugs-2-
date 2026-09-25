"""Response: decision table, circuit breaker, containment, and the post-containment playbook.

Covers flaws #9 (contain only confirmed hosts), #26 (never auto-isolate critical assets;
circuit breaker against decoy abuse), #27 (preserve evidence before clean-up) and #28
(rotate the real secrets next to the decoy).

Isolation is step one, not the end. Every HIGH incident gets a playbook:
contain -> preserve -> scope -> eradicate -> recover. Low-risk steps run automatically,
risky ones need a person, and a host can't be released until the required steps are done.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Callable, Protocol

from .alerting import Alerter
from .config import Settings
from .registry import Registry

ROLE_LABEL = {"workstation": "workstation", "server": "server", "crown_jewel": "crown-jewel asset"}
PHASES = ("contain", "preserve", "scope", "eradicate", "recover")
FINISHED = ("done", "n/a")
HOST_STEPS = ("reimage",)  # one rebuild covers every incident on that machine
HUNT_WINDOW = 24 * 3600


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


# -- connectors (mocks stand in for EDR, firewall and identity provider APIs) ----------------

class EDRConnector(Protocol):
    name: str

    def isolate(self, host: str, reason: str) -> dict: ...

    def release(self, host: str) -> dict: ...

    def collect_evidence(self, host: str, incident_id: str) -> dict: ...


class MockEDR:
    """Stands in for Defender for Endpoint / CrowdStrike / SentinelOne."""

    name = "mock-edr"
    ARTIFACTS = ("memory image", "running processes", "network connections", "autoruns and scheduled tasks",
                 "recent file activity", "logged-on users")

    def __init__(self, registry: Registry, evidence_dir: Path | None = None):
        self.registry = registry
        self.evidence_dir = evidence_dir

    def isolate(self, host: str, reason: str) -> dict:
        self.registry.set_host_status(host, "isolated")
        return {"connector": self.name, "result": "network containment applied (simulated)", "reason": reason}

    def release(self, host: str) -> dict:
        self.registry.set_host_status(host, "online")
        return {"connector": self.name, "result": "network containment lifted (simulated)"}

    def collect_evidence(self, host: str, incident_id: str) -> dict:
        package = {"host": host, "incident": incident_id, "collected_at": time.time(), "collector": self.name,
                   "artifacts": list(self.ARTIFACTS),
                   "note": "simulated package; a real EDR returns the actual artifacts"}
        data = json.dumps(package, indent=2, sort_keys=True).encode()
        digest = hashlib.sha256(data).hexdigest()
        path = None
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            path = self.evidence_dir / f"{incident_id}-{host}.json"
            path.write_bytes(data)
        return {"connector": self.name, "sha256": digest, "path": str(path) if path else None,
                "artifacts": len(self.ARTIFACTS)}


class MockFirewall:
    name = "mock-firewall"

    def __init__(self, registry: Registry):
        self.registry = registry

    def block(self, ip: str, reason: str) -> dict:
        blocked = self.registry.get_meta("blocked_ips", [])
        if ip not in blocked:
            blocked.append(ip)
            self.registry.set_meta("blocked_ips", blocked)
        return {"connector": self.name, "result": f"{ip} blocked at the egress firewall and WAF (simulated)", "reason": reason}


class MockIdentity:
    name = "mock-idp"

    def revoke_sessions(self, owner: str) -> dict:
        return {"connector": self.name, "result": f"all sessions revoked and a password reset forced for {owner} (simulated)"}


# -- responder -----------------------------------------------------------------------------

def _step(step_id: str, phase: str, title: str, mode: str, required: bool = True) -> dict:
    """mode: auto (Mirage does it), approval (waits for containment approval),
    action (a person clicks Run and Mirage does it), manual (a person does it and confirms)."""
    return {"id": step_id, "phase": phase, "title": title, "mode": mode, "required": required,
            "status": "pending", "at": None, "by": None, "detail": ""}


class Responder:
    def __init__(self, settings: Settings, registry: Registry, edr: EDRConnector, alerter: Alerter, clock=time.time,
                 firewall: MockFirewall | None = None, identity: MockIdentity | None = None,
                 replace_decoy: Callable[[str], dict] | None = None):
        self.settings = settings
        self.registry = registry
        self.edr = edr
        self.alerter = alerter
        self.clock = clock
        self.firewall = firewall or MockFirewall(registry)
        self.identity = identity or MockIdentity()
        self.replace_decoy = replace_decoy

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
            self._sync(incident, placement, host)
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
        self._sync(incident, placement, host)
        return incident

    def _contain(self, incident: dict, host: dict, *, actor: str, kind: str) -> None:
        # Evidence first: isolating can end the attacker's session and change what's in memory.
        self._collect_evidence(incident, host["name"], actor)
        result = self.edr.isolate(host["name"], reason=f"{incident['id']}: {incident['label']}")
        self.registry.add_action(kind, host=host["name"], incident_id=incident["id"], actor=actor, detail=result)
        host["status"] = "isolated"
        incident["status"] = "contained"
        incident["summary"]["contained"] = {"ts": self.clock(), "by": actor, **result}

    def _collect_evidence(self, incident: dict, host_name: str, actor: str) -> dict:
        result = self.edr.collect_evidence(host_name, incident["id"])
        self.registry.add_action("evidence_collected", host=host_name, incident_id=incident["id"], actor=actor, detail=result)
        incident["summary"]["evidence"] = {"ts": self.clock(), "by": actor, **result}
        return result

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
        self._sync(incident, placement, host)
        incident["updated_at"] = self.clock()
        self.registry.update_incident(incident)
        self.alerter.changed()
        return incident

    # -- the playbook ----------------------------------------------------------------
    def playbook(self, incident: dict, placement: dict, host: dict) -> list[dict]:
        """The steps this incident needs, keeping the status of steps already done."""
        summary = incident["summary"]
        source = summary.get("source") or {}
        steps: list[dict] = []
        if incident["bucket"] == "benign":
            steps.append(_step("verify_scanner", "scope",
                               f"Confirm with the owner of {source.get('name', 'the scanner')} ({source.get('ip')}) "
                               "that this scan was expected", "manual", required=False))
        else:
            high = incident["severity"] == "HIGH"
            if high:
                mode = "approval" if incident["action"] == "approval_required" else "auto"
                steps.append(_step("isolate", "contain", f"Isolate {host['name']} from the network", mode))
                if source.get("zone") == "external":
                    steps.append(_step("block_ip", "contain",
                                       f"Block {source.get('ip')} ({source.get('name')}) at the egress firewall and WAF", "auto"))
                elif source.get("ip"):
                    steps.append(_step("investigate_source", "contain",
                                       f"Investigate the internal source {source.get('ip')} ({source.get('name')}): "
                                       "it may be another compromised machine", "manual"))
                steps.append(_step("revoke_sessions", "contain",
                                   f"Revoke all sessions and force a password reset for {host['owner']}", "auto"))
            steps.append(_step("evidence", "preserve",
                               f"Capture evidence on {host['name']} (memory, processes, connections) before any clean-up",
                               "auto" if high else "action"))
            steps.append(_step("hunt", "scope", "Hunt for the same attacker elsewhere (same address, same user, other decoys)", "auto"))
            if placement["colocated"]:
                steps.append(_step("rotate_secrets", "eradicate",
                                   "Rotate the real secrets stored next to the decoy: " + "; ".join(placement["colocated"]),
                                   "manual"))
            steps.append(_step("replace_decoy", "eradicate",
                               "Replace the burned decoy with a fresh one (the attacker now knows this one)", "action"))
            if high:
                steps.append(_step("reimage", "eradicate",
                                   f"Reimage {host['name']} from a clean build (only after evidence is captured)", "manual"))
                steps.append(_step("release", "recover",
                               f"Release {host['name']} back to the network once every step above is done", "manual",
                               required=False))
        previous = {s["id"]: s for s in incident.get("tasks") or [] if isinstance(s, dict)}
        for step in steps:
            old = previous.get(step["id"])
            if old and old["status"] != "pending":
                step.update(status=old["status"], at=old["at"], by=old["by"], detail=old["detail"])
        return steps

    def _mark(self, step: dict, by: str, detail: str = "", status: str = "done") -> None:
        step.update(status=status, at=self.clock(), by=by, detail=detail)

    def _sync(self, incident: dict, placement: dict, host: dict) -> None:
        """Rebuild the playbook and run the steps that are safe to automate."""
        steps = {s["id"]: s for s in self.playbook(incident, placement, host)}
        incident["tasks"] = list(steps.values())
        summary = incident["summary"]
        pending = lambda sid: sid in steps and steps[sid]["status"] == "pending"  # noqa: E731

        if pending("isolate") and (incident["status"] == "contained" or host["status"] == "isolated"):
            contained = summary.get("contained") or {}
            self._mark(steps["isolate"], contained.get("by", "mirage:auto"),
                       contained.get("result", "host was already isolated by an earlier incident"))
        if pending("block_ip"):
            source = summary["source"]
            result = self.firewall.block(source["ip"], reason=incident["id"])
            self.registry.add_action("block_ip", host=host["name"], incident_id=incident["id"], actor="mirage:auto", detail=result)
            self._mark(steps["block_ip"], "mirage:auto", result["result"])
        if pending("revoke_sessions"):
            result = self.identity.revoke_sessions(host["owner"])
            self.registry.add_action("revoke_sessions", host=host["name"], incident_id=incident["id"], actor="mirage:auto", detail=result)
            self._mark(steps["revoke_sessions"], "mirage:auto", result["result"])
        if pending("evidence") and steps["evidence"]["mode"] == "auto":
            evidence = summary.get("evidence")
            if evidence is None:  # contained by an earlier incident: reuse that host's package
                earlier = self.registry.latest_action("evidence_collected", host=host["name"])
                evidence = earlier and {"by": earlier["actor"], **earlier["detail"]}
            if evidence:
                self._mark(steps["evidence"], evidence.get("by", "mirage:auto"),
                           f"{evidence.get('artifacts', 0)} artifacts, sha256 {evidence['sha256'][:16]}...")
        if "hunt" in steps:
            related = self.hunt(incident)
            steps["hunt"].update(status="done", at=steps["hunt"]["at"] or self.clock(), by="mirage:auto",
                                 detail=self._hunt_text(incident, related))
            self._propagate_hunt(incident, related)

    # -- scoping ----------------------------------------------------------------------
    def hunt(self, incident: dict, extra: list[dict] = ()) -> list[dict]:
        """Other open incidents that share this attacker's address or the same reading user.
        `extra` covers an incident that is being created and isn't in the registry yet."""
        summary = incident["summary"]
        ip = (summary.get("source") or {}).get("ip")
        user = (summary.get("reader") or {}).get("user")
        related, seen = [], set()
        for other in [*self.registry.recent_threat_incidents(self.clock() - HUNT_WINDOW), *extra]:
            if other["id"] in seen or other["id"] == incident["id"] or other["host"] == incident["host"]:
                continue
            seen.add(other["id"])
            osum = other["summary"]
            same_ip = ip and (osum.get("source") or {}).get("ip") == ip
            same_user = user and (osum.get("reader") or {}).get("user") == user
            if same_ip or same_user:
                related.append(other)
        return related

    def _hunt_text(self, incident: dict, related: list[dict]) -> str:
        if not related:
            return "No related activity yet. Re-checked automatically whenever a new incident arrives."
        ip = (incident["summary"].get("source") or {}).get("ip")
        hosts = sorted({r["host"] for r in related})
        return (f"The same attacker ({ip}) also touched decoys on {', '.join(hosts)}. "
                "Treat those hosts as compromised too.")

    def _propagate_hunt(self, incident: dict, related: list[dict]) -> None:
        """A new incident can change what earlier incidents know about their attacker."""
        for other in related:
            steps = {s["id"]: s for s in other["tasks"] if isinstance(s, dict)}
            if "hunt" not in steps:
                continue
            text = self._hunt_text(other, self.hunt(other, extra=[incident]))
            if steps["hunt"]["detail"] != text:
                steps["hunt"]["detail"] = text
                self.registry.update_incident(other)

    def campaigns(self) -> list[dict]:
        """Attacker addresses seen on two or more hosts: the break-in has spread."""
        by_ip: dict[str, dict] = {}
        for incident in self.registry.recent_threat_incidents(self.clock() - HUNT_WINDOW):
            source = incident["summary"].get("source") or {}
            if not source.get("ip"):
                continue
            entry = by_ip.setdefault(source["ip"], {"ip": source["ip"], "name": source.get("name"), "hosts": set()})
            entry["hosts"].add(incident["host"])
        return [{**c, "hosts": sorted(c["hosts"])} for c in by_ip.values() if len(c["hosts"]) >= 2]

    # -- people finishing the playbook ------------------------------------------------
    def _load(self, incident_id: str, step_id: str) -> tuple[dict, dict] | tuple[None, str]:
        incident = self.registry.get_incident(incident_id)
        if incident is None:
            return None, "incident not found"
        step = next((s for s in incident["tasks"] if isinstance(s, dict) and s["id"] == step_id), None)
        if step is None:
            return None, "no such step on this incident"
        return incident, step

    def complete_step(self, incident_id: str, step_id: str, actor: str, note: str = "") -> dict:
        incident, step = self._load(incident_id, step_id)
        if incident is None:
            return {"ok": False, "error": step}
        if step["mode"] != "manual" or step_id == "release":
            return {"ok": False, "error": "Mirage runs this step itself; it can't be ticked off by hand."}
        if step["status"] in FINISHED:
            return {"ok": True, "incident": incident}
        if step_id == "reimage":
            evidence = next((s for s in incident["tasks"] if s["id"] == "evidence"), None)
            if evidence and evidence["status"] not in FINISHED:
                return {"ok": False, "error": "Capture evidence before reimaging: a rebuild destroys it."}
        self._mark(step, actor, note or "confirmed")
        result = self._save_step(incident, step, actor, "step_done")
        if step_id in HOST_STEPS:
            for other in self.registry.open_incidents_for_host(incident["host"]):
                twin = next((s for s in other["tasks"] if isinstance(s, dict) and s["id"] == step_id), None)
                if other["id"] != incident["id"] and twin and twin["status"] not in FINISHED:
                    self._mark(twin, actor, f"covered by {incident['id']}: {note or 'confirmed'}")
                    self.registry.update_incident(other)
        return result

    def run_step(self, incident_id: str, step_id: str, actor: str) -> dict:
        incident, step = self._load(incident_id, step_id)
        if incident is None:
            return {"ok": False, "error": step}
        if step["mode"] != "action":
            return {"ok": False, "error": "This step isn't something Mirage can run on request."}
        if step["status"] in FINISHED:
            return {"ok": True, "incident": incident}
        if step_id == "evidence":
            result = self._collect_evidence(incident, incident["host"], actor)
            self._mark(step, actor, f"{result['artifacts']} artifacts, sha256 {result['sha256'][:16]}...")
        elif step_id == "replace_decoy":
            if self.replace_decoy is None:
                return {"ok": False, "error": "Decoy replacement isn't available in this setup."}
            result = self.replace_decoy(incident["placement_id"])
            self._mark(step, actor, f"Fresh decoy {result['display']} deployed at the same path. "
                                    "The burned key stays monitored, so any reuse still alerts.")
        else:
            return {"ok": False, "error": "unknown action"}
        return self._save_step(incident, step, actor, "step_run")

    def _save_step(self, incident: dict, step: dict, actor: str, kind: str) -> dict:
        self.registry.add_action(kind, host=incident["host"], incident_id=incident["id"], actor=actor,
                                 detail={"step": step["id"], "detail": step["detail"]})
        incident["updated_at"] = self.clock()
        self.registry.update_incident(incident)
        self.alerter.changed()
        return {"ok": True, "incident": incident}

    # -- recovery ----------------------------------------------------------------------
    def release_blockers(self, host_name: str) -> list[dict]:
        """Required steps still open on this host's HIGH incidents."""
        missing, seen_host_steps = [], set()
        for incident in self.registry.open_incidents_for_host(host_name):
            if incident["bucket"] != "threat" or incident["severity"] != "HIGH":
                continue
            for step in incident["tasks"]:
                if isinstance(step, dict) and step["required"] and step["id"] != "isolate" and step["status"] not in FINISHED:
                    if step["id"] in HOST_STEPS:
                        if step["id"] in seen_host_steps:
                            continue
                        seen_host_steps.add(step["id"])
                    missing.append({"incident": incident["id"], "step": step["id"], "title": step["title"]})
        return missing

    def release(self, host_name: str, actor: str, force: bool = False, reason: str = "") -> dict | None:
        host = self.registry.get_host(host_name)
        if host is None:
            return None
        missing = self.release_blockers(host_name)
        if missing and not force:
            return {"ok": False, "error": f"{len(missing)} required step(s) still open before {host_name} can go back online.",
                    "missing": missing}
        if missing and not reason.strip():
            return {"ok": False, "error": "A forced release needs a written reason; it goes into the audit log.",
                    "missing": missing}
        result = self.edr.release(host_name)
        kind = "forced_release" if missing else "release"
        self.registry.add_action(kind, host=host_name, actor=actor,
                                 detail={**result, "reason": reason, "skipped": [m["step"] for m in missing]})
        for incident in self.registry.open_incidents_for_host(host_name):
            for step in incident["tasks"]:
                if isinstance(step, dict) and step["id"] == "release":
                    self._mark(step, actor, "released with open steps: " + reason if missing else "released")
            incident["status"] = "closed"
            incident["updated_at"] = self.clock()
            self.registry.update_incident(incident)
        self.alerter.changed()
        return {"ok": True, "forced": bool(missing), "host": self.registry.get_host(host_name)}


# -- report ----------------------------------------------------------------------------------

def render_report(incident: dict, placement: dict, host: dict, actions: list[dict]) -> str:
    """A plain Markdown incident report: what happened, what was done, by whom, and when."""
    def when(ts):
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"

    s = incident["summary"]
    source = s.get("source") or {}
    lines = [
        f"# Incident {incident['id']}: {incident['severity']} on {incident['host']}",
        "",
        f"- **Status:** {incident['status']} (action: {incident['action']})",
        f"- **Opened:** {when(incident['opened_at'])} · **Last update:** {when(incident['updated_at'])} · "
        f"**Events:** {incident['event_count']}",
        f"- **Host:** {host['name']} ({ROLE_LABEL.get(host['role'], host['role'])}), owner {host['owner']}",
        f"- **Decoy:** `{placement['rel_path']}` ({placement['label']}), key {s.get('display')}, identity {s.get('identity')}",
        f"- **Source:** {source.get('ip', '-')} ({source.get('zone', '-')}, {source.get('name', '-')})",
        f"- **Attribution:** {incident['attribution']}",
        f"- **Decision:** {s.get('why', '')}",
    ]
    if s.get("evidence"):
        ev = s["evidence"]
        lines.append(f"- **Evidence:** {ev.get('artifacts')} artifacts, sha256 `{ev.get('sha256')}`"
                     + (f", stored at `{ev['path']}`" if ev.get("path") else ""))
    lines += ["", "## Timeline", ""]
    for t in s.get("timeline", []):
        count = f" (x{t['count']})" if t.get("count") else ""
        lines.append(f"- {when(t['ts'])} **{t['stage'].upper()}** {t['text']}{count}")
    if s.get("attempts"):
        lines += ["", "## What the attacker tried", ""]
        lines += [f"- {when(a['ts'])} `{a['what']}` from {a['ip']} ({a['ua']})" for a in s["attempts"]]
    lines += ["", "## Response playbook", "", "| Phase | Step | Status | By | When | Detail |", "|---|---|---|---|---|---|"]
    for step in incident["tasks"]:
        if isinstance(step, dict):
            lines.append(f"| {step['phase']} | {step['title']} | {step['status']} | {step['by'] or '-'} | "
                         f"{when(step['at'])} | {step['detail'] or '-'} |")
    lines += ["", "## Audit log (chain of custody)", ""]
    lines += [f"- {when(a['ts'])} `{a['kind']}` by {a['actor']}" + (f" on {a['host']}" if a.get("host") else "")
              + (f": sha256 `{a['detail']['sha256']}`" if a["detail"].get("sha256") else "")
              for a in actions]
    return "\n".join(lines) + "\n"
