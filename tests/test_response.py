import hashlib
import re
from pathlib import Path

import pytest

from mirage.response import decide


@pytest.mark.parametrize("severity, role, scope, attribution, breaker, status, expected", [
    ("HIGH", "workstation", "host-local", "planted-location", False, "online", "auto_contain"),
    ("HIGH", "workstation", "shared", "planted-location", False, "online", "approval_required"),
    ("HIGH", "workstation", "shared", "confirmed", False, "online", "auto_contain"),
    ("HIGH", "server", "host-local", "confirmed", False, "online", "approval_required"),
    ("HIGH", "crown_jewel", "host-local", "confirmed", False, "online", "approval_required"),
    ("HIGH", "workstation", "host-local", "confirmed", True, "online", "approval_required"),
    ("HIGH", "workstation", "host-local", "planted-location", False, "isolated", "already_contained"),
    ("MEDIUM", "crown_jewel", "host-local", "confirmed", False, "online", "page"),
    ("LOW", "workstation", "host-local", "confirmed", False, "online", "ticket"),
])
def test_decision_table(severity, role, scope, attribution, breaker, status, expected):
    assert decide(severity, role, scope, attribution, breaker, status) == expected


def _use(engine, placement, key):
    return engine.handle({"sensor": "http-decoy", "kind": "token_use", "src_ip": "127.0.0.66", "user_agent": "python-requests/2.32.3",
                          "credential": {"type": "api", "key": key, "action": "GET /v1/x"}})


def _key(placement):
    text = Path(placement["abs_path"]).read_text(encoding="utf-8")
    return re.search(r"acme_live_[A-Za-z0-9]+", text)


def test_circuit_breaker_pauses_auto_containment(engine, registry, deployed, settings):
    workstation_api = [p for p in deployed.values() if p["host"].startswith("laptop") and _key(p)]
    hosts = []
    for placement in workstation_api:
        if placement["host"] in hosts:
            continue
        hosts.append(placement["host"])
        _use(engine, placement, _key(placement).group(0))
    assert len(hosts) >= 3
    actions = {i["host"]: i for i in registry.list_incidents()}
    auto = [h for h in hosts if actions[h]["action"] == "auto_contain"]
    tripped = [h for h in hosts if actions[h]["breaker_tripped"]]
    assert len(auto) == settings.breaker_limit
    assert len(tripped) == 1 and actions[tripped[0]]["action"] == "approval_required"
    assert registry.get_host(tripped[0])["status"] == "online"
    assert engine.responder.breaker_open()

    engine.responder.reset_breaker("test")
    assert not engine.responder.breaker_open()


def _steps(incident):
    return {step["id"]: step for step in incident["tasks"]}


def test_approval_contains_and_runs_the_safe_steps(engine, registry, deployed, settings):
    placement = deployed["db-prod-01:opt/reporting/config/.env.old"]
    _use(engine, placement, _key(placement).group(0))
    incident = registry.list_incidents()[0]
    assert incident["action"] == "approval_required"
    assert registry.get_host("db-prod-01")["status"] == "online", "crown jewels are never isolated automatically"
    steps = _steps(incident)
    assert steps["isolate"]["status"] == "pending" and steps["isolate"]["mode"] == "approval"
    assert steps["block_ip"]["status"] == "done", "blocking the attacker's address is safe to automate"
    assert "127.0.0.66" in registry.get_meta("blocked_ips")
    assert "DATABASE_URL" in steps["rotate_secrets"]["title"]

    engine.responder.approve(incident["id"], "analyst")
    incident = registry.get_incident(incident["id"])
    assert registry.get_host("db-prod-01")["status"] == "isolated"
    evidence = incident["summary"]["evidence"]
    stored = Path(evidence["path"]).read_bytes()
    assert hashlib.sha256(stored).hexdigest() == evidence["sha256"], "chain of custody: the hash matches the package"
    assert _steps(incident)["evidence"]["status"] == "done"


def test_release_is_gated_until_the_playbook_is_done(engine, registry, deployed):
    placement = deployed["db-prod-01:opt/reporting/config/.env.old"]
    _use(engine, placement, _key(placement).group(0))
    incident_id = registry.list_incidents()[0]["id"]
    responder = engine.responder

    early = responder.complete_step(incident_id, "reimage", "analyst")
    assert early["ok"] is False and "evidence" in early["error"], "no rebuild before evidence is captured"

    responder.approve(incident_id, "analyst")
    blocked = responder.release("db-prod-01", "analyst")
    assert blocked["ok"] is False
    assert {m["step"] for m in blocked["missing"]} == {"rotate_secrets", "replace_decoy", "reimage"}
    assert responder.complete_step(incident_id, "block_ip", "analyst")["ok"] is False, "automatic steps can't be faked"
    no_reason = responder.release("db-prod-01", "analyst", force=True)
    assert no_reason["ok"] is False and "reason" in no_reason["error"]

    assert responder.complete_step(incident_id, "rotate_secrets", "analyst", "rotated in Vault")["ok"]
    assert responder.run_step(incident_id, "replace_decoy", "analyst")["ok"]
    assert responder.complete_step(incident_id, "reimage", "analyst")["ok"]
    released = responder.release("db-prod-01", "analyst")
    assert released["ok"] and released["forced"] is False
    assert registry.get_host("db-prod-01")["status"] == "online"
    assert registry.get_incident(incident_id)["status"] == "closed"


def test_forced_release_needs_a_reason_and_is_logged(engine, registry, deployed):
    placement = deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]
    _use(engine, placement, _key(placement).group(0))
    result = engine.responder.release("laptop-hr-05", "analyst", force=True, reason="CEO laptop needed for board meeting")
    assert result["ok"] and result["forced"] is True
    action = registry.latest_action("forced_release", host="laptop-hr-05")
    assert action["detail"]["reason"] == "CEO laptop needed for board meeting"
    assert "reimage" in action["detail"]["skipped"]


def test_replaced_decoy_is_fresh_and_the_burned_key_still_alerts(engine, registry, deployed):
    placement = deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]
    old_key = _key(placement).group(0)
    _use(engine, placement, old_key)
    incident = registry.list_incidents()[0]
    assert engine.responder.run_step(incident["id"], "replace_decoy", "analyst")["ok"]

    new_key = _key(placement).group(0)  # same path, new content
    assert new_key != old_key and old_key not in Path(placement["abs_path"]).read_text(encoding="utf-8")
    fresh = registry.find_placement("laptop-hr-05", placement["rel_path"], placement["template"])
    assert fresh["id"] != placement["id"] and registry.get_placement(placement["id"])["status"] == "burned"

    assert _use(engine, placement, old_key)["known"] is True, "the attacker reusing the burned key is still caught"
    assert _use(engine, placement, new_key)["known"] is True


def test_hunt_links_every_host_the_same_attacker_touched(engine, registry, deployed):
    first = deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]
    second = deployed["db-prod-01:opt/reporting/config/.env.old"]
    _use(engine, first, _key(first).group(0))
    _use(engine, second, _key(second).group(0))
    by_host = {i["host"]: _steps(i)["hunt"]["detail"] for i in registry.list_incidents()}
    assert "db-prod-01" in by_host["laptop-hr-05"], "the earlier incident learns about the later one"
    assert "laptop-hr-05" in by_host["db-prod-01"]
    (campaign,) = engine.responder.campaigns()
    assert campaign["ip"] == "127.0.0.66" and campaign["hosts"] == ["db-prod-01", "laptop-hr-05"]
