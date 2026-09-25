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


def test_approval_contains_and_release_closes(engine, registry, deployed):
    placement = deployed["db-prod-01:opt/reporting/config/.env.old"]
    _use(engine, placement, _key(placement).group(0))
    incident = registry.list_incidents()[0]
    assert incident["action"] == "approval_required"
    assert registry.get_host("db-prod-01")["status"] == "online", "crown jewels are never isolated automatically"
    assert any("Rotate the real secrets" in t and "DATABASE_URL" in t for t in incident["tasks"])

    engine.responder.approve(incident["id"], "analyst")
    assert registry.get_host("db-prod-01")["status"] == "isolated"
    assert registry.get_incident(incident["id"])["action"] == "approved_contained"

    engine.responder.release("db-prod-01", "analyst")
    assert registry.get_host("db-prod-01")["status"] == "online"
    assert registry.get_incident(incident["id"])["status"] == "closed"
