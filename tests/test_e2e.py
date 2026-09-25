"""The whole demo, end to end, against real HTTP servers on free ports."""

import httpx

from conftest import ServerThread, load_demo, wait_for
from mirage.control import create_control_app
from mirage.sensor import create_sensor_app

sim = load_demo("attacker_sim")


def incidents_by_host(client):
    grouped = {}
    for incident in client.get("/api/incidents").json():
        grouped.setdefault(incident["host"], []).append(incident)
    return grouped


def test_demo_scenario_end_to_end(settings, registry, deployed):
    pages = []
    control = ServerThread(create_control_app(settings, registry=registry, out=pages.append), settings.control_port).start()
    sensor = ServerThread(create_sensor_app(settings), settings.sensor_port).start()
    client = httpx.Client(base_url=settings.control_url, timeout=5)
    try:
        wait_for(lambda: client.get("/api/health").json()["pipeline_ok"])

        # Scene 2: attacker harvests laptop-dev-07 and the fs-01 share.
        run = sim.run("attacker", settings, pause=0, out=None)
        assert run["findings"] == 5  # 2 decoys + 1 real AWS key + 1 real Stripe key on the laptop, 1 decoy on fs-01
        by_host = incidents_by_host(client)
        dev = sorted(by_host["laptop-dev-07"], key=lambda i: i["opened_at"])
        assert [i["action"] for i in dev] == ["auto_contain", "already_contained"]
        assert all(i["severity"] == "HIGH" and i["stage"] == "used" for i in dev)
        aws_incident = next(i for i in dev if i["summary"]["token_kind"] == "aws")
        assert {a["what"] for a in aws_incident["summary"]["attempts"]} == {"sts:GetCallerIdentity", "s3:ListBuckets"}
        assert any("AWS profile [default] (same file)" in t for t in aws_incident["tasks"])
        assert any("Block 127.0.0.66" in t for t in aws_incident["tasks"])
        (share,) = by_host["fs-01"]
        assert (share["action"], share["status"]) == ("approval_required", "open")
        hosts = {h["name"]: h["status"] for h in client.get("/api/hosts").json()}
        assert hosts["laptop-dev-07"] == "isolated" and hosts["fs-01"] == "online"
        assert registry.stats()["unknown_credentials"] == 2  # the real key hit the emulator twice: not ours, ignored

        # Scene 3: crown jewel needs a person; the approve button needs the CSRF header.
        sim.run("crown-jewel", settings, pause=0, out=None)
        (crown,) = incidents_by_host(client)["db-prod-01"]
        assert crown["action"] == "approval_required"
        assert client.post(f"/api/incidents/{crown['id']}/approve").status_code == 403
        approved = client.post(f"/api/incidents/{crown['id']}/approve", headers={"x-mirage-action": "1"}).json()
        assert approved["action"] == "approved_contained"

        # Scene 4: known scanner is LOW; the same user-agent from elsewhere is HIGH.
        sim.run("scanner", settings, pause=0, out=None)
        benign = [i for i in incidents_by_host(client)["fs-01"] if i["bucket"] == "benign"]
        assert len(benign) == 1 and (benign[0]["severity"], benign[0]["action"]) == ("LOW", "ticket")
        sim.run("spoofed-scanner", settings, pause=0, out=None)
        (spoofed,) = incidents_by_host(client)["laptop-fin-02"]
        assert spoofed["classification"] == "suspicious:spoofed-scanner" and spoofed["action"] == "auto_contain"

        # Scene 5: flood is grouped and trips the circuit breaker.
        sim.run("flood", settings, pause=0, repeat=50, out=None)
        by_host = incidents_by_host(client)
        (hr,) = by_host["laptop-hr-05"]
        assert hr["event_count"] == 50
        assert hr["breaker_tripped"] == 1 and hr["action"] == "approval_required"
        (ops,) = by_host["laptop-ops-03"]
        assert ops["action"] == "approval_required"
        health = client.get("/api/health").json()
        assert health["breaker"]["open"] is True
        assert registry.count_actions("auto_contain", 0) == 2

        # Dashboard is served and the decoy sensor doesn't advertise its framework.
        assert "MIRAGE ENGINE" in client.get("/").text
        probe = httpx.get(settings.sensor_url + "/docs")
        assert probe.status_code == 401 and "server" not in probe.headers and "fastapi" not in probe.text.lower()

        # Scene 6: kill the sensor; the self-test notices.
        sensor.stop()
        wait_for(lambda: not client.get("/api/health").json()["pipeline_ok"], timeout=6)
        assert any("Detection pipeline DOWN" in line for line in pages)
        assert sum("Circuit breaker tripped" in line for line in pages) == 1
    finally:
        client.close()
        sensor.stop()
        control.stop()


def test_sensor_spools_while_control_is_down(settings, registry, deployed):
    sensor = ServerThread(create_sensor_app(settings), settings.sensor_port).start()
    control = None
    try:
        result = sim.run("crown-jewel", settings, pause=0, out=None)
        assert result["results"][0]["status"] == 401  # no answer from control: reply as if the key were invalid
        assert (settings.spool_dir / "http-decoy.jsonl").exists()

        control = ServerThread(create_control_app(settings, registry=registry, out=lambda line: None), settings.control_port).start()
        incident = wait_for(lambda: next(iter(registry.list_incidents()), None), timeout=6)
        assert incident["host"] == "db-prod-01"
        assert incident["summary"]["attempts"][0]["late"] is True
        wait_for(lambda: not (settings.spool_dir / "http-decoy.jsonl").exists(), timeout=3)
    finally:
        sensor.stop()
        if control:
            control.stop()
