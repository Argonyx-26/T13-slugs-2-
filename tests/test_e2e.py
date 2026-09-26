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
        steps = {step["id"]: step for step in aws_incident["tasks"]}
        assert "AWS profile [default] (same file)" in steps["rotate_secrets"]["title"]
        assert "Block 127.0.0.66" in steps["block_ip"]["title"]
        for automatic in ("isolate", "block_ip", "revoke_sessions", "evidence", "hunt"):
            assert steps[automatic]["status"] == "done", automatic
        assert "sha256" in steps["evidence"]["detail"]
        assert "fs-01" in steps["hunt"]["detail"], "same attacker hit the file share"
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

        # After containment: the laptop can't go back online until the playbook is finished.
        act = {"x-mirage-action": "1"}
        blocked = client.post("/api/hosts/laptop-dev-07/release", headers=act)
        assert blocked.status_code == 409
        assert {m["step"] for m in blocked.json()["missing"]} >= {"rotate_secrets", "replace_decoy", "reimage"}
        for incident in incidents_by_host(client)["laptop-dev-07"]:
            for step in incident["tasks"]:
                if step["status"] != "pending" or not step["required"]:
                    continue
                verb = "run" if step["mode"] == "action" else "done"
                reply = client.post(f"/api/incidents/{incident['id']}/steps/{step['id']}/{verb}", headers=act,
                                    json={"note": "demo"})
                assert reply.status_code == 200, reply.text
        released = client.post("/api/hosts/laptop-dev-07/release", headers=act)
        assert released.status_code == 200 and released.json()["forced"] is False
        report = client.get(f"/api/incidents/{aws_incident['id']}/report").text
        assert "Response playbook" in report and "evidence_collected" in report and "release" in report

        # Dashboard is served and the decoy sensor doesn't advertise its framework.
        assert "MIRAGE ENGINE" in client.get("/classic").text
        for route in ("/", "/dashboard"):  # React UI when built, classic dashboard otherwise
            page = client.get(route)
            assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
            assert page.headers["cache-control"] == "no-store"
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


def test_built_ui_and_its_assets_are_served(settings, registry):
    import re

    from mirage.control import APP

    control = ServerThread(create_control_app(settings, registry=registry, out=lambda line: None), settings.control_port).start()
    try:
        index = httpx.get(settings.control_url + "/dashboard").text
        if not (APP / "index.html").exists():
            assert "MIRAGE ENGINE" in index  # classic fallback when the React UI isn't built
            return
        assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', index)
        assert assets, "the built index.html should reference hashed assets"
        for asset in assets:
            response = httpx.get(settings.control_url + asset)
            assert response.status_code == 200 and len(response.content) > 0, asset
    finally:
        control.stop()
