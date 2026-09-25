"""Play the analyst after containment: work through a host's response playbook, then release it.

    python demo/respond.py laptop-dev-07

Shows the rigor after "cut the network":
1. release is refused while required steps are open
2. evidence exists before any rebuild (with its SHA-256)
3. manual steps are confirmed by a person, actions are run by Mirage
4. only then does the host go back online, and a report is produced
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirage.config import Settings, load_settings  # noqa: E402

ACT = {"x-mirage-action": "1"}
NOTES = {
    "rotate_secrets": "rotated in the secrets manager; old values revoked",
    "reimage": "rebuilt from the golden image; EDR re-enrolled",
    "investigate_source": "source host checked and contained",
}


def run(host: str, settings: Settings | None = None, actor: str = "analyst (demo)", out=print) -> dict:
    settings = settings or load_settings()
    say = out or (lambda *_: None)
    with httpx.Client(base_url=settings.control_url, timeout=10) as client:
        say(f"[respond] trying to release {host} straight away...")
        first = client.post(f"/api/hosts/{host}/release", headers=ACT, json={"actor": actor})
        if first.status_code == 200:
            say("  released (no open steps)")
            return {"blocked": [], "done": [], "released": True}
        blocked = first.json().get("missing", [])
        say(f"  refused: {first.json().get('error')}")
        for m in blocked:
            say(f"    - {m['title']}")

        done = []
        incidents = [i for i in client.get("/api/incidents").json() if i["host"] == host and i["status"] != "closed"]
        for incident in incidents:
            say(f"[respond] working through {incident['id']}")
            for step in incident["tasks"]:
                if step["status"] != "pending" or not step["required"] or step["mode"] not in ("manual", "action"):
                    continue
                verb = "run" if step["mode"] == "action" else "done"
                reply = client.post(f"/api/incidents/{incident['id']}/steps/{step['id']}/{verb}", headers=ACT,
                                    json={"actor": actor, "note": NOTES.get(step["id"], "done")})
                ok = reply.status_code == 200
                detail = next((s["detail"] for s in reply.json().get("incident", {}).get("tasks", []) if s["id"] == step["id"]), "")
                say(f"  {'done' if ok else 'FAILED'}  {step['title']}" + (f"\n        {detail}" if ok and detail else ""))
                if ok:
                    done.append(step["id"])

        final = client.post(f"/api/hosts/{host}/release", headers=ACT, json={"actor": actor})
        released = final.status_code == 200
        say(f"[respond] release {host}: {'OK, back online' if released else final.json().get('error')}")
        for incident in incidents:
            say(f"  report: {settings.control_url}/api/incidents/{incident['id']}/report")
        return {"blocked": blocked, "done": done, "released": released}


def main() -> int:
    parser = argparse.ArgumentParser(description="Finish a host's response playbook, then release it.")
    parser.add_argument("host")
    args = parser.parse_args()
    return 0 if run(args.host)["released"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
