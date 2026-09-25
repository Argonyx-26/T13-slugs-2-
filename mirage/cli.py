"""Command line: python -m mirage <command>."""

from __future__ import annotations

import argparse
import shutil
import time

from . import pids, tokens
from .config import PROJECT_ROOT, Settings, load_settings
from .keys import create_master, load_keys
from .placer import Placer
from .registry import Registry


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(str(r[i])) for r in [headers, *rows]) for i in range(len(headers))]
    lines = ["  ".join(str(h).ljust(w) for h, w in zip(headers, widths))]
    lines.append("  ".join("-" * w for w in widths))
    lines += ["  ".join(str(c).ljust(w) for c, w in zip(row, widths)) for row in rows]
    return "\n".join(lines)


def initialise(settings: Settings, registry: Registry | None = None) -> dict:
    """Create the master key, register hosts and mint the self-test token. Safe to run twice."""
    if not settings.key_path.exists():
        create_master(settings.key_path)
    keys = load_keys(settings.key_path)
    registry = registry or Registry(settings.db_path)
    manifest = settings.load_manifest()
    registry.set_meta("org", manifest["org"])
    for host in manifest["hosts"]:
        registry.upsert_host(host["name"], host["role"], host["owner"], host.get("team", ""), host.get("os", ""))
    if not settings.selftest_token_path.exists():
        # Same format as a decoy API key, so the self-test exercises exactly the path a real trigger takes.
        value = tokens.api_key(f"{manifest['org']['slug']}_live", keys.tag)
        registry.add_token(tokens.token_id(), "selftest", tokens.fingerprint(value, keys.fingerprint),
                           tokens.mask(value), "selftest")
        settings.selftest_token_path.write_text(value, encoding="ascii")
    return manifest


def cmd_init(settings: Settings, _args) -> int:
    manifest = initialise(settings)
    print(f"Initialised {settings.data_dir} ({len(manifest['hosts'])} hosts from {settings.estate_manifest.name}).")
    return 0


def cmd_deploy(settings: Settings, args) -> int:
    registry = Registry(settings.db_path)
    placer = Placer(settings, registry, load_keys(settings.key_path))
    results = placer.deploy(dry_run=args.dry_run)
    rows = [[r["host"], r["path"], r["kind"], r["status"], r.get("display", ""), r.get("scope", "")] for r in results]
    print(_table(rows, ["HOST", "DECOY FILE", "TYPE", "STATUS", "KEY", "SCOPE"]))
    for r in results:
        if r.get("colocated"):
            print(f"  {r['host']}: real secrets next to this decoy -> {'; '.join(r['colocated'])}")
    if args.dry_run:
        print("\nDry run: nothing was written.")
    return 0


def cmd_serve(settings: Settings, args) -> int:
    import uvicorn

    pids.register(settings, args.role)
    if args.role == "control":
        from .control import create_control_app

        print(f"Mirage control plane on {settings.control_url} (dashboard at {settings.control_url}/)", flush=True)
        uvicorn.run(create_control_app(settings), host=settings.control_host, port=settings.control_port,
                    log_level="warning", server_header=False)
    elif args.role == "sensor":
        from .sensor import create_sensor_app

        print(f"Mirage decoy sensor on {settings.sensor_url}", flush=True)
        uvicorn.run(create_sensor_app(settings), host=settings.sensor_host, port=settings.sensor_port,
                    log_level="warning", server_header=False, access_log=False)
    else:
        from . import readaudit

        return readaudit.run(settings)
    return 0


def cmd_status(settings: Settings, _args) -> int:
    registry = Registry(settings.db_path)
    hosts = registry.list_hosts()
    print(_table([[h["name"], h["role"], h["owner"], h["status"].upper()] for h in hosts], ["HOST", "ROLE", "OWNER", "STATUS"]))
    print()
    incidents = [i for i in registry.list_incidents(200) if i["status"] != "closed"]
    rows = [[time.strftime("%H:%M:%S", time.localtime(i["updated_at"])), i["severity"], i["host"], i["stage"],
             i["action"], i["event_count"], i["label"][:60]] for i in incidents]
    print(_table(rows, ["TIME", "SEV", "HOST", "STAGE", "ACTION", "EVENTS", "WHY"]) if rows else "No open incidents.")
    tripped = registry.get_meta("breaker_tripped_at")
    print(f"\nCircuit breaker: {'OPEN since ' + time.strftime('%H:%M:%S', time.localtime(tripped)) if tripped else 'closed'}")
    return 0


def cmd_retire(settings: Settings, _args) -> int:
    registry = Registry(settings.db_path)
    results = Placer(settings, registry, load_keys(settings.key_path)).retire_all()
    print(f"Retired {len(results)} decoys.")
    return 0


def cmd_reset(settings: Settings, args) -> int:
    if not args.yes:
        print("This deletes the registry, keys and the generated estate. Re-run with --yes to confirm.")
        return 1
    if (settings.data_dir / "auditpol-backup.csv").exists():
        print("Windows read auditing is still on and its policy backup lives in data\\. "
              "Run demo\\disable_read_audit.ps1 (as Administrator) first, then reset.")
        return 1
    for path in (settings.data_dir, settings.estate_root):
        resolved = path.resolve()
        if not resolved.is_relative_to(PROJECT_ROOT) or resolved == PROJECT_ROOT:
            print(f"Refusing to delete {resolved}: it is outside the project folder.")
            return 1
        if resolved.exists():
            try:
                shutil.rmtree(resolved)
            except PermissionError as exc:
                print(f"Could not delete {resolved} ({exc}). Stop any running Mirage processes and try again.")
                return 1
    print("Reset complete.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mirage", description="Mirage Engine: decoy credentials that call home.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create keys, the registry and the self-test token")
    deploy = sub.add_parser("deploy", help="place one unique decoy per location listed in the estate manifest")
    deploy.add_argument("--dry-run", action="store_true", help="show what would be written, write nothing")
    serve = sub.add_parser("serve", help="run a component")
    serve.add_argument("role", choices=["control", "sensor", "readaudit"])
    sub.add_parser("status", help="hosts, open incidents and breaker state")
    sub.add_parser("retire", help="remove every deployed decoy")
    reset = sub.add_parser("reset", help="delete all state and the generated estate")
    reset.add_argument("--yes", action="store_true")
    args = parser.parse_args(argv)

    settings = load_settings()
    handlers = {"init": cmd_init, "deploy": cmd_deploy, "serve": cmd_serve, "status": cmd_status,
                "retire": cmd_retire, "reset": cmd_reset}
    try:
        return handlers[args.command](settings, args)
    except FileNotFoundError as exc:
        print(exc)
        return 1
