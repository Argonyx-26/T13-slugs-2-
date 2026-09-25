"""Windows read-audit sensor: Event 4663 on decoy files -> "stolen" warnings with process and user.

Needs an elevated shell: turning on auditing (demo/enable_read_audit.ps1) and reading the
Security log both require Administrator rights. Uses the built-in wevtutil, no pywin32.
"""

from __future__ import annotations

import ctypes
import locale
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime

from .config import Settings
from .forwarder import Forwarder
from .keys import load_keys

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
FILE_SYSTEM_SUBCATEGORY = "{0CCE921D-69AE-11D9-BED3-505054503030}"
READ_DATA = 0x1


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8", locale.getpreferredencoding(False)):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", "replace")


def _parse_time(value: str | None) -> float:
    if not value:
        return time.time()
    head, _, frac = value.rstrip("Z").partition(".")
    try:
        stamp = datetime.fromisoformat(head + "+00:00").timestamp()
    except ValueError:
        return time.time()
    return stamp + (float("0." + frac[:6]) if frac else 0.0)


def parse_events(xml_text: str) -> list[dict]:
    """Parse `wevtutil qe ... /f:xml /e:Events` output into plain dicts."""
    xml_text = xml_text.strip()
    if not xml_text:
        return []
    root = ET.fromstring(xml_text)
    events = []
    for node in root.iter(f"{{{NS['e']}}}Event"):
        system = node.find("e:System", NS)
        data = {d.get("Name"): (d.text or "").strip() for d in node.findall("e:EventData/e:Data", NS)}
        time_node = system.find("e:TimeCreated", NS)
        try:
            pid = int(data.get("ProcessId", "0"), 16)
        except ValueError:
            pid = 0
        try:
            mask = int(data.get("AccessMask", "0"), 16)
        except ValueError:
            mask = 0
        domain, user = data.get("SubjectDomainName", ""), data.get("SubjectUserName", "")
        events.append({
            "record_id": int(system.findtext("e:EventRecordID", "0", NS)),
            "event_id": int(system.findtext("e:EventID", "0", NS)),
            "ts": _parse_time(time_node.get("SystemTime") if time_node is not None else None),
            "computer": system.findtext("e:Computer", "", NS),
            "object_name": data.get("ObjectName", ""),
            "process_name": data.get("ProcessName", ""),
            "process_id": pid,
            "user": f"{domain}\\{user}" if domain else user,
            "access_mask": mask,
        })
    return events


def to_file_read_event(event: dict, estate_root: str) -> dict | None:
    """Keep only data reads of files under the estate; shape them for control."""
    if event["event_id"] != 4663 or not event["access_mask"] & READ_DATA:
        return None
    root = os.path.normcase(os.path.abspath(estate_root))
    path = os.path.normcase(event["object_name"])
    if not path.startswith(root + os.sep):
        return None
    return {
        "sensor": "readaudit", "kind": "file_read", "ts": event["ts"], "path": event["object_name"],
        "process_name": event["process_name"], "process_id": event["process_id"], "user": event["user"],
        "computer": event["computer"], "record_id": event["record_id"],
    }


def _wevtutil(args: list[str]) -> str:
    result = subprocess.run(["wevtutil", *args], capture_output=True, timeout=20)
    if result.returncode != 0:
        raise RuntimeError(_decode(result.stderr or result.stdout).strip() or f"wevtutil exited {result.returncode}")
    return _decode(result.stdout)


def latest_record_id() -> int:
    events = parse_events(_wevtutil(["qe", "Security", "/c:1", "/rd:true", "/f:xml", "/e:Events"]))
    return events[0]["record_id"] if events else 0


def query_since(record_id: int) -> list[dict]:
    query = f"*[System[(EventID=4663) and (EventRecordID>{record_id})]]"
    return parse_events(_wevtutil(["qe", "Security", f"/q:{query}", "/f:xml", "/e:Events", "/c:500"]))


def audit_policy_enabled() -> bool | None:
    result = subprocess.run(["auditpol", "/get", f"/subcategory:{FILE_SYSTEM_SUBCATEGORY}", "/r"], capture_output=True, timeout=20)
    if result.returncode != 0:
        return None
    return "success" in _decode(result.stdout).lower()


def run(settings: Settings) -> int:
    if sys.platform != "win32":
        print("The read-audit sensor is Windows-only (it reads Security Event 4663).")
        return 2
    if not is_admin():
        print("The read-audit sensor must run in an elevated (Administrator) PowerShell.")
        return 2
    if audit_policy_enabled() is False:
        print("Warning: File System auditing is off. Run demo\\enable_read_audit.ps1 first.")

    forwarder = Forwarder(settings, load_keys(settings.key_path), "readaudit")
    forwarder.start_flusher()
    last = latest_record_id()
    next_beat = 0.0
    print(f"readaudit: watching Security Event 4663 for files under {settings.estate_root}")
    while True:
        now = time.time()
        if now >= next_beat:
            forwarder.send({"sensor": "readaudit", "kind": "heartbeat", "ts": now})
            next_beat = now + settings.heartbeat_interval
        try:
            events = query_since(last)
        except (RuntimeError, subprocess.TimeoutExpired, ET.ParseError) as exc:
            print(f"readaudit: query failed: {exc}")
            time.sleep(2)
            continue
        for event in events:
            last = max(last, event["record_id"])
            shaped = to_file_read_event(event, str(settings.estate_root))
            if shaped:
                forwarder.send(shaped)
                print(f"readaudit: {shaped['process_name']} (PID {shaped['process_id']}) read {shaped['path']}")
        time.sleep(settings.readaudit_poll_interval)
