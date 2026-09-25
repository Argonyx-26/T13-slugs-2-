import re
from pathlib import Path

from mirage import readaudit
from mirage.triage import classify_read, classify_use

SAMPLE_4663 = """<Events>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4663</EventID><Version>1</Version><Level>0</Level><Task>12800</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-26T10:01:02.1234567Z'/><EventRecordID>48213</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='8120'/><Channel>Security</Channel><Computer>DESKTOP-DEMO</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1111111111-2222222222-3333333333-1001</Data><Data Name='SubjectUserName'>demo-user</Data><Data Name='SubjectDomainName'>DESKTOP-DEMO</Data><Data Name='SubjectLogonId'>0x2c5a1</Data><Data Name='ObjectServer'>Security</Data><Data Name='ObjectType'>File</Data><Data Name='ObjectName'>__PATH__</Data><Data Name='HandleId'>0x5f4</Data><Data Name='AccessList'>%%4416
				</Data><Data Name='AccessMask'>__MASK__</Data><Data Name='ProcessId'>0x10d8</Data><Data Name='ProcessName'>C:\\Tools\\python.exe</Data><Data Name='ResourceAttributes'>S:AI</Data></EventData></Event>
</Events>"""


def sample_4663(path, mask):
    return SAMPLE_4663.replace("__PATH__", path).replace("__MASK__", mask)


def use_event(key, ip="127.0.0.66", ua="python-requests/2.32.3", aws=False):
    cred = {"type": "aws", "key_id": key, "service": "sts", "action": "sts:GetCallerIdentity"} if aws else {"type": "api", "key": key, "action": "GET /v1/accounts"}
    return {"sensor": "http-decoy", "kind": "token_use", "src_ip": ip, "user_agent": ua, "method": "GET", "path": "/v1/accounts", "credential": cred}


def read_event(path, process="C:\\Tools\\python.exe", pid=999):
    return {"sensor": "readaudit", "kind": "file_read", "path": path, "process_name": process, "process_id": pid, "user": "DESKTOP\\demo-user"}


def api_key_in(path):
    return re.search(r"acme_live_[A-Za-z0-9]+", Path(path).read_text(encoding="utf-8")).group(0)


# -- classification ----------------------------------------------------------------------

def test_known_scanner_needs_both_ip_and_user_agent(settings):
    assert classify_use(settings, "127.0.0.10", "TruffleHog").severity == "LOW"
    spoofed = classify_use(settings, "127.0.0.20", "TruffleHog")
    assert (spoofed.severity, spoofed.classification) == ("HIGH", "suspicious:spoofed-scanner")
    assert classify_use(settings, "127.0.0.10", "curl/8.0").severity == "HIGH"
    assert classify_use(settings, "127.0.0.66", "aws-cli/2").source["zone"] == "external"


def test_read_classification(settings):
    assert classify_read(settings, "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", 10, set()).bucket == "benign"
    assert classify_read(settings, "C:\\Tools\\python.exe", 10, {10}) is None
    assert classify_read(settings, "C:\\Tools\\python.exe", 11, {10}).severity == "MEDIUM"


# -- Windows 4663 parsing --------------------------------------------------------------------

def test_parse_4663_and_filter_to_decoy_reads(tmp_path):
    root = tmp_path / "estate"
    inside = str(root / "host" / "secret.ps1")
    events = readaudit.parse_events(sample_4663(inside, "0x1"))
    assert len(events) == 1
    event = events[0]
    assert (event["record_id"], event["process_id"], event["user"]) == (48213, 0x10D8, "DESKTOP-DEMO\\demo-user")
    shaped = readaudit.to_file_read_event(event, str(root))
    assert shaped["kind"] == "file_read" and shaped["path"] == inside
    outside = readaudit.parse_events(sample_4663(str(tmp_path / "elsewhere.txt"), "0x1"))[0]
    assert readaudit.to_file_read_event(outside, str(root)) is None
    write_only = readaudit.parse_events(sample_4663(inside, "0x2"))[0]
    assert readaudit.to_file_read_event(write_only, str(root)) is None
    assert readaudit.parse_events("") == []


# -- engine: grouping, attribution, escalation -----------------------------------------------

def test_read_then_use_escalates_one_incident(engine, registry, deployed):
    placement = deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]
    engine.handle(read_event(placement["abs_path"]))
    stolen = registry.list_incidents()[0]
    assert (stolen["stage"], stolen["severity"], stolen["action"]) == ("stolen", "MEDIUM", "page")
    assert stolen["attribution"] == "confirmed"
    assert registry.get_host("laptop-hr-05")["status"] == "online"

    reply = engine.handle(use_event(api_key_in(placement["abs_path"])))
    assert reply["known"] is True
    incidents = registry.list_incidents()
    assert len(incidents) == 1, "the use joins the 'stolen' incident instead of opening a new one"
    used = incidents[0]
    assert (used["stage"], used["severity"], used["action"], used["status"]) == ("used", "HIGH", "auto_contain", "contained")
    assert used["summary"]["reader"]["process"].endswith("python.exe")
    assert registry.get_host("laptop-hr-05")["status"] == "isolated"


def test_harmless_reads_and_own_reads_open_nothing(engine, registry, deployed):
    path = deployed["laptop-fin-02:Users/m.okafor/Documents/IT/vpn-and-api-access.md"]["abs_path"]
    engine.handle(read_event(path, process="C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe"))
    engine.handle(read_event(path, pid=4242))  # Mirage itself
    engine.handle(read_event(str(Path(path).parent / "expense-policy.md")))  # not a decoy
    assert registry.list_incidents() == []
    assert registry.stats()["benign_reads"] == 1


def test_unknown_and_forged_credentials_are_dropped(engine, registry, deployed):
    assert engine.handle(use_event("acme_live_" + "A" * 34))["known"] is False
    assert engine.handle(use_event("AKIAIOSFODNN7EXAMPLE", aws=True))["known"] is False
    assert registry.list_incidents() == []
    assert registry.stats()["unknown_credentials"] == 2


def test_benign_scanner_never_merges_into_a_threat_incident(engine, registry, deployed):
    placement = deployed["laptop-hr-05:Users/s.lindqvist/scripts/sync_reports.ps1"]
    key = api_key_in(placement["abs_path"])
    engine.handle(use_event(key, ip="127.0.0.10", ua="TruffleHog"))
    engine.handle(use_event(key))
    by_bucket = {i["bucket"]: i for i in registry.list_incidents()}
    assert by_bucket["benign"]["severity"] == "LOW" and by_bucket["benign"]["action"] == "ticket"
    assert by_bucket["threat"]["severity"] == "HIGH"


def test_aws_reply_carries_a_realistic_identity(engine, deployed):
    placement = deployed["laptop-ops-03:Users/d.mensah/.aws/credentials"]
    key_id = re.search(r"AKIA[A-Z2-7]{16}", Path(placement["abs_path"]).read_text()).group(0)
    reply = engine.handle(use_event(key_id, aws=True))
    assert re.fullmatch(r"arn:aws:iam::\d{12}:user/svc-acme-[a-z0-9-]+", reply["identity"]["arn"])
    assert "canary" not in reply["identity"]["arn"] and "honey" not in reply["identity"]["arn"]
