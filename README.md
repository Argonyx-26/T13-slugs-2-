# Mirage Engine

**Decoy credentials that call home.** Mirage plants a unique decoy credential in each place attackers look for secrets: `~/.aws/credentials`, old `.env` backups, scripts on file shares, IT onboarding docs. Nobody was ever given these credentials, so any use of one is worth investigating. When a decoy fires, Mirage:

- tells you which machine and file it was stolen from
- works out whether the trigger is harmless
- contains the machine when that's safe, and asks a person when it isn't
- lists the real secrets that were stored next to the decoy, because those were stolen too

> Near-zero false positives, and every alert explains itself.
> Confirmed use of a credential nobody was ever given.
> Within minutes, tells you which machine and file the credential was stolen from, and contains it automatically when that's safe.

The review of the original pitch (38 flaws, each with a fix, plus answers to likely judge questions) is in [docs/flaws-and-fixes.md](docs/flaws-and-fixes.md).

## What's different from Canarytokens or GitGuardian Honeytoken

Those products tell you a decoy fired. Mirage finishes the job:

| | Mirage |
|---|---|
| **Attribution** | Every decoy is unique, so a key maps back to one host and one file. With read auditing on, Mirage also shows the process and user that read the file. |
| **Harmless triggers** | A known secret scanner (source IP **and** user-agent match) is logged as LOW and never contained. The same user-agent from anywhere else is HIGH, "possible spoofing". |
| **Guarded response** | Automatic containment only for workstations with solid attribution. Servers and crown jewels wait for one-click approval. A circuit breaker pauses automation if decoys are fired in bulk. |
| **The real damage** | Each incident lists the real secrets stored next to the decoy, for example the `[default]` AWS profile in the same file, and says to rotate them. |
| **Silent-failure detection** | A self-test token goes around the whole pipeline every few seconds. If it stops coming back, that's an alert. |
| **No shared fingerprint** | Self-hosted, with names in the organisation's own style and backdated files. TruffleHog can already recognise free canarytokens.org AWS keys offline. |

## How it works

```
  decoy files on hosts (one unique token each)
        |                                   |
   file read (Event 4663)            stolen key is used
        v                                   v
  readaudit sensor                 decoy sensor :8080
  (Windows, admin)                 internal-API decoy + AWS API emulator
        \                                   /
         \   raw events, HMAC-signed, spooled to disk if control is down
          v                                v
          control plane :7000  -- triage -> response -> alerts, dashboard
          registry (SQLite, HMAC fingerprints only, no decoy values)
          self-test loop: control -> sensor -> control
```

- **Sensors hold no map.** They forward what they see; control decides. A decoy service answers like the real thing: a zero-permission AWS key can call `GetCallerIdentity` but gets `AccessDenied` for everything else. There are no framework banners or `/docs` pages.
- **Decision table** (`mirage/response.py`):

| Confidence ↓ / Asset → | Workstation | Server | Crown jewel |
|---|---|---|---|
| **HIGH** | contain automatically if the decoy was local to the host or the reader is confirmed; otherwise approval | approval | approval |
| **MEDIUM** (file read, not used yet) | page | page | page |
| **LOW** (known scanner) | ticket | ticket | ticket |

  Circuit breaker: after 2 automatic containments inside the window, further containment needs approval, and Mirage raises "possible decoy abuse".

## Run the demo

Requirements: Windows, Python 3.10+, and `pip install -r requirements.txt` (FastAPI, uvicorn, httpx, pytest).

```powershell
cd C:\Users\sbsai\Downloads\mirage
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1
```

The script builds a fresh simulated company (six "hosts"), deploys the decoys, starts both services and opens the dashboard at http://127.0.0.1:7000. Press Enter to move to the next scene. Use `-Auto` for a hands-free rehearsal and `-NoBrowser` to skip opening the page.

**With read auditing** (Administrator PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File demo\run_demo.ps1 -ReadAudit
```

This backs up your audit policy, turns on File System auditing, and adds a read-audit rule to the decoy files only. "Stolen" warnings, with the process and user, then appear *before* the key is used. Clean-up restores the policy. If a run is interrupted, run `demo\disable_read_audit.ps1` as Administrator; `mirage reset` refuses to run until you have.

### Scene by scene

| Scene | What happens | Judge question it answers |
|---|---|---|
| 1. Deploy | Seven unique decoys on six hosts; the registry shows where each lives and what real secrets sit next to it | "How do you know which machine it came from?" |
| 2. Attacker | Harvests laptop-dev-07 and the fs-01 share from an "external VPS". The laptop is contained automatically. The share waits for approval, because the planted host may not be the breached one. A task appears: rotate the `[default]` AWS key in the same file. | "The attacker used their own laptop, so what do you isolate?" |
| 3. Crown jewel | A decoy from db-prod-01 is used. It's never auto-isolated; click **Approve containment**. | "What if a trigger takes down production?" |
| 4. Scanner | The AppSec scanner (known IP **and** user-agent) is LOW, nothing contained. The same user-agent from an unknown host is HIGH, "possible spoofing". | "What if a normal tool triggers it?" / "Can't attackers fake being the scanner?" |
| 5. Flood | 50 uses of one key become one incident; the circuit breaker trips and automation pauses. | "What if attackers fire decoys on purpose to make you isolate your own machines?" |
| 6. Kill the sensor | The header turns to **PIPELINE DOWN** within about 15 seconds. | "What if your server goes down?" |

## Honest limits (say these before a judge does)

- **AWS is emulated.** In the demo, AWS API calls go to a local emulator (like pointing a tool at LocalStack), because real CloudTrail alerts take 2–30 minutes. Production uses real keys for a zero-permission IAM user in a dedicated account (deny-all SCP), detected through CloudTrail and EventBridge.
- **The hosts are simulated.** The six "hosts" are folders on one laptop. Loopback addresses (`127.0.0.66` = "external VPS", `127.0.0.10` = the AppSec scanner) stand in for real networks, and `*.acme.internal` resolves to the local sensor.
- **Containment is a mock EDR.** `MockEDR` in `mirage/response.py` marks hosts as isolated. The same interface is where Defender for Endpoint, CrowdStrike or SentinelOne network containment would plug in.
- **Read auditing hasn't been run live here.** The read-audit sensor's parsing and triage are covered by tests against a sample Event 4663 record. The live path needs an Administrator shell and has not yet been run on this machine.
- **No login on the control plane.** It listens only on localhost, and action buttons need a custom header so other web pages can't click them. Production needs SSO/MFA and a host outside the production AD trust boundary.

## Manual use

```powershell
python demo/build_estate.py                 # simulated company
python -m mirage init                       # keys, registry, self-test token
python -m mirage deploy --dry-run           # preview; writes nothing
python -m mirage deploy                     # one unique decoy per location
python -m mirage serve control              # terminal 1 (dashboard at http://127.0.0.1:7000)
python -m mirage serve sensor               # terminal 2
python demo/attacker_sim.py attacker        # or: crown-jewel, scanner, spoofed-scanner, flood
python -m mirage status                     # hosts, open incidents, breaker
python -m mirage retire                     # remove every decoy, restore appended files
python -m mirage reset --yes                # delete all state and the generated estate
```

Settings are overridable through environment variables: `MIRAGE_CONTROL_PORT`, `MIRAGE_SENSOR_PORT`, `MIRAGE_SELFTEST_INTERVAL`, `MIRAGE_SELFTEST_STALE_AFTER`, `MIRAGE_BREAKER_LIMIT`, `MIRAGE_BREAKER_WINDOW`, `MIRAGE_WEBHOOK_URL` (a Slack-compatible webhook for HIGH alerts), `MIRAGE_DATA_DIR` and `MIRAGE_ESTATE_ROOT`. `run_demo.ps1` shortens the self-test to 5 s / 15 s and widens the breaker window to 30 minutes, so Q&A pauses don't reset it.

## Tests

```powershell
python -m pytest -q
```

39 tests cover:
- token formats, uniqueness and forged-key rejection
- safe placement: existing profiles untouched, a backup made, idempotent re-runs, no writes outside the estate, backdated files, dry-run
- no decoy values stored in the registry
- classification, including spoofed scanners and Event 4663 parsing
- grouping from "stolen" to "used", every cell of the decision table, and the circuit breaker
- two end-to-end runs against real HTTP servers: the full demo, and events spooled while control is down

## Layout

```
mirage/            the engine
  config.py        settings (MIRAGE_* overrides)
  tokens.py        decoy generators (secrets-based, HMAC-tagged API keys)
  placer.py        safe, realistic placement; co-located secret detection
  registry.py      SQLite, fingerprints only
  sensor.py        decoy internal API + AWS emulator
  forwarder.py     signed sensor -> control delivery with disk spool
  readaudit.py     Windows Event 4663 sensor (admin)
  triage.py        classification, attribution, grouping, escalation
  response.py      decision table, circuit breaker, mock EDR, tasks
  alerting.py      pages, webhook, live feed
  control.py       API, dashboard, self-test
  static/dashboard.html
demo/              estate.json, build_estate.py, attacker_sim.py, run_demo.ps1, read-audit scripts
docs/              flaws-and-fixes.md
tests/
```

`data/` and `demo/estate/` are generated and git-ignored. The estate contains AKIA-format decoy keys, and GitHub push protection would rightly block a push that includes them.

## Roadmap

Real EDR connectors, real AWS/Azure/GCP decoy identities with CloudTrail/Entra/Audit Logs, AD honey accounts and honey SPNs (Kerberoasting), LSASS honey hashes, decoy DB and SSH listeners, browser-store decoys, deployment through Intune/GPO/Jamf/Ansible, and decoy rotation.
