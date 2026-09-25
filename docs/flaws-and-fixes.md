# Mirage Engine: flaws in the original pitch and how to fix them

This is a review of the original Mirage Engine pitch ("0% false positives, instant isolation") and the implementation it proposed: generate random fake AWS keys, drop them in folders, and flash the screen red when a listening server receives a ping.

**Verdict:** the core idea is sound and already proven in industry. A credential that nobody was ever given is one of the strongest alerts in security. There are three problems:

1. **The proposed implementation can't detect anything.** Tools send a fake AWS key to AWS, not to your server.
2. **Three pitch claims each fall apart after one judge question:** "0% false positives", "instant", and "isolates the compromised machine".
3. **It isn't new as described.** Canarytokens, GitGuardian Honeytoken and Microsoft Defender for Identity already do this, so the pitch has to say what's different.

Every flaw below has a fix, and the demo in this repository implements the most important ones (see the README).

---

## Part 1 — Fatal: the prototype as described detects nothing

| # | Flaw | Fix |
|---|---|---|
| 1 | **Fake AWS keys never reach your server.** An attacker's tool sends an AWS key to AWS (`sts.amazonaws.com`), not to you. AWS rejects the random key and your listener sees nothing. Fake Stripe/GitHub/OpenAI keys have the same problem: they go to the vendor. | Every decoy needs a **callback path you control** (table below). Drop any decoy type whose use you can't observe. |
| 2 | **Badly formatted fakes get skipped.** The last 6 characters of a GitHub token are a CRC32 checksum. Scanners check it offline and ignore invalid tokens, so a random `ghp_…` string is never even tried. | Generate decoys in the exact real format (prefix, length, checksum). Run TruffleHog or gitleaks against your own decoys. If the scanner doesn't flag a decoy as a credential, an attacker's scanner won't either. |
| 3 | **A "fake user file" can't report that someone read it.** Beacons inside documents don't fire in Protected View, offline viewers, `grep`, or when outbound traffic is blocked. Static scanners such as CanaryTokenScanner find them without triggering them. | Put a **decoy credential inside the document**: the attacker steals it, uses it later, and the alert fires. Also turn on OS read-auditing for decoy files (Windows SACL → Event 4663, Linux auditd, or EDR/Sysmon file events). A beacon is then just a bonus signal. |
| 4 | **Without a registry you can't tell where a key was stolen.** If one key is copied everywhere, the alert can't say where it came from. | Use **one unique token per placement**. Keep a registry that maps each token to its host, path, owner, how critical the asset is, deploy time, and **which real secrets are in the same file**. Never bake tokens into golden VM or container images, because every clone would share the same token. Generate them per instance at boot. |
| 5 | **"The screen flashes red" doesn't alert anyone or stop anything.** Nobody watches the screen at 3 a.m., and nothing gets isolated. | Send alerts to the SIEM, Slack/Teams, PagerDuty or a webhook, with full context. Contain through EDR APIs (Defender for Endpoint "isolate machine", CrowdStrike "network contain", SentinelOne "disconnect from network"). Also act on identity (disable the user, revoke sessions) and cloud (move to a quarantine security group). |
| 6 | **It can fail silently.** If the listener is down, DNS breaks or outbound traffic is blocked, you get zero alerts and think you're safe. | **Self-test:** every few minutes, send a reserved test token through the whole pipeline and raise an alert if it doesn't arrive. Buffer events in a queue or on-disk spool so none are lost during downtime. Run decoy endpoints **inside** the network, on internal DNS names, so an attacker in a locked-down segment can still reach them. |

**Decoys that actually call home:**

| Decoy | How its use is detected |
|---|---|
| Cloud key (AWS / Azure / GCP) | A real key for a **zero-permission identity in a dedicated account**, watched through CloudTrail, Entra ID sign-in logs or GCP audit logs |
| Internal API key **plus its URL** | The bait contains both, e.g. `PAYMENTS_API_URL=https://payments-api.<corp>/`, and that host is a Mirage decoy service |
| Database or SSH connection string | Points to a low-interaction decoy listener that logs the login attempt |
| DNS name | A unique hostname under a domain whose DNS server you run |
| Active Directory account (in scripts, in Group Policy Preferences, or injected into memory) | Domain controller logs: 4625, 4768/4771, 4769 (Kerberoasting), 4776 |

## Part 2 — Pitch claims a judge can break

| # | Claim | Why it breaks | Fix |
|---|---|---|---|
| 7 | **"0% false positives, 100% confirmed breach"** | Many harmless things trigger decoys, and they're documented:<br>• the company's own secret scanners testing keys (Thinkst ships a "TruffleHog Scan" alert label because of this)<br>• Microsoft Safe Links, Proofpoint, and Slack/Teams link previews opening URL tokens<br>• antivirus sandboxes, search indexers, backup and DLP agents reading decoy files<br>• tools that loop over every stored credential profile<br>• **AI coding agents (Claude Code, Cursor, Copilot) that read `.env` files and try the keys after an auth error**<br>• curious staff, pentesters and auditors<br>• decoys placed in default locations that real software loads | Say **"near-zero false positives, and every alert deserves a look"** (GitGuardian also claims "near-zero").<br>Build triage for harmless triggers. It checks for a known scanner **host plus user-agent** (never the user-agent alone), mail-scanner and link-preview IP ranges, sandbox signs, and the red-team calendar. A match lowers severity and blocks automatic response but **never deletes the alert**, because attackers can fake a scanner's user-agent.<br>Never put decoys in default or auto-loaded paths. Run 1–2 weeks in alert-only "burn-in" mode before turning on automatic response. |
| 8 | **"Instant"** | Alerts for AWS keys come from CloudTrail logs and arrive about 2–30 minutes after use. Credentials stolen by infostealer malware are often sold and only tried days later. | Say **"minutes, not weeks"**. Mandiant's M-Trends 2026 puts the median time an attacker goes unnoticed at **14 days**. Add an earlier signal: read-auditing fires when the file is stolen, before the key is used. |
| 9 | **"Instantly isolates the compromised machine"** | The attacker uses the key from their own server, VPN or Tor, so the source IP isn't your machine. The decoy may also have been copied from a file share, a repo cloned on 50 laptops, a backup or a synced folder. The host where it was planted isn't necessarily the breached one. | Find the machine in three steps: **token ID → where it was planted** (registry), then **who read that file** (read-audit or EDR: host, user, process), then **NAT/proxy logs** if the source is your own outbound IP. Contain automatically only when the host is confirmed; otherwise page a person. |
| 10 | **"A normal user can't find them"** | Decoys have to sit where attackers look, and attackers look exactly where admins and developers work: `~/.aws`, `.env`, scripts, shares. | Use non-default names and stale-looking locations. Add an acceptable-use rule: never use credentials you weren't issued. Treat an employee trigger as a **policy violation**, not as "a hacker". |
| 11 | **"If they ignore them, standard security catches them"** | This contradicts your own problem statement, which says standard tools are noisy and miss attackers who use credentials. | Position Mirage as a **high-signal layer that works alongside existing tools**. Make ignoring it statistically hard by covering the **whole attack path** (list below). Example: if an intruder touches 10 credential sources and 20% are decoys, the chance they miss every decoy is 0.8¹⁰ ≈ 11%, so about 89% get caught. |
| 12 | **The solution doesn't match the problem** | Your problem statement says attackers are invisible because they use **real** stolen credentials. Honeytokens only catch the use of **fake** ones. | Connect the two. Almost every intrusion goes through a **credential-harvesting stage** before the attacker has real credentials. Mirage **poisons that harvest** (memory, browsers, files, CI), so the pile of stolen credentials contains traps.<br>Also say plainly what Mirage does **not** cover. An attacker who phishes a real password and goes straight to Microsoft 365 or Okta never touches a decoy. That's the job of identity threat detection, and saying so first stops a judge from using it against you. |
| 13 | **"Attackers are hard-coded to test every key"** | This is true for automated bots: Unit 42's EleKtra-Leak campaign used AWS keys leaked on GitHub within about 5 minutes. But the same group **blocklists AWS accounts that leak keys repeatedly, to avoid honey traps**. Attackers working by hand are more careful. | Make decoys hard to recognize (Part 3) and use many decoy types, not one. |
| 14 | **Novelty** | Canarytokens (free), Thinkst Canary, **GitGuardian Honeytoken** (decoy AWS keys pushed to every developer laptop through MDM, with machine and file attribution, since June 2026), Microsoft Defender for Identity honeytoken accounts, Acalvio, SentinelOne (Attivo), Zscaler Deception. | Name these products in the pitch (judges reward it), then claim a specific combination:<br>• **self-hosted, per-company decoys**, so there's no shared fingerprint<br>• **attribution through read logs**<br>• **automatic response with guardrails** (most tools stop at the alert)<br>• **triage for harmless triggers**<br>• **rotating the real secrets stored next to the decoy**<br>• **a coverage score across the attack path** |
| 15 | **"Intelligent Automation", but it's a fixed script** | Nothing in the build you described is intelligent. | Make the intelligence concrete. Mirage:<br>1. scans the environment<br>2. picks placements based on attacker techniques<br>3. names decoys in the company's own style<br>4. ages and rotates them<br>5. scores each trigger<br>6. picks a response from confidence × how critical the asset is<br>7. reports coverage |

**Decoys across the whole attack path (MITRE ATT&CK IDs):**
- Credentials in files, private keys, shell history, Group Policy Preferences (T1552.001 / .004 / .003 / .006)
- Browser and password-manager stores (T1555.003 / .005)
- A fake credential planted in LSASS memory, a "honey hash" (e.g. via `runas /netonly`). Catches attackers using Mimikatz (T1003.001)
- A honey service account with an SPN. Catches Kerberoasting (T1558.003)
- A honey AD user or group with read-auditing. Catches BloodHound-style enumeration (T1087.002)
- Decoy file shares and documents (T1083 / T1039)
- Decoy cloud keys, buckets and secrets (T1078.004 / T1530)
- CI/CD secret stores. Catches pipeline and supply-chain compromise
- Honey database rows and honey email addresses. Catches stolen data being used

## Part 3 — How attackers spot or avoid decoys

| # | Technique | Fix |
|---|---|---|
| 16 | **Offline AWS fingerprinting.** An AWS key ID encodes the owner's account number. TruffleHog uses this to flag free canarytokens.org keys **without triggering them**. | Use **your own dedicated AWS account(s)**, never a shared public canary service. Ideally put the account inside the company's AWS Organization with a believable name. Rotate it if attackers learn it. |
| 17 | **Silent probing.** `sts:GetAccessKeyInfo` is logged only in the *attacker's* account. Some AWS APIs don't log to CloudTrail at all (Thinkst built a "safety-net" check for this). | Also poll IAM "access key last used" as a backstop, and watch all regions. |
| 18 | **Obvious giveaways:**<br>• an IAM user called `honeytoken`, or `canary` in the ARN<br>• alert domains like `mirage-alerts.io` or a `Server: Mirage` header<br>• the same file with the same timestamp on every host<br>• an AD honey account created yesterday that has never logged on<br>• `passwords.txt` on every desktop | • Derive names from the environment (`svc-acme-backup-legacy`)<br>• Use different random templates per deployment, backdated timestamps and realistic surrounding content<br>• Use company-looking domains and TLS certificates<br>• Make decoy services return normal errors (401/403), never "gotcha"<br>• Give AD honey accounts realistic attributes |
| 19 | **Static document scanners** detect beacons: remote references, known callback domains, Office `WEBSERVICE()` formulas. | Prefer credentials inside documents over beacons (#3). |
| 20 | **Turning your automatic response against you.** An attacker who spots a decoy fires it on purpose, for example the one on the domain controller, so Mirage isolates your own critical server. Or they flood triggers to bury their real activity. | Use the guardrails in Part 5 (#26, #29). |

## Part 4 — Deployment and operations

| # | Flaw | Fix |
|---|---|---|
| 21 | **Breaking real configs.** Writing a decoy into `~/.aws/credentials` can overwrite real keys or become the default profile. Legitimate tools then use it, causing a false positive and a broken developer setup. | Only append a named, non-default profile. Never modify existing entries. Back up first, make writes repeatable without duplicates, and offer a dry-run mode. |
| 22 | **Scale and lifecycle.** There are thousands of endpoints, servers, repos, CI systems and Kubernetes clusters. Re-imaging wipes decoys, retired hosts leave orphans, and users move, sync or copy files (OneDrive, USB), which changes what an alert means. | Deploy through tools the company already uses (Intune, GPO, Jamf, Ansible, MDM). Track each decoy's state: planned → deployed → verified → retired. Re-plant missing decoys automatically, and use integrity checks that record moves. |
| 23 | **The company's own security tools fight you.**<br>• AppSec scanners and GitHub push protection flag decoys in repos.<br>• Auditors see "hard-coded AWS keys".<br>• A decoy in a public repo gets reported to AWS automatically and quarantined.<br>• Cloud posture tools run "unused credential" checks (CIS benchmarks) that can disable or delete decoy keys, which **silently breaks** them. | • Register decoys with internal scanners **on the server side** (allowlist files inside the repo would reveal them).<br>• Agree a documented exception with auditors.<br>• Decide deliberately whether decoys go in public repos.<br>• Tag decoy identities, exempt them from automatic cleanup, and have the drift check confirm every decoy key still exists and is active. |
| 24 | **Honey data pollution.** The company's own marketing system emails honey customer records, which looks like a false positive, and the records skew analytics and billing. | Alert only on mail sent from outside your own sending infrastructure (SPF/DKIM/IPs). Exclude honey rows using a mechanism that isn't visible in the main schema. |
| 25 | **Stale decoys look fake.** | Rotate decoys and refresh timestamps on a schedule. |

## Part 5 — Automated response risks

| # | Flaw | Fix |
|---|---|---|
| 26 | **Automatic isolation can cause an outage.** A harmless or deliberate trigger can isolate a production database or domain controller. | Use the **response matrix** below plus a **circuit breaker**: more than N automatic containments per hour switches to approval-only mode and raises a "possible decoy abuse" alert. |
| 27 | **Isolation can destroy evidence or warn the attacker.** | Use EDR network containment, which keeps the forensics connection open. Capture memory and the process list first. Offer an observe-only mode. |
| 28 | **Isolating the machine doesn't end the breach.** Whoever read `~/.aws/credentials` to get the decoy also got **every real key in that file**. | Every incident automatically creates two tasks: **rotate the real secrets stored next to the decoy**, and revoke the owner's sessions. This is a strong point to say out loud. |
| 29 | **Alert floods bring alert fatigue back**, e.g. a bot retrying a leaked key 500 times. | Group events for the same token within a time window into one incident, and score severity. |
| 30 | **Alerts can reach the attacker** if they control a mailbox or Slack. | Page high-severity alerts through a separate channel (PagerDuty/SMS). |

| Confidence ↓ / Asset → | Workstation | Server | Crown jewel (DC, prod DB) |
|---|---|---|---|
| **High** | Contain automatically + page | Page + one-click approve | Page + one-click approve |
| **Medium** | Page | Page | Page |
| **Low** (known scanner or sandbox) | Ticket | Ticket | Ticket |

## Part 6 — Security of Mirage itself

| # | Flaw | Fix |
|---|---|---|
| 31 | **The registry is a treasure map.** Anyone who reads it can avoid or abuse every decoy. | • Host it outside the production AD trust boundary, with MFA and least privilege<br>• Audit every read of the registry<br>• Keep sensors dumb: they forward raw events and never hold the map<br>• Store key IDs or fingerprints, not plaintext secrets |
| 32 | **A "fake" identity that accidentally has permissions is a backdoor.** | Use a dedicated account, a deny-all service control policy and an explicit-deny policy. Add an automated check (IAM Access Analyzer or the policy simulator) that the decoy identity can do nothing. |
| 33 | **Decoy services are something attackers can attack.** | Low-interaction only: log the attempt and refuse it. Put them on an isolated network segment with no outbound access, and keep the control plane on a separate port and network. |
| 34 | **Forged or guessable tokens.** | Generate tokens with a cryptographic random generator (Python `secrets`). Tag token IDs with an HMAC so garbage is rejected cheaply. Never put host names inside tokens. |
| 35 | **A privileged agent on every endpoint is a supply-chain target.** | Prefer pushing decoys through existing management tools, with no agent. If there is an agent, keep it signed, minimal and least-privilege. |

## Part 7 — Legal and people

| # | Flaw | Fix |
|---|---|---|
| 36 | **Employee-monitoring laws** (GDPR, works councils): decoys plus read-auditing on staff devices can count as monitoring. | Get legal/HR sign-off, add an acceptable-use clause, and keep personal data in alerts to a minimum. |
| 37 | **Insiders who know where the decoys are** can avoid them. | Need-to-know access, separation of duties, and moving decoys periodically. |
| 38 | **Hack-back risk.** | Decoys only observe and report. They never send anything to the attacker's machine. |

## Part 8 — Corrected pitch and judge Q&A

Rewrite these lines:
- "0% false positives" → **"Near-zero false positives, and every alert explains itself."**
- "100% confirmed breach" → **"Confirmed use of a credential nobody was ever given."**
- "Instantly isolates the machine" → **"Within minutes, tells you which machine and file the credential was stolen from, and contains it automatically when that's safe."**

| Judge asks | Answer |
|---|---|
| What if a normal user triggers it? | It's rare, because decoys sit in non-default, stale places that nothing legitimate reads. We don't claim it's impossible. Scanners, link previews and sandboxes are labelled automatically and never trigger automatic isolation. An employee using a credential they were never given is worth knowing about anyway. |
| What if the attacker ignores them? | We don't rely on one decoy; they cover the whole attack path. If 20% of the credential sources an intruder touches are decoys and they touch 10, there's only about an 11% chance they miss every one. |
| How is this different from Canarytokens or GitGuardian? | Those tell you a decoy fired. Mirage finishes the job: it names the exact file and who read it, triages harmless triggers, rotates the real secrets stored next to the decoy, and contains the machine with guardrails. It's self-hosted, so there's no shared fingerprint. TruffleHog can already detect free canarytokens.org AWS keys offline. |
| The attacker uses the key from their own laptop. Which machine do you isolate? | The source IP doesn't matter. Every decoy is unique, so the key itself tells us where it was planted, and read-audit logs tell us which host and user opened that file. |
| Can't attackers spot fake keys? | Random fakes, yes. Ours are real zero-permission keys in our own account, in the correct format, realistically named and aged, and different in every deployment. |
| What if an attacker fires decoys on purpose so you isolate your own servers? | Critical servers are never isolated automatically; a person approves it with one click. A circuit breaker also switches to approval-only if triggers spike. |
| How fast is "instant"? | Seconds for the decoy endpoints we host, 2–30 minutes for cloud keys. Attackers typically go unnoticed for 14 days. |
| Doesn't this only work after they're in? | Yes, by design. It assumes a breach will happen and targets the credential-harvesting stage, before the attacker reaches real credentials and data. |
| How do you deploy to 10,000 machines? | Through tools companies already run (Intune, GPO, Jamf, Ansible). Each machine gets one unique token generated at deploy time and tracked in the registry. |
| What if your server goes down? | A self-test sends a test token through the whole pipeline every few minutes. If it doesn't arrive, that's an alert. |

## Sources

- AWS key ID → account ID, and TruffleHog detecting canary keys offline: [trufflesecurity.com](https://trufflesecurity.com/blog/canaries) · [trufflesecurity.com](https://trufflesecurity.com/blog/research-uncovers-aws-account-numbers-hidden-in-access-keys)
- GetAccessKeyInfo logged only in the caller's account: [hackingthe.cloud](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/)
- Thinkst "safety-net" for AWS APIs that aren't logged: [help.canary.tools](https://help.canary.tools/hc/en-gb/articles/4415516925585-AWS-API-Key-Canarytoken-safety-net-triggered)
- TruffleHog scans triggering canaries: [help.canary.tools](https://help.canary.tools/hc/en-gb/articles/18185364902813-Alert-Annotation-TruffleHog-Scan)
- False-positive sources and the 2–30 minute AWS delay: [hivesecurity.gitlab.io](https://hivesecurity.gitlab.io/blog/canary-tokens-deception-blue-team/)
- EleKtra-Leak (keys used within about 5 minutes; honey accounts blocklisted): [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/)
- M-Trends 2026 (14-day median dwell time): [cloud.google.com](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- GitHub token checksum: [github.blog](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/)
- GitGuardian Honeytoken (fleet-wide through MDM, 2026): [www.helpnetsecurity.com](https://www.helpnetsecurity.com/2026/09/10/product-showcase-gitguardian-honeytoken-decoy-service/)
- Thinkst AWS Infrastructure Canarytoken (AI-matched decoy names): [blog.thinkst.com](https://blog.thinkst.com/2025/09/introducing-the-aws-infrastructure-canarytoken.html)
- Static detection of document canaries: [github.com](https://github.com/0xNslabs/CanaryTokenScanner)
- AI coding agents reading `.env`: [blog.gitguardian.com](https://blog.gitguardian.com/ai-coding-agents-credential-security/)
