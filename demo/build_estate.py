"""Build the simulated company estate: six "hosts" as folders, with ordinary files in them.

Some hosts also get simulated *real* secrets (clearly labelled) so the demo can show
Mirage telling you which real secrets to rotate when a decoy next to them is stolen.
Decoys themselves are added later by `python -m mirage deploy`.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirage.config import PROJECT_ROOT, load_settings  # noqa: E402
from mirage.placer import backdate  # noqa: E402

FILES: dict[str, dict[str, str]] = {
    "laptop-dev-07": {
        # AWS's own documentation example key: realistic shape, known to every scanner as fake.
        "Users/r.iyer/.aws/credentials": (
            "# SIMULATED real credential for the demo (AWS documentation example key)\n"
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        ),
        "Users/r.iyer/.aws/config": "[default]\nregion = eu-west-1\noutput = json\n",
        "Users/r.iyer/.gitconfig": "[user]\n\tname = R. Iyer\n\temail = r.iyer@acme.example\n[pull]\n\trebase = true\n",
        "Users/r.iyer/projects/billing-service/README.md": (
            "# billing-service\n\nInvoices, refunds and payment webhooks.\n\n"
            "Run locally with `docker compose up`, then `npm run dev`.\n"
        ),
        "Users/r.iyer/projects/billing-service/src/app.js": (
            "const express = require('express');\nconst app = express();\n"
            "app.get('/healthz', (_req, res) => res.send('ok'));\n"
            "app.listen(process.env.PORT || 3000);\n"
        ),
        "Users/r.iyer/projects/billing-service/deploy/.env": (
            "# SIMULATED real secrets for the demo\n"
            "STRIPE_SECRET_KEY=sk_test_SIMULATED_demo_value_not_a_real_key\n"
            "DATABASE_URL=postgres://billing:SIMULATED-password@db-prod-01.acme.internal:5432/billing\n"
            "JWT_SIGNING_SECRET=SIMULATED-jwt-signing-secret\n"
        ),
        "Users/r.iyer/projects/billing-service/deploy/docker-compose.yml": (
            "services:\n  billing:\n    build: ..\n    env_file: .env\n    ports:\n      - \"3000:3000\"\n"
        ),
        "Users/r.iyer/Documents/notes.txt": "standup: refunds retry bug, check queue depth alarms\n",
    },
    "laptop-fin-02": {
        "Users/m.okafor/Documents/IT/expense-policy.md": "# Expense policy\n\nSubmit receipts within 30 days.\n",
        "Users/m.okafor/Documents/Q3-close-checklist.md": "# Q3 close\n\n- [ ] Accruals\n- [ ] Intercompany\n- [ ] Revenue recognition review\n",
    },
    "laptop-hr-05": {
        "Users/s.lindqvist/scripts/cleanup_temp.ps1": "Get-ChildItem $env:TEMP -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue\n",
        "Users/s.lindqvist/Documents/benefits-2025.md": "# Benefits 2025\n\nOpen enrolment runs 1-15 November.\n",
    },
    "laptop-ops-03": {
        "Users/d.mensah/.ssh/known_hosts": "fs-01.acme.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISIMULATEDHOSTKEY\n",
        "Users/d.mensah/runbooks/patching.md": "# Patching runbook\n\n1. Drain the node\n2. Patch\n3. Reboot and verify\n",
    },
    "fs-01": {
        "Shares/IT/scripts/legacy/README.txt": "Old scripts kept for reference. Do not schedule anything from this folder.\n",
        "Shares/IT/scripts/map_drives.ps1": 'New-PSDrive -Name F -PSProvider FileSystem -Root "\\\\fs-01\\Finance" -Persist\n',
        "Shares/Finance/README.txt": "Finance shared drive. Month-end exports go in /exports.\n",
    },
    "db-prod-01": {
        "opt/reporting/config/.env": (
            "# SIMULATED real secrets for the demo\n"
            "DATABASE_URL=postgres://reporting:SIMULATED-password@localhost:5432/reporting\n"
            "REPORTING_SIGNING_SECRET=SIMULATED-signing-secret\n"
        ),
        "opt/reporting/config/app.yaml": "server:\n  port: 8081\nreports:\n  schedule: \"0 2 * * *\"\n",
        "opt/reporting/README.md": "# reporting\n\nNightly finance reports. Owned by Data Platform.\n",
    },
}


def build(estate_root: Path, allow_outside_project: bool = False) -> int:
    estate_root = estate_root.resolve()
    if not allow_outside_project and not estate_root.is_relative_to(PROJECT_ROOT):
        raise SystemExit(f"Refusing to build the estate outside the project: {estate_root}")
    if estate_root.exists():
        shutil.rmtree(estate_root)
    count = 0
    for host, files in FILES.items():
        for rel, content in files.items():
            path = estate_root / host / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
            # A lived-in machine has files of every age; otherwise the backdated decoys
            # would be the only old files on the host, which is its own giveaway.
            backdate(path, min_days=20, max_days=700)
            count += 1
    return count


if __name__ == "__main__":
    settings = load_settings()
    written = build(settings.estate_root)
    print(f"Built the demo estate: {len(FILES)} hosts, {written} ordinary files in {settings.estate_root}")
