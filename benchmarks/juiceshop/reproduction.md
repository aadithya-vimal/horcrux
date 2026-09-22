# Juice Shop benchmark — reproduction playbook

Target: `127.0.0.1:3000` (docker `bkimminich/juice-shop`, v20.x).
All commands run from the repository root. No AI required.

## 1. Baseline run

```bash
python -m pytest -q
horcrux scan 127.0.0.1:3000 --deep
horcrux coverage security 127.0.0.1:3000
horcrux report 127.0.0.1:3000
```

## 2. Score the run

```bash
py benchmarks/juiceshop/check.py workspaces/127.0.0.1_3000/state.json \
    benchmarks/juiceshop/expected.yaml
```

Expected output shape:

```text
ground_truth=12 TP=n FP=n FN=n precision=x recall=y
VULN-001 ... CONFIRMED/MISSED ...
```

## 3. Triage every MISSED item

For each missed `VULN-xxx` with asset `A`:

```python
from horcrux.engine.triage import triage_miss
triage_miss(A, state)  # -> stage + responsible layer
```

Stages: NOT_DISCOVERED, DISCOVERED_BUT_NOT_MODELED,
MODELED_BUT_NOT_APPLICABLE, APPLICABLE_BUT_NOT_SCHEDULED,
SCHEDULED_BUT_BLOCKED, EXECUTED_BUT_BAD_REQUEST,
EXECUTED_BUT_BAD_OBSERVATION, OBSERVATION_BUT_BAD_ORACLE,
ORACLE_BUT_BAD_ADJUDICATION, FINDING_DEDUPE_ERROR, REPORTING_ERROR.

## 4. Manual ground-truth probes (curl)

- SQLi login bypass: POST /rest/user/login
  `{"email": "' OR 1=1--", "password": "x"}` → 200 + admin JWT.
- Mass assignment: POST /api/Users with `"role": "admin"` → 201, role persisted.
- Memories leak: GET /rest/memories → password hashes/roles/tokens anonymous.
- FTP listing: GET /ftp/ → "listing directory" + .bak/.kdbx entries.
- IDOR: register A + B, login both, A GET /api/Users/1 → 200 admin record.
- CORS: OPTIONS + GET with `Origin: https://attacker.example`.
- Headers: GET / → absence of CSP/HSTS/Referrer-Policy/Permissions-Policy.
- Rate limit: 25–30 sequential POST /api/Users → all 2xx, no 429.
- Feedback: POST /api/Feedbacks anonymous → 500 (captcha gate).
- Search XSS: GET /rest/products/search?q=<svg> → `{"data":[]}` (no server reflection).

## 5. Patch loop

For each miss: regression test → production patch → focused tests →
full suite → rescan → re-score until 12/12 or documented disagreement.

## 6. Second target

Repeat steps 1–3 against a materially different stack (VAmPI used for
API-shape validation). No target-specific logic allowed.
