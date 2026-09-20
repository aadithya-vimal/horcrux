# Deploying a Genuine OWASP Juice Shop for Live Acceptance

To perform true live-target acceptance validation for HORCRUX (and avoid the `LIVE ACCEPTANCE BLOCKED` gate), run a genuine OWASP Juice Shop instance using one of the following official methods.

> **CRITICAL RULE**: Synthetic fixtures (such as `tests/fixtures/live_target_server.py`) satisfy unit and integration tests only. They will be rejected by `horcrux.core.acceptance.evaluate_live_acceptance` with `LIVE ACCEPTANCE BLOCKED`.

---

## Option 1: Docker (Recommended)

Ensure Docker Desktop or Docker Engine is running on your host:

```bash
docker pull bkimminich/juice-shop:latest
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

Verify reachability:
```bash
curl -i http://127.0.0.1:3000/
```

---

## Option 2: Node.js / NPM (Local)

Requires Node.js v18+ and Git:

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
npm install
npm start
```

Juice Shop will start on `http://127.0.0.1:3000`.

---

## Running Genuine HORCRUX Live Acceptance

Once a real Juice Shop instance is running:

1. Remove any previous synthetic workspace data for a clean assessment:
   ```bash
   rm -rf workspaces/127.0.0.1
   ```

2. Run the deep scan:
   ```bash
   $env:HORCRUX_LIVE_LOCAL = "1"
   python -m horcrux scan 127.0.0.1:3000 --profile deep
   ```

3. Run the live acceptance gate evaluation:
   ```bash
   python -c "from horcrux.core.storage import Workspace; from horcrux.core.acceptance import evaluate_live_acceptance, print_acceptance_report; ws = Workspace('127.0.0.1'); print_acceptance_report(evaluate_live_acceptance(ws.load()))"
   ```

4. Verify persistence and operator queries:
   ```bash
   python -m horcrux status 127.0.0.1
   python -m horcrux report 127.0.0.1
   python -m horcrux ask --target 127.0.0.1 "What vulnerabilities did you actually confirm?"
   python -m horcrux ask --target 127.0.0.1 "Which confirmed findings have no CVE?"
   ```
