# Shadow API Scanner — Web Application

A web front-end for the [Shadow / Unmanaged API Scanner](https://github.com/kabila5h/API-Scanner).
It **wraps the validated CLI/library** as a backend service and adds a browser UI with
login, level-based scanning, live progress, dual-audience reporting, charts, and PDF/CSV export.

The scanner's core logic is **not reimplemented** — it is vendored (`scanner/`) and installed as a package, so the CLI/library layer stays untouched and
independently testable.

---

## Quick start (Python — Linux / macOS / Windows)

**Requires Python 3.10+.** No Docker needed.

```bash
# 1. Clone (the scanner is vendored in — no submodule flags needed)
git clone https://github.com/kabila5h/API-Scanner-WebApp.git
cd API-Scanner-WebApp

# 2. One command: sets up a local environment on first run, then starts the app
python3 run.py            # on Windows:  python run.py
```

The first run creates a `.venv`, installs the backend, the vendored scanner, and
a Chromium build for Playwright (this can take a few minutes). Later runs start
straight away. When it's ready you'll see:

```
  Shadow API Scanner is starting on  http://127.0.0.1:8000
```

Override the address with `SAS_HOST` / `SAS_PORT` if 8000 is taken
(e.g. `SAS_PORT=8010 python3 run.py`).

### First login (step by step)

There is **no default password** — a random one is generated the first time the
app starts and shown **once** in the logs. The username is always `admin`.

1. **Find the one-time admin password.** When the container starts for the first
   time, this banner is printed to the console:

   ```
   ====================================================================
     FIRST-RUN ADMIN ACCOUNT CREATED
     username: admin
     password: <random-string-shown-once>
     You must change this password at first login. It is shown ONCE.
   ====================================================================
   ```

   It is printed to the **same terminal** where you ran `python3 run.py`.

2. **Open the app:** <http://localhost:8000>

3. **Sign in** with username `admin` and the password from step 1.

4. **Set your own password** — you are immediately required to choose a new one
   (minimum 10 characters). After this, the original random password no longer
   works.

5. You're in. Enter a target URL, pick a scan level (Basic / Standard /
   Advanced), confirm authorization if prompted, and start the scan.

### Forgot the password / want to start over?

The random password is only shown on the **very first** run (before any user
exists). If you lose it, reset the app to a clean state — this **erases all
users, scan history, and reports** and generates a brand-new admin password:

```bash
# stop the app (Ctrl+C), then delete the local data folder, then start again
rm -rf data        # on Windows:  rmdir /s /q data
python3 run.py     # first-run banner appears again
```

Data (users, scan history, reports) otherwise persists in the local `data/`
folder next to the project, so a normal restart keeps your account and history.

---

## What it does

- **Login** — session-based; a random admin password is generated on first run and
  printed once to the console (no hardcoded credentials in the source), with a forced
  change on first login.
- **Users & roles** — two roles:
  - **admin** (e.g. the first-run `admin`) — full access, including a **Profile → Users**
    page to create/delete accounts and assign roles.
  - **user** (e.g. an account named `kishan`) — can run scans and view reports, but
    **cannot** manage users (enforced server-side).
  New accounts get a one-time password (shown once to the admin who created them) and
  must set their own password at first login. Everyone can change their own password on
  the **Profile** page.
- **Level selector**
  - **Basic** — shadow-API discovery only (Phase 1 + 2)
  - **Standard** — discovery + all Phase 3 security validators
  - **Advanced** — full pipeline, most thorough
- **Pre-scan target check** — before a scan runs, the tool loads the target in a headless
  browser and confirms it looks like a Single-Page Application and/or calls APIs (the
  scanner's specialty), so you know it's a good fit. If it isn't, you can still scan anyway.
- **Authorized-host gate** — Standard/Advanced require you to explicitly confirm you are
  authorized to test the exact target. This is enforced **server-side** (mirrors the CLI's
  `--authorized-host`) and cannot be bypassed from the browser.
- **Advanced options (full CLI parity)** — an expandable panel exposes every scanner option
  through guided forms: discovery toggles (skip-browser, discovery-only, concurrency, OpenAPI
  spec), **authentication** (token/cookie/custom headers, or a full login — Mode A API or
  Mode B browser), evidence imports (HAR / traffic log / API inventory), an **active-testing**
  switch, and point-and-click **security-validator** builders (BOLA, broken-auth,
  mass-assignment, safe-injection, access-control). Credentials you type are sent once over
  the authenticated request and swapped server-side for a **per-scan environment variable** —
  they are **never written to disk**; the generated config files reference only the variable
  name.
- **Live progress** — Server-Sent Events stream each phase/finding as it happens.
- **Dual-audience report** — a plain-language **Summary** view (risk level, what it means,
  what to do) and a **Technical** view (full evidence, PoC, validator confidence), on tabs.
- **Charts** — confirmed-vs-potential severity bars, OWASP-category bar, and a risk-score gauge.
- **Reference links** — each finding links to its authoritative **CWE** (weakness type)
  and **OWASP API Top 10** entry.
- **Evidence-based statuses** — findings are labelled *Confirmed* (scanner evidence
  attached), *Potential* (needs validation) or *Unknown*; the scanner's own status and
  confidence are shown unchanged. Checks that did not complete are called out.
- **Local CVE database + component matching** — after each scan, the app identifies
  component versions (runtime globals, server headers, script names) and matches them
  **offline** against a local copy of NVD data, with real version-range comparison.
  Results are *version matches* (not proof of exploitability), *potential* matches (weaker
  evidence) or *unknown* — missing data is never reported as "no vulnerabilities".
- **Remediation** — deterministic actions, verified-only upgrade targets, documented
  workarounds, verification steps and remaining uncertainty for every finding and match.
- **Optional AI analysis** — server-side, off by default; sends a minimised, redacted
  summary and validates every generated statement against the evidence.
- **Scan history** — reopen any past report without rescanning; re-check components on
  demand (with or without contacting the target).
- **Export** — **PDF** (scanner HTML + enrichment), **CSV** (original columns + additive
  columns/record types), and **JSON** (scanner report + `enrichment`).

See **[docs/ENRICHMENT.md](docs/ENRICHMENT.md)** for how statuses, matching, remediation,
AI data handling, exports and their limitations work.

---

## CVE database, AI analysis and tests

```bash
python3 run.py cvedb update --full     # first population from NVD (catalog products)
python3 run.py cvedb update            # later: incremental changes only
python3 run.py cvedb status            # state + per-component coverage
python3 run.py cvedb import FILE.json --complete-for jquery:jquery   # offline import
python3 run.py test                    # automated test suite (no network needed)
```

Administrators can also update the database from **Profile → Vulnerability database**.
Updates are atomic: if one fails, the previous database stays in use.

Optional settings go in a `.env` file (copy `.env.example`). `python3 run.py` loads it
automatically; shell variables take precedence. If you start uvicorn yourself, export the
variables instead. Keys (`SAS_NVD_API_KEY`, `SAS_AI_API_KEY`) stay on the server — they are
never sent to the browser, written to reports, or logged.

To enable AI analysis (Anthropic Claude): set `SAS_AI_ENABLED=true` and `SAS_AI_API_KEY`.
Read the *AI analysis and data handling* section of
[docs/ENRICHMENT.md](docs/ENRICHMENT.md) first — it lists exactly what is sent.

---

## Architecture

```
frontend/            separate pages (login / set-password / app), Chart.js vendored
  login.html  set-password.html  app.html
  static/            styles.css, per-page JS, vendored Chart.js
backend/app/
  main.py            FastAPI app: auth, scan, SSE progress, report + export routes
  auth.py            first-run admin, PBKDF2 password hashing, sessions
  scans.py           scan job manager; forwards scanner logs to an SSE event queue
  scanner_adapter.py maps level -> ScanConfig; enforces the authorized-host gate
  reports.py         summary/technical shaping, CSV, JSON, PDF (via Playwright)
  db.py              SQLite (users, scan history, enrichment status)
  enrichment.py      post-scan enrichment pipeline + persistence + enriched HTML
  findings.py        evidence-based finding statuses
  cve.py             component fingerprinting (live page, headers, script names)
  component_catalog.py, versioning.py, matching.py   identity, versions, offline matching
  cvedb.py, nvd_client.py, cvedb_cli.py            local CVE database + NVD updates
  remediation.py     deterministic remediation guidance
  ai_analysis.py     optional AI explanations with validation
  secrets_guard.py   keeps keys out of logs and errors
backend/tests/       pytest suite (fixtures, mocked NVD and AI)
docs/ENRICHMENT.md   enrichment design, data handling, limitations
scanner/             vendored copy of the validated API-Scanner (installed as a package)
```

- **Backend:** FastAPI (imports the scanner library directly).
- **Real-time:** Server-Sent Events (one-directional, simplest reliable option).
- **PDF:** Playwright print-to-PDF (reuses a dependency the scanner already ships).
- **Auth hashing:** stdlib PBKDF2-HMAC-SHA256 (no external crypto dependency).

---

## Manual setup (alternative to `run.py`)

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
pip install ./scanner
python -m playwright install chromium
SAS_DATA_DIR=./data uvicorn app.main:app --app-dir backend --reload --port 8000
# (uvicorn does not read .env — export SAS_* variables yourself)
PYTHONPATH=backend python -m app.cvedb_cli status     # CVE database CLI
python -m pytest backend/tests                         # tests
```

---

## Security notes

- Credentials are never hardcoded; the admin password is random per install.
- The authorized-host confirmation is required and enforced on the server for any
  active security testing — the tool will not run Phase 3 against a target you have
  not explicitly confirmed you may test.
- Evidence in reports is redacted by the underlying scanner before it reaches this UI.
- API keys are read from the environment only, never returned by any endpoint, and
  scrubbed from logs and error messages. `.env` is git-ignored.
- Exported CSV cells are protected against spreadsheet formula injection; report links
  are restricted to validated http(s) URLs.
