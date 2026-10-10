# Shadow / Unmanaged API Scanner

**Specialist Shadow / Unmanaged API Detection and Security Testing for SPAs**

In this project, **Shadow API** and **Unmanaged API** are exact synonyms. They
mean an API endpoint that is active in production but invisible to IT security,
lacks central management such as an API gateway, has no official documentation,
and lacks active security monitoring. The shared risks are missing
authentication, data leakage, and zero security visibility.

The scanner combines static JavaScript analysis, runtime traffic, imported
traffic evidence, and authoritative API baselines. An undocumented JavaScript
reference remains unverified until live evidence confirms that the operation is
active. External discovery can establish live operation and absence from the
supplied baseline, while gateway ownership and internal monitoring status must
be validated with organizational evidence.

---

## Quick Start

Requires Python 3.10 or newer. TLS certificates are verified by default.

### Interactive mode (TUI)

New users can drive every option from an interactive Terminal UI instead of
memorising flags. It exposes the target, scan mode, baseline/evidence,
authentication, Phase 3 security testing, browser, performance, and output
settings, then runs the scan.

The default TUI is a **mouse-driven, cyber-themed** full-screen console
(built on Textual): click the collapsible sections, dropdowns, switches, and
the **RUN SCAN** button — no flags to remember. Keyboard also works
(`Tab`/arrows, `Ctrl+R` to run, `Ctrl+Q` to quit). If Textual is not
installed, it automatically falls back to a Rich menu-driven prompt UI, so
the interface always works.

```bash
# Launch the interactive Terminal UI
./run.sh run --tui

# ...or just run with no target URL
python -m shadow_api_scanner
```

### Linux

```bash
# Setup (installs deps + Playwright)
./run.sh setup

# Interactive Terminal UI (all options, menu-driven)
./run.sh run --tui

# Or scan a target directly
./run.sh run http://127.0.0.1:8888 --discovery-only

# Portable package entry point
python -m shadow_api_scanner http://127.0.0.1:8888 --discovery-only
```

### Windows

```cmd
REM Setup
run.bat setup

REM Scan an authorized local lab
run.bat run http://127.0.0.1:8888 --discovery-only

REM Portable package entry point
py -3 -m shadow_api_scanner http://127.0.0.1:8888 --discovery-only
```

Both wrappers keep paths quoted, invoke modules through the virtual
environment's Python executable, and install Playwright Chromium without
assuming a browser installation path. Core scanner code uses `pathlib` and
explicit UTF-8 encodings for user-supplied specifications and generated
reports. The current automated suite and Playwright execution are tested on
Linux. Windows path, encoding, entry-point, and wrapper behavior are covered by
platform-independent tests and code review; this checkpoint has not been
executed on a Windows host.

### Reproduce The Research Baseline

Install the exact dependency versions used by the frozen checkpoint:

```bash
./run.sh setup-locked
```

Run the complete test suite and all pinned benchmark cases:

```bash
./run.sh validate
```

The validation gate requires at least the 131 tests present at the v3 freeze;
new regression tests may increase that count without invalidating the gate.

The command writes an ignored local record to
`reports/research-baseline/validation.json`. The version-controlled checkpoint
is `benchmarks/baselines/research-baseline-v3.json`; it records the environment,
metric checks, Git base commit, per-file hashes, and a deterministic SHA-256
snapshot digest. The v1 and v2 checkpoints remain available under their
original tags. See `benchmarks/baselines/README.md` for the freeze workflow.

---

## Features

### Phase 1: Static JavaScript Analysis
- Crawls and downloads all frontend JS files (external + inline + webpack chunks)
- Extracts API endpoints via regex patterns (fetch, axios, XHR, WebSocket, GraphQL)
- Detects hardcoded API keys, tokens, and secrets
- Discovers base URLs, route patterns, and request configurations
- Resolves JavaScript template URLs using real query and form values
- Groups repeated concrete URLs into logical routes with observed examples

### Phase 2: Dynamic Traffic Monitoring
- Launches headless Chromium via Playwright
- Captures live XHR, Fetch, WebSocket, EventSource, and API form traffic
- Records method, sanitized request metadata, query/body parameters, response
  status/content type, originating page, redirect source, and UTC timestamp
- Crawls bounded same-origin pages and performs conservative interactions
- Reuses Playwright storage state and propagates captured cookies to API tests
- Compares against OpenAPI/Swagger specs (auto-discovered or user-provided)
- Extracts inline or URL-referenced OpenAPI documents from Swagger UI bootstrap
  scripts without executing the JavaScript
- Compares against approved API inventory exports when OpenAPI is unavailable
- Imports gateway/proxy/access logs to discover runtime-only APIs
- Preserves raw observations while reporting one inventory record per route
- Reports one combined **Shadow / Unmanaged API** security category
- Keeps endpoints without sufficient live evidence as Unknown API rather than
  claiming that they are active
- Bounds retained JSON response bodies and redacts authorization headers,
  cookies, API keys, session/CSRF tokens, passwords, and nested secret fields
  before runtime evidence reaches JSON reports

### Phase 3: Controlled Security Validation

The registry-driven validation layer currently covers:

1. **BOLA / IDOR** with two researcher-controlled identities and semantic
   ownership proof.
2. **Broken authentication** with controlled valid, anonymous, malformed,
   invalid, and expired credential states.
3. **Excessive data exposure** through bounded nested-JSON field analysis.
4. **Parameter manipulation / mass assignment** through passive inventory and
   optional verified synthetic-record mutation with cleanup.
5. **Rate-limit policy signals** using a read-only request and concurrency cap.
6. **Safe injection indicators** using fixed GET-only baseline, control, and
   non-destructive probes.
7. **Role, function, endpoint, cross-user, and stale-session boundaries** using
   environment-backed controlled identities.

All results use the same vulnerable/protected/inconclusive/skipped/error
schema. The scanner does not guess administrative paths, replay an observed
write operation, brute-force identifiers, or turn a lone HTTP 200/500 into a
confirmed vulnerability. OWASP API categories not listed above require manual
testing or a future controlled validator.

Inventory remains operation-specific: `GET /api/products/{productId}/price`
and `PATCH /api/products/{productId}/price` are separate records. An operation
seen only in `OPTIONS Allow` remains an unverified candidate until runtime or
configured validation provides live evidence.

### Phase 4: Risk Scoring & Reporting
- Per-vulnerability risk scores (0-10) based on OWASP severity + exploit evidence
- Overall scan risk level (Critical/High/Medium/Low/Info)
- Reports documented, Shadow / Unmanaged, and unknown inventory in **JSON**
  and **HTML**
- Proof-of-concept request/response pairs
- Redacts cookies, authorization headers, and sensitive request fields
- Remediation guidance per finding

---

## CLI Options

```
Usage: shadow-scan [OPTIONS] TARGET_URL

Options:
  -o, --output TEXT       Output directory for reports [default: reports]
  --openapi-spec TEXT     Path or URL to OpenAPI spec file
  --auth-token TEXT       Authorization value; prefer SHADOW_API_AUTH_TOKEN
  --auth-header TEXT      Auth header name [default: Authorization]
  --cookie TEXT           Cookie value; prefer SHADOW_API_COOKIE
  --har TEXT              Import observed traffic from HAR file
  --traffic-log TEXT      Import gateway/proxy/access log traffic
  --api-inventory TEXT    Approved API inventory JSON/YAML/CSV baseline
  --save-baseline TEXT    Save endpoint inventory baseline JSON
  --compare-baseline TEXT Compare endpoint inventory with baseline JSON
  --no-auto-evidence      Disable automatic local evidence discovery
  --no-history            Disable automatic per-target inventory history
  --no-browser            Skip Phase 2 dynamic monitoring
  --discovery-concurrency INTEGER
                          Static/specification concurrency cap [default: 10]
  --discovery-only        Skip all Phase 3 security tests
  --active-testing        Allow state-changing exploit validation
  --authorized-host TEXT  Exact host authorized for security validation;
                          repeatable
  --bola-config FILE      Controlled two-identity BOLA configuration JSON/YAML
  --auth-validation-config FILE
                          Controlled broken-auth configuration JSON/YAML
  --parameter-validation-config FILE
                          Controlled parameter-mutation configuration JSON/YAML
  --injection-validation-config FILE
                          Controlled safe-injection configuration JSON/YAML
  --access-validation-config FILE
                          Controlled session/access configuration JSON/YAML
  --sensitive-field-pattern TEXT
                          Additional sensitive JSON field/path regex;
                          repeatable
  --rate-limit-requests INTEGER
                          Hard request ceiling per bounded rate assessment
                          [default: 5; range: 2-10]
  --rate-limit-delay FLOAT
                          Delay between probe batches [default: 0.25]
  --rate-limit-concurrency INTEGER
                          Probe concurrency cap [default: 1; range: 1-3]
  --rate-limit-timeout FLOAT
                          Per-request probe timeout [default: 5 seconds]
  --request-timeout FLOAT Timeout for non-browser HTTP requests [default: 15]
  --request-delay FLOAT   Delay between ordinary security requests [default: 0.5]
  --max-security-requests INTEGER
                          Global Phase 3 network-attempt budget [default: 250]
  --max-security-response-bytes INTEGER
                          Per-response Phase 3 retention cap [default: 1048576]
  --max-redirects INTEGER Maximum redirects [default: 5]
  --insecure              Disable TLS verification for authorized labs
  --headed                Show browser window (not headless)
  --timeout INTEGER       Browser timeout in seconds [default: 60]
  --interaction-wait INTEGER  Manual headed-browser interaction window
  --storage-state FILE    Playwright authentication state JSON
  --max-response-bytes INTEGER
                          Maximum JSON response bytes retained per runtime API
                          [default: 65536]
  --ground-truth FILE     Labeled endpoint benchmark JSON
  --format TEXT           Report formats: json,html [default: json,html]
  --version               Show the version and exit
  -v, --verbose           Verbose output
  --help                  Show this message and exit
```

### Testing Modes

Discovery can enumerate advertised methods with `OPTIONS`, but the validator
pipeline never invokes an unconfigured write method. `--active-testing` has no
effect by itself: it only unlocks a case that also opts into state change in a
controlled parameter, BOLA, or authentication configuration. Use it only
against an explicitly authorized disposable target. Security tests use one
concrete representative per logical route, so repeated IDs are not probed
repeatedly. Advertised methods become separate candidates; only methods
actually observed or explicitly validated receive `tested` or `responsive`
evidence and become API operations.
Methods seen only in `OPTIONS Allow` metadata are retained separately as
unverified method candidates. They do not count as active API operations,
baseline drift, or benchmark discoveries until traffic or method-level
validation confirms them.
If controlled validation receives `401` or `403`, the result is normally
protected or inconclusive rather than vulnerable.

Use `--discovery-only` when you only want API inventory, documentation
classification, baseline comparison, and reports:

```bash
./run.sh run http://127.0.0.1:8888 --discovery-only
```

### Global Validation Safety

Static JavaScript downloads and specification discovery are capped at ten
concurrent requests by default. Phase 3 fails closed unless every request and
redirect remains on an exact `--authorized-host`. The shared HTTP client
enforces a 250-attempt global
budget, a 15-second timeout, a 0.5-second ordinary-request delay, a five-redirect
limit, and a 1 MiB retained-response cap by default. Concurrent requests share
the same atomic budget. `POST`, `PUT`, `PATCH`, and `DELETE` are never retried
automatically. Adjust the bounded defaults with the corresponding CLI options.

TLS verification is enabled by default across static discovery, OpenAPI
discovery, browser capture, and validation. `--insecure` is only for an
authorized lab with a self-signed certificate. Prefer environment variables so
credentials do not appear in shell history or process listings:

```bash
export SHADOW_API_AUTH_TOKEN="Bearer <temporary-lab-token>"
export SHADOW_API_COOKIE="session=<temporary-lab-session>"
./run.sh run http://127.0.0.1:8888 --authorized-host 127.0.0.1
```

### Controlled Two-User BOLA / IDOR Validation

BOLA validation is disabled unless `--bola-config` is supplied. It does not
guess object identifiers or obtain credentials. The researcher must declare an
existing synthetic User A resource, explicitly allow-list the lab host, and
provide two distinct controlled identities through environment variables.

Example `bola-config.json` for a localhost lab:

```json
{
  "authorized_hosts": ["127.0.0.1"],
  "identities": {
    "user_a": {
      "header_env": {
        "Authorization": "LAB_USER_A_AUTHORIZATION"
      }
    },
    "user_b": {
      "header_env": {
        "Authorization": "LAB_USER_B_AUTHORIZATION"
      }
    }
  },
  "cases": [
    {
      "name": "user-a-order",
      "method": "GET",
      "url": "/api/orders/1001",
      "object_location": "path",
      "object_name": "orderId",
      "object_value": "1001",
      "evidence_paths": ["id", "ownerId"]
    }
  ]
}
```

Supply the complete controlled header values without writing them to the
configuration file:

```bash
export LAB_USER_A_AUTHORIZATION="Bearer <temporary-user-a-token>"
export LAB_USER_B_AUTHORIZATION="Bearer <temporary-user-b-token>"
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --bola-config bola-config.json
```

Only `GET` and `HEAD` cases run by default. A state-changing case requires both
`"allow_state_change": true` in that individual case and the global
`--active-testing` option. Missing environment variables, ambiguous scope,
wildcard hosts, identical credentials, or out-of-scope case URLs stop BOLA
validation without sending requests.

Results use `vulnerable`, `protected`, `inconclusive`, `skipped`, or `error`.
A successful User B status alone is inconclusive; a confirmed finding requires
response semantics tying User B's response to the researcher-declared User A
resource. Authentication material is redacted, and the dedicated object-value
evidence uses a one-way SHA-256 representation.

### Controlled Broken-Authentication Validation

Active security validators fail closed unless the target hostname is supplied
through `--authorized-host`. Without that option, discovery, documentation
comparison, inventory, and reporting continue, but Phase 3 security requests
are skipped. Hosts must be exact names or IP addresses; wildcard, URL, path,
and host-with-port values are rejected.

Broken-authentication validation also requires a configuration file whose
credential fields name environment variables. It never performs password
guessing, credential stuffing/spraying, MFA bypass, or token discovery.

Example `auth-validation-config.json`:

```json
{
  "header_name": "Authorization",
  "valid_env": "LAB_VALID_AUTHORIZATION",
  "invalid_env": "LAB_INVALID_AUTHORIZATION",
  "expired_env": "LAB_EXPIRED_AUTHORIZATION",
  "cases": [
    {
      "name": "protected-profile",
      "method": "GET",
      "url": "/api/profile",
      "evidence_paths": ["profile.id", "profile.email"]
    }
  ]
}
```

Run against an explicitly approved localhost lab:

```bash
export LAB_VALID_AUTHORIZATION="Bearer <temporary-valid-token>"
export LAB_INVALID_AUTHORIZATION="Bearer <controlled-invalid-token>"
export LAB_EXPIRED_AUTHORIZATION="Bearer <controlled-expired-token>"
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --auth-validation-config auth-validation-config.json
```

The validator compares the valid baseline with an anonymous request, a fixed
malformed scheme, and optional researcher-supplied invalid and expired test
credentials. A `200` response alone is inconclusive. Confirmation requires all
declared protected JSON evidence paths to match the authenticated baseline with
sufficient response similarity. Authentication failures are reported
separately from BOLA/authorization failures. State-changing cases require the
same per-case plus global double opt-in used by BOLA.

### Excessive / Unnecessary Data Exposure

For explicitly authorized hosts, the scanner analyzes successful JSON
responses recursively, including objects nested inside arrays. High-signal
categories include password material, reset/access/refresh tokens, application
secrets, personal identifiers, financial fields, and internal infrastructure
metadata. Lower-context profile and role/permission fields require correlated
evidence before they become a potential finding; one email address alone is
reported as inconclusive rather than vulnerable.

Additional application-specific field or JSON-path patterns can be supplied as
bounded regular expressions:

```bash
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --sensitive-field-pattern 'medicalRecordNumber$' \
  --sensitive-field-pattern '\.taxIdentifier$'
```

Evidence contains the JSON path, category, confidence, value type/length, and
a short SHA-256 fingerprint. Raw sensitive values and full sensitive response
bodies are not copied into findings. Masked/null values are ignored, response
analysis is size-bounded, and a non-JSON or context-poor response remains
inconclusive.

### Parameter Manipulation and Mass Assignment

Passive analysis inventories parameter names from static URLs, Playwright
runtime requests, OpenAPI operations, and JSON responses. It reports observed
but undocumented parameters, response-only fields, and security-relevant
writable candidates without treating those discrepancies as proven
vulnerabilities.

Active proof is limited to researcher-declared synthetic records. A case must
define the exact write, a separate read-only state check, expected original and
mutated values, and a cleanup write:

```json
{
  "cases": [{
    "name": "synthetic-profile-role",
    "method": "PATCH",
    "url": "/lab/profiles/synthetic-1",
    "parameter": "role",
    "mutation_body": {"role": "administrator"},
    "synthetic_record": true,
    "allow_state_change": true,
    "verify": {
      "method": "GET",
      "url": "/lab/profiles/synthetic-1",
      "json_path": "$.role",
      "original_value": "member",
      "mutated_value": "administrator"
    },
    "cleanup": {
      "method": "PATCH",
      "url": "/lab/profiles/synthetic-1",
      "json_body": {"role": "member"}
    }
  }]
}
```

Run it only with both opt-ins and an exact host allow-list:

```bash
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --active-testing \
  --parameter-validation-config parameter-validation-config.json
```

Request acceptance alone is not a vulnerability. A confirmed finding requires
a separate verification request proving the declared field changed; cleanup is
then attempted and verified. Evidence retains status codes and value
fingerprints, not raw configured values.

### Bounded Rate-Limit Assessment

Rate assessment is read-only and only runs for exact `--authorized-host`
targets. Defaults are deliberately small: five requests, one concurrent
request, a 0.25-second inter-batch delay, and a five-second per-request timeout.
The hard implementation limits are ten requests and concurrency three.

```bash
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --rate-limit-requests 5 \
  --rate-limit-delay 0.25 \
  --rate-limit-concurrency 1 \
  --rate-limit-timeout 5
```

Probing stops after the active batch on HTTP 429, `Retry-After`, transport
failure, timeout, or a 502/503/504 service-protection response. HTTP 429 and
quota-policy headers are retained as protection signals. A handful of
successful requests without a 429 is always inconclusive, never proof of a
missing rate limit. A success after the server explicitly advertises zero
remaining quota is only a low-confidence potential policy inconsistency.

### Safe Injection Indicators

Injection checks are config-driven, GET-only, and require an exact authorized
host. Each case names one known-safe baseline value and one or more categories:
`sql`, `nosql`, `command`, or `template`.

```json
{
  "cases": [{
    "name": "synthetic-search",
    "method": "GET",
    "url": "/lab/search",
    "parameter": "q",
    "baseline_value": "known-safe-record",
    "categories": ["sql", "nosql", "command", "template"]
  }]
}
```

```bash
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --injection-validation-config injection-validation-config.json
```

The validator compares each fixed, non-destructive probe with both the declared
baseline and a neutral control. It does not use data-extraction queries,
destructive commands, file reads, timing delays, callbacks, or shells. A 5xx
response alone remains inconclusive; findings require a category-specific
error unique to the probe or an exact evaluated template marker. Reports retain
only response status, length, digest, and named indicators—not probe values or
response bodies.

### Session and Access-Control Boundaries

Role, function, endpoint, cross-user, stale-session, and session-invalidation
cases use manually supplied environment-backed identities. The scanner never
creates or elevates an identity. Cases are read-only and require protected JSON
evidence paths so a `200` response alone cannot become a finding.

```json
{
  "identities": {
    "normal-user-a": {"value_env": "LAB_NORMAL_A_AUTHORIZATION"},
    "privileged-user": {"value_env": "LAB_PRIVILEGED_AUTHORIZATION"},
    "stale-session": {"value_env": "LAB_STALE_AUTHORIZATION"}
  },
  "cases": [{
    "name": "admin-role-boundary",
    "type": "role_boundary",
    "method": "GET",
    "url": "/api/admin/settings",
    "allowed_identity": "privileged-user",
    "denied_identities": ["normal-user-a", "stale-session"],
    "evidence_paths": ["$.settings.tenant", "$.settings.policy"]
  }]
}
```

```bash
export LAB_NORMAL_A_AUTHORIZATION="Bearer <controlled-normal-token>"
export LAB_PRIVILEGED_AUTHORIZATION="Bearer <controlled-privileged-token>"
export LAB_STALE_AUTHORIZATION="Bearer <already-invalidated-test-token>"
./run.sh run http://127.0.0.1:8888 \
  --authorized-host 127.0.0.1 \
  --access-validation-config access-validation-config.json
```

`stale_session` and `session_invalidation` cases use a researcher-supplied
already-invalidated session; the scanner does not log users out or invalidate
live sessions. Evidence stores identity labels, status codes, and semantic
fingerprints, never credential values.

### Unified Validation Pipeline

Security validators implement one asynchronous interface and are registered in
a CLI-independent orchestrator. The pipeline is:

`discovery -> normalization -> documentation comparison -> shadow classification -> validation -> evidence/confidence -> reporting`

Every structured validation result carries the endpoint and method, normalized
route, discovery sources, documentation/shadow status, validator/category,
outcome, severity, confidence, redacted evidence, affected parameter, bounded
response metadata, remediation, and references. A validator configuration error
is isolated to that validator and recorded without aborting the rest of the
pipeline.

JSON reports include a top-level `findings` object. `findings.discovery`
separates documented, Shadow / Unmanaged, undocumented-parameter, runtime-only,
and static-only observations. `findings.security` separates BOLA/IDOR,
authentication, data exposure, parameter manipulation, rate limiting,
injection, and session/access-control findings. The HTML report includes the
same category counts plus a concise validation-evidence table, and the terminal
summary shows the highest-value counts without printing response bodies or
credentials.

### Accuracy Benchmark

Supply a labeled ground-truth file to measure one-to-one operation discovery
and classification. Evaluation runs after Phase 3, so methods discovered by
security validation are included. Reports contain TP/FP/FN, precision, recall,
F1, documentation-status confusion, and report-facing API-classification
confusion:

```json
{
  "endpoints": [
    {
      "method": "PATCH",
      "url": "/api/products/{productId}/price",
      "documentation_status": "unknown",
      "api_classification": "Shadow / Unmanaged API"
    }
  ]
}
```

```bash
./run.sh run http://127.0.0.1:8888 \
  --discovery-only \
  --openapi-spec openapi.json \
  --ground-truth benchmark.json
```

The ground-truth file measures results; it does not become an authoritative API
baseline. Use `--openapi-spec` or `--api-inventory` for shadow classification.
`api_classification` is optional; supported labels are Documented API,
Shadow / Unmanaged API, and Unknown API. Historical benchmark labels are
accepted as input aliases and normalized to this combined taxonomy.

Saved JSON reports can be evaluated without rerunning a target:

```bash
python -m shadow_api_scanner.evaluation.benchmark \
  --report reports/example/scan_report.json \
  --ground-truth benchmarks/ground_truth/example.json \
  --output reports/example/benchmark_metrics.json
```

Run every case in the repository manifest:

```bash
python -m shadow_api_scanner.evaluation.benchmark \
  --manifest benchmarks/manifest.json \
  --output reports/benchmark_suite_metrics.json
```

The initial corpus and labeling rules are documented in
`benchmarks/README.md`. A single perfect lab result is not evidence of general
90% accuracy; the corpus must cover multiple applications and API patterns.
Ground-truth files may also include `required_findings` to assert that a
specific confirmed detector result is present. Required-finding recall is
reported separately and does not treat unrelated findings as false positives.

The corpus also includes pinned authenticated OWASP crAPI, DVAPI, and VAmPI
cases using full and controlled-stale OpenAPI specifications under
`benchmarks/specs/` and sanitized traffic under `benchmarks/traffic/`. These
cases test method-level documented-vs-Shadow/Unmanaged classification across three
independent open-source applications without depending on temporary hosted
labs.

### API Inventory Baseline
Use `--api-inventory` when OpenAPI is missing but you still have an
authoritative route catalog, gateway export, or service ownership file.
Active routes found at runtime but missing from this file can be classified as
confirmed Shadow / Unmanaged APIs.

```yaml
apis:
  - method: GET
    path: /api/products/{productId}/price
    owner: catalog-team
    lifecycle: active
  - method: PATCH
    path: /api/products/{productId}/price
    owner: catalog-team
    lifecycle: retired
```

---

## Supported Research Targets and Limitations

The repository contains deterministic offline benchmark cases derived from
authenticated OWASP crAPI, DVAPI, and VAmPI evidence, plus a live local fixture
used by the integration suite. Other intentionally vulnerable applications can
be scanned when the researcher supplies authorization, authentication state,
and ground truth, but they are not claimed as validated by the pinned corpus.

Current limitations:

- The browser crawl is bounded and cannot guarantee coverage of every SPA state
  or workflow; authenticated storage state and representative navigation still
  matter.
- External evidence cannot prove gateway ownership or internal monitoring;
  those parts of the Shadow / Unmanaged definition require organizational data.
- Controlled BOLA, authentication, injection, access-control, and mutation
  findings require explicit configuration. Unsupported OWASP categories remain
  manual research work rather than heuristic scanner findings.
- The frozen corpus result is corpus-specific and is not a universal accuracy
  claim. Expand ground truth across more applications before generalizing it.
- Linux and Chromium are executed in the current test environment. Windows is
  code-reviewed and simulated by platform tests, but still needs a native CI
  runner before distributing the Windows executable.

---

## Build Standalone Binary

### Linux
```bash
./run.sh build
# Output: dist/shadow-scan
```

### Windows

```cmd
run.bat build
REM Output: dist\shadow-scan.exe
```

The Windows build command is code-reviewed but must still be exercised on a
Windows CI runner or workstation before distributing the executable.

---

## Project Structure

```
shadow-api-scanner/
|-- shadow_api_scanner/
|   |-- __init__.py          # Package metadata
|   |-- __main__.py          # python -m entry point
|   |-- cli.py               # CLI argument parsing + orchestration
|   |-- core/
|   |   |-- config.py        # OWASP categories and bounded scan settings
|   |   `-- models.py        # APIEndpoint, Vulnerability, ScanResult
|   |-- phase1/
|   |   |-- crawler.py       # JS file crawler (external + chunks)
|   |   |-- js_parser.py     # Regex-based API extraction from JS
|   |   |-- template_resolver.py  # Concrete URLs from page context
|   |   |-- path_explorer.py # Parent paths and OPTIONS exploration
|   |   `-- static_analyzer.py  # Phase 1 orchestrator
|   |-- phase2/
|   |   |-- traffic_monitor.py  # Playwright network interception
|   |   |-- route_clusterer.py  # Logical routes + observed examples
|   |   |-- traffic_importer.py # HAR and proxy/access-log import
|   |   |-- api_inventory.py    # Approved inventory baselines
|   |   |-- baseline.py         # Inventory save/compare history
|   |   |-- spec_comparator.py  # OpenAPI spec parsing + comparison
|   |   `-- shadow_detector.py  # Shadow API classification
|   |-- evaluation/
|   |   |-- metrics.py       # TP/FP/FN, F1, confusion matrices
|   |   `-- benchmark.py     # Offline saved-report evaluation
|   |-- phase3/
|   |   |-- validators/      # Controlled evidence-based validators
|   |   |-- validation_orchestrator.py # Modular validator registry
|   |   `-- security_tester.py  # Phase 3 integration
|   |-- phase4/
|   |   |-- risk_scorer.py   # Risk score calculation
|   |   `-- report_generator.py  # JSON + HTML report output
|   `-- utils/
|       |-- http_client.py   # Async httpx client with rate limiting
|       |-- helpers.py       # URL normalization, logging, utilities
|       `-- redaction.py     # Report credential and token redaction
|-- benchmarks/              # Labeled operation ground truth
|-- requirements.txt
|-- scripts/
|   |-- validate_research_baseline.py
|   `-- windows_launcher.py
|-- setup.py
|-- run.sh                   # Linux build/run script
`-- run.bat                  # Windows build/run script
```

---

## Legal Disclaimer

This tool is for **authorized security testing only**. Always obtain proper authorization before scanning any target. Unauthorized testing may violate laws. Use responsibly.
