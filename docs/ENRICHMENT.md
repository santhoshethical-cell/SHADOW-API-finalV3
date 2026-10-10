# Enrichment: finding statuses, local CVE database, remediation and AI analysis

This document describes the post-scan enrichment added to the web app. The
vendored scanner (`scanner/`) is **unchanged**; everything below lives in
`backend/app/` and runs after a scan has completed.

## Contents

1. [How it fits together](#how-it-fits-together)
2. [Finding statuses](#finding-statuses)
3. [Local CVE database](#local-cve-database)
4. [Component matching](#component-matching)
5. [Remediation](#remediation)
6. [AI analysis and data handling](#ai-analysis-and-data-handling)
7. [Persistence, re-checks and migration](#persistence-re-checks-and-migration)
8. [Exports (JSON, CSV, HTML, PDF)](#exports)
9. [Configuration reference](#configuration-reference)
10. [API endpoints](#api-endpoints)
11. [Limitations](#limitations)
12. [Troubleshooting](#troubleshooting)

---

## How it fits together

```
scan (scanner phases 1-4) ──► "done" event, scan status = completed
                               │
                               ▼  (separate background step; cannot fail the scan)
                     enrichment.run()
                       1. component detection   cve.fingerprint()  ── live page, headers, script names
                       2. CVE matching          matching.py        ── OFFLINE, local SQLite DB
                       3. finding statuses      findings.py        ── from the scanner JSON
                       4. remediation           remediation.py     ── deterministic
                       5. AI analysis           ai_analysis.py     ── optional, validated
                               │
                               ▼
     data/reports/<scan_id>/enrichment.json  + enriched_report.html  (+ enrichment_history/)
```

| Module | Responsibility |
| --- | --- |
| `versioning.py` | Scheme-aware version parsing/comparison (semver, dotted, openssl). Never lexicographic. |
| `component_catalog.py` | Fingerprint token → product identity, NVD CPE `vendor:product` aliases, version scheme, identity confidence. |
| `nvd_client.py` | NVD CVE API 2.0 client: pagination, rolling-window rate limit, retries/back-off. |
| `cvedb.py` | SQLite CVE store, atomic staged updates, imports, coverage/status. |
| `cvedb_cli.py` | `status` / `update` / `import` command line. |
| `matching.py` | Offline matching of detected components against affected ranges. |
| `findings.py` | Evidence-based classification of the scanner's behavioural findings. |
| `remediation.py` | Deterministic remediation + verification guidance. |
| `ai_analysis.py` | Optional AI explanations with schema + claim validation. |
| `enrichment.py` | Orchestration, persistence, enriched HTML. |
| `secrets_guard.py` | Scrubs configured secrets from errors and logs. |

## Finding statuses

The scanner's own `status` and `confidence` are **preserved verbatim** in every
view and export. The app adds an `evidence_category` used for counting and
labels:

| Category | Rule |
| --- | --- |
| `confirmed` | Scanner status `Confirmed` **and** proof-of-concept evidence attached (`poc_request`, `poc_evidence` or `poc_status_code`). |
| `potential` | Scanner status `Potential`, **or** `Confirmed` without attached evidence (flagged for manual review). |
| `dismissed` | Scanner status `False Positive` — listed, never counted. |
| `unknown` | `Not Tested` or anything unrecognised. |

Validator check outcomes are summarised as passed / vulnerable / inconclusive /
skipped / failed, and the UI states when checks did not complete ("absence of
findings there is not evidence of safety").

Component CVE matches are a **separate record type** with their own categories
(`version_match`, `potential`, `unknown`). They are never merged into, or
counted with, behavioural findings, and CVEs are never attached to BOLA,
authentication, injection or other behavioural findings — matching is driven
only by component identity and version, never by CWE.

Previously, the summary headline, the "Confirmed security findings" heading and
the Technical tab's "Confirmed vulnerabilities (N)" heading counted every
scanner entry as confirmed. These now show confirmed, potential and unknown
separately, the severity chart is split into confirmed vs potential, and
dismissed entries are excluded from charts.

## Local CVE database

A dedicated SQLite file (default `data/cvedb.sqlite3`) holds:

| Table | Contents |
| --- | --- |
| `cves` | CVE id, English description, published/last-modified, NVD record status (`vulnStatus`), CVSS score/version/vector/severity and who scored it, CWE ids, record source (`nvd-api` or `import:<file>`), fetch time. |
| `affected` | One row per NVD `cpeMatch`: vendor, product, normalised component key, criteria, exact version + CPE update qualifier, `versionStart/End Including/Excluding`, `fixed_version` (only when a source states it explicitly — NVD does not), vulnerable flag, configuration prerequisite flag + note, target software. |
| `refs` | Reference URL (validated http/https only), source, NVD tags (`Patch`, `Mitigation`, `Vendor Advisory`, …). |
| `coverage` | Per `vendor:product`: `complete` (downloaded from NVD) or `imported` (files of unknown completeness), last success time, record count. |
| `meta` | Schema version, last update time/mode/source. |

The outcome of every update/import run (success or failure, with a scrubbed
error) is written to `cvedb.sqlite3.lastrun.json`.

### Populating and updating

```bash
# Initial population: downloads every product in the component catalog
python3 run.py cvedb update --full

# Incremental: only records modified since each product's last success
python3 run.py cvedb update

# One product only
python3 run.py cvedb update --product jquery:jquery

# Offline import of NVD CVE API 2.0 JSON (API pages or {"vulnerabilities": [...]})
python3 run.py cvedb import nvd-page-1.json nvd-page-2.json --complete-for jquery:jquery

# Show state and per-component coverage
python3 run.py cvedb status
```

Administrators can also start an update from **Profile → Vulnerability
database** (`POST /api/admin/cvedb/update`, admin role required). Only one
update runs at a time.

How updates work:

- **Scope.** Updates query NVD per catalog product with
  `virtualMatchString=cpe:2.3:a:<vendor>:<product>`, not the entire NVD.
- **Pagination.** `startIndex`/`resultsPerPage` (2000 per page) until
  `totalResults` is read; an empty page before the end aborts the run.
- **Incremental.** Products with complete coverage fetch only records with
  `lastModStartDate` ≥ last success − 1 hour, split into ≤120-day windows (NVD
  limit). Products without complete coverage get a full download.
- **Rate limits.** A rolling 30-second window keeps requests at 4 (no key) or
  49 (with `SAS_NVD_API_KEY`) — one under NVD's published 5/50.
- **Retries.** HTTP 403/429/5xx, timeouts and network errors are retried with
  exponential back-off (honouring `Retry-After`); 4xx parameter errors are not.
- **Atomicity.** Each run works on a staged copy of the database (SQLite backup
  API). The copy replaces the live file with `os.replace` only after the whole
  run succeeds and `PRAGMA integrity_check` passes. On any failure the staged
  copy is deleted and **the previous database is kept byte-for-byte**.
- The NVD key is sent only in the `apiKey` request header — never in URLs, logs,
  errors, the UI or `lastrun.json`.

### Status shown in the UI

`missing` (not populated) · `partial` (some catalog products missing or only
imported) · `stale` (complete but older than `SAS_CVEDB_STALE_DAYS`) · `ok`.
A failed last run is reported alongside the (unchanged) data in use.

## Component matching

Detection (extended `cve.fingerprint`) records for every component: product
token, observed version, **detection source** (`runtime`, a header name, or
`bundle`), a short evidence string, **observation time**, and any distribution
hint in a server banner (e.g. `(Ubuntu)`).

Matching then, per component:

1. **Identity** via the catalog — `high` (runtime global or a product-specific
   header), `medium` (script filename, generic header token), `ambiguous`
   (e.g. `angular-1.8.2.min.js` could be AngularJS or Angular), or
   `unrecognized` (no lookup possible).
2. **Version** parsed with the product's scheme (see `versioning.py`).
   Unparseable versions are reported as unknown.
3. **Coverage** for the product; missing coverage ⇒ "unknown", never "no
   vulnerabilities". For ambiguous identities matching proceeds for candidates
   that have data and coverage is reported as partial.
4. **Ranges**: inclusive/exclusive start and end, exact versions with CPE
   update qualifiers (`5.0.0:alpha1` = `5.0.0-alpha.1`), "all versions"
   entries. NVD `Rejected` records are skipped and counted.

Each affected CVE becomes one match:

| Category | Meaning |
| --- | --- |
| `version_match` | Certain identity, clean version, explicit affected range, no configuration prerequisite. **Version evidence only — not confirmed exploitable.** |
| `potential` | In range, but evidence is weaker: ambiguous/indirect identity, pre-release, distribution/vendor build (back-port risk), configuration prerequisite (NVD `AND` configurations), unanalysed NVD record, or unspecified range. Each reason is listed. |
| `unknown` | A bound could not be compared. |

Every match records the affected ranges, CVSS details, NVD status, references,
a deterministic rationale and its uncertainty list.

## Remediation

Built deterministically for every non-dismissed behavioural finding and every
component with CVE matches:

- **Actions** — the scanner's own remediation text first, then OWASP API Top 10
  (2023) category guidance.
- **Upgrade target** — marked *verified* only when a source documents a fixed
  version. Otherwise it says "not verified" and states the NVD range boundary
  ("NVD lists versions before 3.5.0 as affected") with an instruction to
  confirm the fixed release in the vendor advisory. Patch versions are never
  invented.
- **Workarounds** — only references NVD tags as `Mitigation`.
- **Verification steps** after remediation, **references**, and **remaining
  uncertainty**. Wording is advisory; nothing claims a fix was applied.

## AI analysis and data handling

Optional and **off by default**. Provider: **Anthropic Claude Messages API**
(`POST https://api.anthropic.com/v1/messages`, `anthropic-version: 2023-06-01`)
using **structured outputs** (`output_config.format` with a JSON schema), per
Anthropic's documentation:
<https://platform.claude.com/docs/en/build-with-claude/structured-outputs>.
Default model `claude-haiku-5-5` (Anthropic's fast, low-cost model); override
with `SAS_AI_MODEL`. It is called with `httpx` — no SDK dependency.

**When it runs:** after component matching, finding classification and
remediation exist. AI failure never changes the scan's status or any other
enrichment output.

**What is sent (minimised and redacted):**

- Behavioural findings: a reference (`B:<finding id>`), evidence category,
  scanner status/confidence, severity, OWASP id/name, CWE id, short title.
- CVE matches: a reference (`M:<match id>`), category, CVE id, component name,
  observed version, affected range text, CVSS score/version/severity, a short
  CVE summary and the uncertainty reasons.
- All text passes through the scanner's `redact_text` plus extra
  minimisation: URLs → `[url]`, paths → `[path]`, query strings removed,
  `key=value` secrets → `[redacted]`, e-mails, IPv4 addresses and long tokens
  removed, target hostname → `[target]`.

**Never sent:** target hostnames/URLs, endpoints, request/response bodies,
headers, cookies, credentials, proof-of-concept data, dismissed findings. The
UI displays this disclosure in the AI section and on the profile page.

**What the AI may do:** explain supplied findings, potential impact,
remediation and verification steps. **It cannot** decide CVE applicability,
change statuses or scores, or add findings — its output is stored in a separate
`ai_analysis` block and never written into findings.

**Defences that do not rely on the prompt:**

1. The JSON schema restricts `ref` to an `enum` of supplied references and sets
   `additionalProperties: false`.
2. Server-side validation re-parses and re-checks everything: unknown refs,
   duplicates and extra fields are dropped; text is length-capped.
3. Every sentence is checked against the supplied facts. A field is removed if
   it mentions a CVE id, version number or CVSS score not supplied for that
   item; contains a URL; claims confirmation for a non-confirmed item; claims
   real-world exploitation; claims the issue is a false positive or already
   fixed; references an unknown item; or contains instruction-like/markup
   content (prompt-injection echoes).
4. Rejected fields fall back to the deterministic remediation; the UI shows how
   many statements were removed. All AI text is rendered as escaped text.

**Failure handling:** missing key → `skipped`; timeout, network error, auth
error, rate limit (429/529 after two retries), refusal, truncation or malformed
output → `failed` with a scrubbed reason. Scan results and remediation remain.

**Keys:** read from the environment at call time, sent only in the `x-api-key`
header, never returned by any endpoint (`/api/ai/status` reports only
`key_configured: true/false`), and scrubbed from logs and errors by
`secrets_guard`.

## Persistence, re-checks and migration

- `data/reports/<scan_id>/enrichment.json` — versioned (`schema_version: 1`),
  written atomically; previous results are archived to
  `enrichment_history/` on each re-run.
- `scans.enrichment_status` column (added automatically on startup; older rows
  stay `NULL` and show as "not run").
- Opening a report from **Scan history**, viewing or exporting it reads these
  files. **The target is never contacted** for that.
- **Re-check components** (`refingerprint: true`) fingerprints the target again
  and records a new `components_observed_at`. **Re-match offline**
  (`refingerprint: false`) reuses the stored components against the current
  CVE database without contacting the target; it gets a new `matched_at`.
- An enrichment interrupted by a restart is marked failed on startup and can be
  re-run.

**Migration:** none required. Start the new version; the column is added
automatically. Existing scans remain readable and exportable; use
**Re-check components** on an old scan to enrich it.

## Exports

| Format | Contents |
| --- | --- |
| **JSON** (`/export.json`, new) | The scanner's report **unchanged** plus top-level `enrichment` (or `null`) and `webapp_export_schema: 1`. |
| **HTML** | `enriched_report.html` = the scanner's HTML + an escaped enrichment section (statuses, components, CVE matches, remediation, AI). Regenerated after each enrichment. |
| **PDF** | Rendered from `enriched_report.html` when enrichment exists, so it matches the UI; otherwise from the scanner HTML. |
| **CSV** | See below. |

### CSV columns

The original 11 columns are unchanged and first:
`owasp_category, owasp_name, title, severity, status, risk_score, confidence,
cwe_id, affected_methods, poc_status_code, remediation`.

Additive columns follow:
`record_type, record_id, evidence_category, component, observed_version,
detection_source, identity_confidence, cve_id, affected_range, cvss_score,
cvss_version, cvss_vector, match_rationale, references, observed_at`.

`record_type` values:

| Value | Rows | Notes |
| --- | --- | --- |
| `behavioral_finding` | one per scanner vulnerability | Legacy columns as before; `evidence_category` added; `match_rationale` holds the evidence basis. |
| `component_cve_match` | one per CVE match | `status` holds "Version match (not confirmed exploitable)" / "Potential (needs validation)" / "Unknown"; `severity` from CVSS. |
| `component` | one per detected component without matches | Makes unknown/missing coverage visible. |

A CVE match is never also a behavioural row, so nothing is double-counted.
Every text cell starting with `=`, `+`, `-`, `@`, tab or carriage return is
prefixed with `'` to neutralise spreadsheet formula injection.

## Configuration reference

| Variable | Default | Purpose |
| --- | --- | --- |
| `SAS_NVD_API_KEY` | – | Optional NVD key (higher rate limit). |
| `SAS_CVEDB_PATH` | `$SAS_DATA_DIR/cvedb.sqlite3` | CVE database location. |
| `SAS_CVEDB_STALE_DAYS` | `7` | Coverage older than this is "stale". |
| `SAS_AI_ENABLED` | `false` | Enable AI analysis. |
| `SAS_AI_PROVIDER` | `anthropic` | Only `anthropic` is implemented. |
| `SAS_AI_API_KEY` | – | Provider key (server-side only). |
| `SAS_AI_MODEL` | `claude-haiku-5-5` | Model id. |
| `SAS_AI_TIMEOUT_SECONDS` | `45` | Per-request timeout (5–300). |

`python3 run.py` loads a `.env` file from the project root (shell variables
win). Starting uvicorn directly does **not** read `.env`; export variables
instead. `.env` is git-ignored; `.env.example` contains placeholders only.

## API endpoints

| Method & path | Access | Purpose |
| --- | --- | --- |
| `GET /api/scan/{id}/enrichment` | owner | Persisted enrichment (`status: not_run` if none). |
| `POST /api/scan/{id}/enrichment/recheck` | owner | Body `{"refingerprint": true|false}`; 202, runs in background. |
| `POST /api/scan/{id}/cve-check` | owner | Legacy; now an explicit re-check returning the enrichment (no live NVD query). |
| `GET /api/scan/{id}/export.json` | owner | Scanner report + `enrichment`. |
| `GET /api/cvedb/status` | signed-in user | Database state and coverage (no secrets). |
| `GET /api/ai/status` | signed-in user | AI configuration status (no key). |
| `POST /api/admin/cvedb/update` | admin | Body `{"mode": "incremental"|"full"}`; 202. |
| `GET /api/admin/cvedb/update` | admin | Update job progress/result. |

All scan-scoped endpoints use the existing ownership check (another user's
scan returns 404).

## Limitations

- **Version evidence is not exploitability.** A match means the observed
  version is in an NVD range; it does not show the vulnerable code path is
  reachable. Some CVEs affect server-side packages that a client-side version
  cannot reveal (noted for React and Angular).
- **Detection coverage.** Only products in the catalog are matched: jQuery,
  Angular, AngularJS, React, Vue.js, Bootstrap, Lodash, Express, nginx, Apache
  HTTP Server, PHP, Microsoft IIS, OpenSSL. Bundled/minified libraries without
  version globals or versioned filenames are not detected.
- **NVD data quality.** Ranges can be wrong or missing; CVEs "awaiting
  analysis" often have no configurations and therefore cannot be matched at
  all; product-scoped queries do not return such records. NVD does not publish
  fixed versions, so upgrade targets are rarely "verified".
- **Back-ports.** Distribution builds (Ubuntu, RHEL, …) are flagged
  "potential", but a banner without any distribution hint can still be a
  patched vendor build.
- **Banners can be absent or spoofed**, and `Server` headers are often removed
  by proxies.
- **AI validation is conservative.** Legitimate sentences that cite an
  unsupplied version number (e.g. a TLS version next to "upgrade") may be
  removed; the deterministic remediation is always shown.
- **AI provider:** only Anthropic is implemented.
- Not addressed here (from the earlier security review, still open): SSE stream
  ownership check, shared scanner logger across concurrent scans, session
  revocation, login rate limiting.

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| "CVE database: not populated" | Run `python3 run.py cvedb update --full` or use Profile → Vulnerability database. |
| Update fails with HTTP 403/429 | NVD throttling. Retry later, or set `SAS_NVD_API_KEY`. The previous database is still in use; see `data/cvedb.sqlite3.lastrun.json`. |
| Update is slow | Without a key, NVD allows 5 requests / 30 s. A full catalog download needs at least one request per product. |
| Air-gapped host | Download NVD API JSON elsewhere and `python3 run.py cvedb import FILE --complete-for vendor:product`. |
| Component shows "No database coverage — unknown" | That product has no downloaded data. Update it (`--product vendor:product`). |
| Enrichment "partial" | Open the stage list: usually detection failed (target unreachable), coverage is missing/stale, or AI failed. Scan results are unaffected. |
| AI shows "skipped" | `SAS_AI_ENABLED=true` but `SAS_AI_API_KEY` is empty, or nothing to analyse. |
| AI shows "failed: … rejected the configured credentials" | Wrong or revoked key. |
| Many AI statements removed | Expected when the model cites facts not in the evidence; deterministic remediation remains. |
| `.env` values ignored | You started uvicorn directly; export the variables or use `python3 run.py`. |
| PDF lacks enrichment | Enrichment was still running. Wait for "completed/partial", then export again. |
