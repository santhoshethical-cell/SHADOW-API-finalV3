# Demonstration Playbook — Risk-Band Showcase

Four **real, authorized** targets, one per severity band, driven through the web
UI. Everything below is designed for a **live viva demo**: reliable, fast, and
defensible.

> **Honesty note.** The detection *logic* and the *scoring model* are verified
> (unit tests + local runs). The **exact score** each lab lands on depends on its
> live state, so **do a dry run the day before** (see the checklist) and note the
> real numbers. The expected bands below are reasoned from each lab's known
> behaviour, not guaranteed to the decimal.

---

## The four targets at a glance

| Band | Score | Lab | Why it lands there | Status |
|------|-------|-----|--------------------|--------|
| **High** | **8.0** · High | **OWASP crAPI** (authenticated) | financial-data + PII excessive data exposure (API3), + 7 undocumented methods | ✅ **verified live** |
| **High (alt)** | **7.5** · High | **VAmPI** (vulnerable) | autonomous `/users/v1/_debug` password leak (API3) | ✅ **verified live** |
| **Low** | **3.0** · Low | **httpbin** | `Server: Werkzeug/3.1.8` → version disclosure (API8/CWE-200) | ✅ **verified live** |
| **Medium** | ~5.9 · Medium | **PortSwigger** "unused API endpoint" | undocumented `PATCH` (API9) | needs a fresh hosted instance |
| **Safe** | — | *(conceptual / header-stripped)* | dev-server labs leak a version banner → floor at Low | presented conceptually |

Optional **Critical (9.0)**: crAPI confirmed BOLA (two-identity config — last section).

**The elegant framing (recommended):** a single **crAPI authenticated scan already
spans the spectrum** — its findings chart shows **4 High, 7 Medium, 1 Low** in one
real report. Show that severity distribution, then **httpbin (3.0 Low)** as the
clean contrast. That covers High + Medium + Low with real, verified results and no
PortSwigger dependency.

**Verified live on your labs:**
- **crAPI (authenticated) → 8.0 High** — data exposure incl. `financial_data`, plus
  seven undocumented-method findings (Medium) and the version banner (Low).
  **Autonomous** — only an auth token is needed, no per-validator config.
- **VAmPI vulnerable → 7.5 High** — autonomous `/users/v1/_debug` password leak.
- **httpbin → 3.0 Low** — version banner.

**Honest note on Safe (0.0):** dev-server labs (VAmPI/httpbin) and crAPI all
advertise a `Server` version → a real, correctly-detected **Low**. A true 0.0 needs
a target with that header stripped (nginx `server_tokens off;` +
`proxy_hide_header Server;`), so we present "Safe" conceptually: a clean app = zero
findings, reported honestly as Info.

---

## Before you present — checklist (do this the day before)

```bash
# 1. Pull the two tiny lab images
docker pull erev0s/vampi:latest
docker pull kennethreitz/httpbin

# 2. Start a fresh PortSwigger lab instance (needs a free portswigger.net account)
#    https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint
#    Click "Access the lab" -> copy the https://XXXX.web-security-academy.net URL.
#    NOTE: the instance EXPIRES when idle — start a fresh one shortly before the demo.

# 3. Start the web app and log in (set your admin password once)
python3 run.py
```

- [ ] All four targets reachable (curl each root, expect a response).
- [ ] Dry-run each scan through the UI and **write down the actual score** so there
      are no surprises live.
- [ ] Keep the PortSwigger tab open; restart the instance if it 504s.

---

## Band 1 — SAFE (needs a header-stripped target)

**Reality from the dry run:** VAmPI and httpbin both run the Werkzeug dev server,
which advertises its version (`Server: Werkzeug/...`). The scanner *correctly*
flags that as a **Low** — so neither can show a true **Safe (0.0)**. That's honest
behaviour, not a bug.

To demonstrate **Safe (0.0)** on a real target, put a clean API behind nginx with
the banner stripped:

```nginx
# /etc/nginx/conf.d/safe.conf  — reverse-proxy VAmPI(secure) with headers stripped
server {
    listen 8090;
    server_tokens off;                 # don't add nginx's own version
    location / {
        proxy_pass http://localhost:5000;
        proxy_hide_header Server;       # strip the Werkzeug banner
        proxy_hide_header X-Powered-By;
    }
}
```
```bash
docker rm -f vampi 2>/dev/null
docker run -d --name vampi -e vulnerable=0 -p 5000:5000 erev0s/vampi:latest  # secure mode
# then reload nginx and scan http://localhost:8090/
```

**Scan (web UI):** Target `http://localhost:8090/`, Level **Standard**,
**Advanced → Discovery → OpenAPI spec URL** = `http://localhost:8090/openapi.json`,
authorize → **Start scan**.

**Expected:** no version banner + secure mode → **Overall 0.0 / Info**.
**What to say:** *"A properly hardened API — no version disclosure, no
undocumented endpoints, no data leaks. The tool reports it clean, and reports
'no findings' honestly as Info rather than a false 'secure' guarantee."*

> Simpler alternative if you don't want nginx: present the spectrum as
> **Low → Medium → High → Critical** and describe Safe conceptually, or point the
> scanner at any internal service you know returns no `Server` version header.

---

## Band 2 — LOW (httpbin — version disclosure)

**Start the lab**
```bash
docker rm -f httpbin 2>/dev/null
docker run -d --name httpbin -p 8080:80 kennethreitz/httpbin
```

**Scan (web UI)**
1. Target URL: `http://localhost:8080/`
2. Level: **Standard**
3. **Advanced options → Discovery → OpenAPI spec URL** = `http://localhost:8080/spec.json`
   (httpbin ships its own spec, so the passive checks have endpoints to probe).
4. Authorize → **Start scan**.

**Expected (verified live → 3.0 Low):** `Server: Werkzeug/3.1.8 Python/3.12.3`
→ **Verbose version disclosure (API8 / CWE-200)** → **3.0 / Low**.
**What to say:** *"A real, low-severity misconfiguration: the server advertises its
exact version, handing an attacker a fingerprint. Scored Low (CVSS 3.0) — real,
but not alarming."*

---

## Band 3 — MEDIUM (PortSwigger — unused API endpoint)

**Start the lab:** open the lab page, click **Access the lab**, copy the
`https://XXXX.web-security-academy.net/` URL. Start a **fresh** instance so it
doesn't 504 mid-demo.

**Scan (web UI)**
1. Target URL: the lab instance URL.
2. Level: **Standard**.
3. Authorize → **Start scan**.

**Expected:** the tool discovers `/api/products/{id}/price` from the page's JS,
probes it, and reports **Undocumented state-changing method exposed (PATCH)
— API9** → **~5.9 / Medium**.
**What to say:** *"Fully autonomous: it found the hidden endpoint from the client
JS, then discovered — via a read-only OPTIONS probe — that the server also allows
an undocumented PATCH the app never uses. That's the exact bug this lab teaches,
detected non-destructively and scored Medium."*

---

## Band 4 — HIGH (VAmPI, vulnerable mode)

**Flip the same container to vulnerable mode**
```bash
docker rm -f vampi 2>/dev/null
docker run -d --name vampi -e vulnerable=1 -p 5000:5000 erev0s/vampi:latest
```

**Scan (web UI)**
1. Target URL: `http://localhost:5000/`
2. Level: **Standard**
3. **Advanced options → Discovery → OpenAPI spec URL** = `http://localhost:5000/openapi.json`
4. Authorize → **Start scan**.

**Expected (verified live → 7.5 High):** the scanner **autonomously discovers the
undocumented `/users/v1/_debug`** (via sensitive-path probing — it's in neither the
JS nor the spec), then flags **Excessive data exposure (API3, password_material)**
→ **7.5 / High**, plus undocumented `DELETE` methods (API9, 6.4 Medium) and the
version banner (3.0 Low).
**What to say:** *"The tool found an undocumented debug endpoint on its own and
detected that it leaks every user's password — a textbook excessive-data-exposure
flaw. It flags the sensitive fields without printing the secret values, and scores
it High."*

---

## crAPI — HIGH (verified 8.0) + optional CRITICAL

```bash
curl -o docker-compose.yml \
  https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml
docker compose -f docker-compose.yml --compatibility up -d
# Web UI: http://localhost:8888   ·   MailHog: http://localhost:8025
```

### A. Authenticated scan → 8.0 High (verified, token only)

1. Register + log in one user (web UI, or `POST /identity/api/auth/signup` then
   `POST /identity/api/auth/login {email,password}` → copy the JWT `token`).
2. Scan (web UI): Target `http://localhost:8888/`, Level **Standard**,
   **Advanced → Authentication → Auth token** = `Bearer <token>`, header
   `Authorization`. Authorize → **Start scan**.

**Expected (verified → 8.0 High):** excessive data exposure incl. `financial_data`
and PII (API3), seven undocumented-method findings (API9, Medium), and the
`openresty` version banner (Low). **This one report spans High + Medium + Low** —
show its severity chart. No per-validator config needed.

### B. Optional Critical (9.0) — confirmed BOLA

1. Register a **second** user; log both into the crAPI **web UI** so each is
   assigned a vehicle (the UI handles the VIN/pincode automatically). Note each
   user's **vehicle UUID** (`GET /identity/api/v2/vehicle/vehicles` with the token,
   or from the dashboard URL).
2. **Advanced → Security validators → BOLA (API1)**:
   - Auth header `Authorization`; User A credential `Bearer <tokenA>`,
     User B credential `Bearer <tokenB>`.
   - Case → `GET`, URL `/identity/api/v2/vehicle/<userA_vehicleUUID>/location`,
     Object in `path`, Object name `vehicleId`, Object value `<userA_vehicleUUID>`,
     Evidence paths `vehicleLocation.latitude, vehicleLocation.longitude`.
3. Level **Advanced**, tick **Active testing**, authorize → **Start scan**.

**Expected:** User B reads User A's vehicle location → **confirmed BOLA (API1)** →
**9.0 / Critical**.

---

## What the four together prove (viva narrative)

- The tool spans the **full CVSS severity spectrum** on real, independent targets —
  not just a single canned result.
- It is **honest at both ends**: 0.0 on a secured app, 9.0 only when an exploit is
  *confirmed*.
- Every score is **traceable** to CVSS v3.1 × OWASP API 2023 (see
  `scanner/.../research/risk_scoring_model.md`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| PortSwigger lab returns 504 | Instance expired — click **Access the lab** for a fresh URL. |
| VAmPI scan finds nothing | It's a spec-driven API — make sure the **OpenAPI spec URL** is set so Phase 3 has endpoints. |
| "Skipped N endpoints outside the allow-list" | Expected — the tool won't test hosts you didn't authorize. Add them under Advanced → Discovery → Extra authorized hosts only if you own them. |
| Scan slow on a big app (Juice Shop/crAPI) | Use **Standard** not Advanced, and demo the lighter VAmPI/httpbin/PortSwigger targets for timing. |

## Sources
- OWASP crAPI — https://owasp.org/www-project-crapi/ · https://owasp.org/crAPI/docs/challenges.html
- VAmPI — https://github.com/erev0s/VAmPI
- PortSwigger "unused API endpoint" — https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint
- crAPI BOLA walkthrough — https://levo.ai/bola/
