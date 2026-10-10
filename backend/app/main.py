"""FastAPI application: auth, scan orchestration, SSE progress, dual reporting."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app import ai_analysis, auth, cve, cvedb, db, enrichment, reports
from app.config import FRONTEND_DIR, REPORTS_DIR, SECRET_KEY
from app.secrets_guard import install_log_filter, scrub
from app.scanner_adapter import (
    AuthorizationRequired,
    LEVEL_LABELS,
    build_config,
    normalize_target,
)
from app.scans import manager

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("sas.webapp")

app = FastAPI(title="Shadow API Scanner", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY,
                   same_site="lax", https_only=False, max_age=8 * 3600)


# Strong references to background tasks (asyncio only keeps weak ones).
_background: set = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)
    return task


def _enrich_after_scan(job) -> None:
    """Scan finished successfully: start enrichment as a separate stage."""
    db.set_enrichment_status(job.id, "pending")
    _spawn(enrichment.run(job.id, job.output_dir, trigger="scan"))


@app.on_event("startup")
def _startup() -> None:
    install_log_filter()
    db.init_db()
    auth.ensure_first_run_admin()
    manager.on_completed = _enrich_after_scan
    # Enrichment that was running when the process stopped cannot resume.
    for sid in db.all_scan_ids():
        if sid.isalnum() and (REPORTS_DIR / sid).is_dir():
            enrichment.mark_interrupted(REPORTS_DIR / sid)


# -- auth dependencies -----------------------------------------------------

def current_user(request: Request) -> str:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def ready_user(request: Request) -> str:
    user = current_user(request)
    if request.session.get("must_change"):
        raise HTTPException(status_code=403,
                            detail="Password change required before use")
    return user


def require_admin(request: Request) -> str:
    user = ready_user(request)
    if request.session.get("role") != "admin":
        raise HTTPException(status_code=403,
                            detail="Administrator access required")
    return user


# -- auth routes -----------------------------------------------------------

@app.post("/api/login")
async def login(request: Request) -> JSONResponse:
    body = await request.json()
    result = auth.authenticate(body.get("username", ""), body.get("password", ""))
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    request.session["user"] = result["username"]
    request.session["must_change"] = result["must_change_password"]
    request.session["role"] = result["role"]
    return JSONResponse({"username": result["username"],
                         "must_change_password": result["must_change_password"],
                         "role": result["role"]})


@app.post("/api/change-password")
async def change_password(request: Request) -> JSONResponse:
    user = current_user(request)
    body = await request.json()
    new_password = body.get("new_password", "")
    err = auth.is_strong_enough(new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    db.set_password(user, auth.hash_password(new_password))
    request.session["must_change"] = False
    return JSONResponse({"ok": True})


@app.post("/api/logout")
async def logout(request: Request) -> JSONResponse:
    request.session.clear()
    return JSONResponse({"ok": True})


@app.get("/api/me")
async def me(request: Request) -> JSONResponse:
    user = current_user(request)
    return JSONResponse({"username": user,
                         "must_change_password": bool(request.session.get("must_change")),
                         "role": request.session.get("role", "user"),
                         "levels": LEVEL_LABELS})


# -- user management (admin only) ------------------------------------------

@app.get("/api/users")
async def users_list(request: Request) -> JSONResponse:
    require_admin(request)
    return JSONResponse({"users": db.list_users()})


@app.post("/api/users")
async def users_create(request: Request) -> JSONResponse:
    require_admin(request)
    body = await request.json()
    try:
        temp_password = auth.create_managed_user(
            body.get("username", ""), body.get("role", "user"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return JSONResponse({"username": body.get("username"),
                         "role": body.get("role", "user"),
                         "temporary_password": temp_password})


@app.delete("/api/users/{username}")
async def users_delete(username: str, request: Request) -> JSONResponse:
    admin = require_admin(request)
    target = db.get_user(username)
    if target is None:
        raise HTTPException(status_code=404, detail="No such user")
    if username == admin:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    if target["role"] == "admin" and db.count_admins() <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last administrator")
    db.delete_user(username)
    return JSONResponse({"ok": True})


# -- scan routes -----------------------------------------------------------

@app.post("/api/precheck")
async def scan_precheck(request: Request) -> JSONResponse:
    """Before scanning, confirm the target is a SPA and/or uses APIs."""
    ready_user(request)
    body = await request.json()
    try:
        target = normalize_target(body.get("target_url", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return JSONResponse(await cve.precheck(target))


@app.post("/api/scan")
async def start_scan(request: Request) -> JSONResponse:
    user = ready_user(request)
    body = await request.json()
    target = body.get("target_url", "")
    level = body.get("level", "basic")
    authorized = bool(body.get("authorized_confirmed", False))
    options = body.get("options") or {}
    job = manager.create(user, target, level)
    try:
        config, secret_env = build_config(
            target, level, authorized, str(job.output_dir),
            options=options, scan_id=job.id,
        )
    except AuthorizationRequired as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        # OptionsError subclasses ValueError; both surface as a 400.
        raise HTTPException(status_code=400, detail=str(exc))
    _spawn(manager.run(job, config, secret_env))
    return JSONResponse({"scan_id": job.id, "level": level,
                         "target_url": config.target_url})


@app.get("/api/scan/{scan_id}/stream")
async def scan_stream(scan_id: str, request: Request) -> StreamingResponse:
    ready_user(request)
    job = manager.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan")

    async def event_source():
        while True:
            if await request.is_disconnected():
                break
            try:
                event = job.events.get_nowait()
            except Exception:
                await asyncio.sleep(0.3)
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event.get("type") in ("done", "error"):
                break

    return StreamingResponse(event_source(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


@app.get("/api/scans")
async def scans_history(request: Request) -> JSONResponse:
    user = ready_user(request)
    return JSONResponse({"scans": db.list_scans(user)})


# -- report routes ---------------------------------------------------------

def _scan_dir(scan_id: str, username: str):
    """Resolve a scan's report directory from disk (restart-safe) with an
    ownership check, rather than relying on the in-memory job."""
    if not scan_id.isalnum():
        raise HTTPException(status_code=400, detail="Invalid scan id")
    owned = {s["id"] for s in db.list_scans(username, limit=1000)}
    if scan_id not in owned:
        raise HTTPException(status_code=404, detail="Unknown scan")
    path = REPORTS_DIR / scan_id
    if not path.is_dir():
        raise HTTPException(status_code=404, detail="Unknown scan")
    return path


def _report_json(scan_id: str, username: str):
    scan_dir = _scan_dir(scan_id, username)
    files = sorted(scan_dir.glob("scan_report_*.json"))
    if not files:
        raise HTTPException(status_code=404, detail="Report not ready")
    return reports.load_report(files[-1]), scan_dir


@app.get("/api/scan/{scan_id}/summary")
async def scan_summary(scan_id: str, request: Request) -> JSONResponse:
    user = ready_user(request)
    report, _ = _report_json(scan_id, user)
    return JSONResponse(reports.summary_view(report))


@app.get("/api/scan/{scan_id}/technical")
async def scan_technical(scan_id: str, request: Request) -> JSONResponse:
    user = ready_user(request)
    report, _ = _report_json(scan_id, user)
    return JSONResponse(reports.technical_view(report))


@app.post("/api/scan/{scan_id}/cve-check")
async def scan_cve_check(scan_id: str, request: Request) -> JSONResponse:
    """Legacy endpoint (kept for compatibility): an explicit component re-check.
    Re-fingerprints the target, matches against the LOCAL CVE database and
    returns the persisted enrichment. It no longer queries NVD live."""
    user = ready_user(request)
    scan_dir = _scan_dir(scan_id, user)
    _report_json(scan_id, user)
    data = await enrichment.run(scan_id, scan_dir, trigger="recheck", refingerprint=True)
    return JSONResponse(data)


# -- enrichment ------------------------------------------------------------

@app.get("/api/scan/{scan_id}/enrichment")
async def scan_enrichment(scan_id: str, request: Request) -> JSONResponse:
    user = ready_user(request)
    scan_dir = _scan_dir(scan_id, user)
    data = enrichment.load(scan_dir)
    if data is None:
        return JSONResponse({"schema_version": enrichment.SCHEMA_VERSION,
                             "status": "not_run", "scan_id": scan_id,
                             "message": "Enrichment has not run for this scan "
                                        "(older scan or still pending)."})
    return JSONResponse(data)


@app.post("/api/scan/{scan_id}/enrichment/recheck")
async def scan_enrichment_recheck(scan_id: str, request: Request) -> JSONResponse:
    """Explicit re-check. ``refingerprint`` (default true) contacts the target
    again; false re-matches the stored components against the local CVE
    database without contacting the target. Each run gets new timestamps."""
    user = ready_user(request)
    scan_dir = _scan_dir(scan_id, user)
    _report_json(scan_id, user)
    try:
        body = await request.json()
    except Exception:
        body = {}
    refp = bool((body or {}).get("refingerprint", True))
    current = enrichment.load(scan_dir)
    if current and current.get("status") == "running":
        raise HTTPException(status_code=409, detail="Enrichment is already running")
    db.set_enrichment_status(scan_id, "pending")
    _spawn(enrichment.run(scan_id, scan_dir,
                          trigger="recheck" if refp else "rematch", refingerprint=refp))
    return JSONResponse({"ok": True, "status": "pending", "refingerprint": refp},
                        status_code=202)


@app.get("/api/cvedb/status")
async def cvedb_status(request: Request) -> JSONResponse:
    ready_user(request)
    st = cvedb.status()
    st["update_job"] = {k: _cvedb_job.get(k) for k in ("running", "mode", "started_at",
                                                          "finished_at", "error")}
    return JSONResponse(st)


@app.get("/api/ai/status")
async def ai_status(request: Request) -> JSONResponse:
    ready_user(request)
    return JSONResponse(ai_analysis.status())


_cvedb_job: dict = {"running": False, "mode": None, "started_at": None,
                    "finished_at": None, "messages": [], "result": None, "error": None}


@app.post("/api/admin/cvedb/update")
async def cvedb_update(request: Request) -> JSONResponse:
    """Administrator-triggered NVD download into the local CVE database."""
    require_admin(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    mode = (body or {}).get("mode", "incremental")
    if mode not in ("incremental", "full"):
        raise HTTPException(status_code=400, detail="mode must be 'incremental' or 'full'")
    if _cvedb_job["running"]:
        raise HTTPException(status_code=409, detail="An update is already running")
    import time as _t
    _cvedb_job.update(running=True, mode=mode, started_at=_t.time(), finished_at=None,
                      messages=[], result=None, error=None)

    def progress(msg: str) -> None:
        _cvedb_job["messages"] = (_cvedb_job["messages"] + [scrub(str(msg))])[-50:]

    async def job() -> None:
        try:
            _cvedb_job["result"] = await asyncio.to_thread(
                cvedb.update_from_nvd, None, mode=mode, progress=progress)
        except Exception as exc:
            _cvedb_job["error"] = scrub(str(exc))[:400]
        finally:
            _cvedb_job.update(running=False, finished_at=_t.time())

    _spawn(job())
    return JSONResponse({"ok": True, "mode": mode}, status_code=202)


@app.get("/api/admin/cvedb/update")
async def cvedb_update_status(request: Request) -> JSONResponse:
    require_admin(request)
    return JSONResponse(_cvedb_job)


@app.get("/api/scan/{scan_id}/export.csv")
async def export_csv(scan_id: str, request: Request) -> PlainTextResponse:
    user = ready_user(request)
    report, scan_dir = _report_json(scan_id, user)
    return PlainTextResponse(
        reports.export_csv(report, enrichment.load(scan_dir)), media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="scan_{scan_id}.csv"'})


@app.get("/api/scan/{scan_id}/export.json")
async def export_json(scan_id: str, request: Request) -> JSONResponse:
    user = ready_user(request)
    report, scan_dir = _report_json(scan_id, user)
    return JSONResponse(reports.export_json(report, enrichment.load(scan_dir)),
                        headers={"Content-Disposition":
                                 f'attachment; filename="scan_{scan_id}.json"'})


@app.get("/api/scan/{scan_id}/export.pdf")
async def export_pdf(scan_id: str, request: Request) -> Response:
    user = ready_user(request)
    scan_dir = _scan_dir(scan_id, user)
    htmls = sorted(scan_dir.glob("scan_report_*.html"))
    if not htmls:
        raise HTTPException(status_code=404, detail="HTML report not ready")
    # Use the saved enriched HTML so the PDF matches the UI; (re)build it from
    # the persisted enrichment if needed. Never rescans the target.
    source = htmls[-1]
    data = enrichment.load(scan_dir)
    if data and data.get("status") not in ("running", "pending"):
        enriched = scan_dir / enrichment.ENRICHED_HTML
        if not enriched.exists() or enriched.stat().st_mtime < (scan_dir / enrichment.ENRICHMENT_FILE).stat().st_mtime:
            enrichment.write_enriched_html(scan_dir, source, data)
        source = enriched
    pdf = await reports.export_pdf(source)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="scan_{scan_id}.pdf"'})


# -- page routing (separate pages with server-side guards) -----------------

def _session_state(request: Request) -> tuple[str | None, bool]:
    return request.session.get("user"), bool(request.session.get("must_change"))


@app.get("/login", include_in_schema=False)
async def page_login() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "login.html")


@app.get("/set-password", include_in_schema=False)
async def page_set_password(request: Request):
    user, _ = _session_state(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    return FileResponse(FRONTEND_DIR / "set-password.html")


@app.get("/profile", include_in_schema=False)
async def page_profile(request: Request):
    user, must_change = _session_state(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if must_change:
        return RedirectResponse("/set-password", status_code=302)
    return FileResponse(FRONTEND_DIR / "profile.html")


@app.get("/", include_in_schema=False)
async def page_app(request: Request):
    user, must_change = _session_state(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if must_change:
        return RedirectResponse("/set-password", status_code=302)
    return FileResponse(FRONTEND_DIR / "app.html")


# Static assets (css / js / vendored Chart.js). Mounted last; /api and the
# page routes above take precedence.
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR / "static")),
          name="static")
