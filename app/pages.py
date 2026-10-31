"""Server-rendered web pages.

Plain forms and redirects with no scripts or CDN files. The pages keep working
with the network off during the failure demo.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import yaml
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app import connectors, engine_client as engine, formbuilder, health
from store import db

ACTOR = "web"
KEV_SOURCE = "cisa-kev"
FAULT_MODES = ("503x3", "503x4", "429:30", "timeoutx4", "401", "badrecord")
AUTH_TYPES = ("none", "api_key", "basic", "bearer", "oauth2_client_credentials")
PAGING_TYPES = ("none", "link_header", "page_number", "offset", "body_token", "body_next_url")
ENTITY_PAGES = {"users": "user", "devices": "device", "alerts": "alert"}

templates = Jinja2Templates(directory=str(Path(__file__).parent / "web"))


def _render(request: Request, name: str, **context: Any) -> HTMLResponse:
    context.update(stubbed=engine.stubbed_functions(), msg=request.query_params.get("msg"))
    return templates.TemplateResponse(request, name, context)


def _redirect(path: str, msg: str) -> RedirectResponse:
    return RedirectResponse(f"{path}?msg={quote(msg)}", status_code=303)


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, default=str)


def _test_view(result: Any) -> dict[str, Any]:
    """Pair raw and mapped samples for the side-by-side table."""
    data = engine.to_dict(result)
    raw = data.get("sample_raw") or []
    mapped = data.get("sample_mapped") or []
    clean_mapped = [{k: v for k, v in row.items() if k != "raw"} for row in mapped]
    pairs = [
        {
            "raw": _pretty(raw[i]) if i < len(raw) else "",
            "mapped": _pretty(clean_mapped[i]) if i < len(clean_mapped) else "",
        }
        for i in range(max(len(raw), len(clean_mapped)))
    ]
    return {**data, "pairs": pairs}


def build_router(
    run_and_alert: Callable[[str], dict[str, Any]],
    replay_quarantined: Callable[[int, str], dict[str, Any]],
) -> APIRouter:
    router = APIRouter(include_in_schema=False)

    def connector_page(request: Request, name: str, test: dict[str, Any] | None = None) -> HTMLResponse:
        connector = db.get_connector(name)
        if connector is None:
            raise HTTPException(404, f"unknown connector {name!r}")
        return _render(
            request,
            "connector.html",
            connector=connector,
            row=health.connector_row(connector),
            runs=db.list_runs(name, limit=20),
            quarantine=db.list_quarantine(name, limit=50),
            test=test,
        )

    @router.get("/", response_class=HTMLResponse)
    def health_page(request: Request) -> HTMLResponse:
        return _render(request, "health.html", rows=health.health_rows())

    @router.get("/ui/connector/{name}", response_class=HTMLResponse)
    def connector_view(request: Request, name: str) -> HTMLResponse:
        return connector_page(request, name)

    @router.post("/ui/connector/{name}/{action}")
    def connector_action(
        request: Request, name: str, action: str, background: BackgroundTasks
    ) -> Response:
        if db.get_connector(name) is None:
            raise HTTPException(404, f"unknown connector {name!r}")
        back = "/"
        if action == "test":
            return connector_page(request, name, test=_test_view(engine.test_connection(name)))
        if action == "run":
            background.add_task(run_and_alert, name)
            message = f"{name}: run started"
        elif action == "pause":
            engine.pause(name)
            db.audit(ACTOR, "connector.pause", name)
            message = f"{name}: paused"
        elif action == "resume":
            engine.resume(name)
            db.audit(ACTOR, "connector.resume", name)
            message = f"{name}: resumed"
        elif action == "approve":
            connectors.approve(name, ACTOR)
            back = f"/ui/connector/{quote(name)}"
            message = "Config approved"
        else:
            raise HTTPException(404, f"unknown action {action!r}")
        return _redirect(back, message)

    @router.post("/ui/quarantine/{quarantine_id}/replay")
    def replay_action(quarantine_id: int) -> Response:
        outcome = replay_quarantined(quarantine_id, ACTOR)
        name = db.get_quarantine(quarantine_id)["connector"]
        message = "Record replayed" if outcome["ok"] else f"Still invalid: {outcome['reason']}"
        return _redirect(f"/ui/connector/{quote(name)}", message)

    def add_page(request: Request, form: dict[str, str], **extra: Any) -> HTMLResponse:
        return _render(
            request,
            "add_source.html",
            form=form,
            auth_types=AUTH_TYPES,
            paging_types=PAGING_TYPES,
            problems=extra.pop("problems", []),
            **extra,
        )

    @router.get("/ui/add", response_class=HTMLResponse)
    def add_view(request: Request) -> HTMLResponse:
        return add_page(request, formbuilder.default_form())

    @router.post("/ui/add")
    async def add_action(request: Request) -> Response:
        submitted = await request.form()
        form = {key: str(value) for key, value in submitted.items()}
        action = form.pop("action", "build")
        sample = form.pop("sample", "")

        if action == "sample":
            if not sample.strip():
                return add_page(
                    request,
                    form,
                    sample=sample,
                    problems=[{"path": "sample", "message": "paste a sample first", "hint": ""}],
                )
            entity = form.get("entity") or None
            profile = engine.profile_sample(sample, entity=entity)
            filled = formbuilder.yaml_to_form(profile["draft_yaml"])
            preview = [
                {"raw": _pretty(r), "mapped": _pretty(m)}
                for r, m in zip(profile["preview_raw"], profile["preview_mapped"])
            ] or [{"raw": _pretty(r), "mapped": ""} for r in profile["preview_raw"]]
            return add_page(request, filled, sample=sample, profile=profile, preview=preview)

        if action == "build" or not form.get("yaml", "").strip():
            built, problems = formbuilder.form_to_yaml(form)
            form["yaml"] = built
            if action == "build" or problems:
                return add_page(request, form, sample=sample, problems=problems)

        text = form["yaml"]
        checked = engine.validate_config(text)
        problems = connectors.errors_only(checked)
        warnings = connectors.warnings_only(checked)
        if problems:
            return add_page(request, form, sample=sample, problems=problems, warnings=warnings)
        if action == "validate":
            return add_page(request, form, sample=sample, valid=True, warnings=warnings)
        if action == "test":
            result = engine.test_connection(engine.load_config(text))
            return add_page(request, form, sample=sample, test=_test_view(result), warnings=warnings)
        if action == "save":
            problems = connectors.save_and_approve(text, ACTOR)
            if problems:
                return add_page(request, form, sample=sample, problems=problems)
            name = yaml.safe_load(text)["name"]
            return _redirect(f"/ui/connector/{quote(name)}", "Connector saved and approved")
        raise HTTPException(400, f"unknown action {action!r}")

    @router.get("/ui/records/{entity}", response_class=HTMLResponse)
    def records_page(
        request: Request, entity: str, source: str | None = None, q: str | None = None
    ) -> HTMLResponse:
        if entity not in ENTITY_PAGES:
            raise HTTPException(404, f"unknown entity {entity!r}")
        return _render(
            request,
            "records.html",
            entity=entity,
            columns=("source", "id", *db.ENTITY_COLUMNS[entity], "fetched_at"),
            rows=db.query_records(entity, source=source or None, q=q or None),
            sources=db.list_sources(entity),
            source=source or "",
            q=q or "",
        )

    @router.get("/ui/people", response_class=HTMLResponse)
    def people_page(request: Request, email: str | None = None) -> HTMLResponse:
        return _render(
            request,
            "people.html",
            emails=db.list_emails(),
            email=email or "",
            records=db.person_records(email) if email else None,
            user_columns=("source", "id", "name", "status", "last_login"),
            device_columns=("source", "id", "hostname", "ip", "os", "last_seen"),
            alert_columns=("source", "id", "type", "severity", "timestamp", "description"),
        )

    @router.get("/ui/kev", response_class=HTMLResponse)
    def kev_page(request: Request) -> HTMLResponse:
        return _render(
            request,
            "kev.html",
            rows=db.kev_matches(KEV_SOURCE),
            kev_count=db.count_records("alert", KEV_SOURCE),
            kev_source=KEV_SOURCE,
            columns=("source", "id", "cve", "severity", "timestamp", "description"),
        )

    @router.get("/ui/demo", response_class=HTMLResponse)
    def demo_page(request: Request) -> HTMLResponse:
        return _render(
            request, "demo.html", connectors=db.list_connectors(), modes=FAULT_MODES
        )

    @router.post("/ui/demo")
    async def demo_action(request: Request) -> Response:
        form = await request.form()
        name, mode = str(form.get("connector")), str(form.get("mode"))
        if db.get_connector(name) is None:
            raise HTTPException(404, f"unknown connector {name!r}")
        if mode == "off":
            engine.clear_fault(name)
            message = f"{name}: fault cleared"
        else:
            if mode not in FAULT_MODES:
                raise HTTPException(400, f"unknown fault mode {mode!r}")
            engine.set_fault(name, mode)
            message = f"{name}: fault {mode} set"
        db.audit(ACTOR, "fault.set", name, mode)
        return _redirect("/ui/demo", message)

    @router.get("/ui/audit", response_class=HTMLResponse)
    def audit_page(request: Request) -> HTMLResponse:
        return _render(request, "audit.html", rows=db.list_audit())

    return router
