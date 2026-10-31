"""FastAPI app: JSON routes over the engine and store, plus the web pages."""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app import connectors, engine_client as engine, health, notify, pages, runlog
from store import db

log = logging.getLogger(__name__)

ACTOR = "api"
STATIC_DIR = Path(__file__).parent / "static"


class ConfigBody(BaseModel):
    yaml: str


class SampleBody(BaseModel):
    text: str
    entity: str | None = None


class FaultBody(BaseModel):
    connector: str
    mode: str


def _require_connector(name: str) -> dict[str, Any]:
    connector = db.get_connector(name)
    if connector is None:
        raise HTTPException(404, f"unknown connector {name!r}")
    return connector


def run_and_alert(name: str) -> dict[str, Any]:
    """Run a connector, then send any alert the result calls for."""
    result = engine.to_dict(engine.run_connector(name))
    notify.sweep()
    return result


def replay_quarantined(quarantine_id: int, actor: str) -> dict[str, Any]:
    """Try a quarantined record again with the connector's current config."""
    item = db.get_quarantine(quarantine_id)
    if item is None:
        raise HTTPException(404, f"unknown quarantine id {quarantine_id}")
    connector = _require_connector(item["connector"])
    outcome = engine.replay_record(item["connector"], connectors.load_raw(item))
    if outcome["ok"]:
        db.upsert(connector["entity"], item["connector"], [outcome["row"]])
        db.mark_replayed(quarantine_id)
    db.audit(actor, "quarantine.replay", item["connector"], f"id {quarantine_id}: {outcome['ok']}")
    return outcome


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    db.init_db()
    report = connectors.import_configs()
    for key in ("skipped", "invalid", "changed"):
        if report[key]:
            log.warning("configs %s: %s", key, report[key])
    runlog.install()
    engine.start_scheduler()
    stop = threading.Event()
    sweeper = threading.Thread(target=notify.run_sweeper, args=(stop,), daemon=True)
    sweeper.start()
    yield
    stop.set()
    runlog.uninstall()


def create_app() -> FastAPI:
    app = FastAPI(title="Otto", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def same_origin_writes(request: Request, call_next: Any) -> Response:
        """Stop other websites posting to this local app through a browser."""
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            cross_site = request.headers.get("sec-fetch-site") == "cross-site"
            if cross_site or (origin and urlsplit(origin).netloc != request.headers.get("host")):
                return JSONResponse({"detail": "cross-site request refused"}, 403)
        return await call_next(request)

    @app.exception_handler(Exception)
    async def masked_errors(_: Request, exc: Exception) -> JSONResponse:
        log.error("request failed: %s", db.mask_text(str(exc)))
        return JSONResponse({"detail": db.mask_text(str(exc))}, 500)

    @app.post("/connectors/validate")
    def validate(body: ConfigBody) -> dict[str, Any]:
        problems = engine.validate_config(body.yaml)
        return {"valid": not connectors.errors_only(problems), "problems": problems}

    @app.post("/connectors", status_code=201)
    def create_connector(body: ConfigBody) -> Any:
        problems = connectors.save_and_approve(body.yaml, ACTOR)
        if problems:
            return JSONResponse({"valid": False, "problems": problems}, 422)
        return {"saved": True}

    @app.get("/connectors")
    def list_connectors() -> list[dict[str, Any]]:
        return db.list_connectors()

    @app.get("/connectors/{name}")
    def get_connector(name: str) -> dict[str, Any]:
        connector = _require_connector(name)
        return {
            **connector,
            "health": health.connector_row(connector),
            "runs": db.list_runs(name, limit=20),
        }

    @app.post("/connectors/{name}/test")
    def test_connector(name: str) -> dict[str, Any]:
        _require_connector(name)
        return engine.to_dict(engine.test_connection(name))

    @app.post("/connectors/{name}/run")
    def run_connector(name: str) -> dict[str, Any]:
        _require_connector(name)
        return run_and_alert(name)

    @app.post("/connectors/{name}/approve")
    def approve_connector(name: str) -> dict[str, bool]:
        _require_connector(name)
        connectors.approve(name, ACTOR)
        return {"approved": True}

    @app.post("/connectors/{name}/pause")
    def pause_connector(name: str) -> dict[str, str]:
        _require_connector(name)
        engine.pause(name)
        db.audit(ACTOR, "connector.pause", name)
        return {"status": db.get_connector(name)["status"]}

    @app.post("/connectors/{name}/resume")
    def resume_connector(name: str) -> dict[str, str]:
        _require_connector(name)
        engine.resume(name)
        db.audit(ACTOR, "connector.resume", name)
        return {"status": db.get_connector(name)["status"]}

    @app.get("/health")
    def get_health() -> dict[str, Any]:
        return {"stubbed": engine.stubbed_functions(), "connectors": health.health_rows()}

    @app.get("/records/{entity}")
    def get_records(entity: str, source: str | None = None, q: str | None = None) -> list[dict[str, Any]]:
        try:
            return db.query_records(entity, source=source, q=q)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.get("/quarantine")
    def get_quarantine(connector: str | None = None) -> list[dict[str, Any]]:
        return db.list_quarantine(connector)

    @app.post("/quarantine/{quarantine_id}/replay")
    def replay(quarantine_id: int) -> dict[str, Any]:
        return replay_quarantined(quarantine_id, ACTOR)

    @app.get("/audit")
    def get_audit() -> list[dict[str, Any]]:
        return db.list_audit()

    @app.post("/onboard/sample")
    def onboard(body: SampleBody) -> dict[str, Any]:
        return engine.profile_sample(body.text, entity=body.entity)

    @app.post("/faults")
    def set_fault(body: FaultBody) -> dict[str, str]:
        _require_connector(body.connector)
        if body.mode == "off":
            engine.clear_fault(body.connector)
        else:
            try:
                engine.set_fault(body.connector, body.mode)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        db.audit(ACTOR, "fault.set", body.connector, body.mode)
        return {"connector": body.connector, "mode": body.mode}

    app.include_router(pages.build_router(run_and_alert, replay_quarantined))
    return app


app = create_app()
