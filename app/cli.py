"""Command line for the platform: python -m app.cli --help"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import uvicorn

from app import connectors, engine_client as engine, health, notify
from store import db

ACTOR = "cli"
FAILED_STATUSES = ("failed", "auth_failed", "config_changed", "paused", "skipped")

cli = typer.Typer(no_args_is_help=True, add_completion=False)
quarantine_cli = typer.Typer(no_args_is_help=True, help="List or replay quarantined records.")
cli.add_typer(quarantine_cli, name="quarantine")


@cli.callback()
def setup() -> None:
    db.init_db()


def _require_connector(name: str) -> None:
    if db.get_connector(name) is None:
        typer.echo(f"Unknown connector {name!r}. Run import-configs or add it first.", err=True)
        raise typer.Exit(2)


def _print_result(result: dict[str, Any]) -> None:
    typer.echo(
        f"status={result['status']} pulled={result['records_pulled']} bad={result['records_bad']} "
        f"pages={result['pages']} retries={result['retries']}"
    )
    if result.get("last_error"):
        typer.echo(f"last error: {result['last_error']}")


def _warn_if_stubbed() -> None:
    stubbed = engine.stubbed_functions()
    if stubbed:
        typer.echo(f"WARNING: engine stubs active, data is fake: {', '.join(stubbed)}", err=True)


@cli.command()
def validate(file: Path) -> None:
    """Check a config file and print clear errors."""
    problems = engine.validate_config(file.read_text(encoding="utf-8"))
    for problem in problems:
        level = problem.get("level", "error")
        typer.echo(f"{level}: {problem['path'] or 'config'}: {problem['message']}. {problem['hint']}")
    if connectors.errors_only(problems):
        raise typer.Exit(1)
    typer.echo(f"{file}: valid")


@cli.command(name="test")
def test_command(name: str) -> None:
    """Dry run: one page, three mapped rows, nothing stored."""
    _require_connector(name)
    _warn_if_stubbed()
    result = engine.to_dict(engine.test_connection(name))
    _print_result(result)
    for row in result.get("sample_mapped") or []:
        typer.echo(json.dumps({k: v for k, v in row.items() if k != "raw"}, default=str))
    if result.get("unmapped_fields"):
        typer.echo(f"unmapped fields: {', '.join(result['unmapped_fields'])}")
    if result["status"] in FAILED_STATUSES:
        raise typer.Exit(1)


@cli.command()
def run(name: str) -> None:
    """Run a connector now and store the results."""
    _require_connector(name)
    _warn_if_stubbed()
    result = engine.to_dict(engine.run_connector(name))
    notify.sweep()
    _print_result(result)
    if result["status"] in FAILED_STATUSES:
        raise typer.Exit(1)


@cli.command(name="health")
def health_command() -> None:
    """Show status, last run, records and last error per connector."""
    _warn_if_stubbed()
    rows = health.health_rows()
    if not rows:
        typer.echo("No connectors yet. Run import-configs first.")
    for row in rows:
        mock = " [mock]" if row["mock"] else ""
        typer.echo(f"{row['summary']}{mock} (next run: {row['next_run']})")
        if row["last_error"]:
            typer.echo(f"  last error: {row['last_error']}")


@cli.command()
def pause(name: str) -> None:
    """Stop scheduled runs for a connector (kill switch)."""
    _require_connector(name)
    engine.pause(name)
    db.audit(ACTOR, "connector.pause", name)
    typer.echo(f"{name}: paused")


@cli.command()
def resume(name: str) -> None:
    """Start scheduled runs again."""
    _require_connector(name)
    engine.resume(name)
    db.audit(ACTOR, "connector.resume", name)
    typer.echo(f"{name}: resumed")


@cli.command()
def approve(name: str) -> None:
    """Approve a config that changed on disk."""
    _require_connector(name)
    connectors.approve(name, ACTOR)
    typer.echo(f"{name}: approved")


@cli.command(name="import-configs")
def import_configs() -> None:
    """Load the configs folder into the store."""
    report = connectors.import_configs(ACTOR)
    for key in ("added", "changed", "unchanged", "skipped"):
        if report[key]:
            typer.echo(f"{key}: {', '.join(report[key])}")
    if report["changed"]:
        typer.echo("Changed configs will not run until approved. Use: approve <name>")
    if report["skipped"]:
        typer.echo("Skipped files still have YOUR-... placeholders to fill in.")
    for item in report["invalid"]:
        typer.echo(f"invalid: {item['file']}")
        for problem in item["problems"]:
            typer.echo(f"  {problem['path'] or 'config'}: {problem['message']}")
    if report["invalid"]:
        raise typer.Exit(1)


@quarantine_cli.command(name="list")
def quarantine_list(connector: str = typer.Option(None, help="Only this connector.")) -> None:
    """List quarantined records with reasons."""
    items = db.list_quarantine(connector)
    if not items:
        typer.echo("Nothing quarantined.")
    for item in items:
        state = "replayed" if item["replayed"] else "waiting"
        typer.echo(f"{item['id']}  {item['connector']}  {state}  {item['reason']}")


@quarantine_cli.command(name="replay")
def quarantine_replay(quarantine_id: int) -> None:
    """Try a quarantined record again."""
    item = db.get_quarantine(quarantine_id)
    if item is None:
        typer.echo(f"Unknown quarantine id {quarantine_id}.", err=True)
        raise typer.Exit(2)
    _require_connector(item["connector"])
    outcome = engine.replay_record(item["connector"], connectors.load_raw(item))
    if outcome["ok"]:
        entity = db.get_connector(item["connector"])["entity"]
        db.upsert(entity, item["connector"], [outcome["row"]])
        db.mark_replayed(quarantine_id)
        typer.echo("Replayed.")
    db.audit(ACTOR, "quarantine.replay", item["connector"], f"id {quarantine_id}: {outcome['ok']}")
    if not outcome["ok"]:
        typer.echo(f"Still invalid: {outcome['reason']}")
        raise typer.Exit(1)


@cli.command()
def onboard(sample_file: Path, entity: str = typer.Option(None, help="user, device or alert.")) -> None:
    """Draft a config from a sample file."""
    _warn_if_stubbed()
    profile = engine.profile_sample(sample_file.read_text(encoding="utf-8"), entity=entity)
    typer.echo(profile["draft_yaml"])
    confidence = profile["confidence"]
    level = confidence.get("level") if isinstance(confidence, dict) else confidence
    typer.echo(f"# confidence: {level}, paging guess: {profile['paging_guess']}")


@cli.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Address to bind."),
    port: int = typer.Option(8000, help="Port to bind."),
) -> None:
    """Start the web app and scheduler."""
    uvicorn.run("app.api:app", host=host, port=port, access_log=False)


if __name__ == "__main__":
    cli()
