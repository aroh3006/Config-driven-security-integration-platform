"""Developer CLI for the engine, usable before the web app exists.

  python -m engine validate configs/okta-users.yaml
  python -m engine test     configs/okta-users.yaml        # 1 page, nothing stored
  python -m engine run      configs/okta-users.yaml        # full run into the store
  python -m engine profile  sample.json [--entity alert] [--name cisa-kev] [--out configs/x.yaml]
  python -m engine fault    okta-users 503x3              # then `run` to see 1s/2s/4s
  python -m engine serve    [--configs configs]           # load every config and run the scheduler

The Typer CLI (app/cli.py) is the user-facing one. This one is for engine work and demos.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from . import faults, profile_sample, run_connector, save_and_approve, scheduler, test_connection, validate_config
from .memstore import default_store


def _print_problems(problems: list[dict]) -> None:
    for p in problems:
        tip = f"  -> {p['hint']}" if p.get("hint") else ""
        print(f"  [{p['level']}] {p['path'] or '(top)'}: {p['message']}{tip}")


def _print_result(res, verbose: bool) -> None:
    d = res.to_dict()
    print(f"{res.connector}: {res.status}  pulled={res.records_pulled} bad={res.records_bad} "
          f"pages={res.pages} retries={res.retries} waits={d['waits']}")
    if res.last_error:
        print(f"  last error: {d['last_error']}")
    for r in d["requests"][: (50 if verbose else 6)]:
        note = f" ({r['note']})" if r.get("note") else ""
        print(f"  {r['method']} {r['url_masked']} -> {r['status']} {r['ms']}ms attempt {r['attempt']}{note}")
    if d["sample_mapped"]:
        print("  mapped sample:")
        for row in d["sample_mapped"][:3]:
            print("   ", json.dumps({k: v for k, v in row.items() if k not in ("fetched_at", "tenant_id")}, default=str))
    for q in d["quarantined"][:5]:
        print(f"  quarantined: {q['reason']}")
    if d["unmapped_fields"]:
        print(f"  unmapped fields: {', '.join(d['unmapped_fields'][:15])}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m engine")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "test", "run"):
        sp = sub.add_parser(name)
        sp.add_argument("config")
    sp = sub.add_parser("profile")
    sp.add_argument("sample")
    sp.add_argument("--entity", choices=["user", "device", "alert"])
    sp.add_argument("--name")
    sp.add_argument("--base-url")
    sp.add_argument("--path")
    sp.add_argument("--method", default="GET")
    sp.add_argument("--out")
    sp = sub.add_parser("fault")
    sp.add_argument("connector")
    sp.add_argument("mode")
    sp = sub.add_parser("serve")
    sp.add_argument("--configs", default="configs")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(asctime)s %(name)s %(message)s")

    if args.cmd == "validate":
        problems = validate_config(Path(args.config).read_text(encoding="utf-8"))
        print("valid" if not [p for p in problems if p["level"] == "error"] else "INVALID")
        _print_problems(problems)
        return 1 if [p for p in problems if p["level"] == "error"] else 0

    if args.cmd == "test":
        res = test_connection(Path(args.config).read_text(encoding="utf-8"))
        _print_problems(res.validation)
        _print_result(res, args.verbose)
        return 0 if res.ok else 1

    if args.cmd == "run":
        text = Path(args.config).read_text(encoding="utf-8")
        saved = save_and_approve(text, actor="cli")
        if not saved["ok"]:
            _print_problems(saved["errors"])
            return 1
        res = run_connector(saved["name"])
        _print_result(res, args.verbose)
        return 0 if res.ok else 1

    if args.cmd == "profile":
        out = profile_sample(Path(args.sample).read_text(encoding="utf-8"), args.entity, name=args.name,
                             base_url=args.base_url, path=args.path, method=args.method.upper())
        print(out["draft_yaml"])
        print(f"# entity={out['entity']} records={out['record_count']} confidence={out['confidence']}")
        print(f"# paging: {out['paging_guess']}")
        for n in out["notes"]:
            print(f"# note: {n}")
        _print_problems(out["validation"])
        print("# preview (first 2 mapped):")
        for row in out["preview_mapped"][:2]:
            print("#  ", json.dumps(row, default=str))
        if args.out:
            Path(args.out).write_text(out["draft_yaml"], encoding="utf-8")
            print(f"# written to {args.out}")
        return 0

    if args.cmd == "fault":
        print(faults.set_fault(args.connector, args.mode))
        print("note: faults live in this process; use them from `serve` or the web app for demos")
        return 0

    if args.cmd == "serve":
        store = default_store()
        for path in sorted(Path(args.configs).glob("*.y*ml")):
            saved = save_and_approve(path.read_text(encoding="utf-8"), store=store, actor="startup")
            print(f"{path.name}: {'loaded' if saved['ok'] else 'INVALID'}")
            if not saved["ok"]:
                _print_problems(saved["errors"])
        scheduler.start(store)
        try:
            while True:
                time.sleep(15)
                for c in store.list_connectors():
                    print(f"  {c['name']}: {c.get('status')}")
        except KeyboardInterrupt:
            scheduler.get_scheduler().stop()
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
