"""End-to-end check of the store and engine client on a throwaway database.

Run with: python -m app.smoke
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

CONFIG = """\
name: okta-users
entity: user
source:
  type: http
  base_url: https://example.okta.com
  allow_hosts: [example.okta.com]
auth:
  type: api_key
  header: Authorization
  prefix: "SSWS "
  secret: okta_key
pagination:
  type: link_header
schedule: every 15m
map:
  id: id
  email: profile.login
"""


def main() -> None:
    with tempfile.TemporaryDirectory() as folder:
        os.environ["INTEGRATION_DB"] = str(Path(folder) / "smoke.db")

        from app import engine_client as engine
        from store import db

        db.init_db()
        print("stubbed functions:", ", ".join(engine.stubbed_functions()) or "none")
        print("validation problems:", engine.validate_config(CONFIG))

        config = engine.load_config(CONFIG)
        config_hash = hashlib.sha256(CONFIG.encode()).hexdigest()
        db.save_connector(config.name, config.entity, CONFIG, config_hash)
        db.approve_connector(config.name, config_hash)
        db.audit("smoke", "connector.save", config.name, "Authorization: SSWS not-a-real-key")

        for fault in (None, "503x3", "badrecord", "503x4"):
            if fault:
                engine.set_fault(config.name, fault)
            result = engine.run_connector(config.name)
            connector = db.get_connector(config.name)
            print(
                f"fault={fault}: run={result.status} pulled={result.records_pulled} "
                f"bad={result.records_bad} retries={result.retries} "
                f"connector={connector['status']} failures={connector['consecutive_failures']}"
            )
        engine.clear_fault(config.name)

        print("users stored:", len(db.query_records("user", source=config.name)))
        print("quarantined:", len(db.list_quarantine(config.name)))
        print("audit detail:", db.list_audit()[0]["detail"])
        print("health rows:", [(c["name"], c["status"]) for c in db.list_connectors()])


if __name__ == "__main__":
    main()
