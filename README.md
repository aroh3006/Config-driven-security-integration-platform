# Config-driven integration platform

One engine plus one small YAML file per security tool. Adding a tool means writing a config, not code. Every connector gets the same secrets handling, retries, rate limiting, quarantine and health view.

All data lands in one SQLite store with three tables: `users`, `devices` and `alerts`.

## Run it

```bash
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env
```

Fill in `.env`. The mock values are in `mock_server/CREDENTIALS.md`, which the mock server writes when it starts.

Terminal 1, the mock tools on port 9000:

```bash
.\.venv\Scripts\python.exe -m mock_server
```

Terminal 2, the web app and scheduler on http://127.0.0.1:8000:

```bash
.\.venv\Scripts\python.exe -m app.cli serve
```

Tests:

```bash
.\.venv\Scripts\python.exe -m pytest -q
```

## Web app

The web app is called Otto. It runs with no JavaScript and no CDN. It keeps working with the network off.

| Page | What it does |
| --- | --- |
| `/` | Patch panel and the health table |
| `/ui/live/{name}` | Press a scenario, then read the labelled request log |
| `/ui/connector/{name}` | Run history, quarantine and test results |
| `/ui/connector/{name}/config` | A config split into the five parts of the engine it drives |
| `/ui/add` | Add a source from a form or a pasted sample |
| `/ui/records/{users,devices,alerts}`, `/ui/people`, `/ui/kev` | The stored data |
| `/ui/quarantine`, `/ui/audit`, `/ui/demo` | Bad records, the audit log and manual fault switches |

Geist and Geist Mono are served from `app/static/fonts` under the SIL Open Font License (see `OFL.txt`).

## Adding a source

1. Open **Add source**. Paste a sample response or fill in the form.
2. Press **Build YAML**, then **Validate** and **Test**.
3. Add the secret to `.env`, using the upper-case form of its name. `okta_key` reads `OKTA_KEY`.
4. Press **Save**.

The same flow works with a file. Drop it in `configs/` and run `python -m app.cli import-configs`.

## Connectors

| Config | Entity | Login | Paging |
| --- | --- | --- | --- |
| `okta-users` | user | API key header | Link header |
| `okta-signins` | alert | API key header | Link header, incremental |
| `github-members` | user | Bearer | Page number |
| `github-dependabot` | alert | Bearer | Link header |
| `jira-tickets` | alert | Basic | Token in body |
| `nvd-cves` | alert | API key header | Offset |
| `cisa-kev` | alert | None | None |
| `devices-file` | device | None (CSV file) | None |
| `mock-okta-users` | user | API key header | Link header |
| `mock-okta-signins` | alert | API key header | Link header, incremental |
| `mock-github-members` | user | Bearer | Page number |
| `mock-github-dependabot` | alert | Bearer | Link header |
| `mock-jira-tickets` | alert | Basic | Token in body |
| `mock-firewall` | alert | API key header | Offset |
| `mock-edr-hosts` | device | OAuth2 client credentials | Cursor |
| `mock-edr-detections` | alert | OAuth2 client credentials | Cursor |
| `mock-cloud-audit` | alert | API key header | Token in POST body |

Sources named `mock-*` run against the local mock server and carry a `mock` tag on the health page. `mock_server/README.md` explains how they follow the vendors' published API specs and where they differ.

`cisa-kev` runs live with no account. `nvd-cves` needs an `NVD_KEY`. Before the other real sources can load, replace the `YOUR-...` placeholders in their configs: `YOUR-ORG`, `YOUR-SITE`, `YOUR-PROJECT`, `YOUR-GITHUB-ORG` and `YOUR-DEMO-REPO`. Files that still have placeholders are skipped at startup. Moving from a mock to the real service changes only the base URL, the host allowlist and the secret names.

## CLI

```text
python -m app.cli validate <file>
python -m app.cli test <name>
python -m app.cli run <name>
python -m app.cli health
python -m app.cli pause <name>
python -m app.cli resume <name>
python -m app.cli approve <name>
python -m app.cli import-configs
python -m app.cli quarantine list
python -m app.cli quarantine replay <id>
python -m app.cli onboard <sample-file>
python -m app.cli serve
```

## Engine commands

These work directly on a config file:

```bash
python -m engine validate configs/okta-users.yaml
python -m engine test configs/okta-users.yaml
python -m engine profile tests/samples/cisa_kev.json --name cisa-kev
```

## Layout

| Path | What it holds |
| --- | --- |
| `engine/` | The generic engine |
| `store/` | SQLite schema and store functions |
| `app/` | API, web pages, CLI, Slack alerts, config import |
| `mock_server/` | Mock firewall, EDR and cloud audit tools |
| `configs/` | One YAML per connector |
| `data/` | The device CSV and onboarding samples |

## Security notes

- Hosts are allowlisted per connector. Internal and cloud metadata addresses are blocked. Only `mock: true` connectors may call loopback.
- Configs hold secret names only. Values come from environment variables loaded from a gitignored `.env`.
- The store masks secrets in audit details, run errors and quarantine reasons.
- A config edited on disk moves to `config_changed` and needs approval before it runs.
- The web app binds to 127.0.0.1 and refuses cross-site POSTs. It has no login. Keep it local.
- Pages use no scripts or CDN files. Templates escape all record values.
