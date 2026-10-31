# Config-driven security integration platform

Connect a new security tool by writing a YAML config, not code. One engine handles login,
paging, retries (1s, 2s, 4s), rate limits (429 + Retry-After), bad records (quarantine),
secrets (env vars, masked everywhere), SSRF protection and health, the same way for every source.

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                     # fill in your tokens
python -m pytest                                         # engine tests
python -m engine validate configs/okta-users.yaml
python -m engine test configs/okta-users.yaml            # one page, nothing stored
python -m engine profile tests/samples/cisa_kev.json --name cisa-kev   # draft a config from a sample
```

