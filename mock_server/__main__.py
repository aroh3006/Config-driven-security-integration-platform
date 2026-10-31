"""Start the mock server on port 9000: python -m mock_server"""

from __future__ import annotations

from pathlib import Path

import uvicorn

from mock_server import app as mock_app
from mock_server import saas, styles

ENV_BLOCK = f"""\
MOCK_FIREWALL_KEY={mock_app.FIREWALL_KEY}
MOCK_EDR_CLIENT_ID={mock_app.EDR_CLIENT_ID}
MOCK_EDR_CLIENT_SECRET={mock_app.EDR_CLIENT_SECRET}
MOCK_CLOUD_KEY={mock_app.CLOUD_KEY}
MOCK_OKTA_KEY={saas.OKTA_KEY}
MOCK_GITHUB_TOKEN={saas.GITHUB_TOKEN}
MOCK_JIRA_EMAIL={saas.JIRA_EMAIL}
MOCK_JIRA_TOKEN={saas.JIRA_TOKEN}
MOCK_FMC_USER={styles.FMC_USER}
MOCK_FMC_PASSWORD={styles.FMC_PASSWORD}
MOCK_WIZ_CLIENT_ID={styles.WIZ_CLIENT_ID}
MOCK_WIZ_CLIENT_SECRET={styles.WIZ_CLIENT_SECRET}
MOCK_CORTEX_KEY={styles.CORTEX_KEY}
MOCK_CORTEX_KEY_ID={styles.CORTEX_KEY_ID}
"""

CREDENTIALS = f"""\
# Mock credentials

These work only against the local mock server. They are not secrets.

Paste this block into `.env`:

```
{ENV_BLOCK}```

Extra values for failure tests:

| Value | Result |
| --- | --- |
| Firewall key `{mock_app.FIREWALL_KEY_NO_ACCESS}` | 403 insufficient_scope |
| EDR client `{mock_app.EDR_HOSTS_ONLY_CLIENT_ID}` with secret `{mock_app.EDR_HOSTS_ONLY_CLIENT_SECRET}` | Hosts work. Detections give 403. |
| Okta key `{saas.OKTA_KEY_NO_ACCESS}` | 403 E0000006 |
| GitHub token `{saas.GITHUB_TOKEN_NO_ALERTS}` | Members work. Dependabot alerts give 403. |
"""


def main() -> None:
    Path(__file__).with_name("CREDENTIALS.md").write_text(CREDENTIALS, encoding="utf-8")
    print("Mock credentials for .env (also in mock_server/CREDENTIALS.md):")
    print(ENV_BLOCK)
    print("API docs: http://localhost:9000/docs")
    uvicorn.run(mock_app.create_app(), host="127.0.0.1", port=9000)


if __name__ == "__main__":
    main()
