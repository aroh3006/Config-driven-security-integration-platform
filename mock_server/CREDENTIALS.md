# Mock credentials

These work only against the local mock server. They are not secrets.

Paste this block into `.env`:

```
MOCK_FIREWALL_KEY=mock-fw-key-7f3a91c2
MOCK_EDR_CLIENT_ID=mock-edr-client
MOCK_EDR_CLIENT_SECRET=mock-edr-secret-c15e7702
MOCK_CLOUD_KEY=mock-cloud-key-4be810d6
MOCK_OKTA_KEY=mock-okta-key-a84d21f9
MOCK_GITHUB_TOKEN=mock-github-token-52c7e1b0
MOCK_JIRA_EMAIL=sec-bot@example.com
MOCK_JIRA_TOKEN=mock-jira-token-9e03b7d4
MOCK_FMC_USER=mock-fmc-api
MOCK_FMC_PASSWORD=mock-fmc-password-6d1f
MOCK_WIZ_CLIENT_ID=mock-wiz-client
MOCK_WIZ_CLIENT_SECRET=mock-wiz-secret-93ab17e4
MOCK_CORTEX_KEY=mock-cortex-key-2f8a90c1
MOCK_CORTEX_KEY_ID=17
```

Extra values for failure tests:

| Value | Result |
| --- | --- |
| Firewall key `mock-fw-key-no-log-access` | 403 insufficient_scope |
| EDR client `mock-edr-hosts-only` with secret `mock-edr-secret-hosts-only` | Hosts work. Detections give 403. |
| Okta key `mock-okta-key-no-access` | 403 E0000006 |
| GitHub token `mock-github-token-no-alerts` | Members work. Dependabot alerts give 403. |
