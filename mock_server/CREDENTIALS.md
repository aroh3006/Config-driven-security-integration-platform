# Mock credentials

These work only against the local mock server. They are not secrets.

Paste this block into `.env`:

```
MOCK_FIREWALL_KEY=mock-fw-key-7f3a91c2
MOCK_EDR_CLIENT_ID=mock-edr-client
MOCK_EDR_CLIENT_SECRET=mock-edr-secret-c15e7702
MOCK_CLOUD_KEY=mock-cloud-key-4be810d6
```

Extra values for failure tests:

| Value | Result |
| --- | --- |
| Firewall key `mock-fw-key-no-log-access` | 403 insufficient_scope |
| EDR client `mock-edr-hosts-only` with secret `mock-edr-secret-hosts-only` | Hosts work. Detections give 403. |
