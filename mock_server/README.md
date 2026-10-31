# Mock server

Fake security tools for testing and the demo. Run it with `python -m mock_server`. API docs are at http://localhost:9000/docs.

| Mock | Endpoint | Login | Paging | Modelled on |
| --- | --- | --- | --- | --- |
| Firewall | `GET /firewall/api/v1/logs` | `X-API-Key` header | `offset`, `limit`, `total` | CEF field names |
| EDR hosts | `GET /edr/devices/combined/devices/v1` | OAuth2 client credentials | `after` cursor at `meta.pagination.next` | Common EDR API shape |
| EDR detections | `GET /edr/alerts/combined/alerts/v1` | OAuth2 client credentials | Same | Common EDR API shape |
| Cloud audit | `POST /cloud/` | `X-Api-Key` header | `NextToken` in the body | CloudTrail LookupEvents |

Token endpoint: `POST /edr/oauth2/token`. It takes the client in the form body or a Basic header. It returns 201. Tokens last 5 minutes.

## Where the mocks differ from the real thing

- **Cloud login.** Real CloudTrail uses SigV4 signing. The mock uses a simple header key.
- **`Cve` on cloud events.** Real CloudTrail has no such field. It appears only on `BatchImportFindings` events so the KEV match has cloud rows.
- **EDR fields.** The shape follows common EDR APIs. It does not copy one vendor exactly.

## Messy records

Records at positions 50, 150, 250 and so on are damaged on purpose, about 1% of each list. The damage cycles in this order:

1. The id field is missing.
2. The timestamp is null.
3. The timestamp is `yesterday-ish`.
4. A type or severity field is an object when it should be text.

The firewall has 300 events. The EDR has 200 hosts and 300 detections. The cloud mock has 300 events. The random seed is fixed. Timestamps fall in the 7 days before the server started.

## Fault control

```bash
curl -X POST localhost:9000/admin/faults -H "Content-Type: application/json" -d "{\"path\": \"/firewall\", \"mode\": \"503x3\"}"
```

`path` is a path prefix.

| Mode | Effect |
| --- | --- |
| `503x3`, `503x4`, `500x1` | The next N requests get that error. |
| `429:30` | The next request gets 429 with `Retry-After: 30`. |
| `timeout` | Requests hang for 120 seconds until set to `off`. |
| `badrecord` | The first record of each page loses its id until set to `off`. |
| `off` | Clears the fault on that path. |

`POST /admin/expire-tokens` expires all OAuth tokens at once. The server binds to 127.0.0.1 only, because the admin routes have no login.
