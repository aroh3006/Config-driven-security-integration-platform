# Mock server

Fake security tools for testing and the demo. Run it with `python -m mock_server`. API docs are at http://localhost:9000/docs. All data is fake and the server binds to 127.0.0.1 only.

| Mock | Endpoint | Login | Paging | Modelled on |
| --- | --- | --- | --- | --- |
| Okta users | `GET /okta/api/v1/users` | `Authorization: SSWS <key>` | RFC 8288 Link header | Okta management OpenAPI spec |
| Okta logs | `GET /okta/api/v1/logs` | `Authorization: SSWS <key>` | Link header, never ends while polling | Okta management OpenAPI spec |
| GitHub members | `GET /github/orgs/{org}/members` | Bearer token | `page` and `per_page` | GitHub REST OpenAPI spec |
| GitHub Dependabot | `GET /github/repos/{owner}/{repo}/dependabot/alerts` | Bearer token | `after` cursor in the Link header | GitHub REST OpenAPI spec |
| Jira search | `GET /jira/rest/api/3/search/jql` | Basic (email and API token) | `nextPageToken` in the body | Jira Cloud v3 OpenAPI spec |
| Firewall | `GET /firewall/api/v1/logs` | `X-API-Key` header | `offset`, `limit`, `total` | CEF field names |
| EDR hosts | `GET /edr/devices/combined/devices/v1` | OAuth2 client credentials | `after` cursor at `meta.pagination.next` | Common EDR API shape |
| EDR detections | `GET /edr/alerts/combined/alerts/v1` | OAuth2 client credentials | Same | Common EDR API shape |
| Cloud audit | `POST /cloud/` | `X-Api-Key` header | `NextToken` in the body | CloudTrail LookupEvents |

Token endpoint: `POST /edr/oauth2/token`. It takes the client in the form body or a Basic header. It returns 201 with `Cache-Control: no-store`. Tokens last 5 minutes.

## How the shapes are checked

`tests/vendor_schemas.py` holds field lists copied from the vendors' published OpenAPI specs. `tests/test_mock_saas.py` checks clean records against them: required fields are present, no field is outside the spec and enum values are valid. The specs were read on 2026-10-31.

CVE data is real:

- All nine IDs in `KEV_CVES` were checked against the live CISA KEV catalog. Their scores are NVD's CVSS v3.1 base scores.
- GHSA IDs, CVSS vectors, CWEs and version ranges come from GitHub's public advisory database.
- CVE-2022-28346, CVE-2021-44906 and CVE-2021-23337 are real but not in KEV. The KEV match has to leave them out.

Other values follow the standard ranges. External IPs are in 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24. Internal hosts use 10.x. Identities and links use example.com. MITRE technique IDs and SHA-256 hashes use the real formats.

## Vendor behaviour copied on purpose

- **Okta logs:** a polling request (no `until`) always gets a `next` link, even when the page is empty. `since` older than 180 days gives a 400.
- **Okta errors:** `E0000011` for a bad token, `E0000006` for no permission, `E0000047` for rate limiting.
- **GitHub:** `X-RateLimit-*` headers, an API version header, `per_page` capped at 100 and no email on most members.
- **Jira:** returns only ids unless `fields` names some, rejects unbounded JQL, leaves `nextPageToken` off the last page and writes timestamps like `+0000` with no colon. Descriptions use Atlassian Document Format.
- **All:** responses over 500 bytes are gzip compressed when the client accepts it. Keys are compared in constant time.

## Where the mocks differ from the real thing

- **JQL:** only `project = KEY`, with optional `AND` clauses and `ORDER BY`, is understood. The extra clauses are accepted but not applied.
- **Okta filter:** only `eventType eq "..."` is understood.
- **Cloud login:** real CloudTrail uses SigV4 signing. The mock uses a simple header key.
- **`Cve` on cloud events:** real CloudTrail has no such field. It appears only on `BatchImportFindings` events so the KEV match has cloud rows.
- **EDR fields:** the shape follows common EDR APIs. It does not copy one vendor exactly.
- **GitHub 429:** real GitHub can also signal rate limits with a 403. The mock always uses 429.
- **Links in data:** URLs inside records point at example.com, not the mock server.

A mock shows that a connector matches a published API shape. It does not replace a run against the real service.

## Messy records

Records at positions 50, 150, 250 and so on are damaged on purpose, about 1% of each list. The damage cycles in this order:

1. The id field is missing.
2. The timestamp is null.
3. The timestamp is `yesterday-ish`.
4. A type or severity field is an object when it should be text.

The random seed is fixed. Timestamps fall in the 7 days before the server started.

| Source | Records |
| --- | --- |
| Okta users | 120 |
| Okta logs | 300 |
| GitHub members | 130 |
| GitHub Dependabot | 60 |
| Jira issues | 150 |
| Firewall | 300 |
| EDR hosts and detections | 200 and 300 |
| Cloud audit | 300 |

## Fault control

```bash
curl -X POST localhost:9000/admin/faults -H "Content-Type: application/json" -d "{\"path\": \"/okta\", \"mode\": \"503x3\"}"
```

`path` is a path prefix.

| Mode | Effect |
| --- | --- |
| `503x3`, `503x4`, `500x1` | The next N requests get that error. |
| `429:30` | The next request gets 429 with `Retry-After: 30`. |
| `timeout` | Requests hang for 120 seconds until set to `off`. |
| `badrecord` | The first record of each page loses its id until set to `off`. |
| `off` | Clears the fault on that path. |

`POST /admin/expire-tokens` expires all OAuth tokens at once. The admin routes have no login, which is why the server stays on 127.0.0.1.
