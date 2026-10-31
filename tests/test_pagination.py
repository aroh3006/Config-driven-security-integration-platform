"""One test per paging style (FR-3), each through the full runner."""

import json

import httpx

ITEMS = [{"id": str(i), "ts": f"2026-10-31T00:{i:02d}:00Z"} for i in range(7)]
BASE = """
name: src
entity: alert
source: {base_url: https://api.example.com, allow_hosts: [api.example.com]}
request: {path: /items, records_path: RP}
MAP
map: {id: id, timestamp: {path: ts, transform: to_utc}}
"""


def cfg(paging: str, records_path: str = "items", extra: str = "") -> str:
    return BASE.replace("RP", records_path or '""').replace("MAP", f"pagination: {paging}\n{extra}")


def test_link_header(runner):
    def h(req):
        page = int(req.url.params.get("p", 0))
        chunk = ITEMS[page * 3:(page + 1) * 3]
        headers = {}
        if (page + 1) * 3 < len(ITEMS):
            headers["Link"] = f'<https://api.example.com/items?p={page + 1}>; rel="next", <https://api.example.com/items?p=0>; rel="first"'
        return httpx.Response(200, json=chunk, headers=headers)

    r = runner(cfg("{type: link_header}", ""), h)
    assert r.status == "success" and r.records_pulled == 7 and r.pages == 3


def test_page_number_stops_on_empty_page(runner):
    def h(req):
        page, size = int(req.url.params["page"]), int(req.url.params["per_page"])
        return httpx.Response(200, json=ITEMS[(page - 1) * size: page * size])

    r = runner(cfg("{type: page_number, page_param: page, size_param: per_page, size: 3}", ""), h)
    assert r.records_pulled == 7 and r.pages == 4  # 3 + 3 + 1 + empty


def test_offset_with_total(runner):
    def h(req):
        start, n = int(req.url.params["startIndex"]), int(req.url.params["resultsPerPage"])
        return httpx.Response(200, json={"totalResults": 7, "startIndex": start, "vulnerabilities": ITEMS[start:start + n]})

    r = runner(cfg("{type: offset, offset_param: startIndex, limit_param: resultsPerPage, limit: 3, total_path: totalResults}",
                   "vulnerabilities"), h)
    assert r.records_pulled == 7 and r.pages == 3


def test_body_token_query_like_jira(runner):
    def h(req):
        tok = req.url.params.get("nextPageToken")
        i = int(tok) if tok else 0
        body = {"issues": ITEMS[i:i + 3], "isLast": i + 3 >= len(ITEMS)}
        if i + 3 < len(ITEMS):
            body["nextPageToken"] = str(i + 3)
        return httpx.Response(200, json=body)

    r = runner(cfg("{type: body_token, token_path: nextPageToken, token_param: nextPageToken, stop_path: isLast}", "issues"), h)
    assert r.records_pulled == 7 and r.pages == 3


def test_body_token_in_post_body_like_cloudtrail(runner):
    seen = []

    def h(req):
        assert req.method == "POST"
        body = json.loads(req.content or b"{}")
        seen.append(body)
        i = int(body.get("NextToken", 0))
        out = {"Events": ITEMS[i:i + 3]}
        if i + 3 < len(ITEMS):
            out["NextToken"] = str(i + 3)
        return httpx.Response(200, json=out)

    text = cfg("{type: body_token, token_path: NextToken, token_param: NextToken, token_in: body}", "Events")
    text = text.replace("request: {path: /items,", "request: {method: POST, read_only_post: true, body: {MaxResults: 3}, path: /items,")
    r = runner(text, h)
    assert r.records_pulled == 7 and seen[1] == {"MaxResults": 3, "NextToken": "3"}


def test_body_next_url(runner):
    def h(req):
        i = int(req.url.params.get("after", 0))
        nxt = f"https://api.example.com/items?after={i + 3}" if i + 3 < len(ITEMS) else None
        return httpx.Response(200, json={"results": ITEMS[i:i + 3], "next": nxt})

    r = runner(cfg("{type: body_next_url, next_url_path: next}", "results"), h)
    assert r.records_pulled == 7 and r.pages == 3


def test_body_next_url_cursor_nested_like_edr(runner):
    def h(req):
        i = int(req.url.params.get("after", 0))
        nxt = str(i + 3) if i + 3 < len(ITEMS) else None
        return httpx.Response(200, json={"meta": {"pagination": {"next": nxt}}, "resources": ITEMS[i:i + 3]})

    r = runner(cfg("{type: body_token, token_path: meta.pagination.next, token_param: after}", "resources"), h)
    assert r.records_pulled == 7


def test_max_pages_keeps_resume_point(runner, store):
    def h(req):
        page = int(req.url.params["page"])
        return httpx.Response(200, json=ITEMS[(page - 1) * 2: page * 2])

    text = cfg("{type: page_number, size: 2}", "").replace("map:", "limits: {max_pages: 2}\nmap:")
    r = runner(text, h)
    assert r.status == "partial" and r.more_pages and r.records_pulled == 4
    assert store.get_checkpoint("src")["resume_state"]["params"]["page"] == 3


def test_server_repeating_same_page_does_not_loop(runner):
    def h(req):
        return httpx.Response(200, json={"items": ITEMS[:2], "next": "https://api.example.com/items"},)

    r = runner(cfg("{type: body_next_url, next_url_path: next}"), h)
    assert r.pages <= 2


def test_ndjson_and_csv_formats(runner, store):
    def nd(req):
        lines = [json.dumps(x) for x in ITEMS[:3]] + ["{not json"]
        return httpx.Response(200, text="\n".join(lines))

    text = cfg("{type: none}", "").replace("request: {path: /items,", "request: {format: ndjson, path: /items,")
    r = runner(text, nd)
    assert r.records_pulled == 4 and r.records_bad == 1 and "line 4" in store.quarantine[0]["reason"]


INCREMENTAL = "incremental: {field: ts, param: since, template: '{checkpoint}', start: '2026-10-01T00:00:00Z'}"


def test_link_header_stops_on_empty_page_and_advances_watermark(runner, store):
    calls = []

    def h(req):
        calls.append(req.url)
        page = int(req.url.params.get("p", 0))
        link = f'<https://api.example.com/items?p={page + 1}>; rel="next"'  # always present, even on the empty page
        return httpx.Response(200, json=ITEMS[:3] if page == 0 else [], headers={"Link": link})

    r = runner(cfg("{type: link_header}", "", INCREMENTAL), h)
    assert r.status == "success" and r.records_pulled == 3 and r.pages == 2 and len(calls) == 2
    checkpoint = store.get_checkpoint("src")
    assert checkpoint["watermark"] == "2026-10-31T00:02:00Z" and checkpoint["resume_state"] is None


def test_link_header_poll_with_no_new_records_keeps_watermark(runner, store):
    link = '<https://api.example.com/items?p=1>; rel="next"'
    r = runner(cfg("{type: link_header}", "", INCREMENTAL), lambda req: httpx.Response(200, json=[], headers={"Link": link}))
    assert r.status == "success" and r.pages == 1
    assert store.get_checkpoint("src")["watermark"] == "2026-10-01T00:00:00Z"
