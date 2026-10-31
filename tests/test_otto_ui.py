"""The Otto layout: offline assets, sidebar, patch panel and theme rules."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import patch, sidebar, takeapart, theme
from app.api import create_app
from store import db

pytestmark = pytest.mark.usefixtures("isolated_app")

CSS = (Path(__file__).resolve().parent.parent / "app" / "static" / "otto.css").read_text(encoding="utf-8")
CONFIG = """\
name: {name}
entity: {entity}
mock: {mock}
source: {{ type: http, base_url: https://x.example.com, allow_hosts: [x.example.com] }}
auth: {{ type: bearer, secret: demo_token }}
pagination: {{ type: page_number }}
schedule: every 15m
map: {{ id: id }}
"""


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


def add(client, name, entity="user", mock="false"):
    text = CONFIG.format(name=name, entity=entity, mock=mock)
    assert client.post("/connectors", json={"yaml": text}).status_code == 201


def row(name, status="healthy", mock=False, entity="user", stored=1):
    return {"name": name, "status": status, "mock": mock, "entity": entity, "stored": stored, "detail": "x"}


def luminance(colour):
    channels = [int(colour[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


# Offline assets

def test_fonts_and_stylesheet_are_served_locally(client):
    assert client.get("/static/otto.css").status_code == 200
    for font in ("Geist.woff2", "GeistMono.woff2"):
        response = client.get(f"/static/fonts/{font}")
        assert response.status_code == 200
        assert response.content[:4] == b"wOF2"
    assert client.get("/static/fonts/OFL.txt").status_code == 200


def test_pages_load_nothing_from_a_cdn(client):
    page = client.get("/").text
    assert not re.search(r"""(src|href)=["']https?://""", page)
    assert "http" not in re.sub(r"url\(\"/static[^)]*\)", "", CSS)


def test_static_files_cannot_escape_the_folder(client):
    assert client.get("/static/..%2Fapi.py").status_code == 404


# Theme

def test_required_tokens_are_exact():
    expected = {
        "--page": "#000000", "--panel": "#08090B", "--card": "#0E1014", "--raised": "#15181D",
        "--teal-line": "#2DD4BF", "--teal-text": "#5EEAD4", "--teal-fill": "#0D2A27",
        "--amber-line": "#F59E0B", "--amber-text": "#FBBF24", "--amber-fill": "#2A1F0A",
        "--red-line": "#EF4444", "--red-text": "#FCA5A5", "--red-fill": "#2A1212",
        "--engine": "#F2F4F7", "--word": "#0F5D55",
    }
    for name, value in expected.items():
        assert f"{name}: {value};" in CSS


def test_text_contrast_meets_the_minimum():
    pairs = [
        ("#F2F4F7", "#000000"), ("#C3C8D0", "#08090B"), ("#A3A9B3", "#0E1014"), ("#8C939E", "#08090B"),
        ("#8C939E", "#0E1014"), ("#A3A9B3", "#15181D"), ("#5EEAD4", "#0D2A27"), ("#FBBF24", "#2A1F0A"),
        ("#FBBF24", "#1C1608"), ("#FCA5A5", "#2A1212"), ("#FCA5A5", "#1F0F0F"), ("#0A0C0F", "#F2F4F7"),
        ("#F2F4F7", "#1C1608"), ("#F2F4F7", "#1F0F0F"), ("#A3A9B3", "#1C1608"), ("#A3A9B3", "#1F0F0F"),
    ]
    for text, background in pairs:
        assert contrast(text, background) >= 4.5, (text, background)


def test_corner_radius_values_are_on_the_scale():
    values = set(re.findall(r"border-radius:\s*([^;]+);", CSS))
    assert values <= {"8px", "10px", "14px", "999px", "50%"}


def test_cable_animation_respects_reduced_motion():
    assert "prefers-reduced-motion: reduce" in CSS


@pytest.mark.parametrize(
    "status, tone",
    [
        ("healthy", "teal"), ("success", "teal"), ("degraded", "amber"), ("partial", "amber"),
        ("config_changed", "amber"), ("running", "amber"), ("failing", "red"), ("failed", "red"),
        ("auth_failed", "red"), ("circuit_open", "red"), ("paused", "grey"), ("never_run", "grey"),
        (None, "grey"), ("something_new", "grey"),
    ],
)
def test_status_colours(status, tone):
    assert theme.tone(status) == tone


# Sidebar

def test_sidebar_groups_by_entity_with_a_mock_folder():
    side = sidebar.build(
        rows=[row("a", entity="user"), row("b", entity="alert"), row("c", entity="device"), row("m", mock=True, entity="alert")]
    )
    assert [folder["label"] for folder in side["folders"]] == ["users", "devices", "alerts", "Mock tools"]
    assert [r["name"] for r in side["folders"][-1]["rows"]] == ["m"]


def test_sidebar_search_filters_rows_not_totals():
    rows = [row("okta", stored=5), row("jira", stored=7)]
    side = sidebar.build("OK", rows)
    assert [r["name"] for f in side["folders"] for r in f["rows"]] == ["okta"]
    assert side["totals"]["users"] == 12


def test_every_rail_link_has_a_label_and_works(client):
    add(client, "demo")
    page = client.get("/ui/health").text
    for _, label, href in sidebar.RAIL:
        assert f'aria-label="{label}"' in page
        assert client.get(href).status_code == 200, href
    assert 'aria-current="page"' in page


def test_sidebar_shows_status_word_count_and_current_row(client):
    add(client, "demo")
    db.upsert("user", "demo", [{"id": "1"}, {"id": "2"}])
    page = client.get("/ui/connector/demo").text
    row_html = page[page.index('<a class="tree-row" href="/ui/connector/demo"') :]
    assert 'aria-current="page"' in row_html[:120]
    assert "never_run" in row_html[:400]
    assert '<span class="count">2</span>' in row_html[:500]


def test_sidebar_search_is_a_get_query(client):
    add(client, "alpha")
    add(client, "beta")
    page = client.get("/ui/quarantine", params={"find": "alp"}).text
    side = page[page.index('class="side"') : page.index('id="main"')]
    assert "alpha" in side and "beta" not in side
    assert "No source matches" in client.get("/ui/quarantine", params={"find": "zzz"}).text


def test_sidebar_escapes_the_search_text(client):
    page = client.get("/ui/quarantine", params={"find": '"><img src=x>'}).text
    assert "<img src=x>" not in page


# Patch panel

def test_sockets_show_worst_first_and_real_before_mock():
    rows = [
        row("z-ok"), row("a-ok"), row("m-bad", "failed", mock=True), row("r-bad", "failed"),
        row("slow", "degraded"), row("off", "paused"),
    ]
    assert [s["name"] for s in patch.choose(rows, 6)] == ["r-bad", "m-bad", "slow", "off", "a-ok", "z-ok"]


def test_socket_cap_reports_the_rest():
    rows = [row(f"s{n:02d}") for n in range(17)]
    built = patch.build(rows, limit=6)
    assert len(built["sockets"]) == 6
    assert built["more"] == 11


def test_focus_connector_always_shows_first():
    rows = [row("bad", "failed"), row("worse", "failed"), row("calm")]
    assert patch.build(rows, limit=2, focus="calm")["sockets"][0]["name"] == "calm"


def test_cables_stay_inside_the_panel_for_any_count():
    for count in (0, 1, 2, 6, 17):
        built = patch.build([row(f"s{n}") for n in range(count)])
        for cable in built["cables_in"] + built["cables_out"]:
            numbers = [float(n) for n in re.findall(r"-?\d+\.?\d*", cable["d"])]
            ys = numbers[1::2]
            assert all(0 <= y <= built["height"] for y in ys), (count, cable["d"])
        assert all(0 <= o["y"] <= built["height"] for o in built["outputs"])


def test_only_healthy_cables_show_moving_data():
    built = patch.build([row("ok"), row("bad", "failed")], show_slot=False)
    flows = {c["tone"]: c["flows"] for c in built["cables_in"]}
    assert flows == {"red": False, "teal": True}


def test_output_totals_add_up():
    built = patch.build([row("a", stored=3), row("b", stored=4), row("c", entity="alert", stored=9)])
    assert built["totals"] == {"user": 7, "device": 0, "alert": 9}


def test_home_page_draws_the_panel(client):
    add(client, "demo")
    page = client.get("/ui/health").text
    assert "CONNECT" not in page and "hero-word" not in page and "<svg" in page
    assert "Any tool" not in page and "One engine pulls" not in page
    assert "Plug in a new source" in page
    assert 'http-equiv="refresh" content="10"' in page


def test_home_shows_more_link_for_many_connectors(client):
    for n in range(9):
        add(client, f"src{n}")
    assert "+3 more" in client.get("/ui/health").text


def test_home_with_no_connectors_still_renders(client):
    assert client.get("/").status_code == 200


# Landing page

def landing_part(page):
    return page[page.index('class="landing"') : page.index('id="workspace"')]


def test_landing_comes_first_then_the_workspace_below(client):
    page = client.get("/").text
    assert page.index('class="landing"') < page.index('id="workspace"') < page.index('class="rail"')
    assert 'class="side"' in page and "[ Connection health ]" in page
    assert "<title>Otto</title>" in page
    assert "<script" not in page


def test_landing_has_otto_branding_and_no_workspace_button(client):
    landing = landing_part(client.get("/").text)
    assert ">OTTO<" in landing and "CONNECT" not in landing
    assert ">Otto<" in landing
    assert "Any tool." in landing and "One config." in landing
    assert "Open workspace" not in client.get("/").text
    assert "Scroll for the workspace" in landing


def test_landing_has_the_five_sources_and_links_onward(client):
    landing = landing_part(client.get("/").text)
    for name in ("Okta", "GitHub", "Jira", "NVD", "CISA KEV"):
        assert f"<b>{name}</b>" in landing
    assert 'href="/ui/add"' in landing
    assert 'href="/ui/records/alerts"' in landing


def test_landing_counts_real_connectors(client):
    assert "0 configured" in client.get("/").text
    add(client, "demo")
    assert "1 configured" in client.get("/").text


def test_landing_only_claims_what_is_true(client):
    add(client, "demo")
    landing = landing_part(client.get("/").text).lower()
    assert "connected" not in landing
    assert "drag" not in landing


def test_home_workspace_works_like_the_health_page(client):
    add(client, "demo")
    client.post("/connectors/demo/pause")
    page = client.get("/").text
    assert "Resume" in page and 'http-equiv="refresh" content="10"' in page
    assert client.get("/", params={"find": "zzz"}).text.count("No source matches") == 1
    assert 'action="/#workspace"' in page


def test_page_has_one_main_landmark(client):
    assert client.get("/").text.count("<main") == 1


# Connector page and config taken apart

def test_connector_page_has_status_timeline_and_views(client):
    add(client, "demo")
    client.post("/connectors/demo/run")
    page = client.get("/ui/connector/demo").text
    assert "[ Status ]" in page and "[ What Otto did · UTC ]" in page
    assert "/ui/live/demo" in page and "/ui/connector/demo/config" in page
    assert "[ Run history ]" in page and "Nothing quarantined" in page


def test_connector_quarantine_can_be_replayed_from_the_page(client):
    add(client, "demo")
    good = db.add_quarantine("demo", None, {"id": "fixed-1"}, "was bad")
    page = client.get("/ui/connector/demo").text
    assert f'action="/ui/quarantine/{good}/replay"' in page
    done = client.post(f"/ui/quarantine/{good}/replay", follow_redirects=True).text
    assert "Record replayed" in done and "Replayed" in done


def test_config_is_split_into_five_answers():
    text = CONFIG.format(name="demo", entity="user", mock="false") + "retry: { delays_s: [1] }\nnotify: { slack_after_failures: 2 }\n"
    parts = takeapart.split(text)
    assert [block["part"] for block in parts["blocks"]] == [
        "Auth plugin", "Request builder", "Pagination plugin", "Scheduler and checkpoint", "Mapper and validator",
    ]
    assert "demo_token" in parts["blocks"][0]["code"]
    assert "x.example.com" in parts["blocks"][1]["code"]
    assert "page_number" in parts["blocks"][2]["code"]
    assert "every 15m" in parts["blocks"][3]["code"]
    assert "id: id" in parts["blocks"][4]["code"]
    assert "delays_s" in parts["tuning"] and "slack_after_failures" in parts["tuning"]


def test_every_key_of_a_config_lands_somewhere():
    text = "name: a\nentity: user\nmap: { id: id }\nauth_failure: { header: X, contains: Y }\nbrand_new_key: 1\n"
    parts = takeapart.split(text)
    assert "auth_failure" in parts["blocks"][0]["code"]
    assert "brand_new_key" in parts["other"]
    assert "not set" in parts["blocks"][2]["code"]


@pytest.mark.parametrize("text", ["[unclosed", "just text"])
def test_take_apart_survives_a_broken_config(text):
    assert takeapart.split(text)["error"]


def test_take_apart_page(client):
    add(client, "demo")
    page = client.get("/ui/connector/demo/config").text
    assert "demo.yaml" in page and "apart-word" not in page
    assert "Change a block, not code" in page
    assert "demo_token" in page
    assert client.get("/ui/connector/nope/config").status_code == 404


def test_take_apart_page_shows_a_broken_stored_config(client):
    add(client, "demo")
    db.save_connector("demo", "user", "<b>: [unclosed", "bad-hash")
    page = client.get("/ui/connector/demo/config").text
    assert "not valid YAML" in page and "<b>: [unclosed" not in page
    assert client.get("/ui/connector/demo").status_code == 200


def test_configs_page_links_to_take_apart(client):
    add(client, "demo")
    assert 'href="/ui/connector/demo/config"' in client.get("/ui/configs").text


# Remaining pages

ALL_PAGES = (
    "/ui/health", "/ui/add", "/ui/configs", "/ui/quarantine", "/ui/records/users", "/ui/records/devices", "/ui/records/alerts",
    "/ui/people", "/ui/kev", "/ui/demo", "/ui/audit", "/ui/connector/demo", "/ui/connector/demo/config", "/ui/live/demo",
)


@pytest.mark.parametrize("path", ALL_PAGES)
def test_every_page_uses_the_shell_and_stays_script_free(client, path):
    add(client, "demo")
    client.post("/connectors/demo/run")
    page = client.get(path).text
    assert "<script" not in page
    assert 'class="rail"' in page and 'class="side"' in page
    assert "/static/otto.css" in page
    assert " · Otto</title>" in page
    assert 'style="' not in page.split('id="main"')[0]


@pytest.mark.parametrize("path", ALL_PAGES)
def test_every_control_has_a_name(client, path):
    add(client, "demo")
    page = client.get(path).text
    for field_id in re.findall(r'<(?:input|select|textarea)\b[^>]*\bid="([^"]+)"', page):
        assert f'for="{field_id}"' in page, field_id
    for icon_link in re.findall(r'<a\b[^>]*>\s*<svg', page):
        assert "aria-label" in icon_link, icon_link


def test_data_pages_share_a_sub_navigation(client):
    for path, label in (("/ui/records/users", "Users"), ("/ui/people", "People"), ("/ui/kev", "KEV match")):
        page = client.get(path).text
        assert 'aria-label="Data"' in page
        assert re.search(rf'class="pill on"[^>]*aria-current="page">{label}<', page), path


def test_quarantine_page_filters_and_counts(client):
    add(client, "alpha")
    add(client, "beta")
    db.add_quarantine("alpha", None, {"x": 1}, "reason-alpha")
    done = db.add_quarantine("beta", None, {"id": "ok"}, "reason-beta")
    client.post(f"/ui/quarantine/{done}/replay")
    page = client.get("/ui/quarantine").text
    assert "2 records shown, 1 waiting" in page
    assert ">Replayed<" in page.replace("</i>", ">")
    only = client.get("/ui/quarantine", params={"connector": "alpha"}).text
    assert "reason-alpha" in only and "reason-beta" not in only


def test_demo_page_links_to_live_and_labels_each_select(client):
    add(client, "demo")
    page = client.get("/ui/demo").text
    assert 'href="/ui/live/demo"' in page
    assert 'for="fault-1"' in page
    assert "timeoutx4" in page


def test_audit_page_escapes_and_masks(client):
    db.audit("web", "x", "<b>target</b>", "password=hunter22")
    page = client.get("/ui/audit").text
    assert "<b>target</b>" not in page and "hunter22" not in page


def test_new_pages_load(client):
    add(client, "demo")
    assert "demo.yaml" in client.get("/ui/configs").text
    db.add_quarantine("demo", None, {"x": "<b>raw</b>"}, "missing id")
    page = client.get("/ui/quarantine").text
    assert "missing id" in page and "<b>raw</b>" not in page


# Colours must agree with what the row says

STATUS_ERRORS = [
    ("degraded", "partial", "3 of 300 records quarantined as invalid", 3, "t-amber"),
    ("auth_failed", "auth_failed", "HTTP 401: credentials rejected", 0, "t-red"),
    ("failing", "failed", "timeout after 4 attempts", 0, "t-red"),
]


@pytest.mark.parametrize("status, run_status, error, bad, css", STATUS_ERRORS)
def test_home_error_text_takes_the_colour_of_its_status(client, status, run_status, error, bad, css):
    add(client, "demo")
    run_id = db.start_run("demo")
    db.finish_run(run_id, run_status, 10, bad, 1, 0, error)
    db.set_status("demo", status)
    page = client.get("/").text
    assert f'<td class="err {css}">{error}</td>' in page
    assert f'<td class="num{" t-amber" if bad else ""}">{bad}</td>' in page


def test_home_gives_a_healthy_row_no_error_colour(client):
    add(client, "demo")
    run_id = db.start_run("demo")
    db.finish_run(run_id, "success", 10, 0, 1, 0, None)
    db.set_status("demo", "healthy")
    page = client.get("/").text
    assert 'class="err t-teal"></td>' in page and 'class="num t-amber"' not in page


@pytest.mark.parametrize(
    "severity, expected",
    [
        ("critical", "red"), ("CRITICAL", "red"), ("error", "red"), ("high", "amber"), ("medium", "amber"),
        ("warn", "amber"), ("low", "grey"), ("info", "grey"), ("unknown", "grey"), (None, "grey"), ("", "grey"),
    ],
)
def test_severity_colours(severity, expected):
    assert theme.severity_tone(severity) == expected


def test_alert_table_colours_each_severity(client):
    add(client, "demo", entity="alert")
    rows = [
        {"id": "a", "type": "t", "severity": "critical", "timestamp": "2026-10-31T00:00:00Z", "fetched_at": "2026-10-31T00:00:00Z", "raw": {}},
        {"id": "b", "type": "t", "severity": "low", "timestamp": "2026-10-31T00:00:00Z", "fetched_at": "2026-10-31T00:00:00Z", "raw": {}},
    ]
    db.upsert("alert", "demo", rows)
    page = client.get("/ui/records/alerts").text
    assert '<span class="st t-red"><i class="dot" aria-hidden="true"></i>critical</span>' in page
    assert '<span class="st t-grey"><i class="dot" aria-hidden="true"></i>low</span>' in page


def test_every_status_uses_one_colour_on_every_surface(client):
    add(client, "demo")
    for status in ("healthy", "degraded", "failing", "auth_failed", "circuit_open", "paused", "never_run", "config_changed"):
        db.set_status("demo", status)
        page = client.get("/").text
        expected = theme.tone(status)
        assert f'<span class="st t-{expected}"><i class="dot" aria-hidden="true"></i>{status}</span>' in page
        assert f'<i class="dot t-{expected}" aria-hidden="true"></i>' in page


def test_no_giant_background_words_come_back():
    # The landing page's OTTO mark is the only one allowed.
    templates = Path(__file__).resolve().parent.parent / "app" / "web"
    assert "-word {" not in CSS.replace(".landing-word {", "")
    for path in templates.glob("*.html"):
        assert '-word"' not in path.read_text(encoding="utf-8").replace('landing-word"', ""), path.name


def test_page_turn_is_css_only_and_can_be_skipped():
    assert "animation-timeline: scroll(root)" in CSS
    assert "@supports (animation-timeline: scroll())" in CSS
    assert "prefers-reduced-motion: no-preference" in CSS


def test_page_turn_runway_is_only_on_home(client):
    add(client, "demo")
    assert 'class="flip-runway"' in client.get("/").text
    assert 'class="flip-runway"' not in client.get("/ui/health").text
