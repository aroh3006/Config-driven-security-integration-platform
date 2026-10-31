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
        "--page": "#0A0C0F", "--panel": "#0F1217", "--card": "#14181E", "--raised": "#1A1F26",
        "--teal-line": "#2DD4BF", "--teal-text": "#5EEAD4", "--teal-fill": "#0D2A27",
        "--amber-line": "#F59E0B", "--amber-text": "#FBBF24", "--amber-fill": "#2A1F0A",
        "--red-line": "#EF4444", "--red-text": "#FCA5A5", "--red-fill": "#2A1212",
        "--engine": "#F2F4F7", "--word": "#0F5D55",
    }
    for name, value in expected.items():
        assert f"{name}: {value};" in CSS


def test_text_contrast_meets_the_minimum():
    pairs = [
        ("#F2F4F7", "#0A0C0F"), ("#C3C8D0", "#0F1217"), ("#A3A9B3", "#14181E"), ("#8C939E", "#0F1217"),
        ("#8C939E", "#14181E"), ("#A3A9B3", "#1A1F26"), ("#5EEAD4", "#0D2A27"), ("#FBBF24", "#2A1F0A"),
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
    page = client.get("/").text
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
    page = client.get("/").text
    assert "CONNECT" in page and "<svg" in page
    assert "Plug in a new source" in page
    assert 'http-equiv="refresh" content="10"' in page


def test_home_shows_more_link_for_many_connectors(client):
    for n in range(9):
        add(client, f"src{n}")
    assert "+3 more" in client.get("/").text


def test_home_with_no_connectors_still_renders(client):
    assert client.get("/").status_code == 200


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
    assert "demo.yaml" in page and "CONFIG" in page
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


def test_new_pages_load(client):
    add(client, "demo")
    assert "demo.yaml" in client.get("/ui/configs").text
    db.add_quarantine("demo", None, {"x": "<b>raw</b>"}, "missing id")
    page = client.get("/ui/quarantine").text
    assert "missing id" in page and "<b>raw</b>" not in page
