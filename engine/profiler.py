"""Onboard from sample: paste a response, get a draft config (B-5). Rules only.

Steps: detect the format -> find the records list -> flatten records into paths with
example values -> score every (common-schema field, path) pair by name and by value
shape (emails, IPs, dates, CVE ids, unique ids) -> guess the paging style from the
response shape and pasted headers -> emit a commented YAML draft -> validate it ->
map 5 sample records with it so the user sees raw vs mapped side by side.
If a guess is wrong the user edits one line of config. Still no code.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from .config import DEFAULT_REQUIRED, ENTITY_FIELDS, ConfigError, load_config, validate_config
from .errors import MappingError, ParseError
from .mapper import map_record, to_utc, unmapped_fields
from .parse import BadLine, find_list_paths, flatten, get_path, parse_body

# ---------------------------------------------------------------- vocabulary
HINTS: dict[str, dict[str, list[str]]] = {
    "user": {
        "id": ["id", "uuid", "userid", "guid", "objectid", "nodeid", "accountid"],
        "name": ["displayname", "fullname", "name", "username", "login", "realname"],
        "email": ["email", "mail", "emailaddress", "primaryemail", "userprincipalname", "upn", "login"],
        "status": ["status", "state", "accountstatus", "active", "enabled"],
        "last_login": ["lastlogin", "lastsignin", "lastlogon", "lastloginat", "lastsignindatetime", "lastseen", "lastactivity", "lastactive"],
    },
    "device": {
        "id": ["id", "deviceid", "uuid", "aid", "hostid", "assetid", "serialnumber", "serial", "guid"],
        "hostname": ["hostname", "host", "devicename", "computername", "dvchost", "fqdn", "name", "displayname"],
        "ip": ["ip", "ipaddress", "localip", "externalip", "primaryip", "ipv4", "lastip", "address"],
        "os": ["os", "osname", "platform", "platformname", "operatingsystem", "osversion", "osplatform"],
        "owner": ["owner", "owneremail", "assignedto", "user", "username", "primaryuser", "lastloginuser", "email"],
        "last_seen": ["lastseen", "lastcontact", "lastcheckin", "lastseenat", "lastupdated", "updated", "modified", "lastsynced"],
    },
    "alert": {
        "id": ["id", "uuid", "eventid", "alertid", "detectionid", "compositeid", "guid", "number", "key", "cveid"],
        "type": ["type", "eventtype", "eventname", "category", "kind", "alerttype", "issuetype", "classification", "act", "name", "technique"],
        "severity": ["severity", "sev", "priority", "level", "risk", "risklevel", "baseseverity", "criticality", "severityname", "basescore"],
        "timestamp": ["timestamp", "time", "published", "eventtime", "created", "createdat", "detectedat", "occurredat", "dateadded",
                      "date", "rt", "firstseen", "createdtime", "updatedat", "updated"],
        "description": ["description", "message", "displaymessage", "summary", "title", "shortdescription", "msg", "vulnerabilityname", "details"],
        "cve": ["cve", "cveid"],
    },
}
TIME_FIELDS = {"timestamp", "last_login", "last_seen"}
LOWER_FIELDS = {"status", "severity"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
URL_RE = re.compile(r"^https?://", re.I)


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _is_ip(v: Any) -> bool:
    try:
        ipaddress.ip_address(str(v))
        return True
    except ValueError:
        return False


def _is_date(v: Any) -> bool:
    if isinstance(v, bool) or v in (None, ""):
        return False
    if isinstance(v, (int, float)):
        return 1e9 <= v <= 1e13  # epoch seconds or milliseconds in a sensible range
    s = str(v)
    if not re.search(r"\d{2}", s) or not re.search(r"[-/: ]", s) or len(s) > 40:
        return False
    try:
        to_utc(s)
        return True
    except ValueError:
        return False


class PathStats:
    def __init__(self, path: str):
        self.path = path
        self.values: list[Any] = []
        segs = [p for p in path.split(".") if not p.isdigit()]
        self.key = _norm(segs[-1]) if segs else ""
        self.parent_key = _norm(segs[-2]) + self.key if len(segs) > 1 else self.key
        self.depth = len(segs) - 1

    def add(self, v: Any) -> None:
        self.values.append(v)

    def finish(self, n_records: int) -> "PathStats":
        vals = [v for v in self.values if v not in (None, "", [], {})]
        self.present = len(vals) / max(n_records, 1)
        self.n = len(vals)
        strs = [str(v) for v in vals]
        self.distinct = len(set(strs)) / max(len(strs), 1)
        self.n_distinct = len(set(strs))
        frac = lambda f: (sum(1 for v in vals if f(v)) / len(vals)) if vals else 0.0  # noqa: E731
        self.email = frac(lambda v: isinstance(v, str) and bool(EMAIL_RE.match(v)))
        self.ip = frac(_is_ip)
        self.date = frac(_is_date)
        self.cve = frac(lambda v: isinstance(v, str) and bool(CVE_RE.match(v)))
        self.url = frac(lambda v: isinstance(v, str) and bool(URL_RE.match(v)))
        self.numeric = frac(lambda v: isinstance(v, (int, float)) and not isinstance(v, bool))
        self.boolean = frac(lambda v: isinstance(v, bool))
        self.avg_len = (sum(len(s) for s in strs) / len(strs)) if strs else 0
        self.example = vals[0] if vals else None
        return self


GENERIC_KEYS = {"name", "value", "text", "label", "displayname", "displayvalue"}


def _name_score(st: PathStats, hints: list[str]) -> float:
    segs = [_norm(p) for p in st.path.split(".") if not p.isdigit()]
    if st.key in GENERIC_KEYS and len(segs) > 1:
        # fields.priority.name means "priority", fields.status.name means "status"
        parent = segs[-2]
        if parent in hints:
            return 2.8
        if any(len(h) >= 4 and (h in parent or (len(parent) >= 4 and parent in h)) for h in hints):
            return 1.8
        return 0.8 if st.key in hints else 0.0
    if st.key in hints:
        return 3.0 - 0.1 * hints.index(st.key) / max(len(hints), 1)
    if st.parent_key in hints:
        return 2.5
    for h in hints:
        if len(h) >= 4 and (h in st.key or (len(st.key) >= 4 and st.key in h)):
            return 1.5
    for h in hints:
        if len(h) >= 5 and h in st.parent_key:  # e.g. descriptions.0.value
            return 1.5
    return 0.0


def _score(target: str, st: PathStats, entity: str) -> float:
    if st.n == 0 or st.url > 0.5:
        return -9.0
    s = _name_score(st, HINTS[entity][target]) - 0.15 * st.depth
    low_card = st.n_distinct <= max(6, 0.5 * st.n) and st.avg_len <= 40
    if target == "id":
        s += 2.0 if (st.distinct >= 0.95 and st.present >= 0.95) else -3.0
        s += -1.0 if st.avg_len > 80 or st.date > 0.5 else 0.0
    elif target in ("email",) or (target == "owner" and st.email > 0.5):
        s += 3.0 if st.email >= 0.8 else -1.5
    elif target == "ip":
        s += 3.0 if st.ip >= 0.8 else -3.0
    elif target in TIME_FIELDS:
        s += 3.0 if st.date >= 0.8 else -3.0
    elif target == "cve":
        s += 4.0 if st.cve >= 0.8 else -3.0
    elif target in ("status", "type", "severity"):
        s += 1.0 if low_card else -0.5
        s += -2.0 if (st.date > 0.5 or st.email > 0.5 or st.ip > 0.5) else 0.0
        if target == "status" and st.boolean > 0.8:
            s += 0.5
    elif target == "description":
        s += 1.5 if st.avg_len >= 15 else -0.5
    elif target in ("hostname", "name", "os"):
        s += 0.5 if (st.numeric < 0.5 and st.email < 0.5 and st.ip < 0.5 and st.date < 0.5) else -2.0
    if target in ("name", "hostname") and st.n >= 3 and st.distinct < 0.5:
        s -= 2.0  # names differ between records; a constant is not a name
    if target in ("id", "type", "status", "name", "hostname") and re.search(r"\.\d+(\.|$)", st.path):
        s -= 1.5  # a value inside a nested list is rarely the record's own id/type/name
    if st.present < 0.5:
        s -= 1.0
    return s


THRESHOLD = {"id": 3.0, "cve": 3.5}


def _assign(entity: str, stats: list[PathStats]) -> dict[str, tuple[PathStats, float]]:
    pairs = [(t, st, _score(t, st, entity)) for t in ENTITY_FIELDS[entity] for st in stats]
    pairs.sort(key=lambda x: x[2], reverse=True)
    chosen: dict[str, tuple[PathStats, float]] = {}
    used: set[str] = set()
    for target, st, score in pairs:
        if target in chosen or score < THRESHOLD.get(target, 2.5):
            continue
        if st.path in used and target != "cve":
            continue
        chosen[target] = (st, score)
        if target != "cve":  # a CVE id may also serve as the record id
            used.add(st.path)
    return chosen


# ---------------------------------------------------------------- input handling
def _split_headers(text: str) -> tuple[dict[str, str], str]:
    """Accept 'HTTP/1.1 200 OK\\nLink: <...>\\n\\n{...}' or plain bodies."""
    lines = text.lstrip().splitlines()
    if not lines:
        return {}, text
    head_re = re.compile(r"^(HTTP/\d|[A-Za-z][A-Za-z0-9-]*:\s)")
    if not head_re.match(lines[0]) or lines[0].lstrip().startswith(("{", "[")):
        return {}, text
    headers: dict[str, str] = {}
    for i, line in enumerate(lines):
        if not line.strip():
            return headers, "\n".join(lines[i + 1:])
        if ":" in line and not line.startswith("HTTP/"):
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {}, text


def _detect(body: str) -> tuple[str, Any]:
    s = body.strip()
    if s.startswith(("{", "[")):
        try:
            return "json", json.loads(s)
        except json.JSONDecodeError:
            pass
    lines = [ln for ln in s.splitlines() if ln.strip()]
    if lines and all(ln.lstrip().startswith("{") for ln in lines[:5]):
        parsed = parse_body(s.encode(), "ndjson")
        if sum(isinstance(x, dict) for x in parsed) >= max(1, len(parsed) // 2):
            return "ndjson", parsed
    if lines and ("," in lines[0] or "\t" in lines[0] or ";" in lines[0]):
        return "csv", parse_body(s.encode(), "csv")
    raise ParseError("could not recognise the sample: paste a JSON response, NDJSON lines or a CSV with a header row")


def _records(fmt: str, parsed: Any) -> tuple[str, list, list[tuple[str, int]]]:
    if fmt != "json":
        return "", [r for r in parsed if isinstance(r, dict)], []
    cands = find_list_paths(parsed)
    if not cands:
        if isinstance(parsed, dict):
            return "", [parsed], []
        return "", [], []

    def rank(c):
        path, n = c
        node = get_path(parsed, path)
        width = len(node[0]) if node and isinstance(node[0], dict) else 0
        return (n * max(width, 1), -path.count("."))

    cands.sort(key=rank, reverse=True)
    best = cands[0][0]
    return best, get_path(parsed, best), cands


# ---------------------------------------------------------------- paging
TOKEN_KEYS = {"nextpagetoken": "nextPageToken", "nexttoken": "NextToken", "nextcursor": "cursor", "cursor": "cursor",
              "continuationtoken": "continuationToken", "scrollid": "scroll_id", "after": "after", "endcursor": "after"}
NEXT_URL_KEYS = {"next", "nexturl", "nextlink", "odatanextlink", "nextpageurl", "nextpage", "nexthref"}


def guess_paging(parsed: Any, headers: dict, records_path: str, method: str = "GET") -> dict:
    link = headers.get("link", "")
    if 'rel="next"' in link or "rel=next" in link:
        return {"type": "link_header", "why": "the pasted Link header has rel=\"next\""}
    if not isinstance(parsed, dict):
        why = "the response is a bare list; if the API pages with a Link header, paste the response headers too"
        return {"type": "none", "why": why}
    top = {k: v for k, v in parsed.items() if k != records_path.split(".")[0] or not records_path}
    flat = flatten(top)
    for path, value in flat.items():
        key = _norm(path.split(".")[-1])
        if key in NEXT_URL_KEYS and isinstance(value, str) and (URL_RE.match(value) or value.startswith("/")):
            return {"type": "body_next_url", "next_url_path": path, "why": f"'{path}' holds the next page URL"}
    for path, value in flat.items():
        key = _norm(path.split(".")[-1])
        param = TOKEN_KEYS.get(key)
        if key == "next" and "pagination" in path.lower():
            param = "after"
        if param and value not in (None, "") and not isinstance(value, (dict, list, bool)):
            token_in = "body" if method == "POST" else "query"
            out = {"type": "body_token", "token_path": path, "token_param": param, "token_in": token_in,
                   "why": f"'{path}' looks like a next-page token"}
            if "islast" in {_norm(p.split('.')[-1]) for p in flat}:
                out["stop_path"] = next(p for p in flat if _norm(p.split('.')[-1]) == "islast")
            return out
    keys = {_norm(p.split(".")[-1]): p for p in flat}
    if "startindex" in keys and ("totalresults" in keys or "total" in keys):
        return {"type": "offset", "offset_param": keys["startindex"].split(".")[-1],
                "limit_param": keys["resultsperpage"].split(".")[-1] if "resultsperpage" in keys else "limit",
                "total_path": keys.get("totalresults") or keys.get("total"), "why": "startIndex + total fields"}
    if "offset" in keys and ("total" in keys or "limit" in keys):
        return {"type": "offset", "offset_param": keys["offset"].split(".")[-1],
                "limit_param": keys["limit"].split(".")[-1] if "limit" in keys else "limit",
                "total_path": keys.get("total") or keys.get("totalcount"), "why": "offset/limit/total fields"}
    for tp in ("totalpages", "pages", "pagecount", "lastpage"):
        if tp in keys and ("page" in keys or "currentpage" in keys):
            return {"type": "page_number", "page_param": "page", "total_pages_path": keys[tp], "why": "page + total pages fields"}
    return {"type": "none", "why": "no paging fields found; if the API pages, paste the response headers too"}


# ---------------------------------------------------------------- YAML emitter
def _q(s: Any) -> str:
    if isinstance(s, (int, float)) and not isinstance(s, bool):
        return str(s)
    s = str(s)
    return s if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-/]*", s) and s.lower() not in ("true", "false", "null", "yes", "no", "on", "off") else json.dumps(s)


def _field_yaml(target: str, spec: dict) -> str:
    if list(spec) == ["path"]:
        return f"  {target}: {_q(spec['path'])}"
    parts = []
    for k, v in spec.items():
        if isinstance(v, list):
            parts.append(f"{k}: [{', '.join(_q(x) for x in v)}]")
        else:
            parts.append(f"{k}: {_q(v)}")
    return f"  {target}: {{ {', '.join(parts)} }}"


def _base_url_guess(parsed: Any) -> Optional[str]:
    for _, v in flatten(parsed if isinstance(parsed, dict) else {"r": parsed[:3] if isinstance(parsed, list) else parsed}).items():
        if isinstance(v, str) and URL_RE.match(v):
            u = urlsplit(v)
            return f"{u.scheme}://{u.netloc}"
    return None


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (s or "new-source")[:40] if len(s) >= 2 else "new-source"


# ---------------------------------------------------------------- main
def profile_sample(
    text: str,
    entity: Optional[str] = None,
    *,
    name: Optional[str] = None,
    base_url: Optional[str] = None,
    path: Optional[str] = None,
    method: str = "GET",
) -> dict:
    """Return {draft_yaml, records_path, format, guesses, paging_guess, preview_raw,
    preview_mapped, unmapped_fields, confidence, validation, alternatives, notes}."""
    headers, body = _split_headers(text)
    fmt, parsed = _detect(body)
    records_path, records, alternatives = _records(fmt, parsed)
    records = [r for r in records if isinstance(r, dict) and not isinstance(r, BadLine)][:200]
    if not records:
        raise ParseError("no records found in the sample")

    stats: dict[str, PathStats] = {}
    for rec in records[:50]:
        for p, v in flatten(rec).items():
            stats.setdefault(p, PathStats(p)).add(v)
    n = min(len(records), 50)
    all_stats = [st.finish(n) for st in stats.values()]

    # pick the entity by how many of its fields we can fill confidently
    choices = {}
    for ent in ENTITY_FIELDS:
        chosen = _assign(ent, all_stats)
        cover = sum(1 for t in ENTITY_FIELDS[ent] if t in chosen) / len(ENTITY_FIELDS[ent])
        req_ok = all(r in chosen for r in DEFAULT_REQUIRED[ent])
        choices[ent] = (chosen, cover + (0.5 if req_ok else 0) + sum(s for _, s in chosen.values()) / 100)
    if entity not in ENTITY_FIELDS:
        entity = max(choices, key=lambda e: choices[e][1])
    chosen = choices[entity][0]

    specs: dict[str, dict] = {}
    notes: list[str] = []
    for target in ENTITY_FIELDS[entity]:
        if target in chosen:
            st = chosen[target][0]
            spec: dict[str, Any] = {"path": st.path}
            if target in TIME_FIELDS:
                spec["transform"] = "to_utc"
            elif target in LOWER_FIELDS and st.numeric < 0.5 and st.boolean < 0.5:
                spec["transform"] = "lower"
            if target == "severity" and st.numeric >= 0.8:
                notes.append(f"severity '{st.path}' is numeric; add a lookup or keep the number")
            specs[target] = spec
    if entity == "user" and "name" not in specs:
        first = next((s.path for s in all_stats if s.key in ("firstname", "givenname")), None)
        last = next((s.path for s in all_stats if s.key in ("lastname", "surname", "familyname")), None)
        if first and last:
            specs = {**{k: v for k, v in specs.items() if k == "id"}, "name": {"join": [first, last], "sep": " "},
                     **{k: v for k, v in specs.items() if k != "id"}}
    if entity == "alert" and "severity" not in specs:
        notes.append("no severity field found; consider `severity: { const: medium }`")
    for r in DEFAULT_REQUIRED[entity]:
        if r not in specs:
            notes.append(f"required field '{r}' could not be guessed; map it by hand (TODO)")

    paging = guess_paging(parsed, headers, records_path, method) if fmt == "json" else {"type": "none", "why": f"{fmt} body"}
    url_guess = base_url or _base_url_guess(parsed)
    host = urlsplit(url_guess).hostname if url_guess else None

    # ---- draft YAML
    cname = _slug(name or "")
    lines = ["# Draft generated by the profiler from a pasted sample. Review every TODO. Then Test.",
             f"name: {cname}", f"entity: {entity}"]
    if fmt == "csv" and not base_url:
        lines += ["source:", "  type: file", f"  path: data/{cname}.csv   # TODO: put the file in the data folder"]
    else:
        bu = url_guess or "https://api.example.com"
        h = host or "api.example.com"
        lines += ["source:", "  type: http",
                  f"  base_url: {bu}" + ("" if base_url else ("   # guessed from a URL in the sample" if url_guess else "   # TODO")),
                  f"  allow_hosts: [{h}]"]
    lines += ["auth:", "  type: none   # TODO: api_key | basic | bearer | oauth2_client_credentials (+ secret NAME)"]
    if not (fmt == "csv" and not base_url):
        lines += ["request:", f"  method: {method}"]
        if method == "POST":
            lines.append("  read_only_post: true   # TODO: confirm this POST only reads")
        lines += [f"  path: {_q(path) if path else '/TODO/path'}" + ("" if path else "   # TODO"),
                  f"  format: {fmt}", f"  records_path: {_q(records_path) if records_path else chr(34) * 2}"]
        lines.append("pagination:")
        lines.append(f"  type: {paging['type']}   # {paging['why']}")
        for k, v in paging.items():
            if k not in ("type", "why") and v is not None:
                lines.append(f"  {k}: {_q(v)}")
    else:
        lines += ["request:", "  format: csv"]
    lines += ["schedule: every 15m", "map:"]
    for target, spec in specs.items():
        lines.append(_field_yaml(target, spec))
    if not specs:
        lines.append("  id: TODO")
    draft = "\n".join(lines) + "\n"

    validation = validate_config(draft)
    preview_mapped: list[dict] = []
    um: list[str] = []
    try:
        cfg = load_config(draft)
        for rec in records[:5]:
            try:
                preview_mapped.append(map_record(rec, cfg))
            except MappingError as e:
                preview_mapped.append({"_quarantined": str(e)})
        um = unmapped_fields(records, cfg)
    except ConfigError:
        pass

    filled = sum(1 for t in ENTITY_FIELDS[entity] if t in specs) / len(ENTITY_FIELDS[entity])
    req_ok = all(r in specs for r in DEFAULT_REQUIRED[entity])
    level = "high" if filled >= 0.75 and req_ok else "medium" if req_ok else "low"
    guesses = {t: {"spec": specs[t], "example": chosen[t][0].example if t in chosen else None,
                   "score": round(chosen[t][1], 2) if t in chosen else None} for t in specs}
    return {
        "draft_yaml": draft,
        "format": fmt,
        "records_path": records_path,
        "record_count": len(records),
        "entity": entity,
        "guesses": guesses,
        "paging_guess": paging,
        "preview_raw": records[:5],
        "preview_mapped": preview_mapped,
        "unmapped_fields": um,
        "confidence": {"level": level, "fields_filled": round(filled, 2), "required_ok": req_ok},
        "validation": validation,
        "alternatives": [{"records_path": p, "count": c} for p, c in alternatives[1:6]],
        "notes": notes,
    }


def profile_response(resp: httpx.Response, entity: Optional[str] = None, **kw) -> dict:
    """Profile a live response (keeps its Link header)."""
    head = "".join(f"{k}: {v}\n" for k, v in resp.headers.items() if k.lower() == "link")
    text = (f"HTTP/1.1 {resp.status_code}\n{head}\n" if head else "") + resp.text
    return profile_sample(text, entity, **kw)
