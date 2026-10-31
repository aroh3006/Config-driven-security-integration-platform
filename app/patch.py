"""Works out the patch panel: which sockets show and where each cable runs.

Rows have a fixed height, so every y position is known on the server. The cable
columns stretch sideways using a viewBox that is 100 units wide.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from app.theme import RANK, tone

ROW_HEIGHT = 48
ROW_GAP = 12
STEP = ROW_HEIGHT + ROW_GAP
OUTPUTS = (("users", "user"), ("devices", "device"), ("alerts", "alert"))
ENTRY_SPREAD = 150
OUTPUT_GAP = 74


def _curve(start: float, end: float) -> str:
    return f"M0 {start:g} C 50 {start:g}, 50 {end:g}, 100 {end:g}"


def _order(row: dict[str, Any]) -> tuple[int, int, str]:
    return (RANK[tone(row["status"])], 1 if row["mock"] else 0, row["name"])


def choose(rows: list[dict[str, Any]], limit: int, focus: str | None = None) -> list[dict[str, Any]]:
    """Worst status first, real before mock. The focused connector always shows, on top."""
    ordered = sorted(rows, key=_order)
    if focus:
        ordered = [r for r in ordered if r["name"] == focus] + [r for r in ordered if r["name"] != focus]
    return ordered[:limit]


def build(
    rows: list[dict[str, Any]],
    limit: int = 6,
    focus: str | None = None,
    tag: dict[str, str] | None = None,
    show_slot: bool = True,
) -> dict[str, Any]:
    """Return everything the patch panel template draws."""
    chosen = choose(rows, limit, focus)
    more = len(rows) - len(chosen)
    count = len(chosen) + (1 if more else 0) + (1 if show_slot else 0)
    height = max(count, 3) * STEP - ROW_GAP
    middle = height / 2

    sockets = []
    cables_in = []
    entry_gap = min(24, ENTRY_SPREAD / max(len(chosen), 1))
    for index, row in enumerate(chosen):
        y = index * STEP + ROW_HEIGHT / 2
        entry = middle + (index - (len(chosen) - 1) / 2) * entry_gap
        row_tone = tone(row["status"])
        sockets.append(
            {
                "name": row["name"],
                "mock": row["mock"],
                "status": row["status"],
                "tone": row_tone,
                "detail": row.get("detail", ""),
                "href": f"/ui/connector/{quote(row['name'])}",
            }
        )
        cables_in.append(
            {
                "d": _curve(y, entry),
                "tone": row_tone,
                "flows": row_tone == "teal",
            }
        )

    slot_y = None
    if show_slot:
        slot_y = (count - 1) * STEP + ROW_HEIGHT / 2
        cables_in.append({"d": _curve(slot_y, middle), "tone": "grey", "flows": False})

    stored = {entity: 0 for _, entity in OUTPUTS}
    for row in rows:
        stored[row["entity"]] = stored.get(row["entity"], 0) + row["stored"]
    outputs = []
    cables_out = []
    for index, (label, entity) in enumerate(OUTPUTS):
        y = middle + (index - 1) * OUTPUT_GAP
        outputs.append({"label": label, "y": y, "count": stored[entity], "href": f"/ui/records/{label}"})
        cables_out.append({"d": _curve(middle + (index - 1) * 28, y), "flows": any(c["flows"] for c in cables_in)})

    placed_tag = None
    if tag and sockets:
        placed_tag = {**tag, "y": (ROW_HEIGHT / 2 + (middle + (0 - (len(chosen) - 1) / 2) * entry_gap)) / 2}

    return {
        "sockets": sockets,
        "more": more,
        "slot": show_slot,
        "cables_in": cables_in,
        "outputs": outputs,
        "cables_out": cables_out,
        "height": height,
        "tag": placed_tag,
        "totals": stored,
    }
