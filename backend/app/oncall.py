"""On-call rotation and escalation.

P1: page primary now, secondary after 5 min, Tier 3 lead after 15 min unless acknowledged.
P2: page primary now, secondary after 15 min, Tier 3 lead after 30 min.
P3/P4: Slack and queue only (business hours).
Incidents inside an approved maintenance window are not paged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

ENGINEERS = ["Mara Villanueva", "Paolo Reyes", "Kenji Morales", "Bea Santos"]
LEADS = ["Rafael Cruz", "Lia Tan"]
SHIFTS = [("NOC Shift A", 6, 14, ["Jamie Ong", "Carlo Diaz"]), ("NOC Shift B", 14, 22, ["Nina Lopez", "Ivan Sy"]),
          ("NOC Shift C", 22, 6, ["Toni Ramos", "Gab Uy"])]
POLICY = {"P1": [(0, "primary"), (5, "secondary"), (15, "tier3")],
          "P2": [(0, "primary"), (15, "secondary"), (30, "tier3")]}
EPOCH = datetime(2026, 1, 5, tzinfo=UTC)          # a Monday: rotation week 0


def rotation(now: datetime, weeks: int = 4) -> list[dict]:
    out = []
    for k in range(weeks):
        w = (now - EPOCH).days // 7 + k
        start = EPOCH + timedelta(weeks=w)
        out.append({"week_start": start.date().isoformat(), "primary": ENGINEERS[w % 4], "secondary": ENGINEERS[(w + 1) % 4],
                    "tier3": LEADS[w % 2]})
    return out


def shift(now: datetime) -> dict:
    h = now.hour
    for name, a, b, people in SHIFTS:
        if (a < b and a <= h < b) or (a > b and (h >= a or h < b)):
            return {"name": name, "hours": f"{a:02}:00-{b:02}:00 UTC", "analysts": people}
    return {"name": "NOC", "hours": "", "analysts": []}


def current(now: datetime) -> dict:
    r = rotation(now, 1)[0]
    return r | {"shift": shift(now)}


class Escalator:
    def __init__(self):
        self.state: dict[str, dict] = {}            # incident id -> {first_seen, acked_by, acked_at, pages, title, severity}

    def sync(self, incidents: list[dict], now: datetime, minute_seconds: float) -> list[dict]:
        """Returns new pages to send this call."""
        oc = current(now)
        new = []
        live = {i["id"]: i for i in incidents}
        for iid in [k for k in self.state if k not in live]:
            del self.state[iid]
        for iid, inc in live.items():
            st = self.state.setdefault(iid, {"first_seen": now, "acked_by": None, "acked_at": None, "pages": [],
                                             "title": inc["title"], "severity": inc["severity"]})
            st["severity"] = inc["severity"]
            if inc["severity"] not in POLICY or st["acked_by"] or inc.get("maintenance"):
                continue
            elapsed = (now - st["first_seen"]).total_seconds() / max(minute_seconds, 0.001)
            done = {p["level"] for p in st["pages"]}
            for after, level in POLICY[inc["severity"]]:
                if elapsed >= after and level not in done:
                    page = {"at": now.isoformat(), "level": level, "to": oc[level], "incident_id": iid,
                            "severity": inc["severity"], "title": inc["title"], "after_min": after}
                    st["pages"].append(page)
                    new.append(page)
        return new

    def ack(self, iid: str, who: str, now: datetime) -> dict:
        st = self.state.get(iid)
        if not st:
            raise KeyError(iid)
        if st["acked_by"]:
            raise ValueError(f"Already acknowledged by {st['acked_by']}")
        st["acked_by"], st["acked_at"] = who, now.isoformat()
        return st

    def view(self, iid: str) -> dict | None:
        st = self.state.get(iid)
        if not st:
            return None
        return {"acked_by": st["acked_by"], "acked_at": st["acked_at"], "pages": st["pages"],
                "first_seen": st["first_seen"].isoformat()}

    def log(self) -> list[dict]:
        pages = [p | {"acked_by": s["acked_by"]} for s in self.state.values() for p in s["pages"]]
        return sorted(pages, key=lambda p: p["at"], reverse=True)[:40]
