"""Slack notifications: new P1/P2 incidents, on-call escalations and recoveries.

Mode: webhook (SLACK_WEBHOOK_URL set) or mock (messages kept in memory and shown in the dashboard).
Each incident is announced once; incidents inside a maintenance window are logged as suppressed instead.
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime

from .config import settings

SEV_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
EMOJI = {"P1": ":rotating_light:", "P2": ":red_circle:", "P3": ":large_orange_circle:", "P4": ":large_blue_circle:"}


def should_alert(inc: dict) -> bool:
    return SEV_RANK[inc["severity"]] <= SEV_RANK.get(settings.alert_min_severity, 2)


def format_new(inc: dict, oncall: str, base_url: str) -> str:
    sa = "SA" if inc["service_affecting"] else "NSA"
    return "\n".join(x for x in [
        f"{EMOJI[inc['severity']]} *{inc['severity']} {sa} · {inc['title']}*",
        f"Owner: {inc['owner']}" + (f" · Circuit {inc['scope']['circuit']}" if inc["scope"].get("circuit") else ""),
        f"Evidence: {inc['evidence'][0]}" if inc["evidence"] else "",
        f"{inc['symptoms']} raw alarms grouped · On-call: {oncall}",
        f"<{base_url}/#incidents/{inc['id']}|Open in CoreWatch>"] if x)


class SlackAlerter:
    def __init__(self, webhook_url: str | None = None, channel: str = "#noc-core", post=None):
        self.webhook_url, self.channel = webhook_url, channel
        self.mode = "webhook" if webhook_url else "mock"
        self.sent: list[dict] = []
        self.open: dict[str, dict] = {}
        self.suppressed: set[str] = set()
        self._post = post or self._http_post

    def _http_post(self, payload: dict) -> None:  # pragma: no cover - real network call
        req = urllib.request.Request(self.webhook_url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10).read()

    def send(self, text: str, kind: str, inc_id: str, severity: str, now: datetime) -> dict:
        status = "sent"
        if self.mode == "webhook":
            try:
                self._post({"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]})
            except Exception as e:  # noqa: BLE001 - never let Slack break monitoring
                status = f"failed: {type(e).__name__}"
        msg = {"at": now.isoformat(), "kind": kind, "incident_id": inc_id, "severity": severity, "channel": self.channel,
               "text": text, "status": status}
        self.sent.insert(0, msg)
        del self.sent[100:]
        return msg

    def sync(self, incidents: list[dict], oncall: str, now: datetime, base_url: str = "http://localhost:8000") -> list[dict]:
        out = []
        live = {i["id"]: i for i in incidents}
        for iid, inc in live.items():
            if iid in self.open or not should_alert(inc):
                continue
            if inc.get("maintenance"):
                if iid not in self.suppressed:
                    self.suppressed.add(iid)
                    out.append({"kind": "suppressed", "incident_id": iid, "text": f"{inc['title']} (in {inc['maintenance']})",
                                "status": "suppressed", "channel": self.channel})
                continue
            out.append(self.send(format_new(inc, oncall, base_url), "new", iid, inc["severity"], now))
            self.open[iid] = {"title": inc["title"], "started_at": inc["started_at"]}
        for iid in [k for k in self.open if k not in live]:
            snap = self.open.pop(iid)
            mins = max(1, round((now - datetime.fromisoformat(snap["started_at"])).total_seconds() / 60))
            out.append(self.send(f":white_check_mark: *RESOLVED · {snap['title']}* · lasted {mins} min", "resolved", iid, "OK", now))
        self.suppressed &= set(live)
        return out

    def page(self, page: dict, now: datetime) -> dict:
        label = {"primary": "Paged primary on-call", "secondary": "Escalated to secondary on-call",
                 "tier3": "Escalated to Tier 3 lead"}[page["level"]]
        extra = f" (no ack after {page['after_min']} min)" if page["after_min"] else ""
        return self.send(f":pager: *{label}: {page['to']}*{extra} · {page['severity']} · {page['title']}", "page",
                         page["incident_id"], page["severity"], now)
