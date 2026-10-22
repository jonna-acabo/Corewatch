"""AI incident analyst.

`analyze(incident)` returns: summary, likely cause, confidence, next steps, a NOC ticket, a message to the carrier
or peer (when it is their fault) and an escalation note for the on-call engineer.

Providers:
  * AnthropicAnalyst - an LLM through the Anthropic Messages API (needs ANTHROPIC_API_KEY)
  * MockAnalyst      - deterministic offline writer so the demo works without a key
`auto` uses the LLM when a key is set and falls back to the offline writer on any error.
"""

from __future__ import annotations

import json
import re
import urllib.request
from datetime import UTC, datetime
from typing import Protocol

from .config import settings

REQUIRED = ("summary", "likely_cause", "confidence", "next_steps", "ticket_title", "ticket_body", "carrier_message",
            "escalation_note")

SYSTEM_PROMPT = """You are a senior network engineer in the NOC of an ISP that runs a Juniper (Junos) core and edge network:
MX480 core routers, MX204 internet edge routers with IP transit and IX peering, SRX firewalls, QFX data-centre leafs and
EX aggregation switches at POPs connected over carrier circuits. OSPF area 0 inside, iBGP with the cores as route
reflectors, eBGP to transit providers and the IX route server.

You receive one correlated incident as JSON: the evidence the correlation engine used, the symptoms it grouped,
the devices, circuits and carriers involved, and the Junos commands that verify it. Write for a busy NOC engineer.
Be specific: name devices, interfaces, circuit IDs, peers and numbers. Do not invent facts that are not in the data.
If the data is ambiguous, say so and lower the confidence.

Return ONLY a JSON object with these keys:
  "summary": 2-3 sentences, what happened and what it affects,
  "likely_cause": one sentence,
  "confidence": "high" | "medium" | "low",
  "next_steps": array of 3-5 short imperative steps, in order,
  "ticket_title": under 100 characters, format "<P1-P4> | <SA or NSA> | <device or circuit> | <short issue>",
  "ticket_body": plain text (impact, evidence, actions taken, next steps),
  "carrier_message": if a carrier or peer must act, a short professional email to their NOC (first line "Subject: ...")
                     quoting circuit ID, account, times and readings; otherwise "Not needed: <reason>",
  "escalation_note": 2-3 sentences for the on-call / Tier 3 engineer: what is known, what was checked, what is needed."""


class Analyst(Protocol):
    name: str

    def analyze(self, incident: dict) -> dict: ...


def _age(inc: dict) -> str:
    mins = int((datetime.now(UTC) - datetime.fromisoformat(inc["started_at"])).total_seconds() // 60)
    return "just now" if mins < 1 else f"{mins} min" if mins < 120 else f"{mins // 60} h"


CAUSE = {
    "device_down": ("The chassis lost power or crashed: every neighbour lost light at once and management is gone.", "high"),
    "fpc_offline": ("A line card (FPC) failed; everything on it went down together while the rest of the chassis is fine.", "high"),
    "isolated": ("Every uplink path to the site failed; with both carriers involved, look for a shared duct, building or power fault.",
                 "medium"),
    "all_transit_down": ("Both transit circuits failed together: a shared physical path or upstream event is most likely.", "medium"),
    "circuit_down": ("Loss of light on the carrier circuit: a fibre cut or equipment fault in the carrier's network.", "high"),
    "link_down": ("Loss of light on both ends of an internal link: patch, fibre or optic between the two devices.", "medium"),
    "psu_failed": ("A power supply or its feed failed; the chassis runs on the remaining supplies.", "high"),
    "fan_failed": ("A failed fan tray is reducing cooling, so the chassis temperature is climbing.", "high"),
    "temp_high": ("Room cooling problem: the chassis is hot but all fans are fine.", "medium"),
    "bgp_down": ("The physical link is healthy but the neighbour stopped sending keepalives: a remote-side or policy issue.", "medium"),
    "bgp_flap": ("The BGP session is unstable on a clean link: likely the peer's router or a timer problem.", "medium"),
    "circuit_errors": ("Degraded light in the carrier path (receive power down, CRC errors on receive only).", "high"),
    "optics_low": ("Dirty connector, ageing optic or a stressed fibre is reducing receive power.", "medium"),
    "util_high": ("Traffic is close to the link's capacity.", "medium"),
    "cpu_high": ("A routing-engine process is using most of the CPU.", "medium"),
    "mgmt_down": ("The out-of-band management path failed; the device keeps forwarding traffic.", "high"),
    "unauthorized_commit": ("A configuration change was committed outside change control by a non-approved account.", "high"),
}


class MockAnalyst:
    """Offline writer. Same output shape as the LLM, built only from the incident data."""

    name = "mock"

    def analyze(self, inc: dict) -> dict:
        sc, sa = inc["scope"], "SA" if inc["service_affecting"] else "NSA"
        cause, conf = CAUSE.get(inc["kind"], ("See evidence.", "low"))
        where = sc.get("circuit") or sc.get("device") or ", ".join(inc["devices"])
        maint = f" It is inside the maintenance window of {inc['maintenance']}, so it may be expected." if inc.get("maintenance") else ""
        age = _age(inc)
        summary = (f"{inc['title']} ({inc['severity']}, {sa}), started {age if age == 'just now' else age + ' ago'}. "
                   f"{inc['evidence'][0]}. The engine grouped {inc['symptoms']} raw alarm(s) into this one incident.{maint}")
        steps = inc["recommended_actions"][:5]
        body = (f"Impact: {sa}. Owner: {inc['owner']}.\nStarted: {inc['started_at']}\nDevices: {', '.join(inc['devices'])}\n\n"
                "Evidence:\n" + "\n".join(f"- {e}" for e in inc["evidence"])
                + f"\n\nLikely cause: {cause}\n\nVerify with:\n" + "\n".join(f"- {v['device']}> {v['cmd']}" for v in inc["verify"])
                + "\n\nNext steps:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)))
        if inc.get("carrier") and inc["category"] in {"carrier", "routing"}:
            ref = sc.get("circuit") or sc.get("peer") or ""
            carrier_msg = (f"Subject: {inc['severity']} fault on {ref} - please investigate\n\n"
                           f"Hello {inc['carrier']} NOC,\n\nWe are seeing a fault on {ref} since "
                           f"{inc['started_at'][:16].replace('T', ' ')} UTC.\n"
                           + "\n".join(f"- {e}" for e in inc["evidence"][:3])
                           + "\n\nOur side has been checked (optics, interface, configuration). Please open a ticket, check your "
                           "network and share your reference and an ETA.\n\nThank you,\nNOC")
        else:
            carrier_msg = "Not needed: this is not a carrier or peer issue."
        esc = (f"{inc['title']}. {cause} Checked: {', '.join(v['cmd'] for v in inc['verify'][:2])}. "
               f"Needs: {steps[0] if steps else 'review'}")
        return {"summary": summary, "likely_cause": cause, "confidence": conf, "next_steps": steps,
                "ticket_title": f"{inc['severity']} | {sa} | {where} | {inc['kind'].replace('_', ' ').upper()}"[:100],
                "ticket_body": body, "carrier_message": carrier_msg, "escalation_note": esc}


def _extract_json(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("No JSON object in model output")
    data = json.loads(m.group(0))
    missing = [k for k in REQUIRED if k not in data]
    if missing:
        raise ValueError(f"Model output missing keys: {missing}")
    if not isinstance(data["next_steps"], list):
        data["next_steps"] = [str(data["next_steps"])]
    if data["confidence"] not in {"high", "medium", "low"}:
        data["confidence"] = "medium"
    return data


def compact_incident(inc: dict) -> dict:
    return {k: v for k, v in inc.items() if k not in {"analysis", "ticket", "diff", "ack", "pages"}}


class AnthropicAnalyst:
    name = "anthropic"
    url = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str, transport=None):
        self.api_key, self.model = api_key, model
        self._post = transport or self._http_post

    def _http_post(self, payload: dict) -> dict:  # pragma: no cover - real network call
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers={
            "x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=40) as r:
            return json.load(r)

    def analyze(self, incident: dict) -> dict:
        payload = {"model": self.model, "max_tokens": 1200, "system": SYSTEM_PROMPT,
                   "messages": [{"role": "user", "content": json.dumps(compact_incident(incident), default=str)}]}
        resp = self._post(payload)
        text = "".join(b.get("text", "") for b in resp.get("content", []) if b.get("type") == "text")
        return _extract_json(text)


class FallbackAnalyst:
    """Try the LLM, fall back to the offline writer so the UI never breaks."""

    def __init__(self, primary: Analyst, fallback: Analyst):
        self.primary, self.fallback = primary, fallback
        self.name = primary.name

    def analyze(self, incident: dict) -> dict:
        try:
            out = self.primary.analyze(incident)
            out["provider"] = self.primary.name
        except Exception as e:  # noqa: BLE001 - any failure means fall back
            out = self.fallback.analyze(incident)
            out["provider"] = f"{self.fallback.name} (fallback: {type(e).__name__})"
        return out


def make_analyst() -> Analyst:
    mock = MockAnalyst()
    use_llm = settings.ai_provider == "anthropic" or (settings.ai_provider == "auto" and settings.anthropic_api_key)
    if use_llm and settings.anthropic_api_key:
        return FallbackAnalyst(AnthropicAnalyst(settings.anthropic_api_key, settings.ai_model), mock)
    return FallbackAnalyst(mock, mock)
