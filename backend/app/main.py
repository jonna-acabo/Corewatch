"""CoreWatch API.  Run:  uvicorn app.main:app --reload   (from backend/)"""

from __future__ import annotations

import asyncio
import contextlib
import random
import re
import threading
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import audit as aud
from . import lab, oncall
from . import network as net_mod
from .ai import Analyst, MockAnalyst, make_analyst
from .changes import TEMPLATES, ChangeManager
from .config import settings
from .correlation import correlate, stats
from .junos_cli import SUGGESTED, Cli
from .slack import SlackAlerter

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


class State:
    """In-memory network + incident bookkeeping."""

    def __init__(self, seed: int = settings.sim_seed, seeded_faults: bool = True, live_lab: bool | None = None):
        self.lock = threading.RLock()
        self.rnd = random.Random(seed)
        self.lab = bool(settings.lab_devices) if live_lab is None else live_lab
        self.net = lab.poll() if self.lab else net_mod.build_network(seed)
        seeded = net_mod.seed_faults(self.net, utcnow(), self.rnd) if seeded_faults and not self.lab else []
        self.changes = ChangeManager()
        self.escalator = oncall.Escalator()
        self.slack = SlackAlerter(settings.slack_webhook_url, settings.slack_channel)
        self.analyses: dict[str, dict] = {}
        self.tickets: dict[str, dict] = {}
        self.carrier_tickets: dict[str, dict] = {}
        self.events: list[dict] = []
        self.next_ticket = 7301
        self.log(f"Polling {len(self.net.devices)} devices ({'NETCONF lab' if self.lab else 'mock network'})")
        for text in seeded:
            self.log("Detected: " + text)
        if not self.lab:
            self._seed_changes()

    def _seed_changes(self) -> None:
        """A finished change and a draft waiting for approval, so the Changes page is not empty."""
        now, cm = utcnow(), self.changes
        oc = oncall.current(now)
        c = cm.create(self.net, "junos_upgrade", {"device": "srx-fw-02.dc2"}, oc["secondary"], now)
        cm.create(self.net, "transit_drain", {"device": "mx-edge-01.dc1", "peer": "192.0.2.1"}, oc["primary"], now)
        c["history"].append({"at": now.isoformat(), "text": "Waiting for the maintenance window (Sat 02:00 UTC)"})

    def log(self, text: str) -> None:
        self.events.insert(0, {"at": utcnow().isoformat(), "text": text})
        del self.events[60:]

    def incidents(self) -> list[dict]:
        with self.lock:
            incs = correlate(self.net, utcnow(), self.changes.active())
            for i in incs:
                i["analysis"] = self.analyses.get(i["id"])
                i["ticket"] = self.tickets.get(i["id"])
                i["carrier_ticket"] = self.carrier_tickets.get(i["id"])
                i["oncall"] = self.escalator.view(i["id"])
            return incs

    def sync_alerts(self) -> None:
        now = utcnow()
        with self.lock:
            incs = self.incidents()
            primary = oncall.current(now)["primary"]
            for m in self.slack.sync(incs, primary, now, settings.public_url):
                first = re.sub(r":[a-z_]+:|\*|<[^>]+>", "", m["text"].splitlines()[0]).strip()
                self.log(f"Slack {m['channel']} ({m['status']}): {first[:110]}")
            for p in self.escalator.sync(incs, now, settings.escalation_minute_seconds):
                self.slack.page(p, now)
                self.log(f"Paged {p['level']} on-call {p['to']} for {p['severity']} {p['title'][:70]}")
            for line in self.changes.expire(self.net, now):
                self.log(line)


class TicketIn(BaseModel):
    title: str = Field(min_length=5, max_length=140)
    body: str = Field(default="", max_length=10000)


class CliIn(BaseModel):
    device: str
    command: str = Field(min_length=2, max_length=200)


class ChangeIn(BaseModel):
    template: str
    params: dict = Field(default_factory=dict)
    user: str | None = None


class UserIn(BaseModel):
    user: str | None = None


def create_app(state: State | None = None, analyst: Analyst | None = None, simulate: bool | None = None) -> FastAPI:
    state = state or State()
    analyst = analyst or make_analyst()
    simulate = settings.sim_enabled if simulate is None else simulate

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks = []
        state.sync_alerts()
        if simulate or state.lab:
            async def fast():
                while True:
                    await asyncio.sleep(2)
                    state.sync_alerts()

            async def slow():
                while True:
                    await asyncio.sleep(settings.lab_poll_seconds if state.lab else settings.sim_interval_seconds)
                    if state.lab:
                        new = await asyncio.to_thread(lab.poll, state.net)
                        with state.lock:
                            state.net = new
                        continue
                    with state.lock:
                        net_mod.tick(state.net, utcnow(), state.rnd)
                        if state.rnd.random() < settings.sim_fault_chance:
                            state.log("Simulator: " + net_mod.random_fault(state.net, utcnow(), state.rnd))
            tasks = [asyncio.create_task(fast()), asyncio.create_task(slow())]
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title="CoreWatch", version="1.0.0", lifespan=lifespan)
    app.state.cw = state

    def get_incident(iid: str) -> dict:
        inc = next((i for i in state.incidents() if i["id"] == iid), None)
        if not inc:
            raise HTTPException(404, "Incident not found or already resolved")
        return inc

    def user(body: UserIn | ChangeIn | None, role: str = "primary") -> str:
        return (body.user if body and body.user else None) or oncall.current(utcnow())[role]

    # ---------------------------------------------------------------- overview
    @app.get("/api/health")
    def health():
        return {"status": "ok", "mode": "lab" if state.lab else "mock", "ai_provider": analyst.name,
                "ai_model": settings.ai_model if analyst.name != "mock" else None, "simulator": simulate}

    @app.get("/api/summary")
    def summary():
        incs = state.incidents()
        with state.lock:
            a = aud.audit(state.net)
            return stats(state.net, incs) | {"compliance": a["score"], "mode": "lab" if state.lab else "mock",
                                             "ai_provider": analyst.name, "oncall": oncall.current(utcnow()),
                                             "changes_active": len(state.changes.active()),
                                             "changes_pending": sum(c["status"] in {"draft", "approved"}
                                                                    for c in state.changes.changes.values())}

    @app.get("/api/topology")
    def topology():
        with state.lock:
            net = state.net
            devs = [{"id": h, "model": d.model, "role": d.role, "site": d.site, "x": d.x, "y": d.y, "powered": d.powered,
                     "mgmt_ok": d.mgmt_ok, "alarms": len([a for a in d.alarms if a.source != "System"])}
                    for h, d in net.devices.items()]
            links, clouds = [], {}
            for lk in net.links:
                a = net.iface(*lk.a)
                state_ = "up" if a.oper_up and (not lk.b or net.iface(*lk.b).oper_up) else "down"
                if state_ == "up" and (a.crc_per_min or (lk.b and net.iface(*lk.b).crc_per_min)):
                    state_ = "degraded"
                circuit = net.circuits.get(lk.circuit) if lk.circuit else None
                item = {"a": lk.a[0], "a_if": lk.a[1], "b": lk.b[0] if lk.b else None, "b_if": lk.b[1] if lk.b else None,
                        "circuit": lk.circuit, "state": state_, "util": a.util_pct, "costed_out": lk.costed_out,
                        "speed": a.speed_gbps}
                if not lk.b and circuit:
                    car = net.carriers[circuit.carrier]
                    item["cloud"] = car.id
                    clouds[car.id] = {"id": car.id, "name": car.name, "asn": car.asn}
                links.append(item)
            xs = {"tidegate": 170, "bayport": 500, "corvane": 830}
            cl = [c | {"x": xs.get(c["id"], 100 + 200 * k), "y": 42} for k, c in enumerate(clouds.values())]
            return {"devices": devs, "links": links, "clouds": cl, "mode": net.source}

    # ---------------------------------------------------------------- incidents
    @app.get("/api/incidents")
    def list_incidents():
        out = []
        for i in state.incidents():
            light = {k: v for k, v in i.items() if k not in {"analysis", "diff"}}
            light["has_analysis"] = bool(i["analysis"])
            out.append(light)
        return out

    @app.get("/api/incidents/{iid}")
    def incident(iid: str):
        return get_incident(iid)

    @app.post("/api/incidents/{iid}/analyze")
    def analyze(iid: str):
        inc = get_incident(iid)
        result = analyst.analyze(inc) | {"generated_at": utcnow().isoformat()}
        with state.lock:
            state.analyses[iid] = result
        state.log(f"AI analysed: {inc['title'][:80]}")
        return result

    @app.post("/api/incidents/{iid}/verify")
    def verify(iid: str):
        inc = get_incident(iid)
        with state.lock:
            cli = Cli(state.net, utcnow())
            return [{"device": v["device"], "cmd": v["cmd"], "output": cli.run(v["device"], v["cmd"])} for v in inc["verify"]]

    @app.post("/api/incidents/{iid}/ticket", status_code=201)
    def ticket(iid: str, body: TicketIn):
        inc = get_incident(iid)
        if state.tickets.get(iid):
            raise HTTPException(409, f"Ticket {state.tickets[iid]['key']} already exists for this incident.")
        with state.lock:
            t = {"key": f"NOC-{state.next_ticket}", "title": body.title, "body": body.body, "created_at": utcnow().isoformat(),
                 "status": "Open"}
            state.next_ticket += 1
            state.tickets[iid] = t
        state.log(f"{t['key']} opened: {inc['title'][:80]}")
        return t

    @app.post("/api/incidents/{iid}/carrier-ticket", status_code=201)
    def carrier_ticket(iid: str):
        inc = get_incident(iid)
        if not inc.get("carrier"):
            raise HTTPException(409, "This incident is not a carrier or peer issue.")
        if state.carrier_tickets.get(iid):
            raise HTTPException(409, "A fault is already open with the carrier for this incident.")
        msg = (state.analyses.get(iid) or analyst.analyze(inc))["carrier_message"]
        if msg.startswith("Not needed"):
            msg = MockAnalyst().analyze(inc)["carrier_message"]
        with state.lock:
            car = next((c for c in state.net.carriers.values() if c.name == inc["carrier"]), None)
            ref = f"{(car.id[:3] if car else 'EXT').upper()}-TT-{state.rnd.randint(100000, 999999)}"
            t = {"carrier": inc["carrier"], "to": car.noc_email if car else "", "reference": ref, "message": msg,
                 "sla_h": car.sla_mttr_h if car else None, "opened_at": utcnow().isoformat(),
                 "status": "Sent (mock email)"}
            state.carrier_tickets[iid] = t
            cid = inc["scope"].get("circuit")
            if cid and cid in state.net.circuits:
                state.net.circuits[cid].carrier_ticket = t
        state.log(f"Fault raised with {inc['carrier']}: {ref}")
        return t

    @app.post("/api/incidents/{iid}/ack")
    def ack(iid: str, body: UserIn | None = None):
        get_incident(iid)
        who = user(body)
        try:
            st = state.escalator.ack(iid, who, utcnow())
        except KeyError as e:
            raise HTTPException(409, "Not tracked yet, try again in a few seconds") from e
        except ValueError as e:
            raise HTTPException(409, str(e)) from e
        state.slack.send(f":eyes: *{who} acknowledged* · {st['severity']} · {st['title']}", "ack", iid, st["severity"], utcnow())
        state.log(f"{who} acknowledged {st['title'][:80]}")
        return state.escalator.view(iid)

    # ---------------------------------------------------------------- devices + CLI
    @app.get("/api/devices")
    def devices():
        with state.lock:
            a = {x["device"]: x["score"] for x in aud.audit(state.net)["devices"]}
            return [{"hostname": h, "model": d.model, "role": d.role, "site": d.site, "version": d.version, "mgmt_ip": d.mgmt_ip,
                     "powered": d.powered, "mgmt_ok": d.mgmt_ok, "cpu": round(d.re_cpu), "temp_c": round(d.temp_c, 1),
                     "alarms": len([x for x in d.alarms if x.source != "System"]),
                     "interfaces_up": sum(i.oper_up for i in d.interfaces.values() if i.admin_up),
                     "interfaces": sum(i.admin_up for i in d.interfaces.values()),
                     "bgp_up": sum(p.state == "Established" for p in d.bgp), "bgp": len(d.bgp),
                     "ospf_up": sum(n.state == "Full" for n in d.ospf), "ospf": len(d.ospf), "compliance": a.get(h),
                     "uptime_days": d.uptime_days} for h, d in state.net.devices.items()]

    @app.get("/api/devices/{host}")
    def device(host: str):
        with state.lock:
            d = state.net.devices.get(host)
            if not d:
                raise HTTPException(404, "Unknown device")
            net = state.net
            return {"hostname": host, "model": d.model, "family": d.family, "role": d.role, "site": d.site, "version": d.version,
                    "mgmt_ip": d.mgmt_ip, "loopback": d.loopback, "serial": d.serial, "powered": d.powered, "mgmt_ok": d.mgmt_ok,
                    "cpu": round(d.re_cpu), "mem": round(d.re_mem), "temp_c": d.temp_c,
                    "interfaces": [{"name": i.name, "description": i.description, "admin_up": i.admin_up, "oper_up": i.oper_up,
                                    "speed": i.speed_gbps, "rx_dbm": i.rx_dbm, "util": i.util_pct, "crc": int(i.crc_per_min),
                                    "errors": i.in_errors, "history": i.history[-30:],
                                    "circuit": (net.link_of(host, i.name).circuit if net.link_of(host, i.name) else None)}
                                   for i in d.interfaces.values()],
                    "bgp": [{"peer": p.peer_ip, "as": p.peer_as, "group": p.group, "description": p.description,
                             "state": "Idle (deactivated)" if p.admin_down else p.state, "prefixes": p.prefixes_rx,
                             "flaps": p.flaps, "kind": p.kind} for p in d.bgp],
                    "te": [{"peer": p.peer_ip, "description": p.description, "group": p.group, "prepend": te[0], "local_pref": te[1],
                            "in_gbps": round(d.interfaces[p.interface].in_bps / 1e9, 1),
                            "out_gbps": round(d.interfaces[p.interface].out_bps / 1e9, 1)}
                           for p in d.bgp if p.kind == "external" for te in [net_mod.te_policy(d, p.group)]],
                    "ospf": [{"interface": n.interface, "neighbor": n.peer_device, "address": n.address, "state": n.state}
                             for n in d.ospf],
                    "alarms": [{"class": a.klass, "description": a.description, "since": a.since.isoformat()} for a in d.alarms],
                    "commits": [{"rev": c.rev, "at": c.at.isoformat(), "user": c.user, "via": c.via, "comment": c.comment,
                                 "change": c.change_id} for c in d.commits[:8]]}

    @app.post("/api/cli")
    def cli(body: CliIn):
        with state.lock:
            out = Cli(state.net, utcnow()).run(body.device, body.command)
        return {"device": body.device, "command": body.command, "output": out}

    @app.get("/api/cli/suggest")
    def cli_suggest():
        return SUGGESTED

    # ---------------------------------------------------------------- changes
    @app.get("/api/changes")
    def changes():
        return sorted(state.changes.changes.values(), key=lambda c: c["id"], reverse=True)

    @app.get("/api/changes/templates")
    def templates():
        with state.lock:
            net = state.net
            return {"templates": [{"id": k} | v for k, v in TEMPLATES.items()],
                    "devices": list(net.devices),
                    "peers": {h: [{"ip": p.peer_ip, "label": p.description} for p in d.bgp if p.kind == "external"]
                              for h, d in net.devices.items()},
                    "links": {h: [{"if": i.name, "label": i.description} for i in d.interfaces.values()
                                  if net.link_of(h, i.name) and net.link_of(h, i.name).b] for h, d in net.devices.items()}}

    @app.post("/api/changes", status_code=201)
    def create_change(body: ChangeIn):
        with state.lock:
            fix = None
            if body.template == "compliance_fix":
                d = state.net.devices.get(body.params.get("device", ""))
                fix = aud.audit_device(d)["auto_fix"] if d else None
            try:
                c = state.changes.create(state.net, body.template, body.params, user(body), utcnow(), fix)
            except ValueError as e:
                raise HTTPException(400, str(e)) from e
        state.log(f"{c['id']} drafted: {c['title']}")
        return c

    @app.post("/api/changes/{cid}/{action}")
    def change_action(cid: str, action: str, body: UserIn | None = None):
        cm, now = state.changes, utcnow()
        if cid not in cm.changes:
            raise HTTPException(404, "Unknown change")
        with state.lock:
            try:
                if action == "approve":
                    c = cm.approve(cid, user(body, "tier3"), now)
                elif action == "implement":
                    c = cm.implement(state.net, cid, user(body), now)
                elif action == "confirm":
                    c = cm.confirm(state.net, cid, user(body), now)
                elif action == "rollback":
                    c = cm.rollback(state.net, cid, user(body), now)
                elif action == "close":
                    c = cm.close(state.net, cid, user(body), now)
                else:
                    raise HTTPException(400, "Unknown action")
            except ValueError as e:
                raise HTTPException(409, str(e)) from e
            net_mod.derive(state.net, now)
        state.log(f"{cid} {action}: {c['history'][-1]['text']}")
        state.sync_alerts()
        return c

    # ---------------------------------------------------------------- audits, carriers, on-call, slack
    @app.get("/api/audit")
    def audit_view():
        with state.lock:
            return aud.audit(state.net)

    @app.post("/api/audit/{host}/fix", status_code=201)
    def audit_fix(host: str, body: UserIn | None = None):
        return create_change(ChangeIn(template="compliance_fix", params={"device": host}, user=body.user if body else None))

    @app.get("/api/hardware")
    def hardware():
        with state.lock:
            return aud.hardware(state.net)

    @app.get("/api/circuits")
    def circuits():
        with state.lock:
            net, out = state.net, []
            for c in net.circuits.values():
                i = net.iface(*c.a_end)
                car = net.carriers[c.carrier]
                st = "down" if not i.oper_up else "degraded" if i.crc_per_min or i.rx_dbm < settings.rx_low_warn_dbm else "up"
                out.append({"id": c.id, "carrier": car.name, "carrier_id": car.id, "service": c.service,
                            "bandwidth": c.bandwidth_gbps, "a_end": f"{c.a_end[0]} {c.a_end[1]}", "z_end": c.z_end, "state": st,
                            "util": i.util_pct, "rx_dbm": i.rx_dbm, "crc": int(i.crc_per_min), "history": i.history[-30:],
                            "ticket": c.carrier_ticket, "sla_h": car.sla_mttr_h, "noc_email": car.noc_email,
                            "noc_phone": car.noc_phone, "account": car.account})
            return {"circuits": out, "carriers": [vars(c) for c in net.carriers.values()]}

    @app.get("/api/oncall")
    def oncall_view():
        now = utcnow()
        return {"current": oncall.current(now), "rotation": oncall.rotation(now, 4),
                "policy": {k: [{"after_min": a, "level": lv} for a, lv in v] for k, v in oncall.POLICY.items()},
                "minute_seconds": settings.escalation_minute_seconds, "pages": state.escalator.log()}

    @app.get("/api/slack")
    def slack_feed():
        return {"mode": state.slack.mode, "channel": state.slack.channel, "min_severity": settings.alert_min_severity,
                "messages": state.slack.sent[:30]}

    @app.get("/api/events")
    def events():
        return state.events

    @app.post("/api/simulate/{fault}")
    def simulate_fault(fault: str):
        if state.lab:
            raise HTTPException(409, "Simulation is disabled in live lab mode")
        now = utcnow()
        with state.lock:
            if fault == "restore":
                n = net_mod.restore_all(state.net, now)
                state.analyses.clear()
                text = f"Restored the network ({n} faults cleared)"
            elif fault == "tick":
                net_mod.tick(state.net, now, state.rnd)
                text = "Advanced the simulation one poll"
            elif fault in net_mod.FAULTS:
                text = net_mod.inject(state.net, fault, now, state.rnd)
            else:
                raise HTTPException(400, "Unknown fault. Use one of: " + ", ".join(net_mod.FAULTS + ("tick", "restore")))
        state.log("Simulated: " + text)
        state.sync_alerts()
        return {"event": fault, "text": text}

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        with state.lock:
            return render_metrics(state, state.incidents())

    if FRONTEND.exists():
        app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
    return app


def render_metrics(state: State, incs: list[dict]) -> str:
    net = state.net
    out: list[str] = []

    def g(name: str, help_: str, rows: list[tuple[dict, float]]):
        out.extend([f"# HELP {name} {help_}", f"# TYPE {name} gauge"])
        for labels, v in rows:
            lab_ = ",".join(f'{k}="{str(x).replace(chr(34), "")}"' for k, x in labels.items())
            out.append(f"{name}{{{lab_}}} {v}" if lab_ else f"{name} {v}")

    devs = list(net.devices.values())
    g("corewatch_device_up", "Device forwarding (1) or down (0)", [({"device": d.hostname, "site": d.site}, int(d.powered))
                                                                  for d in devs])
    g("corewatch_mgmt_up", "Management reachable", [({"device": d.hostname}, int(d.mgmt_ok)) for d in devs])
    g("corewatch_re_cpu_percent", "Routing engine CPU", [({"device": d.hostname}, round(d.re_cpu, 1)) for d in devs])
    g("corewatch_chassis_temp_celsius", "Chassis temperature", [({"device": d.hostname}, d.temp_c) for d in devs])
    ifs = [(d, i, net.link_of(d.hostname, i.name)) for d in devs for i in d.interfaces.values() if i.admin_up]
    lbl = [(d, i, {"device": d.hostname, "interface": i.name, "circuit": lk.circuit or "" if lk else ""}) for d, i, lk in ifs]
    g("corewatch_interface_up", "Interface oper status", [(x, int(i.oper_up)) for _, i, x in lbl])
    g("corewatch_interface_util_percent", "Interface utilisation", [(x, i.util_pct) for _, i, x in lbl])
    g("corewatch_interface_rx_dbm", "Optic receive power", [(x, i.rx_dbm) for _, i, x in lbl])
    g("corewatch_interface_crc_per_min", "Input/CRC errors per minute", [(x, i.crc_per_min) for _, i, x in lbl])
    g("corewatch_bgp_peer_up", "BGP session established",
      [({"device": d.hostname, "peer": p.peer_ip, "peer_as": p.peer_as, "group": p.group}, int(p.state == "Established"))
       for d in devs for p in d.bgp])
    g("corewatch_bgp_prefixes_received", "Prefixes received",
      [({"device": d.hostname, "peer": p.peer_ip}, p.prefixes_rx) for d in devs for p in d.bgp])
    g("corewatch_ospf_neighbor_up", "OSPF adjacency Full",
      [({"device": d.hostname, "interface": n.interface}, int(n.state == "Full")) for d in devs for n in d.ospf])
    g("corewatch_chassis_alarms", "Active chassis alarms", [({"device": d.hostname}, len(d.alarms)) for d in devs])
    g("corewatch_incidents", "Open incidents by severity",
      [({"severity": s}, sum(i["severity"] == s for i in incs)) for s in ("P1", "P2", "P3", "P4")])
    st = stats(net, incs)
    g("corewatch_symptoms", "Raw alarms before correlation", [({}, st["symptoms"])])
    g("corewatch_compliance_score", "Golden-config compliance %",
      [({"device": x["device"]}, x["score"]) for x in aud.audit(net)["devices"]])
    return "\n".join(out) + "\n"


app = create_app()
