"""Fault correlation: turns raw symptoms (link down, OSPF/BGP down, chassis alarms, errors, ...) into incidents.

Rules run from the most fundamental cause to the least. Each rule claims the symptoms it explains so they
are not reported again: an FPC going offline explains its interfaces going down, which explains the OSPF
adjacencies and BGP sessions over them, which explains a firewall behind it becoming isolated.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from .config import settings
from .models import Link, Network

SEV_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


def short(host: str) -> str:
    return host.split(".")[0]


def _id(kind: str, key: str) -> str:
    return "INC-" + hashlib.sha1(f"{kind}:{key}".encode()).hexdigest()[:6].upper()


def _ago(t: datetime | None, now: datetime) -> str:
    if not t:
        return "unknown"
    m = int((now - t).total_seconds() // 60)
    if m < 1:
        return "just now"
    return f"{m} min ago" if m < 120 else f"{m // 60} h ago" if m < 2880 else f"{m // 1440} days ago"


# ------------------------------------------------------------------ symptoms
def symptoms(net: Network, now: datetime) -> set[tuple]:
    """Every raw alarm the NOC would otherwise see individually."""
    s: set[tuple] = set()
    for h, d in net.devices.items():
        if not d.powered:
            s.add(("DEV", h))
        if not d.mgmt_ok:
            s.add(("MGMT", h))
        if not d.powered:
            continue
        for i in d.interfaces.values():
            if i.admin_up and not i.oper_up and net.link_of(h, i.name):
                s.add(("IF", h, i.name))
            if i.oper_up and i.crc_per_min >= settings.crc_per_min:
                s.add(("CRC", h, i.name))
            if i.oper_up and i.rx_dbm < settings.rx_low_warn_dbm:
                s.add(("RX", h, i.name))
            if i.oper_up and i.util_pct >= settings.util_high_pct:
                s.add(("UTIL", h, i.name))
        for n in d.ospf:
            if n.state != "Full":
                s.add(("OSPF", h, n.interface))
        for p in d.bgp:
            if p.admin_down:
                continue
            if p.state != "Established":
                s.add(("BGP", h, p.peer_ip))
            elif len([t for t in p.flap_times if now - t <= timedelta(hours=1)]) >= settings.bgp_flap_count:
                s.add(("FLAP", h, p.peer_ip))
        for a in d.alarms:
            if a.description != "Rescue configuration is not set":
                s.add(("ALARM", h, a.description))
        if d.re_cpu >= settings.re_cpu_high_pct:
            s.add(("CPU", h))
        c = d.commits[0] if d.commits else None
        if c and not c.change_id and c.user not in {"noc-automation"} and now - c.at <= timedelta(hours=24):
            s.add(("COMMIT", h, c.rev))
    return s


class Ctx:
    def __init__(self, net: Network, now: datetime, maint: list[dict]):
        self.net, self.now, self.maint = net, now, maint
        self.open = symptoms(net, now)
        self.total = len(self.open)
        self.incidents: list[dict] = []

    def claim(self, items) -> int:
        items = set(items) & self.open
        self.open -= items
        return len(items)

    def add(self, kind: str, key: str, title: str, sev: str, sa: bool, owner: str, category: str, devices: list[str],
            scope: dict, evidence: list[str], verify: list[tuple[str, str]], actions: list[str], claimed: set,
            started: datetime | None, carrier: str | None = None) -> dict:
        n = self.claim(claimed)
        inc = {"id": _id(kind, key), "kind": kind, "title": title, "severity": sev, "service_affecting": sa,
               "owner": owner, "category": category, "devices": devices, "scope": scope, "evidence": evidence,
               "verify": [{"device": d, "cmd": c} for d, c in verify], "recommended_actions": actions,
               "symptoms": max(1, n), "started_at": (started or self.now).isoformat(), "carrier": carrier,
               "maintenance": None}
        for m in self.maint:
            # circuit-level incidents match by circuit; device-level ones (no interface) match by device
            if scope.get("circuit") and scope["circuit"] in m.get("circuits", []):
                inc["maintenance"] = m["id"]
            elif not scope.get("interface") and not scope.get("circuit") and set(devices) & set(m["devices"]):
                inc["maintenance"] = m["id"]
        self.incidents.append(inc)
        return inc


def _link_symptoms(net: Network, lk: Link) -> set[tuple]:
    out: set[tuple] = set()
    for h, ifn in lk.ends():
        out |= {("IF", h, ifn), ("OSPF", h, ifn), ("CRC", h, ifn), ("RX", h, ifn)}
        for p in net.devices[h].bgp:
            if p.kind == "external" and p.interface == ifn:
                out |= {("BGP", h, p.peer_ip), ("FLAP", h, p.peer_ip)}
    return out


def _ibgp_symptoms(net: Network, hosts: set[str]) -> set[tuple]:
    return {("BGP", h, p.peer_ip) for h, d in net.devices.items() for p in d.bgp
            if p.kind == "internal" and (h in hosts or p.peer_device in hosts)}


def _carrier(net: Network, cid: str | None):
    if not cid:
        return None, None
    c = net.circuits[cid]
    return c, net.carriers[c.carrier]


def _down_links(net: Network, host: str) -> list[Link]:
    return [lk for lk in net.links if host in (lk.a[0], lk.b[0] if lk.b else None)
            and not all(net.iface(*e).oper_up for e in lk.ends())]


# ------------------------------------------------------------------ rules
def _device_down(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        if d.powered:
            continue
        nbrs, claimed = [], {("DEV", h), ("MGMT", h)}
        for lk in net.links:
            if lk.b and h in (lk.a[0], lk.b[0]):
                far = lk.b if lk.a[0] == h else lk.a
                nbrs.append(far)
                claimed |= _link_symptoms(net, lk)
        claimed |= _ibgp_symptoms(net, {h})
        ev = [f"No response on out-of-band management ({d.mgmt_ip}) since {_ago(d.mgmt_down_since, c.now)}",
              f"{len(nbrs)} neighbour interface(s) lost light at the same moment: "
              + ", ".join(f"{short(x)} {i}" for x, i in nbrs),
              "OSPF adjacencies to its loopback " + d.loopback + " are down on every neighbour",
              "Pattern = whole chassis lost power or crashed, not a single link"]
        verify = [(x, f"show interfaces terse {i}") for x, i in nbrs[:2]] + [(nbrs[0][0], "show ospf neighbor")] if nbrs else []
        c.add("device_down", h, f"{h} down: no management, all links lost", "P1", True, "NOC → DC remote hands", "hardware",
              [h] + [x for x, _ in nbrs], {"device": h, "site": d.site},
              ev, verify,
              [f"Page on-call and open a P1 ticket for {h} ({d.site}).",
               "Ask DC remote hands to check power (PDU / PEM LEDs) and connect to the console port.",
               "If it is booting, wait and watch the console; if it is dead, start an RMA with the vendor.",
               "Confirm traffic has moved to the redundant path and check its utilisation."],
              claimed, d.down_since)


def _fpc_offline(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        if not d.powered:
            continue
        for f in d.frus:
            if f.kind != "fpc" or f.ok:
                continue
            fpc = int(f.item.split()[1])
            ifaces = [i for i in d.interfaces.values() if i.fpc == fpc and i.admin_up]
            claimed = {("ALARM", h, f"{f.item} Major Errors - Offline")}
            affected, isolated = [], []
            for i in ifaces:
                lk = net.link_of(h, i.name)
                if lk:
                    claimed |= _link_symptoms(net, lk)
                    if lk.b:
                        far = lk.b if lk.a[0] == h else lk.a
                        affected.append(f"{i.name} → {short(far[0])} {far[1]}" + (f" ({lk.circuit})" if lk.circuit else ""))
                        fd = net.devices[far[0]]
                        if fd.interfaces and all(not x.oper_up for x in fd.interfaces.values() if x.admin_up):
                            isolated.append(far[0])
                            for lk2 in net.links:
                                if lk2.b and far[0] in (lk2.a[0], lk2.b[0]):
                                    claimed |= _link_symptoms(net, lk2)
                    else:
                        affected.append(f"{i.name} ({lk.circuit})")
            claimed |= _ibgp_symptoms(net, set(isolated))
            alarm = next((a for a in d.alarms if a.source == f.item), None)
            ev = [f"Chassis alarm: {f.item} Major Errors - Offline ({f.description})",
                  f"All {len(ifaces)} interfaces on {f.item} went down at the same moment: " + "; ".join(affected),
                  "Interfaces on other FPCs are up, so the chassis and routing engine are fine"]
            if isolated:
                ev.append("Isolated as a result: " + ", ".join(isolated) + " (its only uplink was on this FPC)")
            c.add("fpc_offline", f"{h}:{fpc}", f"{f.item} offline on {h}: {len(ifaces)} links down"
                  + (f", {short(isolated[0])} isolated" if isolated else ""),
                  "P1" if isolated else "P2", bool(isolated), "NOC → vendor TAC (RMA)", "hardware", [h] + isolated,
                  {"device": h, "fpc": fpc, "site": d.site}, ev,
                  [(h, "show chassis alarms"), (h, f"show chassis fpc {fpc}"), (h, f'show log messages | match "FPC {fpc}"'),
                   (h, "show interfaces terse")],
                  ["Confirm the FPC state and collect logs (request support information).",
                   f"Try one controlled restart: request chassis fpc slot {fpc} restart (only after checking redundancy).",
                   "If it fails again, open a vendor TAC case and arrange an RMA with DC remote hands.",
                   "Move critical circuits to other FPCs if spare ports exist."],
                  claimed, alarm.since if alarm else None)


def _isolated(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        if not d.powered:
            continue
        linked = [i for i in d.interfaces.values() if i.admin_up and net.link_of(h, i.name)]
        if not linked or any(i.oper_up for i in linked) or not any(("IF", h, i.name) in c.open for i in linked):
            continue
        lks = [net.link_of(h, i.name) for i in linked]
        claimed: set = set()
        for lk in lks:
            claimed |= _link_symptoms(net, lk)
        claimed |= _ibgp_symptoms(net, {h})
        cids = [lk.circuit for lk in lks if lk.circuit]
        carriers = sorted({net.carriers[net.circuits[x].carrier].name for x in cids})
        ev = [f"Every uplink on {h} is down: " + ", ".join(i.name for i in linked),
              "Management is still reachable" if d.mgmt_ok else "Management is also unreachable",
              "LOS on both ends of each uplink (no light received), so this is the path, not the device"]
        if cids:
            ev.insert(1, "Uplink circuits: " + ", ".join(f"{x} ({net.carriers[net.circuits[x].carrier].name})" for x in cids))
        since = min((i.down_since for i in linked if i.down_since), default=None)
        inc = c.add("isolated", h, f"{h} ({d.site}) isolated: all uplinks down", "P1", True,
                    ("Carriers: " + ", ".join(carriers)) if carriers else "NOC → field", "carrier" if cids else "network",
                    [h], {"device": h, "site": d.site, "circuits": cids}, ev,
                    [(h, "show interfaces terse"), (h, f"show interfaces diagnostics optics {linked[0].name}"),
                     (lks[0].a[0] if lks[0].a[0] != h else h, "show ospf neighbor")],
                    ["Page on-call: customers at this site have no service.",
                     "Raise a P1 fault with each carrier, quoting the circuit IDs.",
                     "Ask the carriers whether there is a common fault (shared duct or building power).",
                     "Check site power and the device locally if management is also lost."],
                    claimed, since, carrier=carriers[0] if carriers else None)
        inc["scope"]["carriers"] = carriers


REROUTE_GROUP = {"IP Transit": "IP Transit", "IX Peering": "IX Peering", "Dark Fibre": "pop", "Ethernet Private Line": "pop",
                 "Wavelength": "pop"}


def _link_down(c: Ctx) -> None:
    net = c.net
    for lk in net.links:
        ends = lk.ends()
        if not any(("IF", h, i) in c.open for h, i in ends):
            continue
        claimed = _link_symptoms(net, lk)
        circuit, carrier = _carrier(net, lk.circuit)
        a = net.iface(*lk.a)
        since = min((net.iface(*e).down_since for e in ends if net.iface(*e).down_since), default=None)
        both_los = all(net.iface(*e).rx_dbm <= -40 for e in ends)
        hosts = [h for h, _ in ends]
        ev = [f"{short(lk.a[0])} {lk.a[1]}" + (f" ↔ {short(lk.b[0])} {lk.b[1]}" if lk.b else f" → {carrier.name if carrier else ''}")
              + f" down since {_ago(since, c.now)}"]
        ev.append("No light received on either end (LOS both sides): fibre or carrier path, not an optic"
                  if both_los and lk.b else f"Receive power {a.rx_dbm} dBm (LOS)" if a.rx_dbm <= -40 else
                  f"Receive power {a.rx_dbm} dBm")
        ospf_lost = [f"{short(h)} {i}" for h, i in ends if ("OSPF", h, i) in claimed and ("OSPF", h, i) in c.open]
        bgp_lost = [p for h in hosts for p in net.devices[h].bgp if p.kind == "external" and p.interface in (lk.a[1],)
                    and p.state != "Established" and h == lk.a[0]]
        if ospf_lost:
            ev.append("OSPF adjacency lost on " + ", ".join(ospf_lost))
        for p in bgp_lost:
            ev.append(f"eBGP {p.peer_ip} (AS{p.peer_as}) dropped to {p.state}: {p.prefixes_rx} prefixes now")
        # iBGP that died because of this link (e.g. edge single-homed to its core)
        ib = {("BGP", h, p.peer_ip) for h, d in net.devices.items() for p in d.bgp
              if p.kind == "internal" and p.state != "Established" and (h in hosts or p.peer_device in hosts)}
        if ib & c.open:
            ev.append(f"{len(ib & c.open)} iBGP session(s) dropped with it")
            claimed |= ib
        # traffic that moved onto the remaining paths
        group = REROUTE_GROUP.get(circuit.service) if circuit else None
        busy = []
        for cid, other in net.circuits.items():
            if other is circuit or not group or REROUTE_GROUP.get(other.service) != group:
                continue
            oi = net.iface(*other.a_end)
            if ("UTIL", *other.a_end) in c.open:
                busy.append(f"{cid} now at {oi.util_pct}%")
                claimed.add(("UTIL", *other.a_end))
            if group == "pop" and lk.circuit == "ALF-DF-0091":
                for lk2 in net.links:
                    if lk2.circuit and lk2.circuit.startswith(("ALF-EPL", "CVN-WAV")):
                        claimed |= {("UTIL", *e) for e in lk2.ends()}
        if group in {"IP Transit", "IX Peering"}:
            for sym in [x for x in c.open if x[0] == "UTIL" and net.devices[x[1]].role in {"edge", "core"}]:
                if not net.link_of(sym[1], sym[2]).circuit:
                    busy.append(f"{short(sym[1])} {sym[2]} (edge to core) now at {net.iface(sym[1], sym[2]).util_pct}%")
                    claimed.add(sym)
        if busy:
            ev.append("Traffic moved to the remaining path: " + ", ".join(busy))
        congested = any(float(b.rsplit(" ", 1)[1].rstrip("%")) >= 95 for b in busy)
        if not circuit:
            kind, sev, sa = "link_down", "P2", False
            title = f"Core link down: {short(lk.a[0])} {lk.a[1]} ↔ {short(lk.b[0])} {lk.b[1]}"
            owner, cat = "NOC → field / DC remote hands", "network"
        else:
            kind, cat, owner = "circuit_down", "carrier", f"Carrier: {carrier.name}"
            same = [x for x in net.circuits.values() if x.service == circuit.service and x is not circuit
                    and net.iface(*x.a_end).oper_up]
            if circuit.service == "IP Transit":
                sev, sa = ("P2", False) if same and not congested else ("P1", True)
                if congested:
                    ev.append("Remaining transit is above 95%: expect packet loss for customers at peak")
                ev.append(f"Other transit still up: {same[0].id}" if same else "NO other transit left: internet reachability lost")
            elif circuit.service == "IX Peering":
                sev, sa = "P3", False
                ev.append("Peering traffic falls back to IP transit")
            else:
                sev, sa = "P2", False
                ev.append("Redundancy lost: the site is running on one path" if lk.circuit != "ALF-DF-0091"
                          else "Inter-DC traffic now crosses the POP circuits")
            title = f"{circuit.service} down: {lk.circuit} ({carrier.name})"
        verify = [(lk.a[0], f"show interfaces {lk.a[1]} extensive | match \"Physical|Last flapped|errors\""),
                  (lk.a[0], f"show interfaces diagnostics optics {lk.a[1]}"),
                  (lk.a[0], "show ospf neighbor" if lk.b else "show bgp summary")]
        actions = ([f"Raise a fault with {carrier.name} ({carrier.noc_email}, {carrier.noc_phone}) quoting {lk.circuit}, "
                    f"account {carrier.account}.",
                    "Send them the LOS time and the optical readings from both ends.",
                    f"Track their SLA: {carrier.sla_mttr_h} h to repair."] if carrier else
                   ["Check the patch path and optics at both ends with DC remote hands."]) + \
                  ["Watch the utilisation of the remaining path and plan a traffic drain if it nears capacity.",
                   "When it comes back, confirm OSPF/BGP re-establish and errors stay at zero for 30 minutes."]
        c.add(kind, f"{lk.a[0]}:{lk.a[1]}", title, sev, sa, owner, cat, hosts,
              {"device": lk.a[0], "interface": lk.a[1], "circuit": lk.circuit, "far_end": f"{lk.b[0]} {lk.b[1]}" if lk.b else
               (carrier.name if carrier else ""), "site": net.devices[lk.a[0]].site},
              ev, verify, actions, claimed, since, carrier=carrier.name if carrier else None)


def _all_transit(c: Ctx) -> None:
    net = c.net
    transit = [x for x in net.circuits.values() if x.service == "IP Transit"]
    down = [x for x in transit if not net.iface(*x.a_end).oper_up]
    if len(transit) < 2 or len(down) != len(transit):
        return
    claimed: set = set()
    for x in down:
        claimed |= _link_symptoms(net, net.link_of(*x.a_end))
    claimed |= {s for s in c.open if s[0] == "UTIL"}
    ix_up = [x for x in net.circuits.values() if x.service == "IX Peering" and net.iface(*x.a_end).oper_up]
    since = min((net.iface(*x.a_end).down_since for x in down if net.iface(*x.a_end).down_since), default=None)
    carriers = [net.carriers[x.carrier] for x in down]
    c.add("all_transit_down", "all", "ALL IP transit down: internet reachability lost", "P1", True,
          "Carriers: " + ", ".join(k.name for k in carriers), "carrier", sorted({x.a_end[0] for x in down}),
          {"circuits": [x.id for x in down], "carriers": [k.name for k in carriers]},
          [f"{x.id} ({net.carriers[x.carrier].name}) on {short(x.a_end[0])} {x.a_end[1]}: LOS, eBGP down" for x in down]
          + [f"Only {len(ix_up)} IX peering port(s) left: customers reach peers' networks only" if ix_up
             else "IX peering is down too: no external connectivity"],
          [(x.a_end[0], "show bgp summary") for x in down] + [(down[0].a_end[0], "show route summary")],
          ["Page on-call and the Tier 3 lead now (P1).",
           *[f"Call {k.name} NOC on {k.noc_phone} quoting {x.id} and account {k.account}." for k, x in zip(carriers, down, strict=True)],
           "Ask both carriers whether they share a building, duct or upstream; two transits failing together is rarely chance.",
           "Post a customer-facing status update."],
          claimed, since, carrier=carriers[0].name)


def _hardware(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        if not d.powered:
            continue
        for a in d.alarms:
            sym = ("ALARM", h, a.description)
            if sym not in c.open:
                continue
            if "PEM" in a.description:
                remaining = sum(1 for f in d.frus if f.kind == "pem" and f.ok)
                c.add("psu_failed", f"{h}:{a.source}", f"Power supply {a.source} failed on {h}", "P3", False,
                      "NOC → field / vendor RMA", "hardware", [h], {"device": h, "fru": a.source, "site": d.site},
                      [f"Chassis alarm: {a.description} (Major) since {_ago(a.since, c.now)}",
                       f"{remaining} power supplies still OK, so the chassis is running without full power redundancy",
                       "No interfaces or protocols affected"],
                      [(h, "show chassis alarms"), (h, "show chassis environment pem"), (h, "show chassis hardware | match PEM")],
                      ["Ask DC remote hands to check the PEM LEDs and the feed (A/B) from the PDU.",
                       "If the feed is fine, open an RMA for the power supply with its serial number.",
                       "Schedule the swap; PEMs are hot-swappable on this chassis."],
                      {sym}, a.since)
            elif "Fan" in a.description:
                temp = ("ALARM", h, "Temperature Hot")
                hot = d.temp_c >= settings.temp_high_c
                c.add("fan_failed", f"{h}:{a.source}", f"{a.source} failed on {h}" + (f", chassis at {d.temp_c} °C" if hot else ""),
                      "P2" if hot else "P3", False, "NOC → field / vendor RMA", "hardware", [h],
                      {"device": h, "fru": a.source, "site": d.site},
                      [f"Chassis alarm: {a.description} since {_ago(a.since, c.now)}",
                       f"Chassis temperature {d.temp_c} °C (alarm at {settings.temp_high_c} °C) and rising"
                       if hot else f"Chassis temperature {d.temp_c} °C, still below the alarm",
                       "If it keeps rising the device will shut down FPCs to protect itself"],
                      [(h, "show chassis alarms"), (h, "show chassis environment"), (h, "show chassis hardware | match Fan")],
                      ["Ask DC remote hands to reseat or replace the fan tray (hot-swappable).",
                       "Check the room temperature and airflow around the rack.", "Open an RMA if a spare is not on site."],
                      {sym, temp}, a.since)
            elif a.description == "Temperature Hot":
                c.add("temp_high", h, f"High temperature on {h}: {d.temp_c} °C", "P3", False, "NOC → DC facilities",
                      "hardware", [h], {"device": h, "site": d.site},
                      [f"Chassis temperature {d.temp_c} °C, alarm at {settings.temp_high_c} °C", "All fans report OK",
                       "Likely a room cooling problem rather than the device"],
                      [(h, "show chassis environment"), (h, "show chassis alarms")],
                      ["Ask DC facilities to check the hall's cooling.", "Check neighbouring devices in the same rack."],
                      {sym}, a.since)


def _bgp(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        for p in d.bgp:
            if ("BGP", h, p.peer_ip) not in c.open:
                continue
            i = d.interfaces.get(p.interface) if p.interface else None
            commit = d.commits[0] if d.commits else None
            recent = commit and p.last_change and timedelta(0) <= p.last_change - commit.at <= timedelta(minutes=30)
            transit = p.group.startswith("TRANSIT")
            same = [q for dv in net.devices.values() for q in dv.bgp if q.group.startswith("TRANSIT") and q is not p
                    and q.state == "Established"]
            sev, sa = ("P2", False) if transit and same else ("P1", True) if transit else ("P3", False)
            ev = [f"Session {p.peer_ip} (AS{p.peer_as}, {p.description}) in state {p.state} since {_ago(p.last_change, c.now)}"]
            if i:
                ev.append(f"Interface {i.name} is up, receive power {i.rx_dbm} dBm, {int(i.crc_per_min)} errors/min, "
                          "so the physical link is fine")
            ev.append("Last error: Hold Timer Expired: the neighbour stopped sending keepalives")
            if recent:
                ev.append(f"A commit by {commit.user} {_ago(commit.at, c.now)} came just before the drop. Check it first")
            else:
                ev.append("No local commit before the drop: most likely the remote side (their router, policy or maintenance)")
            c.add("bgp_down", f"{h}:{p.peer_ip}", f"BGP down, link up: {p.peer_ip} AS{p.peer_as} on {h}", sev, sa,
                  f"Peer: {p.description.split(' ')[0]} {p.description.split(' ')[1]}" if p.kind == "external" else "NOC",
                  "routing", [h], {"device": h, "peer": p.peer_ip, "interface": p.interface, "group": p.group, "site": d.site},
                  ev,
                  [(h, f"show bgp neighbor {p.peer_ip} | match \"State|Last Error|Holdtime\""),
                   (h, f"ping {p.peer_ip} rapid count 5"), (h, f"show log messages | match {p.peer_ip}"),
                   (h, "show system commit")],
                  (["Roll back the recent commit if it touched this BGP group (rollback 1, commit confirmed)."] if recent else []) +
                  ["Ping the neighbour address to prove layer 3 reachability.",
                   "Contact the peer's NOC and ask whether they made a change or see the session down.",
                   "Check the authentication key and the import/export policies have not changed."],
                  {("BGP", h, p.peer_ip), ("FLAP", h, p.peer_ip)}, p.last_change,
                  carrier=p.description.split(" ")[0] + " " + p.description.split(" ")[1] if p.kind == "external" else None)


def _degradation(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        for i in d.interfaces.values():
            lk = net.link_of(h, i.name)
            circuit, carrier = _carrier(net, lk.circuit if lk else None)
            if ("CRC", h, i.name) in c.open:
                flaps = [p for p in d.bgp if p.interface == i.name and ("FLAP", h, p.peer_ip) in c.open]
                ev = [f"{int(i.crc_per_min)} input/CRC errors per minute on {i.name} ({i.in_errors:,} total)",
                      f"Receive power {i.rx_dbm} dBm, {round(i.baseline_rx - i.rx_dbm, 1)} dB below its normal {i.baseline_rx} dBm",
                      "Errors are only on the receive side: the problem is on the far end or in the carrier path"]
                if flaps:
                    ev.append(f"BGP to {flaps[0].peer_ip} flapped {len(flaps[0].flap_times)} times in the last hour")
                c.add("circuit_errors", f"{h}:{i.name}",
                      f"Errors on {lk.circuit} ({carrier.name})" if circuit else f"Errors on {short(h)} {i.name}",
                      "P3", False, f"Carrier: {carrier.name}" if carrier else "NOC → field", "carrier" if carrier else "network",
                      [h], {"device": h, "interface": i.name, "circuit": lk.circuit if lk else None, "site": d.site}, ev,
                      [(h, f"show interfaces {i.name} extensive | match \"errors|CRC\""),
                       (h, f"show interfaces diagnostics optics {i.name}"), (h, "clear interfaces statistics " + i.name)],
                      ([f"Raise a degradation fault with {carrier.name} for {lk.circuit} with the error counts."] if carrier else []) +
                      ["Clean and re-seat the local optic and patch, then clear counters and watch for 15 minutes.",
                       "If errors continue, cost the link out (OSPF metric 65535) until the carrier fixes it."],
                      {("CRC", h, i.name), ("RX", h, i.name)} | {("FLAP", h, p.peer_ip) for p in flaps}, i.degraded_since,
                      carrier=carrier.name if carrier else None)
            if ("RX", h, i.name) in c.open:
                alarm = i.rx_dbm < settings.rx_low_alarm_dbm
                c.add("optics_low", f"{h}:{i.name}", f"Low receive power on {short(h)} {i.name}: {i.rx_dbm} dBm",
                      "P3" if alarm else "P4", False, "NOC → field", "optics", [h],
                      {"device": h, "interface": i.name, "circuit": lk.circuit if lk else None, "site": d.site},
                      [f"Receive power {i.rx_dbm} dBm; normal for this link is {i.baseline_rx} dBm "
                       f"({round(i.baseline_rx - i.rx_dbm, 1)} dB worse)",
                       f"{'Below' if alarm else 'Approaching'} the receiver's low-power alarm ({settings.rx_low_alarm_dbm} dBm)",
                       "No errors yet" if not i.crc_per_min else f"{int(i.crc_per_min)} errors/min",
                       "Still falling" if i.rx_drift else "Stable at this level"],
                      [(h, f"show interfaces diagnostics optics {i.name}"), (h, f"show interfaces {i.name} | match flapped")],
                      ["Clean the connectors at both ends and re-measure.",
                       "Replace the optic if the transmit side of the far end is normal.",
                       "Book a maintenance window if the link must be touched."],
                      {("RX", h, i.name)}, i.degraded_since)
            if ("UTIL", h, i.name) in c.open:
                c.add("util_high", f"{h}:{i.name}", f"High utilisation on {lk.circuit if circuit else short(h) + ' ' + i.name}: "
                      f"{i.util_pct}%", "P3", False, "NOC → capacity", "performance", [h],
                      {"device": h, "interface": i.name, "circuit": lk.circuit if lk else None, "site": d.site},
                      [f"{i.util_pct}% of {i.speed_gbps} Gbps", "Risk of packet loss at peaks"],
                      [(h, f"show interfaces {i.name} | match rate")],
                      ["Check whether a redundant path is down.", "Plan a capacity upgrade if this is the new normal."],
                      {("UTIL", h, i.name)}, None)


def _routing_engine(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        for p in d.bgp:
            if ("FLAP", h, p.peer_ip) in c.open:
                recent = [t for t in p.flap_times if c.now - t <= timedelta(hours=1)]
                c.add("bgp_flap", f"{h}:{p.peer_ip}", f"BGP flapping: {p.peer_ip} AS{p.peer_as} on {h}", "P3", False,
                      f"Peer: {' '.join(p.description.split(' ')[:2])}", "routing", [h],
                      {"device": h, "peer": p.peer_ip, "interface": p.interface, "site": d.site},
                      [f"{len(recent)} flaps in the last hour, currently {p.state}",
                       f"Interface {p.interface} shows no errors" if p.interface and not d.interfaces[p.interface].crc_per_min
                       else "Interface errors present",
                       "Each flap withdraws and re-learns routes, causing short traffic shifts"],
                      [(h, f"show bgp neighbor {p.peer_ip} | match \"Flap|Last Error|State\""),
                       (h, f"show log messages | match {p.peer_ip}")],
                      ["Ask the peer if their side is unstable.", "Consider BFD timers or damping if it continues.",
                       "If the interface shows errors, treat it as a circuit fault."],
                      {("FLAP", h, p.peer_ip)}, recent[0] if recent else None,
                      carrier=" ".join(p.description.split(" ")[:2]) if p.kind == "external" else None)
        if ("CPU", h) in c.open:
            c.add("cpu_high", h, f"Routing engine CPU at {round(d.re_cpu)}% on {h}", "P3", False, "NOC → engineering", "performance",
                  [h], {"device": h, "site": d.site},
                  [f"RE CPU {round(d.re_cpu)}% (alarm at {settings.re_cpu_high_pct}%), top process: {d.top_process}",
                   "Protocols are stable for now, but a busy RE can miss BGP/OSPF keepalives"],
                  [(h, "show chassis routing-engine"), (h, f"show system processes extensive | match {d.top_process}"),
                   (h, "show bgp summary")],
                  ["Check for a recent change, a route churn event or an SNMP poller hammering the box.",
                   f"If {d.top_process} stays high, collect data for the vendor TAC before restarting anything."],
                  {("CPU", h)}, d.cpu_since)


def _management(c: Ctx) -> None:
    net = c.net
    for h, d in net.devices.items():
        if ("MGMT", h) not in c.open:
            continue
        nbr_ok = [n for n in d.ospf if n.state == "Full"]
        c.add("mgmt_down", h, f"Management unreachable on {h} (forwarding OK)", "P3", False, "NOC → OOB network", "management", [h],
              {"device": h, "site": d.site},
              [f"No response on out-of-band management {d.mgmt_ip} since {_ago(d.mgmt_down_since, c.now)}",
               f"{len(nbr_ok)} OSPF neighbours still Full and passing traffic, so the device itself is fine",
               "Likely the OOB switch, console server or management cabling at the site"],
              [(n.peer_device, f"show lldp neighbors | match {short(h)}") for n in nbr_ok[:1]]
              + [(n.peer_device, "show ospf neighbor") for n in nbr_ok[:1]],
              ["Reach the device in-band via its loopback to confirm.", "Check the site's OOB switch and console server.",
               "Not urgent for customers, but fix it before any change on this device."],
              {("MGMT", h)}, d.mgmt_down_since)


def _security(c: Ctx) -> None:
    net = c.net
    from .changes import compare  # local import to avoid a cycle
    for h, d in net.devices.items():
        cm = d.commits[0] if d.commits else None
        if not cm or ("COMMIT", h, cm.rev) not in c.open:
            continue
        risky = [ln for ln in d.config if ln.startswith(("set system services telnet", "set snmp community"))]
        c.add("unauthorized_commit", f"{h}:{cm.at.isoformat()}", f"Config change without a change ticket on {h}", "P3", False,
              "NOC → security", "security", [h], {"device": h, "user": cm.user, "site": d.site},
              [f"Commit by '{cm.user}' via {cm.via} {_ago(cm.at, c.now)} with no CHG reference and no comment",
               f"User '{cm.user}' is not in the approved automation or NOC change list"]
              + ([f"The change breaks the security baseline: {', '.join(r.replace('set ', '') for r in risky)}"] if risky else []),
              [(h, "show system commit"), (h, "show configuration | compare rollback 1"),
               (h, f'show log messages | match "UI_COMMIT|{cm.user}"')],
              ["Ask the change manager whether this was approved.",
               "If not, roll it back: rollback 1, show | compare, commit confirmed 5 comment \"revert unauthorised\".",
               f"Disable the '{cm.user}' account and review TACACS accounting for what else it did.",
               "Raise a security incident if the access cannot be explained."],
              {("COMMIT", h, cm.rev)}, cm.at)
        c.incidents[-1]["diff"] = compare(d.prev_config or d.config, d.config)


def correlate(net: Network, now: datetime | None = None, maintenance: list[dict] | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    c = Ctx(net, now, maintenance or [])
    for rule in (_device_down, _fpc_offline, _isolated, _all_transit, _link_down, _hardware, _bgp, _degradation, _routing_engine,
                 _management, _security):
        rule(c)
    c.incidents.sort(key=lambda i: (SEV_ORDER[i["severity"]], not i["service_affecting"], i["started_at"]))
    return c.incidents


def stats(net: Network, incidents: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    devs = list(net.devices.values())
    ifs = [(d, i) for d in devs for i in d.interfaces.values() if i.admin_up and net.link_of(d.hostname, i.name)]
    bgp = [p for d in devs for p in d.bgp]
    ospf = [n for d in devs for n in d.ospf]
    raw = len(symptoms(net, now))
    return {"devices": len(devs), "devices_up": sum(d.powered for d in devs), "mgmt_ok": sum(d.mgmt_ok for d in devs),
            "interfaces": len(ifs), "interfaces_up": sum(i.oper_up for d, i in ifs if d.powered),
            "bgp": len(bgp), "bgp_up": sum(p.state == "Established" for p in bgp),
            "ospf": len(ospf), "ospf_up": sum(n.state == "Full" for n in ospf),
            "circuits": len(net.circuits), "circuits_up": sum(net.iface(*c.a_end).oper_up for c in net.circuits.values()),
            "chassis_alarms": sum(len(d.alarms) for d in devs),
            "incidents": len(incidents), "symptoms": raw,
            "by_severity": {s: sum(i["severity"] == s for i in incidents) for s in SEV_ORDER},
            "service_affecting": sum(i["service_affecting"] for i in incidents)}
