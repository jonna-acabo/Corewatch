"""Optional live mode: collect state from real or virtual Junos devices over NETCONF (Junos PyEZ).

Set LAB_DEVICES="r1=172.20.20.2,r2=172.20.20.3" plus LAB_USERNAME and LAB_PASSWORD (or LAB_SSH_KEY).
Each poll runs read-only RPCs, the same data as these CLI commands:

    show version / show chassis hardware / show interfaces terse / show interfaces descriptions
    show bgp summary / show ospf neighbor / show chassis alarms / show lldp neighbors
    show chassis routing-engine / show configuration | display set

The XML is turned into the same model as the mock network, so correlation, audits, the CLI view and the UI
work unchanged. Topology comes from LLDP; carrier circuits come from interface descriptions written as
"<ROLE> | <far end> | CID <circuit id>" (a common NOC convention).

Quick connectivity test:  python -m app.lab
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

from .config import settings
from .models import BgpPeer, Carrier, ChassisAlarm, Circuit, Device, Fru, Interface, Link, Network, OspfNeighbor

PHYS = re.compile(r"^(ge|xe|et|mge)-\d+/\d+/\d+$")
CID = re.compile(r"CID\s+([A-Z0-9][A-Z0-9-]+)", re.I)


def _local(tag) -> str:
    return tag.split("}")[-1] if isinstance(tag, str) else ""


def _all(el, name: str):
    return [x for x in el.iter() if _local(x.tag) == name]


def _text(el, name: str, default: str = "") -> str:
    for x in el.iter():
        if _local(x.tag) == name and x.text is not None:
            return x.text.strip()
    return default


# ------------------------------------------------------------------ parsers (pure, unit-tested with XML fixtures)
def parse_software(xml) -> dict:
    return {"hostname": _text(xml, "host-name"), "model": _text(xml, "product-model").upper(),
            "version": _text(xml, "junos-version") or _text(xml, "package-information")}


def parse_inventory(xml) -> dict:
    chassis = _all(xml, "chassis")
    serial = _text(chassis[0], "serial-number") if chassis else ""
    frus = []
    for m in _all(xml, "chassis-module"):
        frus.append(Fru(_text(m, "name"), _text(m, "part-number"), _text(m, "serial-number"), _text(m, "description"),
                        kind=_kind(_text(m, "name"))))
    return {"serial": serial, "frus": frus}


def _kind(name: str) -> str:
    n = name.lower()
    return ("pem" if n.startswith(("pem", "power")) else "fan" if "fan" in n else "fpc" if n.startswith("fpc")
            else "re" if n.startswith(("routing engine", "cb")) else "chassis")


def parse_interfaces(terse_xml, desc_xml=None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for p in _all(terse_xml, "physical-interface"):
        name = _text(p, "name")
        if PHYS.match(name):
            out[name] = {"admin": _text(p, "admin-status") == "up", "oper": _text(p, "oper-status") == "up", "description": ""}
    if desc_xml is not None:
        for p in _all(desc_xml, "physical-interface"):
            name = _text(p, "name")
            if name in out:
                out[name]["description"] = _text(p, "description")
    return out


def parse_bgp(xml) -> list[dict]:
    peers = []
    for p in _all(xml, "bgp-peer"):
        addr = _text(p, "peer-address").split("+")[0]
        rx = sum(int(x.text) for x in _all(p, "received-prefix-count") if x.text and x.text.isdigit())
        peers.append({"peer_ip": addr, "peer_as": int(_text(p, "peer-as", "0") or 0), "state": _text(p, "peer-state"),
                      "flaps": int(_text(p, "flap-count", "0") or 0), "description": _text(p, "description"),
                      "prefixes_rx": rx})
    return peers


def parse_ospf(xml) -> list[dict]:
    return [{"address": _text(n, "neighbor-address"), "interface": _text(n, "interface-name").removesuffix(".0"),
             "state": _text(n, "ospf-neighbor-state"), "neighbor_id": _text(n, "neighbor-id")}
            for n in _all(xml, "ospf-neighbor")]


def parse_alarms(xml, now: datetime) -> list[ChassisAlarm]:
    out = []
    for a in _all(xml, "alarm-detail"):
        t = next((x for x in a.iter() if _local(x.tag) == "alarm-time"), None)
        secs = next((v for k, v in t.attrib.items() if k.split("}")[-1].endswith("seconds")), None) if t is not None else None
        since = datetime.fromtimestamp(int(secs), UTC) if secs and secs.isdigit() else now
        out.append(ChassisAlarm(_text(a, "alarm-class"), _text(a, "alarm-description"), since, "Chassis"))
    return out


def parse_lldp(xml) -> list[dict]:
    out = []
    for n in _all(xml, "lldp-neighbor-information"):
        ports = [_text(n, "lldp-remote-port-id"), _text(n, "lldp-remote-port-description")]
        out.append({"local": _text(n, "lldp-local-port-id") or _text(n, "lldp-local-interface"),
                    "remote_system": _text(n, "lldp-remote-system-name"),
                    "remote_port": next((p for p in ports if PHYS.match(p)), ports[0])})
    return out


def parse_re(xml) -> dict:
    idle = _text(xml, "cpu-idle", "90")
    mem = _text(xml, "memory-buffer-utilization", "40")
    return {"cpu": 100 - float(idle), "mem": float(mem)}


def parse_config_set(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith(("set ", "deactivate "))]


# ------------------------------------------------------------------ build a Network from snapshots
def _family(model: str) -> str:
    m = model.lower()
    return next((f for f in ("mx", "srx", "qfx", "ex") if m.startswith(f)), "mx")


def _cfg_value(cfg: list[str], prefix: str) -> str:
    ln = next((x for x in cfg if x.startswith(prefix)), "")
    return ln[len(prefix):].strip().split()[0] if ln else ""


def build_lab_network(snaps: dict[str, dict], previous: Network | None = None, now: datetime | None = None) -> Network:
    """snaps: name -> snapshot dict (from collect()) or {"error": "..."} for an unreachable device."""
    now = now or datetime.now(UTC)
    devices: dict[str, Device] = {}
    for n, (name, s) in enumerate(sorted(snaps.items())):
        if "error" in s:
            old = previous.devices.get(name) if previous else None
            d = old or Device(name, "unknown", "mx", "core", "LAB", s.get("host", ""), "", "", "", "")
            d.mgmt_ok = False
            d.mgmt_down_since = d.mgmt_down_since or now
            devices[name] = d
            continue
        cfg = s["config"]
        lo = _cfg_value(cfg, "set interfaces lo0 unit 0 family inet address ").split("/")[0]
        d = Device(name, s["software"]["model"], _family(s["software"]["model"]), "core", "LAB", s["host"], lo,
                   s["software"]["version"], s["inventory"]["serial"], s["inventory"]["serial"],
                   x=140 + (n % 4) * 240, y=120 + (n // 4) * 170, re_cpu=s["re"]["cpu"], re_mem=s["re"]["mem"])
        d.frus, d.config, d.alarms = s["inventory"]["frus"], cfg, s["alarms"]
        d.prev_config = previous.devices[name].config if previous and name in previous.devices else list(cfg)
        d.rescue_saved = True
        old = previous.devices.get(name) if previous else None
        for ifn, st in s["interfaces"].items():
            addr = next((x.split(" address ")[1].split()[0] for x in cfg
                         if x.startswith(f"set interfaces {ifn} unit 0 family inet address ")), "")
            i = Interface(ifn, st["description"], admin_up=st["admin"], oper_up=st["oper"], address=addr, optic="")
            prev = old.interfaces.get(ifn) if old else None
            if prev:
                i.history, i.flaps, i.last_flap = prev.history, prev.flaps, prev.last_flap
                i.down_since = prev.down_since if not i.oper_up else None
                if prev.oper_up and not i.oper_up:
                    i.down_since, i.last_flap, i.flaps = now, now, prev.flaps + 1
            elif not i.oper_up:
                i.down_since = now
            d.interfaces[ifn] = i
        if old:
            d.log = old.log
        devices[name] = d

    by_short = {k.split(".")[0]: k for k in devices}
    loopbacks = {d.loopback: h for h, d in devices.items() if d.loopback}
    asn = int(next((_cfg_value(d.config, "set routing-options autonomous-system ") for d in devices.values()
                    if _cfg_value(d.config, "set routing-options autonomous-system ")), "0") or 0)

    links: list[Link] = []
    seen: set = set()
    for h, s in snaps.items():
        for nb in s.get("lldp", []):
            far = by_short.get(nb["remote_system"].split(".")[0])
            if not far or nb["local"] not in devices[h].interfaces or nb["remote_port"] not in devices[far].interfaces:
                continue
            key = frozenset({(h, nb["local"]), (far, nb["remote_port"])})
            if key not in seen:
                seen.add(key)
                links.append(Link((h, nb["local"]), (far, nb["remote_port"])))
    # keep links learned earlier (LLDP disappears when a link goes down)
    if previous:
        for lk in previous.links:
            key = frozenset(lk.ends()) if lk.b else None
            if lk.b and key not in seen and all(e[0] in devices and e[1] in devices[e[0]].interfaces for e in lk.ends()):
                seen.add(key)
                links.append(Link(lk.a, lk.b, lk.circuit))

    carriers: dict[str, Carrier] = {}
    circuits: dict[str, Circuit] = {}
    linked = {e for lk in links for e in lk.ends()}
    for h, d in devices.items():
        for i in d.interfaces.values():
            m = CID.search(i.description or "")
            if not m:
                continue
            parts = [p.strip() for p in i.description.split("|")]
            cname = re.sub(r"\s+AS\d+$", "", parts[1]) if len(parts) > 1 else "Carrier"
            cid_key = re.sub(r"[^a-z0-9]+", "-", cname.lower())
            carriers.setdefault(cid_key, Carrier(cid_key, cname, None, "", "", "", 4))
            service = "IP Transit" if parts[0].upper().startswith("TRANSIT") else "IX Peering" if "PEER" in parts[0].upper() \
                else "Ethernet Private Line"
            circuits[m.group(1)] = Circuit(m.group(1), cid_key, service, i.speed_gbps, (h, i.name), cname)
            if (h, i.name) not in linked:
                links.append(Link((h, i.name), None, m.group(1)))
            else:
                for lk in links:
                    if (h, i.name) in lk.ends():
                        lk.circuit = m.group(1)

    for h, s in snaps.items():
        if "error" in s:
            continue
        d = devices[h]
        old = previous.devices.get(h) if previous else None
        for p in s["bgp"]:
            kind = "internal" if p["peer_as"] == asn else "external"
            ifn = ""
            if kind == "external":
                for i in d.interfaces.values():
                    if i.address and ipaddress.ip_address(p["peer_ip"]) in ipaddress.ip_interface(i.address).network:
                        ifn = i.name
            grp = next((x.split()[4] for x in d.config if f" neighbor {p['peer_ip']}" in x and "protocols bgp group" in x), "BGP")
            bp = BgpPeer(p["peer_ip"], p["peer_as"], grp, p["description"] or p["peer_ip"], kind, ifn, loopbacks.get(p["peer_ip"], ""),
                         "Established" if p["state"] == "Established" else p["state"], p["prefixes_rx"], 0, p["flaps"])
            prev = next((q for q in old.bgp if q.peer_ip == bp.peer_ip), None) if old else None
            if prev:
                bp.flap_times, bp.last_change = prev.flap_times, prev.last_change
                if prev.state != bp.state:
                    bp.last_change = now
                    if prev.state == "Established":
                        bp.flap_times = prev.flap_times + [now]
            bp.auth = any(x.startswith(f"set protocols bgp group {grp} authentication-key") for x in d.config)
            d.bgp.append(bp)
        current = {n["interface"]: n for n in s["ospf"]}
        expected = {n.interface: n for n in old.ospf} if old else {}
        for ifn, n in current.items():
            d.ospf.append(OspfNeighbor(ifn, n["address"], n["neighbor_id"], loopbacks.get(n["neighbor_id"], ""),
                                       "Full" if n["state"] == "Full" else n["state"]))
        for ifn, n in expected.items():
            if ifn not in current:        # Junos drops dead neighbours from the table; remember them as Down
                d.ospf.append(OspfNeighbor(ifn, n.address, n.neighbor_id, n.peer_device, "Down"))
    # a device that does not answer and whose every neighbour sees its links down is treated as down
    for h, d in devices.items():
        if not d.mgmt_ok:
            ends = [lk.b if lk.a[0] == h else lk.a for lk in links if lk.b and h in (lk.a[0], lk.b[0])]
            d.powered = bool(ends) and any(devices[x].interfaces[i].oper_up for x, i in ends) if ends else True
            if not d.powered:
                d.down_since = d.down_since or now
    net = Network(devices, links, carriers, circuits, asn or 64510, source="lab")
    return net


# ------------------------------------------------------------------ live collection
def lab_targets() -> dict[str, str]:
    out = {}
    for item in filter(None, (x.strip() for x in settings.lab_devices.split(","))):
        name, _, host = item.partition("=")
        out[name.strip()] = (host or name).strip()
    return out


def collect(name: str, host: str) -> dict:  # pragma: no cover - needs a reachable Junos device
    from jnpr.junos import Device as PyEZ
    from jnpr.junos.exception import RpcError

    kw = {"host": host, "user": settings.lab_username, "port": 830, "gather_facts": False, "normalize": True}
    if settings.lab_ssh_key:
        kw["ssh_private_key_file"] = settings.lab_ssh_key
    else:
        kw["password"] = settings.lab_password
    now = datetime.now(UTC)
    with PyEZ(**kw) as dev:
        def rpc(fn, **args):
            try:
                return fn(**args)
            except RpcError:
                return None
        sw = rpc(dev.rpc.get_software_information)
        inv = rpc(dev.rpc.get_chassis_inventory)
        terse = rpc(dev.rpc.get_interface_information, terse=True)
        desc = rpc(dev.rpc.get_interface_information, descriptions=True)
        bgp = rpc(dev.rpc.get_bgp_summary_information)
        ospf = rpc(dev.rpc.get_ospf_neighbor_information)
        alarms = rpc(dev.rpc.get_alarm_information)
        lldp = rpc(dev.rpc.get_lldp_neighbors_information)
        re_info = rpc(dev.rpc.get_route_engine_information)
        cfg = dev.rpc.get_config(options={"format": "set"})
    return {"host": host, "software": parse_software(sw), "inventory": parse_inventory(inv) if inv is not None else
            {"serial": "", "frus": []},
            "interfaces": parse_interfaces(terse, desc), "bgp": parse_bgp(bgp) if bgp is not None else [],
            "ospf": parse_ospf(ospf) if ospf is not None else [], "alarms": parse_alarms(alarms, now) if alarms is not None else [],
            "lldp": parse_lldp(lldp) if lldp is not None else [], "re": parse_re(re_info) if re_info is not None else
            {"cpu": 0, "mem": 0}, "config": parse_config_set(cfg.text or "")}


def poll(previous: Network | None = None) -> Network:  # pragma: no cover - needs devices
    snaps = {}
    for name, host in lab_targets().items():
        try:
            snaps[name] = collect(name, host)
        except Exception as e:  # noqa: BLE001 - an unreachable device is data, not a crash
            snaps[name] = {"error": f"{type(e).__name__}: {e}", "host": host}
    return build_lab_network(snaps, previous)


if __name__ == "__main__":  # pragma: no cover
    net = poll()
    for d in net.devices.values():
        up = sum(i.oper_up for i in d.interfaces.values())
        print(f"{d.hostname:<16} {d.model:<12} {d.version:<12} mgmt={'ok' if d.mgmt_ok else 'DOWN'} "
              f"interfaces {up}/{len(d.interfaces)} up, BGP {sum(p.state == 'Established' for p in d.bgp)}/{len(d.bgp)}, "
              f"OSPF {len(d.ospf)}, alarms {len(d.alarms)}")
    print(f"{len(net.links)} links from LLDP, {len(net.circuits)} circuits from descriptions")
