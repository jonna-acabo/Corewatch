"""Mock Junos network: topology, configuration, protocol state, traffic and fault injection.

All names, ASNs (RFC 5398 documentation range), IP addresses (RFC 5737 / RFC 1918),
serial numbers and carriers are fictional.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from .config import settings
from .models import BgpPeer, Carrier, ChassisAlarm, Circuit, Commit, Device, Fru, Interface, Link, Network, OspfNeighbor

ASN = 64510
OUR_PREFIX = "198.18.0.0/15"           # what AS64510 announces to the internet (benchmarking range, fictional)
INET_AS = 64511                        # "the rest of the internet" in AS paths (documentation range)
TEST_ROUTE = "192.0.2.128/25"          # an internet destination learned from every transit
APPROVED_VERSION = {"mx": "23.4R2-S3", "ex": "23.4R2-S3", "qfx": "23.4R2-S3", "srx": "23.4R2-S3"}

CARRIERS = [
    Carrier("tidegate", "Tidegate Transit", 64496, "noc@tidegate.example", "+1 202 555 0101", "TDG-ACC-55120", 4),
    Carrier("corvane", "Corvane Networks", 64497, "support@corvane.example", "+1 202 555 0102", "CVN-77341", 4),
    Carrier("alderline", "Alderline Fiber", None, "faults@alderline.example", "+1 202 555 0103", "ALF-20931", 6),
    Carrier("bayport", "Bayport IX", 64498, "ops@bayport-ix.example", "+1 202 555 0104", "BPX-M-0417", 8),
]

#          hostname              model       family role       site     version       x    y
DEVICES = [("mx-edge-01.dc1",   "MX204",    "mx",  "edge",     "DC1",   "22.4R3-S2",  250, 150),
           ("mx-edge-02.dc2",   "MX204",    "mx",  "edge",     "DC2",   "23.4R2-S3",  750, 150),
           ("mx-core-01.dc1",   "MX480",    "mx",  "core",     "DC1",   "23.4R2-S3",  250, 285),
           ("mx-core-02.dc2",   "MX480",    "mx",  "core",     "DC2",   "23.4R2-S3",  750, 285),
           ("srx-fw-01.dc1",    "SRX4600",  "srx", "firewall", "DC1",   "23.4R2-S3",   85, 430),
           ("qfx-leaf-01.dc1",  "QFX5120-48Y", "qfx", "leaf",  "DC1",   "23.4R2-S3",  245, 430),
           ("ex-agg-01.qc",     "EX4650-48Y", "ex", "pop",     "POP-QC", "23.4R2-S3", 430, 430),
           ("ex-agg-02.ceb",    "EX4650-48Y", "ex", "pop",     "POP-CEB", "21.4R3-S5", 570, 430),
           ("qfx-leaf-02.dc2",  "QFX5120-48Y", "qfx", "leaf",  "DC2",   "23.4R2-S3",  755, 430),
           ("srx-fw-02.dc2",    "SRX4600",  "srx", "firewall", "DC2",   "22.4R3-S2",  915, 430)]

# Internal links: (a host, a if, b host, b if, speed Gbps, circuit id or None)
LINKS = [("mx-core-01.dc1", "et-0/0/0", "mx-core-02.dc2", "et-0/0/0", 100, "ALF-DF-0091"),
         ("mx-core-01.dc1", "et-1/0/0", "mx-edge-01.dc1", "et-0/0/0", 100, None),
         ("mx-core-02.dc2", "et-1/0/0", "mx-edge-02.dc2", "et-0/0/0", 100, None),
         ("mx-core-01.dc1", "xe-2/0/0", "srx-fw-01.dc1", "xe-1/0/0", 10, None),
         ("mx-core-02.dc2", "xe-2/0/0", "srx-fw-02.dc2", "xe-1/0/0", 10, None),
         ("mx-core-01.dc1", "et-1/0/2", "qfx-leaf-01.dc1", "et-0/0/48", 100, None),
         ("mx-core-02.dc2", "et-1/0/2", "qfx-leaf-02.dc2", "et-0/0/48", 100, None),
         ("mx-core-01.dc1", "xe-2/0/2", "ex-agg-01.qc", "xe-0/0/46", 10, "ALF-EPL-2207"),
         ("mx-core-02.dc2", "xe-2/0/2", "ex-agg-01.qc", "xe-0/0/47", 10, "CVN-WAV-31045"),
         ("mx-core-02.dc2", "xe-2/0/3", "ex-agg-02.ceb", "xe-0/0/46", 10, "ALF-EPL-2311"),
         ("mx-core-01.dc1", "xe-2/0/3", "ex-agg-02.ceb", "xe-0/0/47", 10, "CVN-WAV-31188")]

# External: (host, if, speed, circuit, carrier, service, local address, peer ip, bgp group)
EXTERNAL = [("mx-edge-01.dc1", "et-0/0/2", 100, "TDG-IP-88123", "tidegate", "IP Transit", "192.0.2.2/30", "192.0.2.1",
             "TRANSIT-TIDEGATE"),
            ("mx-edge-02.dc2", "et-0/0/2", 100, "CVN-IP-40517", "corvane", "IP Transit", "198.51.100.2/30", "198.51.100.1",
             "TRANSIT-CORVANE"),
            ("mx-edge-01.dc1", "xe-0/1/0", 10, "BPX-PORT-0417", "bayport", "IX Peering", "203.0.113.10/24", "203.0.113.1",
             "IX-BAYPORT"),
            ("mx-edge-02.dc2", "xe-0/1/0", 10, "BPX-PORT-0418", "bayport", "IX Peering", "203.0.113.11/24", "203.0.113.1",
             "IX-BAYPORT")]

SERVICE = {"ALF-DF-0091": "Dark Fibre", "ALF-EPL-2207": "Ethernet Private Line", "CVN-WAV-31045": "Wavelength",
           "ALF-EPL-2311": "Ethernet Private Line", "CVN-WAV-31188": "Wavelength"}
CIRCUIT_CARRIER = {"ALF": "alderline", "CVN": "corvane", "TDG": "tidegate", "BPX": "bayport"}

# Traffic model (Gbps)
INTERNET_IN, INTERNET_OUT, IX_SHARE = 96.0, 40.0, 0.10
POP_LOAD = {"ex-agg-01.qc": 6.0, "ex-agg-02.ceb": 5.0}

NOC_USERS = ["noc-automation", "mvillanueva", "preyes", "kmorales"]


def short(host: str) -> str:
    return host.split(".")[0]


def _serial(rnd: random.Random, prefix: str, n: int = 8) -> str:
    return prefix + "".join(rnd.choice("ABCDEFGHJKLMNPRSTUVWXYZ0123456789") for _ in range(n))


def _frus(model: str, rnd: random.Random, chassis_serial: str) -> list[Fru]:
    f = [Fru("Chassis", "", chassis_serial, model, kind="chassis")]
    if model == "MX480":
        f += [Fru("Midplane", "750-047862", _serial(rnd, "AC"), "Enhanced MX480 Midplane", kind="chassis")]
        f += [Fru(f"PEM {i}", "740-063049", _serial(rnd, "1E"), "PS 2.52;3.5kW; 200-240V AC in", kind="pem") for i in range(4)]
        f += [Fru(f"Routing Engine {i}", "750-079562", _serial(rnd, "CA"), "RE-S-X6-64G", kind="re") for i in range(2)]
        f += [Fru(f"CB {i}", "750-070866", _serial(rnd, "CA"), "Enhanced MX SCB 3", kind="re") for i in range(2)]
        f += [Fru("FPC 0", "750-084779", _serial(rnd, "CA"), "MPC10E 3D MRATE-10xQSFPP", kind="fpc"),
              Fru("FPC 1", "750-084779", _serial(rnd, "CA"), "MPC10E 3D MRATE-10xQSFPP", kind="fpc"),
              Fru("FPC 2", "750-056519", _serial(rnd, "CA"), "MPC7E 3D 40XGE", kind="fpc")]
        f += [Fru(f"Fan Tray {i}", "740-057995", _serial(rnd, "AC"), "Enhanced Fan Tray", kind="fan") for i in range(2)]
    elif model == "MX204":
        f += [Fru(f"PEM {i}", "740-069994", _serial(rnd, "1F"), "JPSU-650W-AC-AFO", kind="pem") for i in range(2)]
        f += [Fru("Routing Engine 0", "BUILTIN", "BUILTIN", "RE-S-1600x8", kind="re"),
              Fru("FPC 0", "BUILTIN", "BUILTIN", "MPC7E 8XQSFP28+8XSFPP", kind="fpc")]
        f += [Fru(f"Fan Tray {i}", "", "", "Fan Tray, Front to Back Airflow - AFO", kind="fan") for i in range(3)]
    elif model == "SRX4600":
        f += [Fru(f"PEM {i}", "740-059935", _serial(rnd, "1G"), "JPSU-1600W-AC-AFO", kind="pem") for i in range(2)]
        f += [Fru("Routing Engine 0", "BUILTIN", "BUILTIN", "SRX Routing Engine", kind="re"),
              Fru("FPC 0", "BUILTIN", "BUILTIN", "FEB", kind="fpc"),
              Fru("FPC 1", "BUILTIN", "BUILTIN", "8x10GE SFP+ / 4x40GE QSFP+", kind="fpc")]
        f += [Fru(f"Fan Tray {i}", "", "", "SRX4600 Fan Tray", kind="fan") for i in range(4)]
    else:  # EX4650 / QFX5120
        f += [Fru(f"PEM {i}", "740-073147", _serial(rnd, "1E"), "JPSU-650W-AC-AFO", kind="pem") for i in range(2)]
        f += [Fru("Routing Engine 0", "BUILTIN", "BUILTIN", model, kind="re"),
              Fru("FPC 0", "650-089213", _serial(rnd, "WS"), model, kind="fpc")]
        f += [Fru(f"Fan Tray {i}", "", "", "Fan Module, Airflow Out (AFO)", kind="fan") for i in range(5)]
    return f


def _optic(speed: int) -> str:
    return {100: "QSFP-100GBASE-LR4", 10: "SFP+-10G-LR"}.get(speed, "SFP+-10G-LR")


def _base_config(d: Device) -> list[str]:
    h = short(d.hostname)
    return [f"set version {d.version}",
            f"set system host-name {h}",
            'set system login message "Authorised access only. All activity is logged and monitored."',
            "set system root-authentication encrypted-password \"$6$mOcK$redacted\"",
            "set system services ssh root-login deny",
            "set system services ssh protocol-version v2",
            "set system services netconf ssh",
            "set system authentication-order tacplus",
            "set system authentication-order password",
            "set system tacplus-server 10.250.0.30 secret \"$9$mOcKsEcReT\"",
            "set system ntp server 10.250.0.11",
            "set system ntp server 10.250.0.12",
            "set system syslog host 10.250.0.20 any notice",
            "set system syslog file messages any notice",
            "set snmp v3 usm local-engine user cw-monitor authentication-sha256 authentication-key \"$9$mOcK\"",
            "set snmp v3 vacm security-to-group security-model usm security-name cw-monitor group CW-RO",
            "set protocols lldp interface all",
            f"set routing-options router-id {d.loopback}",
            f"set routing-options autonomous-system {ASN}",
            f"set interfaces lo0 unit 0 family inet address {d.loopback}/32",
            "set interfaces fxp0 unit 0 family inet address " + d.mgmt_ip + "/24"]


def build_network(seed: int = 7) -> Network:
    rnd = random.Random(seed)
    carriers = {c.id: c for c in CARRIERS}
    devices: dict[str, Device] = {}
    for n, (host, model, fam, role, site, ver, x, y) in enumerate(DEVICES, 1):
        serial = _serial(rnd, {"mx": "JN1", "srx": "DS", "ex": "XH", "qfx": "WS"}[fam], 9)
        d = Device(host, model, fam, role, site, mgmt_ip=f"10.254.{n // 10}.{10 + n}", loopback=f"10.255.0.{n}",
                   version=ver, serial=serial, cmdb_serial=serial, x=x, y=y,
                   uptime_days=rnd.randint(40, 400), re_cpu=rnd.uniform(6, 22), re_mem=rnd.uniform(30, 55),
                   temp_c=rnd.uniform(33, 42))
        d.frus = _frus(model, rnd, serial)
        d.config = _base_config(d)
        devices[host] = d

    links: list[Link] = []
    circuits: dict[str, Circuit] = {}
    subnet = 0

    def add_if(host: str, name: str, speed: int, desc: str, addr: str) -> Interface:
        base = round(rnd.uniform(-4.5, -1.5), 2)
        i = Interface(name, desc, speed, _optic(speed), address=addr, baseline_rx=base, rx_dbm=base,
                      tx_dbm=round(rnd.uniform(-1.5, 1.0), 2))
        devices[host].interfaces[name] = i
        devices[host].frus.append(Fru(f"Xcvr {name}", "740-0" + str(rnd.randint(10000, 99999)), _serial(rnd, "1A"),
                                      i.optic, kind="xcvr"))
        return i

    for a, ai, b, bi, speed, cid in LINKS:
        role = "CORE" if devices[b].role in {"core", "edge"} else devices[b].role.upper()
        tag = f" | CID {cid} | {carriers[CIRCUIT_CARRIER[cid[:3]]].name}" if cid else ""
        add_if(a, ai, speed, f"{role} | {short(b)} {bi}{tag}", f"10.0.0.{subnet}/31")
        add_if(b, bi, speed, f"UPLINK | {short(a)} {ai}{tag}", f"10.0.0.{subnet + 1}/31")
        subnet += 2
        links.append(Link((a, ai), (b, bi), cid))
        if cid:
            circuits[cid] = Circuit(cid, CIRCUIT_CARRIER[cid[:3]], SERVICE[cid], speed, (a, ai), f"{b} {bi}")
    for host, name, speed, cid, carrier, service, addr, _peer, _grp in EXTERNAL:
        c = carriers[carrier]
        add_if(host, name, speed, f"{'TRANSIT' if service == 'IP Transit' else 'PEERING'} | {c.name} AS{c.asn} | CID {cid}", addr)
        links.append(Link((host, name), None, cid))
        circuits[cid] = Circuit(cid, carrier, service, speed, (host, name), c.name)
    # spare ports, admin down
    for host, name in (("mx-edge-01.dc1", "xe-0/1/1"), ("mx-core-01.dc1", "xe-2/0/4"), ("mx-core-02.dc2", "xe-2/0/4")):
        i = Interface(name, "SPARE", 10, "", admin_up=False, oper_up=False, rx_dbm=-40.0, baseline_rx=-40.0)
        devices[host].interfaces[name] = i

    net = Network(devices, links, carriers, circuits, ASN)
    _protocols(net)
    for d in devices.values():
        d.config += _iface_config(d) + _protocol_config(net, d)
    _quirks(net, rnd)
    for d in devices.values():
        d.prev_config = list(d.config)
    for d in devices.values():
        start = datetime(2026, 9, 1, 2, 0, tzinfo=UTC)
        d.commits = [Commit(i, start - timedelta(days=9 * i + rnd.randint(0, 5), hours=rnd.randint(0, 4)),
                            rnd.choice(NOC_USERS), rnd.choice(["cli", "netconf"]), cmt, f"CHG-{990 - i}")
                     for i, cmt in enumerate(["CHG standard: syslog + LLDP baseline", "CHG quarterly ACL refresh",
                                              "CHG NTP servers migration"])]
    derive(net, datetime(2026, 9, 1, tzinfo=UTC), quiet=True)
    for d in devices.values():
        for i in d.interfaces.values():
            u = i.util_pct
            i.history = [max(0.0, round(u * rnd.uniform(0.8, 1.15), 1)) for _ in range(40)]
    return net


def _iface_config(d: Device) -> list[str]:
    out = []
    for i in d.interfaces.values():
        out.append(f'set interfaces {i.name} description "{i.description}"')
        if not i.admin_up:
            out.append(f"set interfaces {i.name} disable")
        if i.address:
            out.append(f"set interfaces {i.name} unit 0 family inet address {i.address}")
    return out


def _protocols(net: Network) -> None:
    """Expected OSPF adjacencies and BGP sessions (state is filled in by derive)."""
    for lk in net.links:
        if lk.b:
            (a, ai), (b, bi) = lk.a, lk.b
            da, db = net.devices[a], net.devices[b]
            da.ospf.append(OspfNeighbor(ai, db.interfaces[bi].address.split("/")[0], db.loopback, b))
            db.ospf.append(OspfNeighbor(bi, da.interfaces[ai].address.split("/")[0], da.loopback, a))
    cores = [h for h, d in net.devices.items() if d.role == "core"]
    edges = [h for h, d in net.devices.items() if d.role == "edge"]
    pairs = [(c, e) for c in cores for e in edges] + [(cores[0], cores[1])]
    for a, b in pairs:
        da, db = net.devices[a], net.devices[b]
        da.bgp.append(BgpPeer(db.loopback, ASN, "IBGP", f"{short(b)} (iBGP)", "internal", peer_device=b))
        db.bgp.append(BgpPeer(da.loopback, ASN, "IBGP", f"{short(a)} (iBGP)", "internal", peer_device=a))
    for host, name, _s, cid, carrier, _service, _addr, peer, grp in EXTERNAL:
        c = net.carriers[carrier]
        net.devices[host].bgp.append(BgpPeer(peer, c.asn, grp, f"{c.name} {cid}", "external", interface=name))


def _protocol_config(net: Network, d: Device) -> list[str]:
    out = []
    for n in d.ospf:
        out.append(f"set protocols ospf area 0.0.0.0 interface {n.interface}.0 interface-type p2p")
    if d.ospf:
        out.append("set protocols ospf area 0.0.0.0 interface lo0.0 passive")
    groups: dict[str, list[BgpPeer]] = {}
    for p in d.bgp:
        groups.setdefault(p.group, []).append(p)
    for g, peers in groups.items():
        if g == "IBGP":
            out += ["set protocols bgp group IBGP type internal", f"set protocols bgp group IBGP local-address {d.loopback}",
                    "set protocols bgp group IBGP family inet unicast"]
            if d.role == "core":
                out.append(f"set protocols bgp group IBGP cluster {d.loopback}")
        else:
            out += [f"set protocols bgp group {g} type external",
                    f"set protocols bgp group {g} import {g}-IN",
                    f"set protocols bgp group {g} export {g}-OUT",
                    f"set protocols bgp group {g} peer-as {peers[0].peer_as}",
                    f'set protocols bgp group {g} authentication-key "$9$mOcKbGpKeY"',
                    f"set policy-options policy-statement {g}-IN term ACCEPT then local-preference 100",
                    f"set policy-options policy-statement {g}-IN term ACCEPT then accept",
                    f"set policy-options policy-statement {g}-OUT term ADVERTISE from prefix-list OUR-PREFIXES",
                    f"set policy-options policy-statement {g}-OUT term ADVERTISE then accept",
                    f"set policy-options policy-statement {g}-OUT term REJECT then reject"]
        for p in peers:
            out.append(f'set protocols bgp group {g} neighbor {p.peer_ip} description "{p.description}"')
    if any(p.kind == "external" for p in d.bgp):
        out += [f"set policy-options prefix-list OUR-PREFIXES {OUR_PREFIX}", f"set routing-options static route {OUR_PREFIX} discard"]
    return out


def _quirks(net: Network, rnd: random.Random) -> None:
    """Realistic drift so the audit page has something to find."""
    d = net.devices
    ceb = d["ex-agg-02.ceb"]
    ceb.config.append("set system services telnet")
    ceb.config.remove("set system ntp server 10.250.0.12")
    q2 = d["qfx-leaf-02.dc2"]
    q2.config.append("set snmp community cw-legacy authorization read-only")
    q2.config = [c for c in q2.config if not c.startswith("set system login message")]
    e2 = d["mx-edge-02.dc2"]
    e2.config.remove('set protocols bgp group IX-BAYPORT authentication-key "$9$mOcKbGpKeY"')
    for p in e2.bgp:
        if p.group == "IX-BAYPORT":
            p.auth = False
    s2 = d["srx-fw-02.dc2"]
    s2.rescue_saved = False
    s1 = d["srx-fw-01.dc1"]          # chassis swapped under RMA, asset register never updated
    s1.cmdb_serial = _serial(rnd, "DS", 9)
    l1 = d["qfx-leaf-01.dc1"]
    l1.interfaces["et-0/0/48"].description = ""
    l1.config = [c for c in l1.config if not c.startswith("set interfaces et-0/0/48 description")]


# ------------------------------------------------------------------ derived state
def _laser_on(net: Network, host: str, ifname: str) -> bool:
    d = net.devices[host]
    i = d.interfaces[ifname]
    return d.powered and d.fpc_online(i.fpc) and i.admin_up


def routed_graph(net: Network) -> dict[str, set[str]]:
    g: dict[str, set[str]] = {h: set() for h, d in net.devices.items() if d.powered}
    for lk in net.links:
        if lk.b and net.iface(*lk.a).oper_up and net.iface(*lk.b).oper_up:
            g[lk.a[0]].add(lk.b[0])
            g[lk.b[0]].add(lk.a[0])
    return g


def reachable(g: dict[str, set[str]], src: str, dst: str) -> bool:
    if src not in g or dst not in g:
        return False
    seen, todo = {src}, [src]
    while todo:
        for n in g[todo.pop()]:
            if n not in seen:
                seen.add(n)
                todo.append(n)
    return dst in seen


def derive(net: Network, now: datetime, quiet: bool = False) -> None:
    """Recompute interface, OSPF, BGP, alarm and traffic state from the physical state."""
    if net.source != "mock":
        return
    linked = set()
    for lk in net.links:
        circuit_ok = net.circuits[lk.circuit].ok if lk.circuit else True
        ends = lk.ends()
        up = lk.ok and circuit_ok and all(_laser_on(net, *e) for e in ends)
        for k, (host, ifn) in enumerate(ends):
            linked.add((host, ifn))
            d, i = net.devices[host], net.devices[host].interfaces[ifn]
            if not d.powered:
                i.oper_up = False
                continue
            far_ok = lk.ok and circuit_ok and (_laser_on(net, *ends[1 - k]) if lk.b else True)
            i.rx_dbm = round(i.baseline_rx + i.rx_loss, 2) if far_ok and i.admin_up and d.fpc_online(i.fpc) else -40.0
            _set_oper(d, i, up, now, quiet)
    for d in net.devices.values():
        for i in d.interfaces.values():
            if (d.hostname, i.name) not in linked:
                i.oper_up = False
    _ospf_bgp(net, now, quiet)
    _alarms(net, now)
    _traffic(net)


def _set_oper(d: Device, i: Interface, up: bool, now: datetime, quiet: bool) -> None:
    if i.oper_up == up:
        return
    i.oper_up = up
    if up:
        i.down_since = None
    else:
        i.down_since, i.last_flap = now, now
        i.flaps += 1
    if not quiet:
        state = "up(1)" if up else "down(2)"
        d.syslog(now, f"mib2d[3021]: SNMP_TRAP_LINK_{'UP' if up else 'DOWN'}: ifIndex {500 + hash(i.name) % 300}, "
                      f"ifAdminStatus {'up(1)' if i.admin_up else 'down(2)'}, ifOperStatus {state}, ifName {i.name}")


def _ospf_bgp(net: Network, now: datetime, quiet: bool) -> None:
    for d in net.devices.values():
        for n in d.ospf:
            up = d.powered and d.interfaces[n.interface].oper_up
            new = "Full" if up else "Down"
            if new != n.state:
                n.state = new
                if not quiet and d.powered:
                    d.syslog(now, f"rpd[2871]: RPD_OSPF_NBRDOWN: OSPF neighbor {n.address} (realm ospf-v2 {n.interface}.0 "
                                  f"area 0.0.0.0) state changed from Full to Down due to KillNbr"
                             if new == "Down" else
                             f"rpd[2871]: RPD_OSPF_NBRUP: OSPF neighbor {n.address} (realm ospf-v2 {n.interface}.0 "
                             f"area 0.0.0.0) state changed from Loading to Full due to LoadDone")
    g = routed_graph(net)
    for d in net.devices.values():
        for p in d.bgp:
            if p.kind == "internal":
                up = d.powered and net.devices[p.peer_device].powered and reachable(g, d.hostname, p.peer_device) \
                    and not p.remote_down and not p.admin_down
                p.prefixes_rx = 0 if not up else (412_000 if d.role == "core" else 1_004_310)
                new = "Established" if up else "Active"
            else:
                i = d.interfaces[p.interface]
                up = d.powered and i.oper_up and not p.remote_down and not p.admin_down
                new = "Established" if up else ("Idle" if p.admin_down or not i.oper_up else "Active")
                p.prefixes_rx = (1_004_310 if p.group.startswith("TRANSIT") else 48_212) if up else 0
            p.prefixes_tx = 2_840 if up else 0
            if new != p.state:
                was, p.state = p.state, new
                p.last_change = now
                if was == "Established":
                    p.flaps += 1
                    p.flap_times.append(now)
                if not quiet and d.powered:
                    kind = "External" if p.kind == "external" else "Internal"
                    d.syslog(now, f"rpd[2871]: BGP_STATE_CHANGE: bgp peer {p.peer_ip} ({kind} AS {p.peer_as}) changed state "
                                  f"from {was} to {new} (event {'HoldTime' if new != 'Established' else 'RecvKeepAlive'})")


def _alarms(net: Network, now: datetime) -> None:
    for d in net.devices.values():
        prev = {a.description: a.since for a in d.alarms}
        want: list[tuple[str, str, str]] = []
        for f in d.frus:
            if f.ok:
                continue
            if f.kind == "fpc":
                want.append(("Major", f"{f.item} Major Errors - Offline", f.item))
            elif f.kind == "pem":
                want.append(("Major", f"{f.item} Not OK", f.item))
            elif f.kind == "fan":
                want.append(("Major", f"{f.item} Failure", f.item))
        if d.temp_c >= settings.temp_high_c:
            want.append(("Major" if d.temp_c >= settings.temp_high_c + 8 else "Minor", "Temperature Hot", "Chassis"))
        if not d.rescue_saved:
            want.append(("Minor", "Rescue configuration is not set", "System"))
        d.alarms = [ChassisAlarm(k, desc, prev.get(desc, now), src) for k, desc, src in want]


def te_policy(d: Device, group: str) -> tuple[int, int]:
    """(AS-path prepend count on export, local-preference on import) for one eBGP group, read from the config."""
    prepend, lp = 0, 100
    for x in d.config:
        if x.startswith(f"set policy-options policy-statement {group}-OUT ") and " as-path-prepend " in x:
            prepend = len(x.split(" as-path-prepend ", 1)[1].strip().strip('"').split())
        elif x.startswith(f"set policy-options policy-statement {group}-IN ") and " local-preference " in x:
            lp = int(x.rsplit(" ", 1)[1])
    return prepend, lp


def transit_split(net: Network, override: tuple | None = None) -> dict[str, dict]:
    """How internet traffic spreads over the IP transit circuits, given each group's BGP policy.

    Inbound (internet -> us) follows our announcements: every prepend makes a path much less attractive.
    Outbound (us -> internet) follows local-preference: the highest wins everywhere in the AS (via iBGP).
    override = (host, peer_ip, "prepend" | "local_pref", value) to predict the effect of a change.
    """
    peers = []
    for d in net.devices.values():
        for p in d.bgp:
            if p.kind != "external" or p.state != "Established" or not p.group.startswith("TRANSIT"):
                continue
            lk = net.link_of(d.hostname, p.interface)
            prepend, lp = te_policy(d, p.group)
            if override and override[0] == d.hostname and override[1] == p.peer_ip:
                prepend, lp = (override[3], lp) if override[2] == "prepend" else (prepend, override[3])
            peers.append({"host": d.hostname, "peer": p.peer_ip, "interface": p.interface, "circuit": lk.circuit if lk else "",
                          "prepend": prepend, "local_pref": lp, "speed": d.interfaces[p.interface].speed_gbps})
    ix_up = any(p.state == "Established" for d in net.devices.values() for p in d.bgp if p.group.startswith("IX"))
    t_in = INTERNET_IN * (1 - IX_SHARE if ix_up else 1)
    t_out = INTERNET_OUT * (1 - IX_SHARE if ix_up else 1)
    if not peers:
        return {}
    w = [0.4 ** x["prepend"] for x in peers]
    best = max(x["local_pref"] for x in peers)
    winners = [x for x in peers if x["local_pref"] == best]
    for x, wi in zip(peers, w, strict=True):
        x["in_gbps"] = round(t_in * wi / sum(w), 1)
        x["out_gbps"] = round(t_out / len(winners), 1) if x in winners else 0.0
        x["in_util"] = round(min(98.5, 100 * x["in_gbps"] / x["speed"]), 1)
        x["out_util"] = round(min(98.5, 100 * x["out_gbps"] / x["speed"]), 1)
    return {x["circuit"]: x for x in peers}


def _traffic(net: Network) -> None:
    for d in net.devices.values():
        for i in d.interfaces.values():
            i.in_bps = i.out_bps = 0.0
    up_ext = {lk.circuit: net.iface(*lk.a) for lk in net.links if not lk.b and net.iface(*lk.a).oper_up}
    bgp_up = {p.interface for d in net.devices.values() for p in d.bgp if p.kind == "external" and p.state == "Established"}
    ix = [i for cid, i in up_ext.items() if net.circuits[cid].service == "IX Peering" and i.name in bgp_up]
    ix_in = INTERNET_IN * IX_SHARE if ix else 0
    for i in ix:
        i.in_bps, i.out_bps = ix_in / len(ix) * 1e9, INTERNET_OUT * IX_SHARE / len(ix) * 1e9
    split = transit_split(net)
    for x in split.values():
        i = net.iface(x["host"], x["interface"])
        cap = i.speed_gbps * 1e9
        i.in_bps, i.out_bps = min(cap * 0.985, x["in_gbps"] * 1e9), min(cap * 0.985, x["out_gbps"] * 1e9)
    # edges hand their traffic to the local core
    for lk in net.links:
        if not lk.b:
            continue
        a, b = net.iface(*lk.a), net.iface(*lk.b)
        if not (a.oper_up and b.oper_up):
            continue
        if lk.costed_out:
            a.in_bps = a.out_bps = b.in_bps = b.out_bps = 0.05e9
            continue
        da, db = net.devices[lk.a[0]], net.devices[lk.b[0]]
        if db.role == "edge":
            ext = [x for x in db.interfaces.values() if x.name.startswith(("et-0/0/2", "xe-0/1/0"))]
            cap = a.speed_gbps * 1e9 * 0.985
            bps_in, bps_out = min(cap, sum(x.in_bps for x in ext)), min(cap, sum(x.out_bps for x in ext))
            a.in_bps, a.out_bps, b.in_bps, b.out_bps = bps_out, bps_in, bps_in, bps_out
        elif db.role == "firewall":
            a.out_bps, a.in_bps = 3.1e9, 1.4e9
        elif db.role == "leaf":
            a.out_bps, a.in_bps = 31e9, 12e9
        elif da.role == "core" and db.role == "core":
            a.out_bps, a.in_bps = 28e9, 21e9
        elif db.role == "pop":
            ups = [x for x in db.interfaces.values() if x.oper_up and x.name.startswith("xe-0/0/4")]
            load = POP_LOAD[db.hostname] / max(1, len(ups))
            inter_dc = net.links[0]
            if inter_dc.costed_out or not (net.iface(*inter_dc.a).oper_up and net.iface(*inter_dc.b).oper_up):
                load += 4.0      # inter-DC traffic now crosses the POP circuits
            a.out_bps, a.in_bps = load * 1e9, load * 0.35e9
        if db.role != "edge":
            b.in_bps, b.out_bps = a.out_bps, a.in_bps


# ------------------------------------------------------------------ simulation
def tick(net: Network, now: datetime, rnd: random.Random) -> None:
    for d in net.devices.values():
        if not d.powered:
            continue
        if d.cpu_since is None:
            d.re_cpu = max(3.0, min(40.0, d.re_cpu + rnd.uniform(-3, 3)))
        fan_bad = any(f.kind == "fan" and not f.ok for f in d.frus)
        d.temp_c = round(min(74.0, d.temp_c + 1.8) if fan_bad else max(33.0, d.temp_c + rnd.uniform(-0.6, 0.5)), 1)
        for i in d.interfaces.values():
            if i.rx_drift:
                i.rx_loss = round(i.rx_loss + i.rx_drift, 2)
            if i.crc_per_min:
                i.in_errors += int(i.crc_per_min * rnd.uniform(0.6, 1.4) * settings.sim_interval_seconds / 60 * 4)
    derive(net, now)
    for d in net.devices.values():
        for i in d.interfaces.values():
            u = i.util_pct * rnd.uniform(0.94, 1.06) if i.oper_up else 0.0
            i.history = (i.history + [round(min(u, 99.0), 1)])[-40:]


def _pick(rnd: random.Random, items: list):
    return rnd.choice(items) if items else None


def circuit_down(net: Network, cid: str, now: datetime) -> str:
    c = net.circuits[cid]
    c.ok = False
    derive(net, now)
    return f"Carrier circuit {cid} ({net.carriers[c.carrier].name} {c.service}) went down"


def circuit_errors(net: Network, cid: str, now: datetime, rate: float = 420.0) -> str:
    c = net.circuits[cid]
    i = net.iface(*c.a_end)
    i.crc_per_min, i.rx_loss, i.degraded_since = rate, round(i.rx_loss - 2.4, 2), now
    i.in_errors += int(rate * 12)
    derive(net, now)
    return f"Input/CRC errors rising on {cid} ({short(c.a_end[0])} {c.a_end[1]})"


def bgp_down(net: Network, host: str, peer_ip: str, now: datetime) -> str:
    p = next(p for p in net.devices[host].bgp if p.peer_ip == peer_ip)
    p.remote_down = True
    derive(net, now)
    return f"BGP {peer_ip} on {short(host)} stopped answering (hold timer)"


def bgp_flap(net: Network, host: str, peer_ip: str, now: datetime, times: int = 4) -> str:
    d = net.devices[host]
    p = next(p for p in d.bgp if p.peer_ip == peer_ip)
    for k in range(times):
        t = now - timedelta(minutes=8 * (times - k))
        p.flap_times.append(t)
        p.flaps += 1
        d.syslog(t, f"rpd[2871]: BGP_STATE_CHANGE: bgp peer {p.peer_ip} (External AS {p.peer_as}) changed state from "
                    "Established to Idle (event HoldTime)")
    p.last_change = now - timedelta(minutes=8)
    return f"BGP {peer_ip} on {short(host)} flapped {times} times"


def link_down(net: Network, lk: Link, now: datetime) -> str:
    lk.ok = False
    if lk.circuit:
        net.circuits[lk.circuit].ok = False
    derive(net, now)
    return f"Link {short(lk.a[0])} {lk.a[1]} <-> {short(lk.b[0])} {lk.b[1]} lost light" if lk.b else "External link down"


def fpc_offline(net: Network, host: str, fpc: int, now: datetime) -> str:
    d = net.devices[host]
    next(f for f in d.frus if f.item == f"FPC {fpc}").ok = False
    d.syslog(now, f"chassisd[1702]: CHASSISD_FRU_OFFLINE_NOTICE: Taking FPC {fpc} offline: Error")
    derive(net, now)
    return f"FPC {fpc} on {short(host)} went offline"


def fru_fail(net: Network, host: str, item: str, now: datetime) -> str:
    d = net.devices[host]
    next(f for f in d.frus if f.item == item).ok = False
    d.syslog(now, f"chassisd[1702]: CHASSISD_FRU_FAILED: {item} failed")
    derive(net, now)
    return f"{item} failed on {short(host)}"


def cpu_high(net: Network, host: str, now: datetime, proc: str = "rpd") -> str:
    d = net.devices[host]
    d.re_cpu, d.top_process, d.cpu_since = 96.0, proc, now
    d.syslog(now, f"kernel: {proc} using 9{abs(hash(proc)) % 10}% of CPU")
    return f"Routing engine CPU at 96% on {short(host)} ({proc})"


def optic_degrade(net: Network, host: str, ifname: str, now: datetime, loss: float = -7.5, rate: float = -0.25) -> str:
    i = net.iface(host, ifname)
    i.rx_loss, i.rx_drift, i.degraded_since = loss, rate, now
    derive(net, now)
    return f"Receive power falling on {short(host)} {ifname}"


def device_down(net: Network, host: str, now: datetime) -> str:
    d = net.devices[host]
    d.powered = d.mgmt_ok = False
    d.down_since = d.mgmt_down_since = now
    derive(net, now)
    return f"{host} stopped responding (power or chassis failure)"


def mgmt_down(net: Network, host: str, now: datetime) -> str:
    d = net.devices[host]
    d.mgmt_ok, d.mgmt_down_since = False, now
    return f"Out-of-band management to {host} lost"


def unauthorized_commit(net: Network, host: str, now: datetime) -> str:
    d = net.devices[host]
    lines = ["set system services telnet", "set snmp community public authorization read-write"]
    d.prev_config = list(d.config)
    for ln in lines:
        if ln not in d.config:
            d.config.append(ln)
    for c in d.commits:
        c.rev += 1
    d.commits.insert(0, Commit(0, now, "tmp-vendor", "cli", ""))
    d.syslog(now, "mgd[8812]: UI_COMMIT: User 'tmp-vendor' requested 'commit' operation (comment: none)")
    return f"Commit by tmp-vendor on {short(host)} with no change ticket"


def restore_all(net: Network, now: datetime) -> int:
    n = 0
    for c in net.circuits.values():
        n += not c.ok
        c.ok = True
    for lk in net.links:
        n += not lk.ok
        lk.ok, lk.costed_out = True, False
    for d in net.devices.values():
        if not d.powered or not d.mgmt_ok:
            n += 1
        d.powered = d.mgmt_ok = True
        d.down_since = d.mgmt_down_since = d.cpu_since = None
        d.re_cpu, d.top_process = 14.0, "rpd"
        d.temp_c = min(d.temp_c, 41.0)
        for f in d.frus:
            n += not f.ok
            f.ok = True
        for i in d.interfaces.values():
            i.rx_loss = i.rx_drift = i.crc_per_min = 0.0
            i.degraded_since = None
        for p in d.bgp:
            p.remote_down = False
            p.flap_times = []
    derive(net, now)
    return n


def seed_faults(net: Network, now: datetime, rnd: random.Random) -> None:
    """A realistic starting picture for the demo. Returns what happened, for the event log."""
    out = [optic_degrade(net, "mx-edge-01.dc1", "xe-0/1/0", now - timedelta(hours=6), loss=-8.1, rate=0.0),
           fru_fail(net, "mx-core-02.dc2", "PEM 2", now - timedelta(hours=3, minutes=10)),
           unauthorized_commit(net, "qfx-leaf-02.dc2", now - timedelta(hours=2, minutes=14)),
           circuit_errors(net, "CVN-WAV-31045", now - timedelta(minutes=42)),
           bgp_flap(net, "mx-edge-02.dc2", "203.0.113.1", now, 4),
           mgmt_down(net, "ex-agg-02.ceb", now - timedelta(minutes=25))]
    derive(net, now)
    return out


FAULTS = ("transit_down", "ix_down", "circuit_errors", "bgp_down", "bgp_flap", "inter_dc_cut", "pop_isolated", "fpc_offline",
          "psu_fail", "fan_fail", "cpu_high", "optic_degrade", "device_down", "mgmt_down", "unauthorized_commit")


def inject(net: Network, fault: str, now: datetime, rnd: random.Random) -> str:
    d = net.devices
    if fault == "transit_down":
        ok = [c for c in net.circuits.values() if c.service == "IP Transit" and c.ok]
        return circuit_down(net, ok[0].id, now) if ok else "No transit circuit left to fail"
    if fault == "ix_down":
        ok = [c for c in net.circuits.values() if c.service == "IX Peering" and c.ok]
        return circuit_down(net, rnd.choice(ok).id, now) if ok else "No IX port left to fail"
    if fault == "circuit_errors":
        c = _pick(rnd, [c for c in net.circuits.values() if c.ok and not net.iface(*c.a_end).crc_per_min])
        return circuit_errors(net, c.id, now) if c else "Every circuit already has errors"
    if fault == "bgp_down":
        p = _pick(rnd, [(h, p) for h, dv in d.items() for p in dv.bgp if p.kind == "external" and p.state == "Established"])
        return bgp_down(net, p[0], p[1].peer_ip, now) if p else "No established eBGP session"
    if fault == "bgp_flap":
        h, p = rnd.choice([(h, p) for h, dv in d.items() for p in dv.bgp if p.kind == "external"])
        return bgp_flap(net, h, p.peer_ip, now)
    if fault == "inter_dc_cut":
        return link_down(net, net.links[0], now)
    if fault == "pop_isolated":
        host = rnd.choice(["ex-agg-01.qc", "ex-agg-02.ceb"])
        for lk in net.links:
            if lk.b and lk.b[0] == host:
                lk.ok = False
                net.circuits[lk.circuit].ok = False
        derive(net, now)
        return f"Both uplink circuits to {host} went down"
    if fault == "fpc_offline":
        return fpc_offline(net, "mx-core-01.dc1", 2, now)
    if fault == "psu_fail":
        host = rnd.choice(["mx-core-01.dc1", "mx-edge-01.dc1", "srx-fw-01.dc1", "qfx-leaf-01.dc1"])
        pem = next(f for f in d[host].frus if f.kind == "pem" and f.ok)
        return fru_fail(net, host, pem.item, now)
    if fault == "fan_fail":
        host = rnd.choice(["ex-agg-01.qc", "qfx-leaf-01.dc1", "srx-fw-02.dc2"])
        d[host].temp_c = 55.0
        return fru_fail(net, host, "Fan Tray 1", now)
    if fault == "cpu_high":
        return cpu_high(net, rnd.choice(["mx-edge-01.dc1", "mx-core-02.dc2", "mx-edge-02.dc2"]), now,
                        rnd.choice(["rpd", "snmpd", "mgd"]))
    if fault == "optic_degrade":
        lk = rnd.choice([lk for lk in net.links if lk.b and lk.ok])
        return optic_degrade(net, lk.a[0], lk.a[1], now, loss=-8.6, rate=-0.35)
    if fault == "device_down":
        return device_down(net, rnd.choice(["qfx-leaf-02.dc2", "srx-fw-02.dc2", "ex-agg-01.qc"]), now)
    if fault == "mgmt_down":
        return mgmt_down(net, rnd.choice([h for h, dv in d.items() if dv.mgmt_ok]), now)
    if fault == "unauthorized_commit":
        return unauthorized_commit(net, rnd.choice(["ex-agg-01.qc", "mx-edge-02.dc2", "srx-fw-01.dc1"]), now)
    raise ValueError(fault)


def random_fault(net: Network, now: datetime, rnd: random.Random) -> str:
    return inject(net, rnd.choice(["circuit_errors", "bgp_down", "optic_degrade", "psu_fail", "cpu_high", "transit_down",
                                   "fan_fail", "ix_down"]), now, rnd)
