"""Read-only Junos CLI emulator over the network model.

Renders the operational commands a NOC engineer uses during triage (`show interfaces terse`, `show bgp summary`,
`show chassis alarms`, ...) in Junos style, including pipes: `| match`, `| except`, `| count`, `| last N`.
Anything that changes state (`configure`, `request`, `clear`, ...) is refused: changes go through a MOP.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from .changes import compare
from .config import settings
from .models import Device, Network
from .network import INET_AS, OUR_PREFIX, TEST_ROUTE, reachable, routed_graph, te_policy

READ_ONLY = "error: CoreWatch console is read-only. Make changes through a change request (MOP)."


def _dur(seconds: float) -> str:
    s = int(max(0, seconds))
    w, s = divmod(s, 604800)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if w:
        return f"{w}w{d}d {h}:{m:02}:{s:02}"
    if d:
        return f"{d}d {h}:{m:02}:{s:02}"
    if h:
        return f"{h}:{m:02}:{s:02}"
    return f"{m}:{s:02}"


def _mw(dbm: float) -> str:
    return f"{10 ** (dbm / 10):.4f} mW / {dbm:.2f} dBm" if dbm > -40 else "0.0000 mW / - Inf dBm"


def _ts(t: datetime | None) -> str:
    return f"{t:%Y-%m-%d %H:%M:%S} UTC" if t else "Never"


class Cli:
    def __init__(self, net: Network, now: datetime | None = None):
        self.net = net
        self.now = now or datetime.now(UTC)

    # -------------------------------------------------------------- entry
    def run(self, host: str, command: str) -> str:
        d = self.net.devices.get(host)
        if not d:
            return f"error: unknown device {host}"
        if not d.mgmt_ok:
            return (f"ssh: connect to host {d.mgmt_ip} port 22: Connection timed out\n"
                    f"error: {host} is not reachable on its management address. Run the check from a neighbour instead.")
        parts = [p.strip() for p in command.strip().split(" | ")]
        cmd, pipes = re.sub(r"\s+", " ", parts[0]), parts[1:]
        try:
            out = self._dispatch(d, cmd, pipes)
        except (KeyError, IndexError, ValueError):
            out = f"error: syntax error or unknown object: {cmd}"
        return self._pipes(out, pipes)

    def _pipes(self, text: str, pipes: list[str]) -> str:
        lines = text.split("\n")
        for p in pipes:
            if p.startswith(("display set", "compare")):
                continue
            m = re.match(r"(match|except|count|last|trim)\s*(.*)", p)
            if not m:
                return f"error: unsupported pipe: {p}"
            op, arg = m.group(1), m.group(2).strip().strip('"')
            if op == "match":
                lines = [ln for ln in lines if re.search(arg, ln, re.I)]
            elif op == "except":
                lines = [ln for ln in lines if not re.search(arg, ln, re.I)]
            elif op == "count":
                return f"Count: {len([ln for ln in lines if ln.strip()])} lines"
            elif op == "last":
                lines = lines[-int(arg or 10):]
        return "\n".join(lines)

    def _dispatch(self, d: Device, cmd: str, pipes: list[str]) -> str:
        w = cmd.split()
        if not w or w[0] not in {"show", "ping", "traceroute"}:
            return READ_ONLY
        if w[0] == "ping":
            return self.ping(d, w[1])
        if w[0] == "traceroute":
            return self.ping(d, w[1], trace=True)
        rest = " ".join(w[1:])
        table = [("version", self.version), ("interfaces terse", self.terse), ("interfaces descriptions", self.descriptions),
                 ("interfaces diagnostics optics", self.optics), ("interfaces", self.interface),
                 ("bgp summary", self.bgp_summary), ("bgp neighbor", self.bgp_neighbor), ("route summary", self.route_summary),
                 ("route receive-protocol bgp", self.route_received), ("route advertising-protocol bgp", self.route_advertised),
                 ("ospf neighbor", self.ospf_neighbor),
                 ("ospf interface", self.ospf_interface), ("chassis alarms", self.chassis_alarms),
                 ("system alarms", self.system_alarms), ("chassis hardware", self.hardware),
                 ("chassis environment", self.environment), ("chassis routing-engine", self.routing_engine),
                 ("chassis fpc", self.fpc), ("system commit", self.commits), ("system storage", self.storage),
                 ("system processes", self.processes), ("configuration", self.configuration), ("log messages", self.log),
                 ("lldp neighbors", self.lldp), ("route", self.route)]
        for key, fn in table:
            if rest == key or rest.startswith(key + " "):
                arg = rest[len(key):].strip()
                return fn(d, arg, pipes) if fn in (self.configuration,) else fn(d, arg)
        return f"error: syntax error, expecting <command>: {rest}"

    # -------------------------------------------------------------- show version / interfaces
    def version(self, d: Device, _arg: str) -> str:
        return (f"Hostname: {d.hostname.split('.')[0]}\nModel: {d.model.lower()}\nJunos: {d.version}\n"
                f"JUNOS OS Kernel 64-bit  [{d.version}]\nJUNOS OS runtime [{d.version}]\nJUNOS Routing Software Suite [{d.version}]")

    def terse(self, d: Device, arg: str) -> str:
        rows = ["Interface               Admin Link Proto    Local                 Remote"]
        for i in d.interfaces.values():
            if arg and i.name != arg:
                continue
            adm, lnk = ("up" if i.admin_up else "down"), ("up" if i.oper_up else "down")
            rows.append(f"{i.name:<24}{adm:<6}{lnk}")
            if i.address:
                rows.append(f"{i.name + '.0':<24}{adm:<6}{lnk:<5}{'inet':<9}{i.address}")
        if not arg:
            rows += [f"{'lo0':<24}{'up':<6}up", f"{'lo0.0':<24}{'up':<6}{'up':<5}{'inet':<9}{d.loopback:<22}--> 0/0",
                     f"{'fxp0':<24}{'up':<6}up", f"{'fxp0.0':<24}{'up':<6}{'up':<5}{'inet':<9}{d.mgmt_ip}/24"]
        return "\n".join(rows)

    def descriptions(self, d: Device, _arg: str) -> str:
        rows = ["Interface       Admin Link Description"]
        for i in d.interfaces.values():
            if i.description:
                rows.append(f"{i.name:<16}{'up' if i.admin_up else 'down':<6}{'up' if i.oper_up else 'down':<5}{i.description}")
        return "\n".join(rows)

    def interface(self, d: Device, arg: str) -> str:
        name = arg.split()[0]
        i = d.interfaces[name]
        ext = "extensive" in arg
        idx = 500 + sum(map(ord, name)) % 300
        state = "Up" if i.oper_up else "Down"
        alarms = "None" if i.oper_up else "LINK"
        defects = "None" if i.oper_up else "LINK, LOCAL-FAULT" if i.rx_dbm <= -40 else "LINK"
        flapped = f"{_ts(i.last_flap)} ({_dur((self.now - i.last_flap).total_seconds())} ago)" if i.last_flap else \
            f"{_ts(self.now - timedelta(days=d.uptime_days))} ({d.uptime_days * 24}:00:00 ago)"
        lines = [f"Physical interface: {name}, {'Enabled' if i.admin_up else 'Administratively down'}, Physical link is {state}",
                 f"  Interface index: {idx}, SNMP ifIndex: {idx - 130}",
                 f"  Description: {i.description}" if i.description else "",
                 f"  Link-level type: Ethernet, MTU: 9192, Speed: {i.speed_gbps}Gbps, BPDU Error: None, Loopback: Disabled,",
                 "  Flow control: Enabled, Auto-negotiation: Disabled, Remote fault: Online",
                 f"  Last flapped   : {flapped}",
                 f"  Input rate     : {int(i.in_bps)} bps ({int(i.in_bps / 8 / 900)} pps)",
                 f"  Output rate    : {int(i.out_bps)} bps ({int(i.out_bps / 8 / 900)} pps)",
                 f"  Active alarms  : {alarms}", f"  Active defects : {defects}"]
        if ext:
            crc = i.in_errors
            lines += ["  Input errors:", f"    Errors: {crc}, Drops: 0, Framing errors: {crc}, Runts: 0, Policed discards: 0,",
                      "    L3 incompletes: 0, L2 channel errors: 0, L2 mismatch timeouts: 0, FIFO errors: 0, Resource errors: 0",
                      "  Output errors:", "    Carrier transitions: " + str(i.flaps * 2) + ", Errors: 0, Drops: 0, Collisions: 0",
                      "  MAC statistics:                      Receive         Transmit",
                      f"    CRC/Align errors                    {crc:>7}                0",
                      "    FIFO errors                               0                0"]
        if i.address:
            lines += [f"  Logical interface {name}.0 (Index {idx + 200}) (SNMP ifIndex {idx - 100})",
                      "    Flags: Up SNMP-Traps 0x4004000 Encapsulation: ENET2" if i.oper_up else "    Flags: Down SNMP-Traps",
                      "    Protocol inet, MTU: 9178", "      Addresses, Flags: Is-Preferred Is-Primary",
                      f"        Destination: {i.address}, Local: {i.address.split('/')[0]}"]
        return "\n".join(x for x in lines if x)

    def optics(self, d: Device, arg: str) -> str:
        i = d.interfaces[arg.split()[0]]
        rx = i.rx_dbm if i.oper_up or i.rx_dbm <= -40 else i.rx_dbm
        low_alarm, low_warn = rx < settings.rx_low_alarm_dbm, rx < settings.rx_low_warn_dbm
        return "\n".join([
            f"Physical interface: {i.name}",
            f"    Laser bias current                        :  {35.1 if i.admin_up else 0.0:.3f} mA",
            f"    Laser output power                        :  {_mw(i.tx_dbm if i.admin_up else -40)}",
            "    Module temperature                        :  38 degrees C / 100 degrees F",
            "    Module voltage                            :  3.3010 V",
            f"    Receiver signal average optical power     :  {_mw(rx)}",
            "    Laser bias current high alarm             :  Off",
            "    Laser output power low alarm              :  Off",
            f"    Laser rx power low alarm                  :  {'On' if low_alarm else 'Off'}",
            f"    Laser rx power low warning                :  {'On' if low_warn else 'Off'}",
            f"    Laser rx power low alarm threshold        :  {_mw(settings.rx_low_alarm_dbm)}",
            f"    Laser rx power low warning threshold      :  {_mw(settings.rx_low_warn_dbm)}"])

    # -------------------------------------------------------------- routing
    def bgp_summary(self, d: Device, _arg: str) -> str:
        if not d.bgp:
            return "BGP is not running"
        down = sum(p.state != "Established" for p in d.bgp if not p.admin_down)
        groups = len({p.group for p in d.bgp})
        rx = sum(p.prefixes_rx for p in d.bgp)
        rows = ["Threading mode: BGP I/O", "Default eBGP mode: advertise - accept, receive - accept",
                f"Groups: {groups} Peers: {sum(not p.admin_down for p in d.bgp)} Down peers: {down}",
                "Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending",
                f"inet.0\n               {rx:>10} {rx // 2 if rx else 0:>10}          0          0          0          0",
                "Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped..."]
        for p in d.bgp:
            if p.admin_down:
                continue
            since = p.last_change or (self.now - timedelta(days=d.uptime_days, seconds=sum(map(ord, p.peer_ip)) * 211))
            inpkt = 2_000_000 + sum(map(ord, p.peer_ip)) * 997
            state = "Establ" if p.state == "Established" else p.state
            rows.append(f"{p.peer_ip:<20}{p.peer_as:>8}{inpkt:>11}{inpkt // 6:>11}{0:>8}{p.flaps:>8} "
                        f"{_dur((self.now - since).total_seconds()):>11} {state}")
            if p.state == "Established":
                rows.append(f"  inet.0: {p.prefixes_rx // 2}/{p.prefixes_rx}/{p.prefixes_rx}/0")
        return "\n".join(rows)

    def bgp_neighbor(self, d: Device, arg: str) -> str:
        p = next(p for p in d.bgp if p.peer_ip == arg.split()[0])
        local = d.interfaces[p.interface].address.split("/")[0] if p.interface else d.loopback
        err = "Hold Timer Expired Error" if p.flaps or p.state != "Established" else None
        lines = [f"Peer: {p.peer_ip}+179 AS {p.peer_as}   Local: {local}+51234 AS {self.net.asn}",
                 f"  Description: {p.description}", f"  Group: {p.group:<20} Routing-Instance: master",
                 f"  Type: {p.kind.capitalize():<10} State: {p.state:<12} Flags: <{'Sync' if p.state == 'Established' else 'ImportEval'}>",
                 f"  Last State: {'OpenConfirm' if p.state == 'Established' else 'Established'}   "
                 f"Last Event: {'RecvKeepAlive' if p.state == 'Established' else 'HoldTime'}",
                 f"  Last Error: {err or 'None'}",
                 f"  Export: [ {p.group}-OUT ] Import: [ {p.group}-IN ]" if p.kind == "external" else "  Export: [ NHS ]",
                 f"  Options: <Preference HoldTime {'AuthKey ' if p.auth else ''}PeerAS Refresh>",
                 "  Authentication key is configured" if p.auth else "",
                 "  Holdtime: 90 Preference: 170", f"  Number of flaps: {p.flaps}"]
        if p.flaps:
            lines += ["  Last flap event: HoldTime", f"  Error: 'Hold Timer Expired Error' Sent: {p.flaps} Recv: 0"]
        lines += [f"  Peer ID: {p.peer_ip:<16} Local ID: {d.loopback:<16} Active Holdtime: 90",
                  "  Keepalive Interval: 30         Group index: 0    Peer index: 0"]
        if p.state == "Established":
            lines += ["  Table inet.0 Bit: 20000", f"    Active prefixes:              {p.prefixes_rx // 2}",
                      f"    Received prefixes:            {p.prefixes_rx}", f"    Accepted prefixes:            {p.prefixes_rx}",
                      f"    Advertised prefixes:          {p.prefixes_tx}"]
        return "\n".join(x for x in lines if x)

    def route_summary(self, d: Device, _arg: str) -> str:
        bgp = sum(p.prefixes_rx for p in d.bgp)
        active = max([p.prefixes_rx for p in d.bgp] + [0])
        ospf = sum(n.state == "Full" for n in d.ospf) * 3 + 10
        dest = active + ospf + 30
        return (f"Autonomous system number: {self.net.asn}\nRouter ID: {d.loopback}\n\n"
                f"inet.0: {dest} destinations, {bgp + ospf + 30} routes ({dest} active, 0 holddown, 0 hidden)\n"
                f"              Direct: {len(d.interfaces) + 2:>7} routes, {len(d.interfaces) + 2:>7} active\n"
                f"               Local: {len(d.interfaces) + 2:>7} routes, {len(d.interfaces) + 2:>7} active\n"
                f"                OSPF: {ospf:>7} routes, {ospf:>7} active\n"
                f"                 BGP: {bgp:>7} routes, {active:>7} active")

    def route_received(self, d: Device, arg: str) -> str:
        p = next(p for p in d.bgp if p.peer_ip == arg.split()[0])
        n = min(p.prefixes_rx, 25)
        rows = ["inet.0: 1004890 destinations, 2009120 routes (1004890 active, 0 holddown, 0 hidden)",
                "  Prefix                  Nexthop              MED     Lclpref    AS path"]
        rows += [f"* 198.18.{k}.0/24          {p.peer_ip:<20}                    {p.peer_as} {65000 + k} I" for k in range(n)]
        if p.prefixes_rx > n:
            rows.append(f"  ... {p.prefixes_rx - n} more")
        return "\n".join(rows) if p.prefixes_rx else ""

    def ospf_neighbor(self, d: Device, _arg: str) -> str:
        rows = ["Address          Interface              State           ID               Pri  Dead"]
        for n in d.ospf:
            if n.state == "Full":
                rows.append(f"{n.address:<17}{n.interface + '.0':<23}{'Full':<16}{n.neighbor_id:<17}128    3{n.address[-1]}")
        return "\n".join(rows)

    def ospf_interface(self, d: Device, arg: str) -> str:
        ifn = arg.split()[0].removesuffix(".0")
        n = next(n for n in d.ospf if n.interface == ifn)
        i = d.interfaces[ifn]
        cost = 65535 if any(f"interface {ifn}.0 metric 65535" in x for x in d.config) else 1
        return (f"Interface           State   Area            DR ID           BDR ID          Nbrs\n"
                f"{ifn + '.0':<20}{'PtToPt' if i.oper_up else 'Down':<8}0.0.0.0         0.0.0.0         0.0.0.0         "
                f"{1 if n.state == 'Full' else 0:>4}\n"
                f"  Type: P2P, Address: {i.address.split('/')[0]}, Mask: 255.255.255.254, MTU: 9178, Cost: {cost}\n"
                f"  Adj count: {1 if n.state == 'Full' else 0}, Hello: 10, Dead: 40, ReXmit: 5, Not Stub")

    # -------------------------------------------------------------- chassis / system
    def chassis_alarms(self, d: Device, _arg: str) -> str:
        al = [a for a in d.alarms if a.source != "System"]
        if not al:
            return "No alarms currently active"
        return f"{len(al)} alarm{'s' if len(al) > 1 else ''} currently active\nAlarm time               Class  Description\n" + \
            "\n".join(f"{a.since:%Y-%m-%d %H:%M:%S} UTC  {a.klass:<6} {a.description}" for a in al)

    def system_alarms(self, d: Device, _arg: str) -> str:
        al = [a for a in d.alarms if a.source == "System"]
        if not al:
            return "No alarms currently active"
        return f"{len(al)} alarm currently active\nAlarm time               Class  Description\n" + \
            "\n".join(f"{a.since:%Y-%m-%d %H:%M:%S} UTC  {a.klass:<6} {a.description}" for a in al)

    def hardware(self, d: Device, _arg: str) -> str:
        rows = ["Hardware inventory:", "Item             Version  Part number  Serial number     Description"]
        for f in d.frus:
            item = f.item if f.kind != "xcvr" else "  Xcvr " + f.item.split()[-1]
            rows.append(f"{item:<17}{'REV 05' if f.part and f.part != 'BUILTIN' else '':<9}{f.part:<13}{f.serial:<18}"
                        f"{f.description}{'' if f.ok else '   [FAILED]'}")
        return "\n".join(rows)

    def environment(self, d: Device, arg: str) -> str:
        rows = ["Class Item                           Status     Measurement"]
        for f in d.frus:
            if f.kind == "pem" and (not arg or arg == "pem"):
                rows.append(f"Power {f.item:<31}{'OK' if f.ok else 'Check':<11}{'' if f.ok else 'Not OK'}")
        if arg == "pem":
            return "\n".join(rows)
        t = d.temp_c
        hot = "OK" if t < settings.temp_high_c else "Hot"
        rows += [f"Temp  {'Chassis':<31}{hot:<11}{t:.0f} degrees C / {t * 9 / 5 + 32:.0f} degrees F",
                 f"      {'Routing Engine 0':<31}{'OK':<11}{t - 2:.0f} degrees C / {(t - 2) * 9 / 5 + 32:.0f} degrees F"]
        for f in d.frus:
            if f.kind == "fan":
                rows.append(f"Fans  {f.item + ' Fan 1':<31}{'OK' if f.ok else 'Failed':<11}"
                            f"{'Spinning at normal speed' if f.ok else 'Not spinning'}")
        return "\n".join(rows)

    def routing_engine(self, d: Device, _arg: str) -> str:
        re0 = next((f for f in d.frus if f.kind == "re"), None)
        cpu = round(d.re_cpu)
        return "\n".join(["Routing Engine status:", "  Slot 0:", "    Current state                  Master",
                          f"    Temperature                 {d.temp_c - 2:.0f} degrees C", "    DRAM                      32768 MB",
                          f"    Memory utilization          {round(d.re_mem)} percent", "    5 sec CPU utilization:",
                          f"      User                      {round(cpu * 0.8)} percent",
                          f"      Kernel                    {cpu - round(cpu * 0.8)} percent",
                          f"      Idle                      {100 - cpu} percent",
                          f"    Model                          {re0.description if re0 else d.model}",
                          f"    Uptime                         {d.uptime_days} days",
                          "    Load averages:                 1 minute   5 minute  15 minute",
                          f"                                       {cpu / 50:.2f}       {cpu / 60:.2f}       {cpu / 70:.2f}"])

    def fpc(self, d: Device, arg: str) -> str:
        rows = ["                     Temp  CPU Utilization (%)   Memory    Utilization (%)",
                "Slot State            (C)  Total  Interrupt      DRAM (MB) Heap     Buffer"]
        for f in d.frus:
            if f.kind != "fpc":
                continue
            n = f.item.split()[1]
            if arg and arg != n:
                continue
            rows.append(f"{n:>3}  {'Online':<16}{d.temp_c + 4:>3.0f}     11          0       8192       24         0" if f.ok
                        else f"{n:>3}  Offline         ---Error---")
        return "\n".join(rows)

    def commits(self, d: Device, _arg: str) -> str:
        return "\n".join(f"{c.rev}   {c.at:%Y-%m-%d %H:%M:%S} UTC by {c.user} via {c.via}" + (f"\n    {c.comment}" if c.comment else "")
                         for c in d.commits[:10])

    def storage(self, d: Device, _arg: str) -> str:
        return ("Filesystem              Size       Used      Avail  Capacity  Mounted on\n"
                "/dev/gpt/junos           20G       6.1G        12G       34%  /.mount\n"
                "/dev/gpt/var             40G       9.8G        27G       27%  /.mount/var")

    def processes(self, d: Device, arg: str) -> str:
        rows = ["  PID USERNAME  PRI NICE   SIZE    RES STATE   C   TIME    WCPU COMMAND"]
        procs = {"rpd": 6, "snmpd": 1, "mgd": 1, "chassisd": 1, "mib2d": 1}
        for name, cpu in procs.items():
            c = d.re_cpu - 4 if name == d.top_process and d.cpu_since else cpu
            rows.append(f" {4000 + len(name) * 37:>4} root       20    0  {900 + len(name) * 80}M  {300 + len(name) * 20}M select  3  "
                        f"{len(name) * 7}:12 {c:>6.2f}% {name}")
        return "\n".join(rows)

    def configuration(self, d: Device, arg: str, pipes: list[str]) -> str:
        if any(p.startswith("compare rollback") for p in pipes):
            return compare(d.prev_config or d.config, d.config)
        lines = [x for x in d.config if not arg or x.split(" ", 1)[1].startswith(arg + " ") or x.split(" ", 1)[1] == arg]
        return "\n".join(lines)

    def route_advertised(self, d: Device, arg: str) -> str:
        p = next(p for p in d.bgp if p.peer_ip == arg.split()[0])
        if p.state != "Established":
            return ""
        if p.kind != "external":
            return "inet.0: (iBGP: advertises the best external paths with next-hop self)"
        prepend, _ = te_policy(d, p.group)
        path = " ".join([str(self.net.asn)] * prepend + ["I"])
        return ("inet.0: 1004890 destinations, 2009120 routes (1004890 active, 0 holddown, 0 hidden)\n"
                "  Prefix                  Nexthop              MED     Lclpref    AS path\n"
                f"* {OUR_PREFIX:<24}Self                                    {path}")

    def route(self, d: Device, arg: str) -> str:
        if arg.split()[0] != TEST_ROUTE:
            return f"error: CoreWatch only models the test destination {TEST_ROUTE}. Try: show route {TEST_ROUTE}"
        hdr = ("inet.0: 1004890 destinations, 2009120 routes (1004890 active, 0 holddown, 0 hidden)\n"
               "+ = Active Route, - = Last Active, * = Both\n\n")
        if not d.bgp:
            return hdr + (f"0.0.0.0/0          *[OSPF/150] {d.uptime_days}d 00:00:00, metric 0, tag 0\n"
                          "                    >  via the core (OSPF default)")
        g = routed_graph(self.net)
        paths = []
        for h, e in self.net.devices.items():
            for p in e.bgp:
                if p.kind != "external" or p.state != "Established" or not p.group.startswith("TRANSIT"):
                    continue
                _, lp = te_policy(e, p.group)
                local = h == d.hostname
                if not local and not reachable(g, d.hostname, h):
                    continue
                paths.append((lp, local, p, e))
        if not paths:
            return hdr + f"{TEST_ROUTE}: no route (no transit available)"
        paths.sort(key=lambda x: (-x[0], not x[1], x[3].loopback))
        out = [hdr.rstrip("\n")]
        for k, (lp, local, p, e) in enumerate(paths):
            mark = "*" if k == 0 else " "
            prefix = TEST_ROUTE if k == 0 else ""
            via = f"to {p.peer_ip} via {p.interface}.0" if local else f"to {e.loopback} (iBGP from {e.hostname.split('.')[0]})"
            out += [f"{prefix:<19}{mark}[BGP/170] 3w2d 04:11:09, localpref {lp}" + ("" if local else f", from {e.loopback}"),
                    f"                      AS path: {p.peer_as} {INET_AS} I, validation-state: unverified",
                    f"                    {'>' if k == 0 else ' '}  {via}"]
        return "\n".join(out)

    def log(self, d: Device, _arg: str) -> str:
        return "\n".join(d.log) if d.log else ""

    def lldp(self, d: Device, _arg: str) -> str:
        rows = ["Local Interface    Parent Interface    Chassis Id          Port info          System Name"]
        for i in d.interfaces.values():
            far = self.net.peer_end(d.hostname, i.name)
            if far and i.oper_up:
                mac = ":".join(f"{(sum(map(ord, far[0])) * (k + 3)) % 256:02x}" for k in range(6))
                rows.append(f"{i.name:<19}{'-':<20}{mac:<20}{far[1]:<19}{far[0].split('.')[0]}")
        return "\n".join(rows)

    def ping(self, d: Device, target: str, trace: bool = False) -> str:
        ok, rtt = False, 0.5
        for p in d.bgp:
            if p.peer_ip == target:
                if p.kind == "external":
                    ok = d.interfaces[p.interface].oper_up
                else:
                    ok = reachable(routed_graph(self.net), d.hostname, p.peer_device)
                    rtt = 2.1
        for n in d.ospf:
            if n.address == target:
                ok = d.interfaces[n.interface].oper_up
        for h, other in self.net.devices.items():
            if other.loopback == target:
                ok = reachable(routed_graph(self.net), d.hostname, h)
                rtt = 1.4
        if trace:
            return f"traceroute to {target} ({target}), 30 hops max, 52 byte packets\n" + \
                (f" 1  {target} ({target})  {rtt:.3f} ms  {rtt * 1.1:.3f} ms  {rtt * 0.9:.3f} ms" if ok else
                 " 1  * * *\n 2  * * *\n 3  * * *")
        recv = 5 if ok else 0
        return (f"PING {target} ({target}): 56 data bytes\n{'!!!!!' if ok else '.....'}\n--- {target} ping statistics ---\n"
                f"5 packets transmitted, {recv} packets received, {100 - recv * 20}% packet loss"
                + (f"\nround-trip min/avg/max/stddev = {rtt * 0.8:.3f}/{rtt:.3f}/{rtt * 1.3:.3f}/{rtt * 0.1:.3f} ms" if ok else ""))


SUGGESTED = ["show interfaces terse", "show interfaces descriptions", "show bgp summary", "show ospf neighbor",
             "show chassis alarms", "show system alarms", "show chassis hardware", "show chassis environment",
             "show chassis routing-engine", "show chassis fpc", "show route summary", "show lldp neighbors", "show system commit",
             "show configuration | display set", "show configuration | compare rollback 1", "show log messages | last 20",
             "show route 192.0.2.128/25",
             "show version"]

