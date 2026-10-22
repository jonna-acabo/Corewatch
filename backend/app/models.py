"""Data model for a Junos core / edge network.

Device -> FRUs (chassis hardware) -> interfaces -> links / carrier circuits
Device -> BGP peers, OSPF neighbours, chassis alarms, configuration (set format), commit history
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

IFNAME = re.compile(r"^(?P<media>[a-z]+)-(?P<fpc>\d+)/(?P<pic>\d+)/(?P<port>\d+)$")


def fpc_of(ifname: str) -> int | None:
    m = IFNAME.match(ifname)
    return int(m.group("fpc")) if m else None


@dataclass
class Interface:
    name: str                       # et-0/0/2, xe-2/0/1
    description: str = ""
    speed_gbps: int = 10
    optic: str = "10GBASE-LR"
    admin_up: bool = True
    oper_up: bool = True
    address: str = ""               # 10.0.0.0/31
    rx_dbm: float = -3.0
    tx_dbm: float = -1.5
    baseline_rx: float = -3.0
    rx_loss: float = 0.0            # extra loss on top of baseline (dirty connector, bend, ageing optic)
    rx_drift: float = 0.0           # dB added per tick while degrading
    crc_per_min: float = 0.0        # input/CRC errors per minute right now
    in_errors: int = 0              # cumulative
    in_bps: float = 0.0
    out_bps: float = 0.0
    history: list[float] = field(default_factory=list)   # utilisation % samples, oldest first
    flaps: int = 0
    last_flap: datetime | None = None
    down_since: datetime | None = None
    degraded_since: datetime | None = None

    @property
    def fpc(self) -> int | None:
        return fpc_of(self.name)

    @property
    def util_pct(self) -> float:
        return round(100 * max(self.in_bps, self.out_bps) / (self.speed_gbps * 1e9), 1) if self.oper_up else 0.0


@dataclass
class Fru:
    item: str                       # "FPC 2", "PEM 1", "Fan Tray 0", "Routing Engine 0"
    part: str
    serial: str
    description: str
    ok: bool = True
    kind: str = "fpc"               # chassis | re | fpc | pic | pem | fan | xcvr


@dataclass
class ChassisAlarm:
    klass: str                      # Major | Minor
    description: str
    since: datetime
    source: str = ""                # FRU item that raised it


@dataclass
class BgpPeer:
    peer_ip: str
    peer_as: int
    group: str
    description: str
    kind: str                       # external | internal
    interface: str = ""             # local interface for eBGP
    peer_device: str = ""           # hostname for iBGP
    state: str = "Established"
    prefixes_rx: int = 0
    prefixes_tx: int = 0
    flaps: int = 0
    flap_times: list[datetime] = field(default_factory=list)
    last_change: datetime | None = None
    admin_down: bool = False        # deactivated in config (planned)
    remote_down: bool = False       # simulated: the far end stopped answering (hold timer / remote config)
    auth: bool = True


@dataclass
class OspfNeighbor:
    interface: str
    address: str
    neighbor_id: str                # router-id (loopback) of the far end
    peer_device: str
    state: str = "Full"


@dataclass
class Commit:
    rev: int                        # 0 = current
    at: datetime
    user: str
    via: str                        # cli | netconf
    comment: str = ""
    change_id: str = ""             # CHG this commit belongs to, if any


@dataclass
class Device:
    hostname: str                   # mx-core-01.dc1
    model: str                      # MX480
    family: str                     # mx | ex | qfx | srx
    role: str                       # core | edge | firewall | leaf | pop
    site: str                       # DC1
    mgmt_ip: str
    loopback: str
    version: str
    serial: str
    cmdb_serial: str                # what the asset register says
    x: int = 0                      # topology diagram position
    y: int = 0
    powered: bool = True            # forwarding plane alive
    mgmt_ok: bool = True            # reachable on the out-of-band management network
    down_since: datetime | None = None
    mgmt_down_since: datetime | None = None
    cpu_since: datetime | None = None
    re_cpu: float = 12.0
    re_mem: float = 41.0
    temp_c: float = 38.0
    uptime_days: int = 120
    top_process: str = "rpd"
    rescue_saved: bool = True
    frus: list[Fru] = field(default_factory=list)
    interfaces: dict[str, Interface] = field(default_factory=dict)
    bgp: list[BgpPeer] = field(default_factory=list)
    ospf: list[OspfNeighbor] = field(default_factory=list)
    alarms: list[ChassisAlarm] = field(default_factory=list)
    config: list[str] = field(default_factory=list)       # "show configuration | display set"
    prev_config: list[str] = field(default_factory=list)  # rollback 1
    commits: list[Commit] = field(default_factory=list)   # newest first
    log: list[str] = field(default_factory=list)          # syslog lines, newest last

    def fpc_online(self, n: int | None) -> bool:
        if n is None:
            return True
        fru = next((f for f in self.frus if f.item == f"FPC {n}"), None)
        return fru.ok if fru else True

    def syslog(self, at: datetime, text: str) -> None:
        self.log.append(f"{at:%b %d %H:%M:%S} {self.hostname.split('.')[0]} {text}")
        del self.log[:-60]


@dataclass
class Carrier:
    id: str
    name: str
    asn: int | None
    noc_email: str
    noc_phone: str
    account: str
    sla_mttr_h: int


@dataclass
class Circuit:
    id: str                         # carrier circuit ID
    carrier: str                    # Carrier.id
    service: str                    # IP Transit | IX Peering | Ethernet Private Line | Wavelength | Dark Fibre
    bandwidth_gbps: int
    a_end: tuple[str, str]          # (hostname, interface)
    z_end: str                      # "mx-core-01.dc1 xe-0/0/1" or "Tidegate Transit"
    ok: bool = True                 # carrier side healthy
    carrier_ticket: dict | None = None


@dataclass
class Link:
    """A physical connection. Internal links have two device ends; external ones have b=None."""

    a: tuple[str, str]
    b: tuple[str, str] | None
    circuit: str | None = None      # carrier circuit carrying this link, if any
    ok: bool = True                 # fibre / carrier path healthy
    costed_out: bool = False        # OSPF metric raised for maintenance

    def ends(self) -> list[tuple[str, str]]:
        return [self.a] + ([self.b] if self.b else [])


@dataclass
class Network:
    devices: dict[str, Device]
    links: list[Link]
    carriers: dict[str, Carrier]
    circuits: dict[str, Circuit]
    asn: int = 64510
    source: str = "mock"            # mock | lab

    def link_of(self, host: str, ifname: str) -> Link | None:
        return next((lk for lk in self.links if (host, ifname) in lk.ends()), None)

    def peer_end(self, host: str, ifname: str) -> tuple[str, str] | None:
        lk = self.link_of(host, ifname)
        if not lk or not lk.b:
            return None
        return lk.b if lk.a == (host, ifname) else lk.a

    def iface(self, host: str, ifname: str) -> Interface | None:
        d = self.devices.get(host)
        return d.interfaces.get(ifname) if d else None
