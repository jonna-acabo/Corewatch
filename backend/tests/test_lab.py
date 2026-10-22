"""Live-lab collector: Junos RPC XML -> model -> correlation, without needing a device."""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

from app import lab
from app.correlation import correlate

NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
ROOT = ET.parse(Path(__file__).parent / "fixtures" / "r1.xml").getroot()


def rpc(tag, **attr):
    return next(e for e in ROOT if e.tag == tag and all(e.get(k) == v for k, v in attr.items()))


def snapshot_r1():
    return {"host": "172.20.20.2", "software": lab.parse_software(rpc("software-information")),
            "inventory": lab.parse_inventory(rpc("chassis-inventory")),
            "interfaces": lab.parse_interfaces(rpc("interface-information", terse="1"), rpc("interface-information", descriptions="1")),
            "bgp": lab.parse_bgp(rpc("bgp-information")), "ospf": lab.parse_ospf(rpc("ospf-neighbor-information")),
            "alarms": lab.parse_alarms(rpc("alarm-information"), NOW), "lldp": lab.parse_lldp(rpc("lldp-neighbors-information")),
            "re": lab.parse_re(rpc("route-engine-information")), "config": lab.parse_config_set(rpc("configuration-set").text)}


def snapshot_r2():
    return {"host": "172.20.20.3", "software": {"hostname": "r2", "model": "VMX", "version": "23.2R1.14"},
            "inventory": {"serial": "VM65Z9", "frus": []},
            "interfaces": {"ge-0/0/0": {"admin": True, "oper": True, "description": "CORE | r1 ge-0/0/0"}},
            "bgp": [{"peer_ip": "10.255.0.1", "peer_as": 64510, "state": "Established", "flaps": 0, "description": "",
                     "prefixes_rx": 3}],
            "ospf": [{"address": "10.0.0.0", "interface": "ge-0/0/0", "state": "Full", "neighbor_id": "10.255.0.1"}],
            "alarms": [], "lldp": [{"local": "ge-0/0/0", "remote_system": "r1", "remote_port": "ge-0/0/0"}],
            "re": {"cpu": 5, "mem": 30},
            "config": ["set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/31",
                       "set interfaces lo0 unit 0 family inet address 10.255.0.2/32", "set routing-options autonomous-system 64510",
                       "set protocols bgp group IBGP neighbor 10.255.0.1"]}


def test_parsers_read_junos_xml():
    s = snapshot_r1()
    assert s["software"] == {"hostname": "r1", "model": "VMX", "version": "23.2R1.14"}
    assert s["inventory"]["serial"] == "VM65A1B2C3"
    assert set(s["interfaces"]) == {"ge-0/0/0", "ge-0/0/1"}                       # lo0 is ignored
    assert s["interfaces"]["ge-0/0/1"] == {"admin": True, "oper": False,
                                           "description": "TRANSIT | Tidegate Transit AS64496 | CID TDG-LAB-0001"}
    assert s["bgp"][1]["prefixes_rx"] == 12 and s["bgp"][0]["state"] == "Idle"
    assert s["ospf"][0]["interface"] == "ge-0/0/0"
    assert s["alarms"][0].description == "PEM 1 Not OK" and s["alarms"][0].since.year == 2026
    assert s["lldp"][0]["remote_port"] == "ge-0/0/0"                               # name preferred over ifIndex
    assert s["re"]["cpu"] == 9
    assert "set routing-options autonomous-system 64510" in s["config"]


def test_lab_network_builds_topology_and_circuits():
    net = lab.build_lab_network({"r1": snapshot_r1(), "r2": snapshot_r2()}, now=NOW)
    assert net.source == "lab"
    internal = [lk for lk in net.links if lk.b]
    assert len(internal) == 1 and {internal[0].a[0], internal[0].b[0]} == {"r1", "r2"}
    assert "TDG-LAB-0001" in net.circuits and net.carriers["tidegate-transit"].name == "Tidegate Transit"
    r1 = net.devices["r1"]
    ext = next(p for p in r1.bgp if p.kind == "external")
    assert ext.interface == "ge-0/0/1" and ext.group == "TRANSIT-TIDEGATE"
    ibgp = next(p for p in r1.bgp if p.kind == "internal")
    assert ibgp.peer_device == "r2"


def test_lab_correlation_finds_the_down_transit_and_the_alarm():
    net = lab.build_lab_network({"r1": snapshot_r1(), "r2": snapshot_r2()}, now=NOW)
    incs = correlate(net, NOW)
    kinds = {i["kind"] for i in incs}
    assert "circuit_down" in kinds and "psu_failed" in kinds
    transit = next(i for i in incs if i["kind"] == "circuit_down")
    assert transit["scope"]["circuit"] == "TDG-LAB-0001" and transit["severity"] == "P1"   # the only transit


def test_lab_remembers_ospf_neighbours_that_disappear():
    first = lab.build_lab_network({"r1": snapshot_r1(), "r2": snapshot_r2()}, now=NOW)
    s1 = snapshot_r1()
    s1["ospf"] = []
    s1["interfaces"]["ge-0/0/0"]["oper"] = False
    s2 = snapshot_r2()
    s2["ospf"], s2["lldp"] = [], []
    s2["interfaces"]["ge-0/0/0"]["oper"] = False
    second = lab.build_lab_network({"r1": s1, "r2": s2}, previous=first, now=NOW)
    assert any(n.state == "Down" for n in second.devices["r1"].ospf)
    assert any(lk.b for lk in second.links)                      # link kept although LLDP lost it
    # r2 lost both of its links (and r1's uplink to the transit is down too) -> the engine sees isolation
    assert any(i["kind"] in {"link_down", "isolated"} for i in correlate(second, NOW))


def test_unreachable_lab_device_is_reported():
    first = lab.build_lab_network({"r1": snapshot_r1(), "r2": snapshot_r2()}, now=NOW)
    second = lab.build_lab_network({"r1": snapshot_r1(), "r2": {"error": "ConnectTimeoutError", "host": "172.20.20.3"}},
                                   previous=first, now=NOW)
    assert not second.devices["r2"].mgmt_ok
