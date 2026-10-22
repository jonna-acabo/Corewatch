import random
from datetime import UTC, datetime, timedelta

import pytest

from app import network as net
from app.correlation import correlate, stats, symptoms

NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)


def fresh():
    return net.build_network(seed=7)


def kinds(n):
    return [i["kind"] for i in correlate(n, NOW)]


def test_healthy_network_has_no_incidents():
    n = fresh()
    net.derive(n, NOW)
    assert correlate(n, NOW) == []
    s = stats(n, [], NOW)
    assert s["bgp_up"] == s["bgp"] == 14 and s["ospf_up"] == s["ospf"] == 22 and s["circuits_up"] == 9


def test_fpc_failure_is_one_incident_that_explains_everything():
    n = fresh()
    net.fpc_offline(n, "mx-core-01.dc1", 2, NOW)
    incs = correlate(n, NOW)
    assert len(incs) == 1
    i = incs[0]
    assert i["kind"] == "fpc_offline" and i["severity"] == "P1" and i["service_affecting"]
    assert "srx-fw-01.dc1" in i["devices"]                  # firewall isolated by the card
    assert i["symptoms"] == len(symptoms(fresh_with(lambda x: net.fpc_offline(x, "mx-core-01.dc1", 2, NOW)), NOW))
    assert i["symptoms"] >= 10


def fresh_with(fn):
    n = fresh()
    fn(n)
    return n


def test_single_transit_loss_is_p2_and_names_the_carrier():
    n = fresh()
    net.circuit_down(n, "TDG-IP-88123", NOW)
    incs = correlate(n, NOW)
    assert [i["kind"] for i in incs] == ["circuit_down"]
    i = incs[0]
    assert i["severity"] == "P2" and i["carrier"] == "Tidegate Transit" and i["scope"]["circuit"] == "TDG-IP-88123"
    assert any("CVN-IP-40517 now at" in e for e in i["evidence"])      # traffic moved to the other transit


def test_losing_both_transits_is_one_p1():
    n = fresh()
    net.circuit_down(n, "TDG-IP-88123", NOW)
    net.circuit_down(n, "CVN-IP-40517", NOW)
    incs = correlate(n, NOW)
    assert [i["kind"] for i in incs] == ["all_transit_down"] and incs[0]["severity"] == "P1"


def test_pop_with_both_circuits_down_is_isolated():
    n = fresh()
    for lk in n.links:
        if lk.b and lk.b[0] == "ex-agg-01.qc":
            net.link_down(n, lk, NOW)
    incs = correlate(n, NOW)
    assert [i["kind"] for i in incs] == ["isolated"]
    assert set(incs[0]["scope"]["carriers"]) == {"Alderline Fiber", "Corvane Networks"}


def test_device_down_absorbs_neighbour_alarms():
    n = fresh()
    net.device_down(n, "qfx-leaf-02.dc2", NOW)
    incs = correlate(n, NOW)
    assert [i["kind"] for i in incs] == ["device_down"]
    assert "mx-core-02.dc2" in incs[0]["devices"]


def test_inter_dc_cut_keeps_ibgp_up_through_pops():
    n = fresh()
    net.link_down(n, n.links[0], NOW)
    assert all(p.state == "Established" for d in n.devices.values() for p in d.bgp)
    assert kinds(n) == ["circuit_down"]


def test_bgp_down_with_link_up_points_at_recent_commit():
    n = fresh()
    d = n.devices["mx-edge-02.dc2"]
    net.unauthorized_commit(n, "mx-edge-02.dc2", NOW - timedelta(minutes=3))
    net.bgp_down(n, "mx-edge-02.dc2", "198.51.100.1", NOW)
    inc = next(i for i in correlate(n, NOW) if i["kind"] == "bgp_down")
    assert inc["severity"] == "P2" and any("commit by tmp-vendor" in e for e in inc["evidence"])
    assert d.interfaces["et-0/0/2"].oper_up


def test_errors_and_flaps_on_the_same_circuit_are_one_incident():
    n = fresh()
    net.circuit_errors(n, "BPX-PORT-0418", NOW)
    net.bgp_flap(n, "mx-edge-02.dc2", "203.0.113.1", NOW)
    incs = correlate(n, NOW)
    assert [i["kind"] for i in incs] == ["circuit_errors"]
    assert any("flapped" in e for e in incs[0]["evidence"])


@pytest.mark.parametrize("fault", net.FAULTS)
def test_every_fault_is_explained(fault):
    n = fresh()
    net.inject(n, fault, NOW, random.Random(2))
    incs = correlate(n, NOW)
    assert incs, fault
    claimed = sum(i["symptoms"] for i in incs)
    assert claimed >= len(symptoms(n, NOW)), "every raw alarm belongs to an incident"
    for i in incs:
        assert i["evidence"] and i["verify"] and i["recommended_actions"]


def test_fan_failure_raises_temperature_and_severity():
    n = fresh()
    net.fru_fail(n, "ex-agg-01.qc", "Fan Tray 1", NOW)
    for _ in range(14):
        net.tick(n, NOW, random.Random(1))
    inc = next(i for i in correlate(n, NOW) if i["kind"] == "fan_failed")
    assert inc["severity"] == "P2"


def test_maintenance_window_tags_incidents():
    n = fresh()
    net.circuit_down(n, "TDG-IP-88123", NOW)
    incs = correlate(n, NOW, [{"id": "CHG-1", "devices": ["mx-edge-01.dc1"], "circuits": ["TDG-IP-88123"]}])
    assert incs[0]["maintenance"] == "CHG-1"


def test_restore_clears_everything():
    n = fresh()
    for f in net.FAULTS:
        net.inject(n, f, NOW, random.Random(5))
    assert correlate(n, NOW)
    net.restore_all(n, NOW)
    left = [i["kind"] for i in correlate(n, NOW)]
    assert set(left) <= {"unauthorized_commit"}          # the commit itself stays in history until reviewed


def test_maintenance_on_a_device_does_not_hide_unrelated_interface_faults():
    n = fresh()
    net.optic_degrade(n, "mx-edge-01.dc1", "xe-0/1/0", NOW, loss=-9.5, rate=0)
    incs = correlate(n, NOW, [{"id": "CHG-1", "devices": ["mx-edge-01.dc1"], "circuits": ["TDG-IP-88123"]}])
    assert incs[0]["kind"] == "optics_low" and incs[0]["maintenance"] is None
