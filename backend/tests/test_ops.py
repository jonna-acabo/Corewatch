from datetime import UTC, datetime, timedelta

import pytest

from app import audit as aud
from app import network as net
from app import oncall
from app.changes import ChangeManager, apply_lines, compare
from app.correlation import correlate
from app.junos_cli import READ_ONLY, Cli
from app.slack import SlackAlerter

NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)


# ---------------------------------------------------------------- CLI
def test_cli_renders_junos_views():
    n = net.build_network()
    cli = Cli(n, NOW)
    s = cli.run("mx-edge-01.dc1", "show bgp summary")
    assert "Peer                     AS" in s and "192.0.2.1" in s and "Establ" in s
    assert "et-0/0/2.0" in cli.run("mx-edge-01.dc1", "show interfaces terse")
    assert cli.run("mx-core-01.dc1", "show chassis alarms") == "No alarms currently active"
    assert cli.run("srx-fw-02.dc2", "show system alarms").endswith("Rescue configuration is not set")
    assert cli.run("mx-core-01.dc1", "show ospf neighbor | count") == "Count: 7 lines"   # header + 6 neighbours
    assert "Full" in cli.run("mx-core-01.dc1", "show ospf neighbor | match et-0/0/0")
    assert "!!!!!" in cli.run("mx-edge-01.dc1", "ping 192.0.2.1 rapid count 5")


def test_cli_is_read_only_and_respects_management_reachability():
    n = net.build_network()
    cli = Cli(n, NOW)
    for cmd in ("configure", "request system reboot", "clear bgp neighbor all", "set system services telnet"):
        assert cli.run("mx-core-01.dc1", cmd) == READ_ONLY
    net.mgmt_down(n, "mx-core-01.dc1", NOW)
    assert "Connection timed out" in cli.run("mx-core-01.dc1", "show version")


def test_cli_reflects_faults():
    n = net.build_network()
    net.fpc_offline(n, "mx-core-01.dc1", 2, NOW)
    cli = Cli(n, NOW)
    assert "FPC 2 Major Errors - Offline" in cli.run("mx-core-01.dc1", "show chassis alarms")
    assert "xe-2/0/0                up    down" in cli.run("mx-core-01.dc1", "show interfaces terse xe-2/0/0")
    assert "Offline" in cli.run("mx-core-01.dc1", "show chassis fpc 2")
    net.circuit_down(n, "TDG-IP-88123", NOW)
    assert "- Inf dBm" in cli.run("mx-edge-01.dc1", "show interfaces diagnostics optics et-0/0/2")
    assert "BGP_STATE_CHANGE" in cli.run("mx-edge-01.dc1", "show log messages | last 5")


# ---------------------------------------------------------------- config diff / changes
def test_compare_looks_like_junos():
    old = ["set system services ssh root-login deny"]
    new = apply_lines(old, ["set system services telnet", "deactivate protocols bgp group T neighbor 192.0.2.1"])
    diff = compare(old, new)
    assert "[edit system services]\n+    telnet;" in diff
    assert "!    inactive: neighbor 192.0.2.1" in diff
    assert apply_lines(new, ["delete system services telnet", "activate protocols bgp group T neighbor 192.0.2.1"]) == old


def test_transit_drain_lifecycle_suppresses_alerts_and_restores():
    n = net.build_network()
    cm = ChangeManager()
    c = cm.create(n, "transit_drain", {"device": "mx-edge-01.dc1", "peer": "192.0.2.1"}, "alice", NOW)
    assert c["mop"]["risk"] == "High" and c["mop"]["warnings"]          # remaining transit would run hot
    assert c["mop"]["procedure"][0]["steps"][0] == "configure exclusive"
    assert any(s.startswith("commit confirmed 5") for s in c["mop"]["procedure"][0]["steps"])
    with pytest.raises(ValueError):
        cm.approve(c["id"], "alice", NOW)                                 # four-eyes rule
    cm.approve(c["id"], "bob", NOW)
    cm.implement(n, c["id"], "alice", NOW)
    net.derive(n, NOW)
    peer = next(p for p in n.devices["mx-edge-01.dc1"].bgp if p.peer_ip == "192.0.2.1")
    assert peer.admin_down and peer.state == "Idle"
    assert "bgp_down" not in {i["kind"] for i in correlate(n, NOW, cm.active())}   # planned, not a fault
    net.circuit_down(n, "TDG-IP-88123", NOW)
    assert correlate(n, NOW, cm.active())[0]["maintenance"] == c["id"]
    cm.confirm(n, c["id"], "alice", NOW)
    n.circuits["TDG-IP-88123"].ok = True
    cm.close(n, c["id"], "alice", NOW)
    net.derive(n, NOW)
    assert peer.state == "Established" and not peer.admin_down
    assert n.devices["mx-edge-01.dc1"].commits[0].change_id == c["id"]


def test_unconfirmed_commit_rolls_back_automatically():
    n = net.build_network()
    cm = ChangeManager()
    before = list(n.devices["mx-core-01.dc1"].config)
    c = cm.create(n, "cost_out", {"device": "mx-core-01.dc1", "interface": "et-0/0/0"}, "alice", NOW)
    cm.approve(c["id"], "bob", NOW)
    cm.implement(n, c["id"], "alice", NOW)
    assert n.links[0].costed_out
    assert cm.expire(n, NOW + timedelta(minutes=6))
    assert c["status"] == "rolled_back" and n.devices["mx-core-01.dc1"].config == before and not n.links[0].costed_out


def test_upgrade_and_compliance_fix_change_the_audit():
    n = net.build_network()
    cm = ChangeManager()
    dev = "ex-agg-02.ceb"
    assert aud.audit_device(n.devices[dev])["score"] < 100
    c = cm.create(n, "compliance_fix", {"device": dev}, "alice", NOW, aud.audit_device(n.devices[dev])["auto_fix"])
    cm.approve(c["id"], "bob", NOW)
    cm.implement(n, c["id"], "alice", NOW)
    u = cm.create(n, "junos_upgrade", {"device": dev}, "alice", NOW)
    cm.approve(u["id"], "bob", NOW)
    cm.implement(n, u["id"], "alice", NOW)
    assert aud.audit_device(n.devices[dev])["score"] == 100
    with pytest.raises(ValueError):
        cm.create(n, "junos_upgrade", {"device": dev}, "alice", NOW)       # already on the approved release


# ---------------------------------------------------------------- audit
def test_audit_finds_the_seeded_drift():
    n = net.build_network()
    a = {x["device"]: {r["id"]: r for r in x["results"]} for x in aud.audit(n)["devices"]}
    assert not a["ex-agg-02.ceb"]["SEC-02"]["ok"] and not a["ex-agg-02.ceb"]["OPS-01"]["ok"]
    assert not a["qfx-leaf-02.dc2"]["SEC-03"]["ok"] and not a["qfx-leaf-02.dc2"]["SEC-06"]["ok"]
    assert not a["mx-edge-02.dc2"]["SEC-05"]["ok"]
    assert not a["srx-fw-02.dc2"]["OPS-04"]["ok"]
    assert all(r["ok"] for r in a["mx-core-01.dc1"].values())
    hw = {x["device"]: x for x in aud.hardware(n)}
    assert not hw["srx-fw-01.dc1"]["serial_match"] and hw["mx-core-01.dc1"]["serial_match"]


# ---------------------------------------------------------------- on-call + slack
def test_escalation_follows_policy_until_acknowledged():
    n = net.build_network()
    net.circuit_down(n, "TDG-IP-88123", NOW)
    net.circuit_down(n, "CVN-IP-40517", NOW)
    incs = correlate(n, NOW)
    esc = oncall.Escalator()
    assert [p["level"] for p in esc.sync(incs, NOW, 60)] == ["primary"]
    assert [p["level"] for p in esc.sync(incs, NOW + timedelta(minutes=6), 60)] == ["secondary"]
    esc.ack(incs[0]["id"], "someone", NOW + timedelta(minutes=7))
    assert esc.sync(incs, NOW + timedelta(minutes=20), 60) == []


def test_p3_is_not_paged_and_maintenance_is_not_paged():
    n = net.build_network()
    net.circuit_errors(n, "CVN-WAV-31045", NOW)
    esc = oncall.Escalator()
    assert esc.sync(correlate(n, NOW), NOW, 60) == []
    net.circuit_down(n, "TDG-IP-88123", NOW)
    incs = correlate(n, NOW, [{"id": "CHG-9", "devices": ["mx-edge-01.dc1"], "circuits": ["TDG-IP-88123"]}])
    assert esc.sync(incs, NOW, 60) == []


def test_rotation_is_weekly_and_four_eyes_friendly():
    r = oncall.rotation(NOW, 3)
    assert len({x["primary"] for x in r}) == 3 and all(x["primary"] != x["secondary"] for x in r)
    assert oncall.shift(datetime(2026, 10, 22, 23, 0, tzinfo=UTC))["name"] == "NOC Shift C"


def test_slack_announces_once_suppresses_maintenance_and_resolves():
    n = net.build_network()
    net.circuit_down(n, "TDG-IP-88123", NOW)
    sent = []
    s = SlackAlerter("https://hooks.example/x", post=sent.append)
    incs = correlate(n, NOW)
    assert [m["kind"] for m in s.sync(incs, "Mara", NOW)] == ["new"]
    assert s.sync(incs, "Mara", NOW) == []
    net.restore_all(n, NOW)
    assert [m["kind"] for m in s.sync(correlate(n, NOW), "Mara", NOW + timedelta(minutes=9))] == ["resolved"]
    net.circuit_down(n, "CVN-IP-40517", NOW)
    out = s.sync(correlate(n, NOW, [{"id": "CHG-2", "devices": ["mx-edge-02.dc2"], "circuits": ["CVN-IP-40517"]}]), "Mara", NOW)
    assert out[0]["status"] == "suppressed" and len(sent) == 2


# ---------------------------------------------------------------- BGP traffic engineering
def test_prepend_moves_inbound_traffic_and_is_reversible():
    n = net.build_network()
    cm = ChangeManager()
    c = cm.create(n, "bgp_te", {"device": "mx-edge-01.dc1", "peer": "192.0.2.1", "action": "prepend", "value": 2}, "a", NOW)
    assert 'as-path-prepend "64510 64510"' in c["mop"]["diff"]["mx-edge-01.dc1"]
    assert "TDG-IP-88123 43.2 → 11.9 Gbps" in c["mop"]["impact"]
    cm.approve(c["id"], "b", NOW)
    cm.implement(n, c["id"], "a", NOW)
    net.derive(n, NOW)
    split = net.transit_split(n)
    assert split["TDG-IP-88123"]["in_gbps"] < 15 < split["CVN-IP-40517"]["in_gbps"]
    assert split["TDG-IP-88123"]["out_gbps"] == split["CVN-IP-40517"]["out_gbps"]          # outbound untouched
    assert "64510 64510 I" in Cli(n, NOW).run("mx-edge-01.dc1", "show route advertising-protocol bgp 192.0.2.1")
    cm.rollback(n, c["id"], "a", NOW)
    net.derive(n, NOW)
    assert net.transit_split(n)["TDG-IP-88123"]["in_gbps"] == 43.2


def test_local_preference_moves_outbound_traffic_everywhere():
    n = net.build_network()
    cm = ChangeManager()
    c = cm.create(n, "bgp_te", {"device": "mx-edge-02.dc2", "peer": "198.51.100.1", "action": "local_pref", "value": 200}, "a", NOW)
    cm.approve(c["id"], "b", NOW)
    cm.implement(n, c["id"], "a", NOW)
    net.derive(n, NOW)
    split = net.transit_split(n)
    assert split["TDG-IP-88123"]["out_gbps"] == 0 and split["CVN-IP-40517"]["out_gbps"] == 36.0
    route = Cli(n, NOW).run("mx-edge-01.dc1", "show route 192.0.2.128/25")
    active = next(ln for ln in route.splitlines() if ln.startswith("192.0.2.128/25"))
    assert "*[BGP/170]" in active and "localpref 200" in active


def test_te_validation_and_warnings():
    n = net.build_network()
    cm = ChangeManager()
    with pytest.raises(ValueError):
        cm.create(n, "bgp_te", {"device": "mx-edge-01.dc1", "peer": "203.0.113.1", "action": "prepend", "value": 2}, "a", NOW)  # IX
    with pytest.raises(ValueError):
        cm.create(n, "bgp_te", {"device": "mx-edge-01.dc1", "peer": "192.0.2.1", "action": "prepend", "value": 0}, "a", NOW)  # no-op
    c = cm.create(n, "bgp_te", {"device": "mx-edge-01.dc1", "peer": "192.0.2.1", "action": "prepend", "value": 5}, "a", NOW)
    assert c["mop"]["warnings"] and "CVN-IP-40517" in c["mop"]["warnings"][0]
