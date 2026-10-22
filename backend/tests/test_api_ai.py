import json

from fastapi.testclient import TestClient

from app.ai import AnthropicAnalyst, FallbackAnalyst, MockAnalyst
from app.main import State, create_app


def client():
    return TestClient(create_app(State(seed=7), analyst=FallbackAnalyst(MockAnalyst(), MockAnalyst()), simulate=False))


def test_summary_and_incidents():
    with client() as c:
        s = c.get("/api/summary").json()
        assert s["devices"] == 10 and s["incidents"] >= 5 and 0 < s["compliance"] < 100
        incs = c.get("/api/incidents").json()
        assert {i["kind"] for i in incs} >= {"psu_failed", "circuit_errors", "unauthorized_commit", "mgmt_down"}
        assert c.get("/api/incidents/INC-NOPE").status_code == 404


def test_incident_workflow_analysis_verify_tickets_ack():
    with client() as c:
        c.post("/api/simulate/transit_down")
        inc = next(i for i in c.get("/api/incidents").json() if i["kind"] == "circuit_down")
        a = c.post(f"/api/incidents/{inc['id']}/analyze").json()
        assert a["carrier_message"].startswith("Subject:") and a["provider"] == "mock"
        out = c.post(f"/api/incidents/{inc['id']}/verify").json()
        assert out and all(o["output"] for o in out)
        t = c.post(f"/api/incidents/{inc['id']}/carrier-ticket").json()
        assert t["reference"].startswith("TID-TT-")
        assert c.post(f"/api/incidents/{inc['id']}/carrier-ticket").status_code == 409
        assert c.post(f"/api/incidents/{inc['id']}/ticket", json={"title": a["ticket_title"], "body": "x"}).status_code == 201
        c.app.state.cw.sync_alerts()
        ack = c.post(f"/api/incidents/{inc['id']}/ack", json={}).json()
        assert ack["acked_by"]
        circ = {x["id"]: x for x in c.get("/api/circuits").json()["circuits"]}
        assert circ["TDG-IP-88123"]["state"] == "down" and circ["TDG-IP-88123"]["ticket"]


def test_cli_devices_topology_metrics():
    with client() as c:
        assert "Establ" in c.post("/api/cli", json={"device": "mx-edge-01.dc1", "command": "show bgp summary"}).json()["output"]
        assert len(c.get("/api/devices").json()) == 10
        d = c.get("/api/devices/mx-core-02.dc2").json()
        assert d["alarms"] and d["bgp"] and d["ospf"]
        topo = c.get("/api/topology").json()
        assert len(topo["clouds"]) == 3 and len(topo["links"]) == 15
        m = c.get("/metrics").text
        assert 'corewatch_bgp_peer_up{device="mx-edge-01.dc1",peer="192.0.2.1"' in m and "corewatch_compliance_score" in m


def test_change_api_and_audit_fix():
    with client() as c:
        tpl = c.get("/api/changes/templates").json()
        assert {t["id"] for t in tpl["templates"]} == {"transit_drain", "bgp_te", "cost_out", "junos_upgrade", "compliance_fix"}
        ch = c.post("/api/audit/qfx-leaf-02.dc2/fix", json={}).json()
        assert "snmp community" in ch["mop"]["diff"]["qfx-leaf-02.dc2"]
        assert c.post(f"/api/changes/{ch['id']}/implement", json={}).status_code == 409    # not approved
        assert c.post(f"/api/changes/{ch['id']}/approve", json={}).json()["status"] == "approved"
        assert c.post(f"/api/changes/{ch['id']}/implement", json={}).json()["status"] == "in_progress"
        assert c.post(f"/api/changes/{ch['id']}/confirm", json={}).json()["status"] == "implemented"
        a = {x["device"]: x for x in c.get("/api/audit").json()["devices"]}
        assert a["qfx-leaf-02.dc2"]["score"] == 100
        assert c.post("/api/changes", json={"template": "nope", "params": {"device": "x"}}).status_code == 400


def test_llm_output_is_validated_and_falls_back():
    good = {"summary": "s", "likely_cause": "c", "confidence": "high", "next_steps": ["a"], "ticket_title": "t",
            "ticket_body": "b", "carrier_message": "Not needed: x", "escalation_note": "e"}
    llm = AnthropicAnalyst("k", "m", transport=lambda p: {"content": [{"type": "text", "text": "ok " + json.dumps(good)}]})
    broken = AnthropicAnalyst("k", "m", transport=lambda p: {"content": [{"type": "text", "text": "{\"summary\": 1}"}]})
    with client() as c:
        inc = c.get(f"/api/incidents/{c.get('/api/incidents').json()[0]['id']}").json()
    assert FallbackAnalyst(llm, MockAnalyst()).analyze(inc)["provider"] == "anthropic"
    out = FallbackAnalyst(broken, MockAnalyst()).analyze(inc)
    assert out["provider"].startswith("mock (fallback") and out["summary"]


def test_simulate_validates_fault():
    with client() as c:
        assert c.post("/api/simulate/meteor").status_code == 400
        assert c.post("/api/simulate/restore").json()["event"] == "restore"
