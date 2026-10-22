"""Configuration and hardware audits.

Golden-config rules run against each device's `show configuration | display set`. Each failure comes with
the exact Junos lines that fix it, so a compliance-fix MOP can be generated in one click.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .models import Device, Network
from .network import APPROVED_VERSION

NTP = ["10.250.0.11", "10.250.0.12"]
BANNER = 'set system login message "Authorised access only. All activity is logged and monitored."'


@dataclass
class Rule:
    id: str
    title: str
    severity: str                   # high | medium | low
    check: Callable[[Device], tuple[bool, str, list[str], list[str]]]   # ok, detail, fix lines, fix operational cmds


def _has(d: Device, prefix: str) -> list[str]:
    return [x for x in d.config if x == prefix or x.startswith(prefix + " ")]


def r_root_ssh(d):
    ok = bool(_has(d, "set system services ssh root-login deny"))
    return ok, "root-login deny" if ok else "root may log in over SSH", [] if ok else ["set system services ssh root-login deny"], []


def r_telnet(d):
    bad = _has(d, "set system services telnet")
    return not bad, "telnet disabled" if not bad else "telnet is enabled (clear-text logins)", \
        ["delete system services telnet"] if bad else [], []


def r_snmp(d):
    bad = _has(d, "set snmp community")
    names = sorted({x.split()[3] for x in bad})
    return not bad, "SNMPv3 only" if not bad else f"SNMPv1/v2c community configured: {', '.join(names)}", \
        [f"delete snmp community {n}" for n in names], []


def r_ntp(d):
    have = [x.split()[-1] for x in _has(d, "set system ntp server")]
    missing = [s for s in NTP if s not in have]
    return not missing, f"{len(have)} NTP servers" if not missing else f"only {len(have)} NTP server(s), missing {', '.join(missing)}", \
        [f"set system ntp server {s}" for s in missing], []


def r_syslog(d):
    ok = bool(_has(d, "set system syslog host"))
    return ok, "remote syslog configured" if ok else "no remote syslog host", \
        [] if ok else ["set system syslog host 10.250.0.20 any notice"], []


def r_banner(d):
    ok = bool(_has(d, "set system login message"))
    return ok, "login banner present" if ok else "no login banner", [] if ok else [BANNER], []


def r_aaa(d):
    ok = bool(_has(d, "set system tacplus-server")) and "set system authentication-order tacplus" in d.config
    return ok, "TACACS+ first in authentication order" if ok else "local accounts only (no TACACS+)", \
        [] if ok else ["set system authentication-order tacplus", "set system authentication-order password"], []


def r_lldp(d):
    ok = "set protocols lldp interface all" in d.config
    return ok, "LLDP on all interfaces" if ok else "LLDP disabled", [] if ok else ["set protocols lldp interface all"], []


def r_bgp_auth(d):
    groups = sorted({p.group for p in d.bgp if p.kind == "external"})
    missing = [g for g in groups if not _has(d, f"set protocols bgp group {g} authentication-key")]
    if not groups:
        return True, "no eBGP sessions", [], []
    return not missing, "all eBGP groups use MD5 authentication" if not missing else \
        f"no authentication-key on {', '.join(missing)}", \
        [f'set protocols bgp group {g} authentication-key "<agree with the peer>"' for g in missing], []


def r_version(d):
    target = APPROVED_VERSION[d.family]
    ok = d.version == target
    return ok, f"Junos {d.version}" if ok else f"Junos {d.version}, approved release is {target} (use the upgrade MOP)", [], []


def r_rescue(d):
    return d.rescue_saved, "rescue configuration saved" if d.rescue_saved else "no rescue configuration", [], \
        [] if d.rescue_saved else ["request system configuration rescue save"]


def r_descriptions(d):
    missing = [i.name for i in d.interfaces.values() if i.admin_up and i.oper_up and not i.description]
    return not missing, "every active interface has a description" if not missing else \
        f"no description on {', '.join(missing)}", \
        [f'set interfaces {n} description "<far end | CID>"' for n in missing], []


RULES = [Rule("SEC-01", "SSH root login denied", "high", r_root_ssh),
         Rule("SEC-02", "Telnet disabled", "high", r_telnet),
         Rule("SEC-03", "SNMPv3 only, no community strings", "high", r_snmp),
         Rule("SEC-04", "TACACS+ authentication", "medium", r_aaa),
         Rule("SEC-05", "eBGP sessions authenticated", "medium", r_bgp_auth),
         Rule("SEC-06", "Login banner", "low", r_banner),
         Rule("OPS-01", "Two NTP servers", "medium", r_ntp),
         Rule("OPS-02", "Remote syslog", "medium", r_syslog),
         Rule("OPS-03", "LLDP enabled", "low", r_lldp),
         Rule("OPS-04", "Rescue configuration saved", "medium", r_rescue),
         Rule("OPS-05", "Interface descriptions", "low", r_descriptions),
         Rule("SW-01", "Approved Junos release", "medium", r_version)]


def audit_device(d: Device) -> dict:
    results = []
    for r in RULES:
        ok, detail, lines, ops = r.check(d)
        results.append({"id": r.id, "title": r.title, "severity": r.severity, "ok": ok, "detail": detail,
                        "fix": lines, "ops": ops})
    passed = sum(x["ok"] for x in results)
    fixable = [ln for x in results if not x["ok"] for ln in x["fix"] if "<" not in ln]
    ops = [o for x in results if not x["ok"] for o in x["ops"]]
    return {"device": d.hostname, "score": round(100 * passed / len(results)), "passed": passed, "total": len(results),
            "results": results, "auto_fix": {"lines": fixable, "ops": ops}}


def audit(net: Network) -> dict:
    devices = [audit_device(d) for d in net.devices.values()]
    total = sum(x["total"] for x in devices)
    return {"rules": [{"id": r.id, "title": r.title, "severity": r.severity} for r in RULES], "devices": devices,
            "score": round(100 * sum(x["passed"] for x in devices) / total) if total else 100}


def hardware(net: Network) -> list[dict]:
    out = []
    for d in net.devices.values():
        out.append({"device": d.hostname, "model": d.model, "site": d.site, "serial": d.serial, "cmdb_serial": d.cmdb_serial,
                    "serial_match": d.serial == d.cmdb_serial, "version": d.version,
                    "approved": d.version == APPROVED_VERSION[d.family],
                    "frus": [{"item": f.item, "part": f.part, "serial": f.serial, "description": f.description, "ok": f.ok,
                              "kind": f.kind} for f in d.frus],
                    "failed": [f.item for f in d.frus if not f.ok],
                    "optics": sum(f.kind == "xcvr" for f in d.frus)})
    return out
