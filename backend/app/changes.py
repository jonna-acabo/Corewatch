"""Change control: MOP generation, Junos-style `show | compare`, commit confirmed and rollback.

A change (CHG) moves through:  draft -> approved -> in_progress (commit confirmed, 5 min timer)
-> implemented (maintenance window open, alerts suppressed) -> closed, or -> rolled_back.
"""

from __future__ import annotations

import shlex
from datetime import UTC, datetime, timedelta

from .models import Commit, Network

VALUE_KW = {"description", "peer-as", "metric", "message", "address", "host-name", "local-address", "cluster", "import",
            "export", "authentication-key", "secret", "encrypted-password", "type", "interface-type", "router-id",
            "autonomous-system", "version", "server", "authorization", "any", "protocol-version", "root-login",
            "authentication-order", "group", "neighbor", "community", "user", "host", "local-preference", "as-path-prepend"}
SINGLE_VALUE = {"description", "peer-as", "metric", "message", "local-address", "authentication-key", "router-id",
                "autonomous-system", "version", "host-name", "cluster", "root-login", "authorization", "local-preference",
                "as-path-prepend"}
CONFIRM_MINUTES = 5
OUR_PREFIX_HINT = "198.18.0.0/15"
SHORT = {"transit_drain": "drain", "cost_out": "OSPF cost-out", "junos_upgrade": "Junos upgrade", "compliance_fix": "golden-config fix",
         "bgp_te": "BGP TE"}


def _tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, posix=False)
    except ValueError:
        return line.split()


def _split(path: list[str]) -> tuple[str, str]:
    """Parent hierarchy and leaf statement, e.g. ['system','ntp','server','10.1.1.1'] -> ('system ntp', 'server 10.1.1.1')."""
    if len(path) >= 2 and path[-2] in VALUE_KW:
        return " ".join(path[:-2]), " ".join(path[-2:])
    return " ".join(path[:-1]), path[-1]


def compare(old: list[str], new: list[str]) -> str:
    """Render the difference between two set-format configs the way `show | compare` does."""
    removed = [ln for ln in old if ln not in new]
    added = [ln for ln in new if ln not in old]
    blocks: dict[str, list[str]] = {}
    for sign, lines in (("-", removed), ("+", added)):
        for ln in lines:
            t = _tokens(ln)
            verb, path = t[0], t[1:]
            if verb == "deactivate":
                parent, leaf = _split(path)
                text = f"!    inactive: {leaf} {{ ... }}" if sign == "+" else f"!    active: {leaf} {{ ... }}"
                blocks.setdefault(parent, []).append(text)
                continue
            parent, leaf = _split(path)
            blocks.setdefault(parent, []).append(f"{sign}    {leaf};")
    return "\n".join(f"[edit {p}]\n" + "\n".join(v) for p, v in blocks.items()) or "(no changes)"


def apply_lines(config: list[str], lines: list[str]) -> list[str]:
    out = list(config)
    for ln in lines:
        t = _tokens(ln)
        if not t:
            continue
        verb, rest = t[0], " ".join(t[1:])
        if verb == "set":
            parent, leaf = _split(t[1:])
            kw = leaf.split()[0]
            if kw in SINGLE_VALUE and len(leaf.split()) > 1:
                prefix = f"set {parent} {kw} "
                out = [x for x in out if not x.startswith(prefix)]
            if ln not in out:
                out.append(ln)
        elif verb == "delete":
            out = [x for x in out if x != f"set {rest}" and not x.startswith(f"set {rest} ")]
        elif verb == "deactivate":
            if f"deactivate {rest}" not in out:
                out.append(f"deactivate {rest}")
        elif verb == "activate":
            out = [x for x in out if x != f"deactivate {rest}"]
    return out


def sync_from_config(net: Network, host: str) -> None:
    """Push config state (disabled interfaces, deactivated peers, OSPF metrics, descriptions) into the live model."""
    d = net.devices[host]
    cfg = set(d.config)
    for i in d.interfaces.values():
        i.admin_up = f"set interfaces {i.name} disable" not in cfg
        desc = next((x for x in d.config if x.startswith(f"set interfaces {i.name} description ")), None)
        i.description = desc.split(" description ", 1)[1].strip('"') if desc else ""
    for p in d.bgp:
        p.admin_down = (f"deactivate protocols bgp group {p.group} neighbor {p.peer_ip}" in cfg
                        or f"deactivate protocols bgp group {p.group}" in cfg)
        if p.kind == "external":
            p.auth = any(x.startswith(f"set protocols bgp group {p.group} authentication-key") for x in cfg)
    for lk in net.links:
        if lk.b:
            lk.costed_out = any(f"set protocols ospf area 0.0.0.0 interface {i}.0 metric 65535" in net.devices[h].config
                                for h, i in lk.ends())
    if d.version and any(x.startswith("set version ") for x in d.config):
        d.config = [x for x in d.config if not x.startswith("set version ")]
        d.config.insert(0, f"set version {d.version}")


# ------------------------------------------------------------------ MOP templates
TEMPLATES = {
    "transit_drain": {"title": "Drain an IP transit / IX session for carrier maintenance", "needs": ["device", "peer"]},
    "bgp_te": {"title": "BGP traffic engineering on an IP transit (prepend / local-preference)",
               "needs": ["device", "peer", "action", "value"]},
    "cost_out": {"title": "Cost out a core link (OSPF metric 65535) before maintenance", "needs": ["device", "interface"]},
    "junos_upgrade": {"title": "Upgrade Junos to the approved release", "needs": ["device"]},
    "compliance_fix": {"title": "Bring a device back to the golden configuration", "needs": ["device"]},
}


def _bgp_peer(net: Network, host: str, peer_ip: str):
    d = net.devices[host]
    p = next((p for p in d.bgp if p.peer_ip == peer_ip and p.kind == "external"), None)
    if not p:
        raise ValueError(f"{peer_ip} is not an eBGP neighbour on {host}")
    return d, p


def build_mop(net: Network, template: str, params: dict, chg_id: str, audit_fix: dict | None = None) -> dict:
    """Return the full method of procedure: impact, pre-checks, config lines per device, commit, post-checks, rollback."""
    if template not in TEMPLATES:
        raise ValueError("Unknown template")
    host = params.get("device", "")
    if host not in net.devices:
        raise ValueError("Unknown device")
    d = net.devices[host]
    lines: dict[str, list[str]] = {}
    restore: dict[str, list[str]] = {}
    ops: dict[str, list[str]] = {}
    pre: list[tuple[str, str]] = []
    post: list[tuple[str, str]] = []
    circuits: list[str] = []
    risk, impact, warnings = "Low", "", []

    if template == "transit_drain":
        d, p = _bgp_peer(net, host, params.get("peer", ""))
        lk = net.link_of(host, p.interface)
        circuits = [lk.circuit] if lk and lk.circuit else []
        service = net.circuits[lk.circuit].service if circuits else "IP Transit"
        others = [c for c in net.circuits.values() if c.service == service and c.id not in circuits and net.iface(*c.a_end).oper_up]
        lines[host] = [f"deactivate protocols bgp group {p.group} neighbor {p.peer_ip}"]
        restore[host] = [f"activate protocols bgp group {p.group} neighbor {p.peer_ip}"]
        cur = net.iface(host, p.interface)
        pre = [(host, f"show bgp summary | match {p.peer_ip}"), (host, f"show route receive-protocol bgp {p.peer_ip} | count"),
               (host, f"show interfaces {p.interface} | match rate")]
        for o in others:
            pre.append((o.a_end[0], f"show interfaces {o.a_end[1]} | match rate"))
            oi = net.iface(*o.a_end)
            after = round(oi.util_pct + cur.util_pct * cur.speed_gbps / oi.speed_gbps / max(1, len(others)), 1)
            if after >= 85:
                warnings.append(f"{o.id} would run at about {after}% after the drain (now {oi.util_pct}%). "
                                "Schedule outside peak hours.")
                risk = "High"
        post = [(host, f"show bgp summary | match {p.peer_ip}"), (host, "show route summary")] + \
               [(o.a_end[0], f"show interfaces {o.a_end[1]} | match rate") for o in others]
        impact = (f"Traffic on {p.description} moves to " + (", ".join(o.id for o in others) or "nothing (NO other path!)")
                  + ". No customer impact expected if the remaining path has headroom.")
        risk = risk if others else "High"
        if not others:
            warnings.append("There is no other path for this traffic. Do not drain without a plan.")
        risk = "Medium" if risk == "Low" else risk
    elif template == "bgp_te":
        from .network import TEST_ROUTE, te_policy, transit_split
        d, p = _bgp_peer(net, host, params.get("peer", ""))
        if not p.group.startswith("TRANSIT"):
            raise ValueError("Traffic engineering applies to IP transit sessions")
        action = params.get("action", "prepend")
        if action not in {"prepend", "local_pref"}:
            raise ValueError("action must be prepend or local_pref")
        try:
            value = int(params.get("value", 2 if action == "prepend" else 200))
        except (TypeError, ValueError) as e:
            raise ValueError("value must be a number") from e
        if action == "prepend" and not 0 <= value <= 5:
            raise ValueError("Prepend between 0 and 5 times (more is rarely useful and some networks filter it)")
        if action == "local_pref" and not 1 <= value <= 1000:
            raise ValueError("local-preference between 1 and 1000")
        params["value"] = value
        cur_prepend, cur_lp = te_policy(d, p.group)
        if (action == "prepend" and value == cur_prepend) or (action == "local_pref" and value == cur_lp):
            raise ValueError(f"No change: {p.group} already has that setting")
        g = p.group
        if action == "prepend":
            path = " ".join([str(net.asn)] * value)
            lines[host] = ([f'set policy-options policy-statement {g}-OUT term ADVERTISE then as-path-prepend "{path}"'] if value
                           else [f"delete policy-options policy-statement {g}-OUT term ADVERTISE then as-path-prepend"])
        else:
            lines[host] = [f"set policy-options policy-statement {g}-IN term ACCEPT then local-preference {value}"]
        restore[host] = []
        lk = net.link_of(host, p.interface)
        circuits = [lk.circuit] if lk and lk.circuit else []
        before, after = transit_split(net), transit_split(net, (host, p.peer_ip, action, value))
        direction = "in" if action == "prepend" else "out"
        moves = []
        for cid, b in before.items():
            a = after.get(cid, b)
            moves.append(f"{cid} {b[direction + '_gbps']} → {a[direction + '_gbps']} Gbps")
            if a[direction + "_util"] >= 85:
                warnings.append(f"{cid} would carry {a[direction + '_gbps']} Gbps {'inbound' if direction == 'in' else 'outbound'} "
                                f"({a[direction + '_util']}% of {a['speed']}G). Check headroom before going ahead.")
        what = (f"AS-path prepend x{value} towards {p.description.split(' ')[0]} {p.description.split(' ')[1]} makes our "
                f"{OUR_PREFIX_HINT} look longer through this transit, so the internet sends more inbound traffic via the other one"
                if action == "prepend" and value else
                "Removes the AS-path prepend, so inbound traffic balances again" if action == "prepend" else
                f"local-preference {value} on routes from {p.description.split(' ')[0]} {p.description.split(' ')[1]}: every router in "
                f"AS{net.asn} {'prefers' if value > 100 else 'avoids'} this exit for outbound traffic")
        impact = f"{what}. Predicted {'inbound' if direction == 'in' else 'outbound'}: " + "; ".join(moves) + "."
        others = [x for x in before.values() if x["host"] != host]
        pre = [(host, f"show route advertising-protocol bgp {p.peer_ip}"), (host, f"show route {TEST_ROUTE}"),
               (host, f"show interfaces {p.interface} | match rate")] + \
              [(x["host"], f"show interfaces {x['interface']} | match rate") for x in others]
        post = [(host, f"show configuration policy-options policy-statement {g}-{'OUT' if action == 'prepend' else 'IN'}"),
                (host, f"show route advertising-protocol bgp {p.peer_ip}"), (host, f"show route {TEST_ROUTE}")] + \
               [(x["host"], f"show interfaces {x['interface']} | match rate") for x in before.values()]
        risk = "High" if any("would carry" in w and float(w.split("(")[1].split("%")[0]) >= 95 for w in warnings) else "Medium"
    elif template == "cost_out":
        ifn = params.get("interface", "")
        lk = net.link_of(host, ifn)
        if not lk or not lk.b:
            raise ValueError("Pick an internal link (both ends on our devices)")
        circuits = [lk.circuit] if lk.circuit else []
        for h, i in lk.ends():
            lines[h] = [f"set protocols ospf area 0.0.0.0 interface {i}.0 metric 65535"]
            restore[h] = [f"delete protocols ospf area 0.0.0.0 interface {i}.0 metric 65535"]
            pre += [(h, "show ospf neighbor"), (h, f"show interfaces {i} | match rate")]
            post += [(h, f"show ospf interface {i}.0 detail | match Cost"), (h, f"show interfaces {i} | match rate")]
        impact = "Traffic leaves this link and takes the next best OSPF path; the adjacency stays up so it can return instantly."
        risk = "Low"
    elif template == "junos_upgrade":
        from .network import APPROVED_VERSION
        target = APPROVED_VERSION[d.family]
        if d.version == target:
            raise ValueError(f"{host} already runs the approved release {target}")
        image = f"/var/tmp/junos-{d.family}-x86-64-{target}.tgz"
        pre = [(host, "show version"), (host, "show system storage"), (host, "show chassis alarms"), (host, "show bgp summary"),
               (host, "show ospf neighbor")]
        ops[host] = ["request system configuration rescue save", "request system snapshot",
                     f"file checksum sha-256 {image}", f"request system software add {image} reboot"]
        post = [(host, "show version"), (host, "show chassis alarms"), (host, "show bgp summary"), (host, "show ospf neighbor")]
        restore[host] = []
        params["target"] = target
        impact = (f"{host} reboots (about 15-20 minutes). Traffic moves to the redundant device while it is down. "
                  f"Upgrade {d.version} -> {target}.")
        risk = "High" if d.role in {"core", "edge"} else "Medium"
        rollback_ops = ["request system software rollback reboot"]
    else:  # compliance_fix
        fix = audit_fix or {"lines": [], "ops": []}
        if not fix["lines"] and not fix["ops"]:
            raise ValueError(f"{host} already matches the golden configuration")
        lines[host] = fix["lines"]
        if fix["ops"]:
            ops[host] = fix["ops"]
        pre = [(host, "show configuration | display set | match \"telnet|community|ntp|message|authentication-key\""),
               (host, "show system commit")]
        post = [(host, "show configuration | compare rollback 1"), (host, "show system alarms")]
        impact = "Management-plane hardening only. No traffic impact."
        risk = "Low"

    diffs = {h: compare(net.devices[h].config, apply_lines(net.devices[h].config, ls)) for h, ls in lines.items()}
    procedure = []
    for h, ls in lines.items():
        commit_cmt = f'{chg_id} {SHORT[template]} {h.split(".")[0]}'
        procedure.append({"device": h, "steps": ["configure exclusive", *ls, "show | compare", "commit check",
                                                 f'commit confirmed {CONFIRM_MINUTES} comment "{commit_cmt}"',
                                                 "# run the post-checks, then within 5 minutes:",
                                                 f'commit comment "{chg_id} confirmed"', "exit"]})
    for h, o in ops.items():
        procedure.append({"device": h, "steps": o})
    rollback = []
    for h in lines:
        rollback.append({"device": h, "steps": ["configure exclusive", "rollback 1", "show | compare",
                                                f'commit comment "{chg_id} rollback"', "exit"]})
    if template == "junos_upgrade":
        rollback.append({"device": host, "steps": rollback_ops})
    return {"template": template, "title": TEMPLATES[template]["title"], "params": params, "risk": risk, "impact": impact,
            "warnings": warnings, "devices": sorted(set(lines) | set(ops) | {host}), "circuits": circuits,
            "pre_checks": [{"device": h, "cmd": c} for h, c in pre], "lines": lines, "ops": ops, "diff": diffs,
            "procedure": procedure, "post_checks": [{"device": h, "cmd": c} for h, c in post],
            "rollback": rollback, "restore": restore}


class ChangeManager:
    def __init__(self):
        self.changes: dict[str, dict] = {}
        self.next_id = 1001
        self.backups: dict[str, dict[str, list[str]]] = {}

    def active(self) -> list[dict]:
        """Changes with an open maintenance window (used to suppress alerts)."""
        return [{"id": c["id"], "devices": c["mop"]["devices"], "circuits": c["mop"]["circuits"]}
                for c in self.changes.values() if c["status"] in {"in_progress", "implemented"}]

    def _log(self, c: dict, now: datetime, text: str) -> None:
        c["history"].append({"at": now.isoformat(), "text": text})

    def create(self, net: Network, template: str, params: dict, requester: str, now: datetime, audit_fix=None) -> dict:
        cid = f"CHG-{self.next_id}"
        mop = build_mop(net, template, dict(params), cid, audit_fix)
        self.next_id += 1
        c = {"id": cid, "title": mop["title"] + f": {params.get('device', '')}", "template": template, "status": "draft",
             "requested_by": requester, "approved_by": None, "created_at": now.isoformat(), "mop": mop, "history": [],
             "confirm_by": None}
        self._log(c, now, f"Draft created by {requester}")
        self.changes[cid] = c
        return c

    def approve(self, cid: str, approver: str, now: datetime) -> dict:
        c = self.changes[cid]
        if c["status"] != "draft":
            raise ValueError(f"{cid} is {c['status']}, only drafts can be approved")
        if approver == c["requested_by"]:
            raise ValueError("Four-eyes rule: the requester cannot approve their own change")
        c["status"], c["approved_by"] = "approved", approver
        self._log(c, now, f"Approved by {approver}")
        return c

    def implement(self, net: Network, cid: str, user: str, now: datetime) -> dict:
        c = self.changes[cid]
        if c["status"] != "approved":
            raise ValueError(f"{cid} must be approved first (now {c['status']})")
        mop = c["mop"]
        self.backups[cid] = {h: list(net.devices[h].config) for h in mop["devices"]}
        for h, ls in mop["lines"].items():
            d = net.devices[h]
            d.prev_config = list(d.config)
            d.config = apply_lines(d.config, ls)
            self._commit(d, now, user, f'{cid} {SHORT[c["template"]]} {h.split(".")[0]} (commit confirmed {CONFIRM_MINUTES})', cid)
            sync_from_config(net, h)
        for h, o in mop["ops"].items():
            d = net.devices[h]
            for cmd in o:
                d.syslog(now, f"mgd[8812]: UI_CMDLINE_READ_LINE: User '{user}', command '{cmd}'")
                if cmd == "request system configuration rescue save":
                    d.rescue_saved = True
                if cmd.startswith("request system software add"):
                    c["old_version"] = d.version
                    d.version, d.uptime_days = mop["params"]["target"], 0
                    d.syslog(now, f"init: Junos {d.version} booted after software upgrade")
            sync_from_config(net, h)
        c["status"] = "in_progress" if mop["lines"] else "implemented"
        c["confirm_by"] = (now + timedelta(minutes=CONFIRM_MINUTES)).isoformat() if mop["lines"] else None
        self._log(c, now, f"Implemented by {user}" + (f"; commit confirmed, auto-rollback at "
                                                         f"{(now + timedelta(minutes=CONFIRM_MINUTES)):%H:%M:%S} UTC unless confirmed"
                                                         if mop["lines"] else ""))
        return c

    def confirm(self, net: Network, cid: str, user: str, now: datetime) -> dict:
        c = self.changes[cid]
        if c["status"] != "in_progress":
            raise ValueError(f"{cid} has no pending commit confirmed")
        for h in c["mop"]["lines"]:
            self._commit(net.devices[h], now, user, f"{cid} confirmed", cid)
        c["status"], c["confirm_by"] = "implemented", None
        self._log(c, now, f"Commit confirmed by {user}; maintenance window open, alerts on these devices are suppressed")
        return c

    def rollback(self, net: Network, cid: str, user: str, now: datetime, reason: str = "manual") -> dict:
        c = self.changes[cid]
        if c["status"] not in {"in_progress", "implemented"}:
            raise ValueError(f"{cid} is {c['status']}, nothing to roll back")
        for h, cfg in self.backups.get(cid, {}).items():
            d = net.devices[h]
            if h in c["mop"]["lines"]:
                d.prev_config, d.config = d.config, list(cfg)
                self._commit(d, now, user, f"{cid} rollback ({reason})", cid)
            if c.get("old_version") and h == c["mop"]["params"]["device"]:
                d.version = c["old_version"]
            sync_from_config(net, h)
        c["status"], c["confirm_by"] = "rolled_back", None
        self._log(c, now, "Automatic rollback: commit was not confirmed within 5 minutes" if reason == "auto"
                  else f"Rolled back by {user}")
        return c

    def close(self, net: Network, cid: str, user: str, now: datetime) -> dict:
        c = self.changes[cid]
        if c["status"] != "implemented":
            raise ValueError(f"{cid} must be implemented before it can be closed")
        for h, ls in c["mop"]["restore"].items():
            if ls:
                d = net.devices[h]
                d.prev_config = list(d.config)
                d.config = apply_lines(d.config, ls)
                self._commit(d, now, user, f"{cid} restore after maintenance", cid)
                sync_from_config(net, h)
        c["status"] = "closed"
        self._log(c, now, f"Closed by {user}; maintenance window ended" +
                  ("; restore lines applied" if any(c["mop"]["restore"].values()) else ""))
        return c

    def expire(self, net: Network, now: datetime) -> list[str]:
        """Junos behaviour: an unconfirmed `commit confirmed` rolls itself back."""
        out = []
        for c in list(self.changes.values()):
            if c["status"] == "in_progress" and c["confirm_by"] and now >= datetime.fromisoformat(c["confirm_by"]):
                self.rollback(net, c["id"], "system", now, reason="auto")
                out.append(f"{c['id']} not confirmed in time: automatic rollback")
        return out

    @staticmethod
    def _commit(d, now: datetime, user: str, comment: str, cid: str) -> None:
        for cm in d.commits:
            cm.rev += 1
        d.commits.insert(0, Commit(0, now, user, "netconf", comment, cid))
        d.commits = d.commits[:50]
        d.syslog(now, f"mgd[8812]: UI_COMMIT: User '{user}' requested 'commit' operation (comment: {comment})")


def utcnow() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)
