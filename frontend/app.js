/* CoreWatch dashboard. Plain JS, no build step. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (h) => String(h || "").split(".")[0];
const ago = (iso) => {
  if (!iso) return "";
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  return m < 1 ? "just now" : m < 120 ? `${m} min ago` : m < 2880 ? `${Math.floor(m / 60)} h ago` : `${Math.floor(m / 1440)} d ago`;
};
const hhmm = (iso) => (iso ? new Date(iso).toISOString().slice(11, 19) : "");

async function api(path, opts = {}) {
  const r = await fetch(path, { headers: { "Content-Type": "application/json" }, ...opts,
    body: opts.body ? JSON.stringify(opts.body) : opts.method === "POST" ? "{}" : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `${r.status} ${r.statusText}`);
  return data;
}
const post = (path, body) => api(path, { method: "POST", body });

function toast(text, err = false) {
  const d = document.createElement("div");
  d.className = err ? "err" : "";
  d.textContent = text;
  $("#toast").appendChild(d);
  setTimeout(() => d.remove(), 4200);
}

const ui = {
  view: "overview", id: null, filter: "all", deviceTab: "interfaces", cli: {}, verify: {}, checks: {}, newChange: false,
  auditDevice: null, busy: false, cache: {},
};
const COLORS = ["#7c8cff", "#f472b6", "#34d399", "#f59e0b", "#60a5fa", "#a78bfa", "#fb7185", "#2dd4bf"];
const avatar = (name) => {
  const i = [...String(name)].reduce((a, c) => a + c.charCodeAt(0), 0) % COLORS.length;
  return `<span class="avatar" style="background:${COLORS[i]}">${esc(String(name).split(" ").map((x) => x[0]).join("").slice(0, 2))}</span>`;
};

/* ------------------------------------------------------------------ small renderers */
const sev = (s) => `<span class="sev ${s}">${s}</span>`;
const saTag = (i) => (i.service_affecting ? `<span class="tag sa">SA</span>` : `<span class="tag">NSA</span>`);
function spark(values, w = 90, h = 22, color = "var(--accent)") {
  const v = (values || []).filter((x) => x != null);
  if (v.length < 2) return `<svg class="spark" width="${w}" height="${h}"></svg>`;
  const max = Math.max(100, ...v);
  const pts = v.map((y, i) => `${((i / (v.length - 1)) * w).toFixed(1)},${(h - 2 - (y / max) * (h - 4)).toFixed(1)}`).join(" ");
  const last = v[v.length - 1];
  const c = last >= 85 ? "var(--warn)" : color;
  return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline points="${pts}" fill="none" stroke="${c}" stroke-width="1.6" stroke-linejoin="round"/></svg>`;
}
function term(device, cmd, out) {
  const err = /^error|Connection timed out/m.test(out || "");
  return `<div class="term"><span class="p">noc@${esc(short(device))}&gt;</span> <span class="c">${esc(cmd)}</span>\n${err ? `<span class="err">${esc(out)}</span>` : esc(out)}</div>`;
}
function diffHtml(text) {
  return `<div class="diff">${String(text || "").split("\n").map((l) => {
    const cls = l.startsWith("[edit") ? "hdr" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : l.startsWith("!") ? "ina" : "";
    return cls ? `<span class="${cls}">${esc(l)}</span>` : esc(l);
  }).join("\n")}</div>`;
}

/* ------------------------------------------------------------------ topology */
function topoSVG(t) {
  const pos = Object.fromEntries(t.devices.map((d) => [d.id, d]));
  const cl = Object.fromEntries(t.clouds.map((c) => [c.id, c]));
  const sites = `
    <rect class="site" x="16" y="100" width="336" height="370" rx="14"/><text class="site-l" x="32" y="122">DC1</text>
    <rect class="site" x="648" y="100" width="336" height="370" rx="14"/><text class="site-l" x="968" y="122" text-anchor="end">DC2</text>
    <rect class="site" x="362" y="392" width="276" height="76" rx="14"/><text class="site-l" x="500" y="488" text-anchor="middle">POPs</text>`;
  const links = t.links.map((l) => {
    const a = pos[l.a];
    const b = l.b ? pos[l.b] : cl[l.cloud];
    if (!a || !b) return "";
    const cls = l.state !== "up" ? l.state : l.costed_out ? "costed" : l.util >= 85 ? "hot" : "up";
    const w = l.speed >= 100 ? 3.2 : 2;
    const f = l.b && pos[l.b].role === "pop" ? (Math.abs(b.x - a.x) < 200 ? 0.27 : 0.6) : 0.5;
    const mx = a.x + (b.x - a.x) * f, my = a.y + (b.y - a.y) * f;
    const lbl = l.circuit ? `<rect class="lkl-bg" x="${mx - 42}" y="${my - 7}" width="84" height="13" rx="3"/>
      <text class="lkl" x="${mx}" y="${my + 3}" text-anchor="middle">${esc(l.circuit)}</text>` : "";
    return `<g><title>${esc(`${short(l.a)} ${l.a_if} ↔ ${l.b ? short(l.b) + " " + l.b_if : (cl[l.cloud] || {}).name}${l.circuit ? " · " + l.circuit : ""}\n${l.state.toUpperCase()} · ${l.util}% of ${l.speed}G${l.costed_out ? " · costed out" : ""}`)}</title>
      <line class="lk ${cls}" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke-width="${w}"/>${lbl}</g>`;
  }).join("");
  const clouds = t.clouds.map((c) => `<g class="cloud"><rect x="${c.x - 78}" y="${c.y - 20}" width="156" height="40" rx="20"/>
    <text x="${c.x}" y="${c.y - 2}" text-anchor="middle">${esc(c.name)}</text><text class="a" x="${c.x}" y="${c.y + 12}" text-anchor="middle">${c.asn ? "AS" + c.asn : ""}</text></g>`).join("");
  const nodes = t.devices.map((d) => {
    const cls = !d.powered ? "down" : d.alarms ? "alarm" : "";
    return `<g class="node ${cls} ${d.mgmt_ok ? "" : "mgmt"}" data-act="device" data-id="${esc(d.id)}">
      <title>${esc(d.id)} · ${esc(d.model)}${d.powered ? "" : " · DOWN"}${d.mgmt_ok ? "" : " · management unreachable"}${d.alarms ? ` · ${d.alarms} alarm(s)` : ""}</title>
      <rect x="${d.x - 62}" y="${d.y - 19}" width="124" height="38" rx="8"/>
      <circle cx="${d.x - 50}" cy="${d.y - 6}" r="3.5" fill="${!d.powered ? "var(--bad)" : d.alarms ? "var(--warn)" : "var(--ok)"}"/>
      <text class="h" x="${d.x - 42}" y="${d.y - 2}">${esc(short(d.id))}</text>
      <text class="m" x="${d.x - 42}" y="${d.y + 11}">${esc(d.model)} · ${esc(d.role)}</text></g>`;
  }).join("");
  return `<svg viewBox="0 0 1000 500" role="img" aria-label="Network topology">${sites}${links}${clouds}${nodes}</svg>`;
}
const legend = `<div class="legend"><span><i style="border-color:var(--ok)"></i>up</span><span><i style="border-color:var(--warn)"></i>errors / ≥85%</span>
  <span><i style="border-color:var(--bad);border-top-style:dashed"></i>down</span><span><i style="border-color:var(--info);border-top-style:dotted"></i>costed out</span></div>`;

/* ------------------------------------------------------------------ views */
async function viewOverview() {
  const [s, topo, incs, slack, events, circ] = await Promise.all([api("/api/summary"), api("/api/topology"), api("/api/incidents"),
    api("/api/slack"), api("/api/events"), api("/api/circuits")]);
  const pct = (a, b) => (b ? Math.round((100 * a) / b) : 100);
  const kpi = (l, v, tot, sub, cls) => `<div class="kpi ${cls || ""}"><div class="l">${l}</div><div class="v">${v}${tot != null ? `<small> / ${tot}</small>` : ""}</div>
    <div class="s">${sub}</div>${tot != null ? `<div class="bar"><i style="width:${pct(v, tot)}%;background:${v === tot ? "var(--ok)" : "var(--warn)"}"></i></div>` : ""}</div>`;
  const bySev = s.by_severity;
  const open = incs.filter((i) => !i.maintenance);
  return `
  <div class="kpis">
    ${kpi("Devices", s.devices_up, s.devices, `${s.mgmt_ok}/${s.devices} reachable on OOB`, s.devices_up < s.devices ? "bad" : "")}
    ${kpi("BGP sessions", s.bgp_up, s.bgp, "eBGP + iBGP established", s.bgp_up < s.bgp ? "warn" : "")}
    ${kpi("OSPF adjacencies", s.ospf_up, s.ospf, "area 0.0.0.0 Full", s.ospf_up < s.ospf ? "warn" : "")}
    ${kpi("Carrier circuits", s.circuits_up, s.circuits, "transit, IX, EPL, waves", s.circuits_up < s.circuits ? "bad" : "")}
    <div class="kpi ${bySev.P1 ? "bad" : bySev.P2 ? "warn" : ""}"><div class="l">Open incidents</div><div class="v">${s.incidents}</div>
      <div class="s row" style="gap:4px;margin-top:4px">${["P1", "P2", "P3", "P4"].map((k) => `${sev(k)}<span class="small">${bySev[k]}</span>`).join(" ")}</div></div>
    <div class="kpi"><div class="l">Noise reduction</div><div class="v">${s.symptoms}<small> alarms</small></div><div class="s">grouped into ${s.incidents} incident${s.incidents === 1 ? "" : "s"}</div></div>
    <div class="kpi ${s.compliance < 90 ? "warn" : "ok"}"><div class="l">Config compliance</div><div class="v">${s.compliance}<small>%</small></div>
      <div class="bar"><i style="width:${s.compliance}%"></i></div></div>
  </div>
  <div class="grid g-main">
    <div class="stack">
      <div class="card topo"><div class="hd"><h2>Topology</h2><span class="sub">AS${esc(String(64510))} · click a device for its CLI</span><div class="r">${legend}</div></div>
        <div class="bd">${topoSVG(topo)}</div></div>
      <div class="card"><div class="hd"><h2>Carrier circuits</h2><span class="sub">utilisation, last 30 polls</span><div class="r"><a href="#carriers" class="small">All circuits →</a></div></div>
        <div class="bd flush tbl-wrap"><table><tr><th></th><th>Circuit</th><th>Carrier</th><th>Service</th><th class="num">Util</th><th>Trend</th><th class="num">Rx dBm</th></tr>
        ${circ.circuits.map((c) => `<tr><td><span class="dot ${c.state}"></span></td><td class="mono">${esc(c.id)}</td><td>${esc(c.carrier)}</td>
          <td class="muted">${esc(c.service)} · ${c.bandwidth}G</td><td class="num">${c.util}%</td><td>${spark(c.history)}</td>
          <td class="num mono ${c.rx_dbm < -10 ? "" : "muted"}" style="${c.rx_dbm < -10 ? "color:var(--warn)" : ""}">${c.rx_dbm <= -40 ? "LOS" : c.rx_dbm}</td></tr>`).join("")}
        </table></div></div>
    </div>
    <div class="stack">
      <div class="card"><div class="hd"><h2>Active incidents</h2><span class="sub">${open.length} open${incs.length - open.length ? ` · ${incs.length - open.length} in maintenance` : ""}</span>
        <div class="r"><a href="#incidents" class="small">Triage →</a></div></div>
        <div class="bd flush inc-list">${incs.length ? incs.slice(0, 7).map(incRow).join("") : `<div class="empty">All quiet. No open incidents.</div>`}</div></div>
      <div class="card"><div class="hd"><h2>On-call now</h2><span class="sub">${esc(s.oncall.shift.name)} · ${esc(s.oncall.shift.hours)}</span><div class="r"><a href="#oncall" class="small">Rota →</a></div></div>
        <div class="bd">${person(s.oncall.primary, "Primary")}${person(s.oncall.secondary, "Secondary")}${person(s.oncall.tier3, "Tier 3 lead")}</div></div>
      <div class="card slack"><div class="hd"><h2>Slack ${esc(slack.channel)}</h2><span class="sub">${slack.mode === "mock" ? "mock mode" : "webhook"}</span></div>
        <div class="bd flush feed">${slack.messages.slice(0, 6).map((m) => `<div class="it"><div class="w">${hhmm(m.at)} · ${esc(m.kind)}</div>${slackText(m.text)}</div>`).join("") || `<div class="empty">No messages yet</div>`}</div></div>
      <div class="card"><div class="hd"><h2>Event log</h2></div>
        <div class="bd flush feed">${events.slice(0, 8).map((e) => `<div class="it"><span class="w">${hhmm(e.at)}</span> ${esc(e.text)}</div>`).join("") || `<div class="empty">No events</div>`}</div></div>
    </div>
  </div>`;
}
const person = (name, role) => `<div class="person">${avatar(name)}<div><div class="role">${esc(role)}</div><div>${esc(name)}</div></div></div>`;
function slackText(t) {
  return esc(t).replace(/:rotating_light:/g, "🚨").replace(/:red_circle:/g, "🔴").replace(/:large_orange_circle:/g, "🟠")
    .replace(/:large_blue_circle:/g, "🔵").replace(/:white_check_mark:/g, "✅").replace(/:pager:/g, "📟").replace(/:eyes:/g, "👀")
    .replace(/\*([^*]+)\*/g, "<b>$1</b>").replace(/&lt;[^|]+\|([^&]+)&gt;/g, '<span class="muted">$1</span>').replace(/\n/g, "<br>");
}
function incRow(i) {
  const sel = ui.view === "incidents" && ui.id === i.id ? "sel" : "";
  const oc = i.oncall || {};
  return `<div class="inc ${sel}" data-act="incident" data-id="${i.id}">${sev(i.severity)}<div class="t">${esc(i.title)}</div><div class="n">${ago(i.started_at)}</div>
    <div class="m">${saTag(i)}<span>${esc(i.owner)}</span>${i.maintenance ? `<span class="tag maint">${esc(i.maintenance)}</span>` : ""}
    <span class="mono">${i.symptoms} alarm${i.symptoms === 1 ? "" : "s"}</span>${oc.acked_by ? `<span class="tag ok">ack ${esc(oc.acked_by.split(" ")[0])}</span>` :
      oc.pages && oc.pages.length ? `<span class="tag warn">paged ${esc(oc.pages[oc.pages.length - 1].to.split(" ")[0])}</span>` : ""}</div></div>`;
}

/* ---- incidents */
async function viewIncidents() {
  const incs = await api("/api/incidents");
  if (!ui.id && incs.length) ui.id = incs[0].id;
  const shown = incs.filter((i) => ui.filter === "all" || i.severity === ui.filter || (ui.filter === "SA" && i.service_affecting));
  let detail = `<div class="card"><div class="empty">No open incidents. Use “Simulate fault” to create one.</div></div>`;
  if (ui.id && incs.some((i) => i.id === ui.id)) detail = await incidentDetail(await api(`/api/incidents/${ui.id}`));
  else if (ui.id) detail = `<div class="card"><div class="empty">This incident has cleared.</div></div>`;
  const f = (k, l) => `<button class="btn sm ${ui.filter === k ? "primary" : "ghost"}" data-act="filter" data-id="${k}">${l}</button>`;
  return `<div class="split"><div class="card"><div class="hd"><h2>Queue</h2><span class="sub">${incs.length}</span>
    <div class="r">${f("all", "All")}${f("SA", "SA")}${f("P1", "P1")}${f("P2", "P2")}${f("P3", "P3")}</div></div>
    <div class="bd flush inc-list">${shown.map(incRow).join("") || `<div class="empty">Nothing here</div>`}</div></div>${detail}</div>`;
}

async function incidentDetail(i) {
  const a = i.analysis;
  const oc = i.oncall || { pages: [] };
  const v = ui.verify[i.id];
  const sc = i.scope || {};
  const fact = (l, val) => `<div class="fact"><div class="l">${l}</div><div class="v">${val || "—"}</div></div>`;
  const pages = (oc.pages || []).map((p) => `${hhmm(p.at)} ${esc(p.level)}: ${esc(p.to)}`).join(" · ");
  return `<div class="stack">
  <div class="card"><div class="bd">
    <div class="detail-head">${sev(i.severity)}<div style="flex:1"><h1>${esc(i.title)}</h1>
      <div class="row small muted" style="margin-top:6px">${saTag(i)}<span class="mono">${esc(i.id)}</span><span>started ${ago(i.started_at)}</span>
      <span>·</span><span>${i.symptoms} raw alarm${i.symptoms === 1 ? "" : "s"} grouped</span>
      ${i.maintenance ? `<span class="tag maint">in maintenance ${esc(i.maintenance)} · not paged</span>` : ""}</div></div>
      <div class="row">${oc.acked_by ? `<span class="tag ok">acknowledged by ${esc(oc.acked_by)}</span>` :
        `<button class="btn" data-act="ack" data-id="${i.id}">Acknowledge</button>`}</div></div>
    <div class="facts">${fact("Owner", esc(i.owner))}${fact("Devices", i.devices.map((d) => `<a href="#devices/${esc(d)}">${esc(short(d))}</a>`).join(", "))}
      ${fact(sc.circuit ? "Circuit" : sc.peer ? "BGP peer" : "Site", esc(sc.circuit || sc.peer || sc.site))}
      ${fact("On-call", oc.acked_by ? "Acknowledged" : pages || (["P1", "P2"].includes(i.severity) ? (i.maintenance ? "Suppressed" : "Paging…") : "Queue only (P3/P4)"))}</div>
  </div></div>
  <div class="grid g-2">
    <div class="card"><div class="hd"><h2>Evidence</h2><span class="sub">why the engine grouped these alarms</span></div>
      <div class="bd"><ul class="ev">${i.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></div></div>
    <div class="card"><div class="hd"><h2>Recommended actions</h2></div>
      <div class="bd"><ol class="steps">${i.recommended_actions.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div></div>
  </div>
  <div class="card"><div class="hd"><h2>Verify on the devices</h2><span class="sub">read-only Junos commands</span>
    <div class="r"><button class="btn primary" data-act="verify" data-id="${i.id}">${v ? "Run again" : "Run checks"}</button></div></div>
    <div class="bd">${v ? v.map((x) => term(x.device, x.cmd, x.output)).join("") :
      i.verify.map((x) => `<div class="vcmd"><span class="d">${esc(short(x.device))}&gt;</span>${esc(x.cmd)}</div>`).join("")}</div></div>
  ${i.diff ? `<div class="card"><div class="hd"><h2>show | compare rollback 1</h2><span class="sub">what the unapproved commit changed</span></div><div class="bd">${diffHtml(i.diff)}</div></div>` : ""}
  <div class="card ai"><div class="hd"><h2>AI analysis</h2><span class="sub">${a ? `${esc(a.provider)} · ${ago(a.generated_at)}` : "summary, cause, ticket, carrier email, escalation note"}</span>
    <div class="r"><button class="btn primary" data-act="analyze" data-id="${i.id}">${a ? "Re-analyse" : "Analyse with AI"}</button></div></div>
    <div class="bd">${a ? aiBlock(i, a) : `<div class="muted">Click <b>Analyse with AI</b> to get a write-up built from the evidence above.</div>`}</div></div>
  </div>`;
}

function aiBlock(i, a) {
  const carrierNeeded = !String(a.carrier_message).startsWith("Not needed");
  return `<div class="stack" style="gap:14px">
    <div class="box"><h3>Summary</h3>${esc(a.summary)}</div>
    <div class="ai-grid">
      <div class="box"><h3>Likely cause <span class="conf ${a.confidence}">${esc(a.confidence)}</span></h3>${esc(a.likely_cause)}</div>
      <div class="box"><h3>Escalation note</h3>${esc(a.escalation_note)}</div>
    </div>
    <div class="box"><h3>Next steps</h3><ol class="steps">${a.next_steps.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
    <div class="ai-grid">
      <div class="box"><h3>NOC ticket</h3>
        ${i.ticket ? `<div class="row"><span class="tag ok">${esc(i.ticket.key)}</span><span>${esc(i.ticket.title)}</span></div>` :
        `<label class="f">Title<input id="t-title" value="${esc(a.ticket_title)}"></label>
         <label class="f" style="margin-top:8px">Body<textarea id="t-body" rows="8">${esc(a.ticket_body)}</textarea></label>
         <div class="row" style="margin-top:8px"><button class="btn primary" data-act="ticket" data-id="${i.id}">Open ticket</button></div>`}</div>
      <div class="box"><h3>Message to ${esc(i.carrier || "carrier")}</h3>
        ${carrierNeeded ? `<textarea rows="10" readonly>${esc(a.carrier_message)}</textarea>
          <div class="row" style="margin-top:8px">${i.carrier_ticket ? `<span class="tag ok">${esc(i.carrier_ticket.reference)}</span><span class="small muted">${esc(i.carrier_ticket.status)} to ${esc(i.carrier_ticket.to)}</span>` :
          `<button class="btn" data-act="carrier" data-id="${i.id}">Raise fault with carrier</button>`}</div>` : `<div class="muted">${esc(a.carrier_message)}</div>`}</div>
    </div></div>`;
}

/* ---- devices + CLI */
async function viewDevices() {
  const devs = await api("/api/devices");
  if (!ui.id) {
    return `<div class="card"><div class="hd"><h2>Inventory</h2><span class="sub">${devs.length} devices · click one for interfaces, protocols, chassis and the CLI</span></div>
    <div class="bd flush tbl-wrap"><table><tr><th></th><th>Device</th><th>Model</th><th>Site</th><th>Junos</th><th class="num">Interfaces</th><th class="num">BGP</th><th class="num">OSPF</th>
      <th class="num">RE CPU</th><th class="num">Temp</th><th class="num">Alarms</th><th class="num">Compliance</th></tr>
    ${devs.map((d) => `<tr class="click" data-act="device" data-id="${esc(d.hostname)}"><td><span class="dot ${!d.powered ? "down" : d.alarms ? "warn" : "up"}"></span></td>
      <td class="mono">${esc(d.hostname)}${d.mgmt_ok ? "" : ` <span class="tag bad">mgmt down</span>`}</td><td>${esc(d.model)}</td><td class="muted">${esc(d.site)}</td>
      <td class="mono small">${esc(d.version)}</td><td class="num">${d.interfaces_up}/${d.interfaces}</td><td class="num">${d.bgp ? `${d.bgp_up}/${d.bgp}` : "—"}</td>
      <td class="num">${d.ospf_up}/${d.ospf}</td><td class="num" style="${d.cpu >= 85 ? "color:var(--bad)" : ""}">${d.cpu}%</td>
      <td class="num" style="${d.temp_c >= 60 ? "color:var(--bad)" : ""}">${d.temp_c}°C</td><td class="num">${d.alarms || "—"}</td>
      <td class="num score" style="color:${d.compliance === 100 ? "var(--ok)" : "var(--warn)"}">${d.compliance}%</td></tr>`).join("")}</table></div></div>`;
  }
  const d = await api(`/api/devices/${encodeURIComponent(ui.id)}`);
  const suggest = ui.cache.suggest || (ui.cache.suggest = await api("/api/cli/suggest"));
  const tab = (k, l) => `<button class="${ui.deviceTab === k ? "on" : ""}" data-act="dtab" data-id="${k}">${l}</button>`;
  let body = "";
  if (ui.deviceTab === "interfaces") {
    body = `<table><tr><th></th><th>Interface</th><th>Description</th><th class="num">Rx dBm</th><th class="num">Util</th><th>Trend</th><th class="num">Errors/min</th></tr>
      ${d.interfaces.map((i) => `<tr><td><span class="dot ${!i.admin_up ? "admin" : i.oper_up ? (i.crc ? "warn" : "up") : "down"}"></span></td>
        <td class="mono">${esc(i.name)}</td><td class="small">${esc(i.description) || '<span class="faint">—</span>'}</td>
        <td class="num mono" style="${i.rx_dbm < -10 && i.rx_dbm > -40 ? "color:var(--warn)" : ""}">${!i.admin_up ? "—" : i.rx_dbm <= -40 ? "LOS" : i.rx_dbm}</td>
        <td class="num">${i.util}%</td><td>${spark(i.history)}</td><td class="num" style="${i.crc ? "color:var(--warn)" : ""}">${i.crc || 0}</td></tr>`).join("")}</table>`;
  } else if (ui.deviceTab === "routing") {
    body = `<table><tr><th></th><th>BGP peer</th><th>AS</th><th>Group</th><th>Description</th><th>State</th><th class="num">Prefixes</th><th class="num">Flaps</th></tr>
      ${d.bgp.map((p) => `<tr><td><span class="dot ${p.state === "Established" ? "up" : p.state.startsWith("Idle (") ? "admin" : "down"}"></span></td><td class="mono">${esc(p.peer)}</td>
        <td class="mono">${p.as}</td><td class="mono small">${esc(p.group)}</td><td class="small">${esc(p.description)}</td><td>${esc(p.state)}</td>
        <td class="num">${p.prefixes.toLocaleString()}</td><td class="num">${p.flaps}</td></tr>`).join("") || `<tr><td colspan="8" class="muted">BGP is not running on this device</td></tr>`}</table>
      ${d.te.length ? `<table style="margin-top:6px"><tr><th>Traffic engineering</th><th>Group</th><th class="num">Local-pref (outbound)</th>
        <th class="num">AS-path prepend (inbound)</th><th class="num">In Gbps</th><th class="num">Out Gbps</th><th></th></tr>
        ${d.te.map((x) => `<tr><td class="mono">${esc(x.peer)} <span class="small muted">${esc(x.description)}</span></td><td class="mono small">${esc(x.group)}</td>
          <td class="num">${x.local_pref}</td><td class="num">${x.prepend ? `x${x.prepend}` : "none"}</td><td class="num">${x.in_gbps}</td><td class="num">${x.out_gbps}</td>
          <td>${/TRANSIT/.test(x.group) ? `<button class="btn sm" data-act="temop" data-id="${esc(x.peer)}">Change…</button>` : ""}</td></tr>`).join("")}</table>` : ""}
      <table style="margin-top:6px"><tr><th></th><th>OSPF interface</th><th>Neighbour</th><th>Address</th><th>State</th></tr>
      ${d.ospf.map((n) => `<tr><td><span class="dot ${n.state === "Full" ? "up" : "down"}"></span></td><td class="mono">${esc(n.interface)}.0</td><td>${esc(short(n.neighbor))}</td>
        <td class="mono">${esc(n.address)}</td><td>${esc(n.state)}</td></tr>`).join("")}</table>`;
  } else if (ui.deviceTab === "chassis") {
    body = `<div class="pad"><h3>Chassis alarms</h3>${d.alarms.length ? `<table>${d.alarms.map((a) => `<tr><td><span class="tag ${a.class === "Major" ? "bad" : "warn"}">${esc(a.class)}</span></td>
      <td>${esc(a.description)}</td><td class="muted small">${ago(a.since)}</td></tr>`).join("")}</table>` : `<div class="muted">No alarms currently active</div>`}
      <h3 style="margin-top:16px">Recent commits</h3><table>${d.commits.map((c) => `<tr><td class="mono">${c.rev}</td><td class="small">${new Date(c.at).toISOString().slice(0, 16).replace("T", " ")}</td>
      <td>${esc(c.user)}</td><td class="muted small">${esc(c.via)}</td><td class="small">${esc(c.comment) || '<span class="tag bad">no comment</span>'}</td>
      <td>${c.change ? `<span class="tag">${esc(c.change)}</span>` : `<span class="tag bad">no CHG</span>`}</td></tr>`).join("")}</table></div>`;
  } else {
    const hist = ui.cli[d.hostname] || [];
    body = `<div class="pad"><div class="cmds">${suggest.map((c) => `<button data-act="clirun" data-id="${esc(c)}">${esc(c)}</button>`).join("")}</div>
      <form class="cli-bar" data-form="cli"><input id="cli-in" placeholder="show interfaces terse | match et-" autocomplete="off" spellcheck="false">
      <button class="btn primary">Run</button><button type="button" class="btn ghost" data-act="cliclear">Clear</button></form>
      ${hist.length ? hist.slice().reverse().map((h) => term(d.hostname, h.cmd, h.out)).join("") : `<div class="muted small">Read-only console. Try a command above, or type your own (pipes: match, except, count, last).</div>`}</div>`;
  }
  const fact = (l, v) => `<div class="fact"><div class="l">${l}</div><div class="v">${v}</div></div>`;
  return `<div class="stack"><div class="card"><div class="bd">
    <div class="detail-head"><span class="dot ${!d.powered ? "down" : d.alarms.length ? "warn" : "up"}" style="margin-top:9px"></span><div style="flex:1">
      <h1 class="mono">${esc(d.hostname)}</h1><div class="row small muted" style="margin-top:4px">${esc(d.model)} · ${esc(d.role)} · ${esc(d.site)} · Junos ${esc(d.version)}
      ${d.mgmt_ok ? "" : `<span class="tag bad">management unreachable</span>`}</div></div>
      <a class="btn ghost" href="#devices">← All devices</a></div>
    <div class="facts">${fact("Loopback / mgmt", `<span class="mono">${esc(d.loopback)} · ${esc(d.mgmt_ip)}</span>`)}${fact("Serial", `<span class="mono">${esc(d.serial)}</span>`)}
      ${fact("RE CPU / memory", `${d.cpu}% · ${d.mem}%`)}${fact("Temperature", `${d.temp_c} °C`)}</div></div></div>
    <div class="card"><div class="tabs">${tab("interfaces", "Interfaces")}${tab("routing", "BGP &amp; OSPF")}${tab("chassis", "Chassis &amp; commits")}${tab("cli", "CLI")}</div>
      <div class="bd flush tbl-wrap">${body}</div></div></div>`;
}

/* ---- changes */
const STEPS = ["draft", "approved", "in_progress", "implemented", "closed"];
async function viewChanges() {
  const [chs, tpl] = await Promise.all([api("/api/changes"), ui.cache.tpl ? Promise.resolve(ui.cache.tpl) : api("/api/changes/templates")]);
  ui.cache.tpl = tpl;
  if (!ui.id && !ui.newChange && chs.length) ui.id = chs[0].id;
  const list = chs.map((c) => `<div class="inc ${ui.id === c.id && !ui.newChange ? "sel" : ""}" data-act="change" data-id="${c.id}">
      <span class="tag ${c.status === "implemented" || c.status === "in_progress" ? "maint" : c.status === "closed" ? "ok" : c.status === "rolled_back" ? "bad" : ""}">${esc(c.status.replace("_", " "))}</span>
      <div class="t">${esc(c.title)}</div><div class="n">${esc(c.id)}</div>
      <div class="m"><span>risk ${esc(c.mop.risk)}</span><span>by ${esc(c.requested_by)}</span></div></div>`).join("");
  let right;
  if (ui.newChange) right = newChangeForm(tpl);
  else {
    const c = chs.find((x) => x.id === ui.id);
    right = c ? changeDetail(c) : `<div class="card"><div class="empty">No changes yet</div></div>`;
  }
  return `<div class="split"><div class="card"><div class="hd"><h2>Change requests</h2><div class="r"><button class="btn primary sm" data-act="newchange">+ New MOP</button></div></div>
    <div class="bd flush inc-list">${list || `<div class="empty">None</div>`}</div></div>${right}</div>`;
}

function newChangeForm(tpl) {
  const t = ui.form?.template || "transit_drain";
  const dev = ui.form?.device || (["transit_drain", "bgp_te"].includes(t) ? "mx-edge-01.dc1" : t === "cost_out" ? "mx-core-01.dc1" : "ex-agg-02.ceb");
  const peers = tpl.peers[dev] || [];
  const links = tpl.links[dev] || [];
  return `<div class="card"><div class="hd"><h2>New method of procedure</h2><span class="sub">CoreWatch writes the Junos commands, checks and rollback</span></div>
    <div class="bd"><form data-form="change" class="stack" style="gap:12px">
      <label class="f">Template<select name="template" data-act="formchg">${tpl.templates.map((x) => `<option value="${x.id}" ${x.id === t ? "selected" : ""}>${esc(x.title)}</option>`).join("")}</select></label>
      <label class="f">Device<select name="device" data-act="formchg">${tpl.devices.map((d) => `<option ${d === dev ? "selected" : ""}>${esc(d)}</option>`).join("")}</select></label>
      ${t === "transit_drain" ? `<label class="f">eBGP neighbour<select name="peer">${peers.map((p) => `<option value="${esc(p.ip)}">${esc(p.ip)} · ${esc(p.label)}</option>`).join("") || "<option value=''>No eBGP peers on this device</option>"}</select></label>` : ""}
      ${t === "bgp_te" ? `<label class="f">IP transit session<select name="peer">${peers.filter((p) => !/IX/.test(p.label)).map((p) => `<option value="${esc(p.ip)}">${esc(p.ip)} · ${esc(p.label)}</option>`).join("") || "<option value=''>Pick an edge router (mx-edge-01 / mx-edge-02)</option>"}</select></label>
        <label class="f">Technique<select name="action">
          <option value="prepend">Inbound: AS-path prepend (make this path look longer)</option>
          <option value="local_pref">Outbound: local-preference (higher = preferred exit)</option></select></label>
        <label class="f">Value<input name="value" type="number" value="2" min="0" max="1000"></label>
        <div class="infobox small">Prepend: number of extra AS64510 hops (0 removes it). Local-preference: default is 100, higher wins.</div>` : ""}
      ${t === "cost_out" ? `<label class="f">Link<select name="interface">${links.map((l) => `<option value="${esc(l.if)}">${esc(l.if)} · ${esc(l.label)}</option>`).join("") || "<option value=''>No internal links</option>"}</select></label>` : ""}
      <div class="row"><button class="btn primary">Generate MOP</button><button type="button" class="btn ghost" data-act="cancelchange">Cancel</button></div>
    </form></div></div>`;
}

function changeDetail(c) {
  const m = c.mop;
  const idx = STEPS.indexOf(c.status);
  const tl = STEPS.map((s, k) => {
    const cls = c.status === "rolled_back" ? (k <= 2 ? "done" : "") : k < idx ? "done" : k === idx ? "cur" : "";
    return `<div class="st ${cls}">${s.replace("_", " ")}</div>`;
  }).join("") + (c.status === "rolled_back" ? `<div class="st cur bad">rolled back</div>` : "");
  const act = (a, l, cls = "") => `<button class="btn ${cls}" data-act="chg" data-id="${c.id}" data-a="${a}">${l}</button>`;
  const actions = { draft: act("approve", "Approve (Tier 3)", "primary"), approved: act("implement", "Implement · commit confirmed 5", "primary"),
    in_progress: act("confirm", "Confirm commit", "primary") + act("rollback", "Roll back", "danger"),
    implemented: act("close", Object.values(m.restore).some((x) => x.length) ? "Close · apply restore" : "Close change", "ok") + act("rollback", "Roll back", "danger") }[c.status] || "";
  const checks = (kind, list) => {
    const key = `${c.id}:${kind}`;
    const out = ui.checks[key];
    return `<div class="card"><div class="hd"><h2>${kind === "pre" ? "Pre-checks" : "Post-checks"}</h2><span class="sub">${list.length} read-only commands</span>
      <div class="r"><button class="btn sm" data-act="checks" data-id="${c.id}" data-a="${kind}">${out ? "Run again" : "Run now"}</button></div></div>
      <div class="bd">${out ? out.map((x) => term(x.device, x.cmd, x.output)).join("") : list.map((x) => `<div class="vcmd"><span class="d">${esc(short(x.device))}&gt;</span>${esc(x.cmd)}</div>`).join("")}</div></div>`;
  };
  const block = (title, items) => items.map((p) => {
    let mode = ">";
    const lines = p.steps.map((s) => {
      if (s.startsWith("#")) return `<span class="faint">${esc(s)}</span>`;
      const line = `<span class="p">noc@${esc(short(p.device))}${mode}</span> ${esc(s)}`;
      if (s.startsWith("configure")) mode = "#";
      if (s === "exit") mode = ">";
      return line;
    });
    return `<div class="small muted" style="margin:6px 0 4px">${title} on <b class="mono">${esc(p.device)}</b></div><div class="term">${lines.join("\n")}</div>`;
  }).join("");
  const confirmLeft = c.confirm_by ? Math.max(0, Math.round((new Date(c.confirm_by) - Date.now()) / 1000)) : null;
  return `<div class="stack">
    <div class="card"><div class="bd">
      <div class="detail-head"><div style="flex:1"><div class="row small muted"><span class="mono">${esc(c.id)}</span><span>requested by ${esc(c.requested_by)}</span>
        ${c.approved_by ? `<span>· approved by ${esc(c.approved_by)}</span>` : ""}</div><h1 style="margin-top:4px">${esc(c.title)}</h1></div>
        <div class="row">${actions}</div></div>
      <div class="timeline" style="margin-top:16px">${tl}</div>
      ${confirmLeft != null ? `<div class="warnbox">commit confirmed is pending: Junos rolls back automatically in <b class="mono">${Math.floor(confirmLeft / 60)}:${String(confirmLeft % 60).padStart(2, "0")}</b> unless you confirm.</div>` : ""}
      ${c.status === "implemented" ? `<div class="infobox">Maintenance window open. Alerts on ${m.devices.map(short).join(", ")} are suppressed and nobody is paged.</div>` : ""}
      <div class="facts"><div class="fact"><div class="l">Risk</div><div class="v"><span class="tag ${m.risk === "High" ? "bad" : m.risk === "Medium" ? "warn" : "ok"}">${esc(m.risk)}</span></div></div>
        <div class="fact" style="grid-column:span 3"><div class="l">Impact</div><div class="v">${esc(m.impact)}</div></div></div>
      ${m.warnings.map((w) => `<div class="warnbox" style="margin-top:10px">⚠ ${esc(w)}</div>`).join("")}
    </div></div>
    ${checks("pre", m.pre_checks)}
    <div class="card"><div class="hd"><h2>Procedure</h2><span class="sub">exactly what gets typed</span></div><div class="bd">${block("Run", m.procedure)}</div></div>
    ${Object.entries(m.diff).map(([h, d]) => `<div class="card"><div class="hd"><h2>show | compare</h2><span class="sub mono">${esc(h)}</span></div><div class="bd">${diffHtml(d)}</div></div>`).join("")}
    ${checks("post", m.post_checks)}
    <div class="grid g-2"><div class="card"><div class="hd"><h2>Rollback</h2></div><div class="bd">${block("If anything looks wrong", m.rollback)}</div></div>
      <div class="card"><div class="hd"><h2>History</h2></div><div class="bd flush feed">${c.history.slice().reverse().map((h) => `<div class="it"><span class="w">${hhmm(h.at)}</span> ${esc(h.text)}</div>`).join("")}</div></div></div>
  </div>`;
}

/* ---- audits */
async function viewAudit() {
  const [a, hw] = await Promise.all([api("/api/audit"), api("/api/hardware")]);
  const sel = a.devices.find((d) => d.device === ui.auditDevice) || [...a.devices].sort((x, y) => x.score - y.score)[0];
  ui.auditDevice = sel.device;
  return `<div class="stack">
    <div class="card matrix"><div class="hd"><h2>Golden configuration</h2><span class="sub">${a.rules.length} rules · fleet score ${a.score}%</span></div>
      <div class="bd flush tbl-wrap"><table><tr><th>Device</th>${a.rules.map((r) => `<th class="c" title="${esc(r.title)}">${esc(r.id)}</th>`).join("")}<th class="num">Score</th></tr>
      ${a.devices.map((d) => `<tr class="click ${d.device === sel.device ? "sel" : ""}" data-act="auditdev" data-id="${esc(d.device)}"><td class="mono">${esc(d.device)}</td>
        ${d.results.map((r) => `<td class="c ${r.ok ? "ok" : "no"}" title="${esc(r.title)}: ${esc(r.detail)}">${r.ok ? "✓" : "✕"}</td>`).join("")}
        <td class="num score" style="color:${d.score === 100 ? "var(--ok)" : "var(--warn)"}">${d.score}%</td></tr>`).join("")}</table></div></div>
    <div class="grid g-2">
      <div class="card"><div class="hd"><h2 class="mono">${esc(sel.device)}</h2><span class="sub">${sel.passed}/${sel.total} rules pass</span>
        <div class="r">${sel.auto_fix.lines.length || sel.auto_fix.ops.length ? `<button class="btn primary sm" data-act="auditfix" data-id="${esc(sel.device)}">Create fix MOP</button>` : ""}</div></div>
        <div class="bd flush"><table>${sel.results.filter((r) => !r.ok).map((r) => `<tr><td><span class="tag ${r.severity === "high" ? "bad" : r.severity === "medium" ? "warn" : ""}">${esc(r.id)}</span></td>
          <td><b>${esc(r.title)}</b><div class="small muted">${esc(r.detail)}</div>${r.fix.length || r.ops.length ? `<div class="mono small" style="margin-top:4px;color:var(--accent2)">${[...r.fix, ...r.ops].map(esc).join("<br>")}</div>` : ""}</td></tr>`).join("") ||
          `<tr><td class="muted">Fully compliant.</td></tr>`}</table></div></div>
      <div class="card"><div class="hd"><h2>Hardware &amp; software</h2><span class="sub">serials vs asset register, approved release</span></div>
        <div class="bd flush tbl-wrap"><table><tr><th>Device</th><th>Serial</th><th>Asset register</th><th>Junos</th><th>FRUs</th></tr>
        ${hw.map((h) => `<tr><td class="mono small">${esc(short(h.device))}</td><td class="mono small">${esc(h.serial)}</td>
          <td>${h.serial_match ? `<span class="tag ok">match</span>` : `<span class="tag bad" title="register says ${esc(h.cmdb_serial)}">mismatch</span>`}</td>
          <td>${h.approved ? `<span class="tag ok">${esc(h.version)}</span>` : `<span class="tag warn">${esc(h.version)}</span>`}</td>
          <td class="small">${h.failed.length ? `<span class="tag bad">${esc(h.failed.join(", "))} failed</span>` : `<span class="muted">${h.frus.length} OK</span>`}</td></tr>`).join("")}</table></div></div>
    </div></div>`;
}

/* ---- carriers */
async function viewCarriers() {
  const c = await api("/api/circuits");
  return `<div class="stack"><div class="card"><div class="hd"><h2>Circuits</h2><span class="sub">${c.circuits.length} circuits · ${c.carriers.length} carriers</span></div>
    <div class="bd flush tbl-wrap"><table><tr><th></th><th>Circuit ID</th><th>Carrier</th><th>Service</th><th>A end</th><th>Z end</th><th class="num">Util</th><th>Trend</th>
      <th class="num">Rx dBm</th><th class="num">Err/min</th><th>Carrier ticket</th></tr>
    ${c.circuits.map((x) => `<tr><td><span class="dot ${x.state}"></span></td><td class="mono">${esc(x.id)}</td><td>${esc(x.carrier)}</td><td class="small">${esc(x.service)} · ${x.bandwidth}G</td>
      <td class="mono small">${esc(x.a_end.replace(/\.(dc\d|qc|ceb)/, ""))}</td><td class="small">${esc(x.z_end.replace(/\.(dc\d|qc|ceb)/, ""))}</td>
      <td class="num">${x.util}%</td><td>${spark(x.history)}</td><td class="num mono">${x.rx_dbm <= -40 ? "LOS" : x.rx_dbm}</td>
      <td class="num" style="${x.crc ? "color:var(--warn)" : ""}">${x.crc}</td>
      <td>${x.ticket ? `<span class="tag ok">${esc(x.ticket.reference)}</span> <span class="small muted">SLA ${x.sla_h} h</span>` : `<span class="faint small">—</span>`}</td></tr>`).join("")}</table></div></div>
    <div class="grid g-2">${c.carriers.map((k) => `<div class="card"><div class="bd"><div class="row"><h2>${esc(k.name)}</h2>${k.asn ? `<span class="tag">AS${k.asn}</span>` : ""}
      <span class="spacer"></span><span class="small muted">SLA ${k.sla_mttr_h} h to repair</span></div>
      <div class="small" style="margin-top:8px"><span class="muted">NOC</span> ${esc(k.noc_email)} · ${esc(k.noc_phone)}<br><span class="muted">Account</span> <span class="mono">${esc(k.account)}</span></div>
      <div class="small muted" style="margin-top:6px">${c.circuits.filter((x) => x.carrier_id === k.id).map((x) => `<span class="mono">${esc(x.id)}</span>`).join(", ")}</div></div></div>`).join("")}</div></div>`;
}

/* ---- on-call */
async function viewOncall() {
  const o = await api("/api/oncall");
  const c = o.current;
  return `<div class="grid g-3">
    <div class="card"><div class="hd"><h2>Now</h2><span class="sub">week of ${esc(c.week_start)}</span></div><div class="bd">
      ${person(c.primary, "Primary network on-call")}${person(c.secondary, "Secondary")}${person(c.tier3, "Tier 3 core lead")}
      <h3 style="margin-top:12px">${esc(c.shift.name)} · ${esc(c.shift.hours)}</h3>${c.shift.analysts.map((a) => person(a, "NOC analyst")).join("")}</div></div>
    <div class="card"><div class="hd"><h2>Escalation policy</h2></div><div class="bd">
      <table>${Object.entries(o.policy).map(([s, steps]) => `<tr><td>${sev(s)}</td><td>${steps.map((x) => `${x.after_min ? `+${x.after_min} min` : "now"}: ${esc(x.level)}`).join(" → ")}</td></tr>`).join("")}
      <tr><td>${sev("P3")} ${sev("P4")}</td><td class="muted">Slack + queue, business hours. Never paged.</td></tr></table>
      <div class="infobox small" style="margin-top:12px">Escalation stops when someone acknowledges. Incidents inside an implemented change are not paged.${o.minute_seconds < 60 ? ` Demo clock: 1 escalation minute = ${o.minute_seconds}s.` : ""}</div></div></div>
    <div class="card"><div class="hd"><h2>Rotation</h2></div><div class="bd flush"><table><tr><th>Week</th><th>Primary</th><th>Secondary</th><th>Tier 3</th></tr>
      ${o.rotation.map((r, k) => `<tr class="${k === 0 ? "sel" : ""}"><td class="mono small" style="white-space:nowrap">${esc(r.week_start)}</td><td>${esc(r.primary)}</td><td>${esc(r.secondary)}</td><td>${esc(r.tier3)}</td></tr>`).join("")}</table></div></div>
  </div>
  <div class="card" style="margin-top:16px"><div class="hd"><h2>Page log</h2></div><div class="bd flush"><table><tr><th>Time</th><th></th><th>Level</th><th>To</th><th>Incident</th><th>Ack</th></tr>
    ${o.pages.map((p) => `<tr class="click" data-act="incident" data-id="${p.incident_id}"><td class="mono small">${hhmm(p.at)}</td><td>${sev(p.severity)}</td><td>${esc(p.level)}</td><td>${esc(p.to)}</td>
      <td>${esc(p.title)}</td><td>${p.acked_by ? `<span class="tag ok">${esc(p.acked_by)}</span>` : `<span class="tag warn">open</span>`}</td></tr>`).join("") || `<tr><td colspan="6" class="muted">No pages. P1/P2 incidents page the on-call engineer automatically.</td></tr>`}</table></div></div>`;
}

/* ------------------------------------------------------------------ router + refresh */
const VIEWS = { overview: viewOverview, incidents: viewIncidents, devices: viewDevices, changes: viewChanges, audit: viewAudit, carriers: viewCarriers, oncall: viewOncall };
const TITLES = { overview: "Overview", incidents: "Incidents", devices: "Devices & CLI", changes: "Change control", audit: "Audits", carriers: "Carriers & circuits", oncall: "On-call" };

function route() {
  const [v, ...rest] = location.hash.replace(/^#/, "").split("/");
  const view = VIEWS[v] ? v : "overview";
  const id = rest.length ? decodeURIComponent(rest.join("/")) : null;
  if (view !== ui.view) { ui.newChange = !!ui.pendingNew; ui.pendingNew = false; ui.deviceTab = view === "devices" && id ? ui.deviceTab : "interfaces"; }
  ui.view = view;
  ui.id = id;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.view === view));
  render(true);
}

async function render(force = false) {
  const busy = document.activeElement && ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName);
  if (!force && (busy || ui.busy || !$("#sim-menu").hidden)) return;
  try {
    const html = await VIEWS[ui.view]();
    const y = window.scrollY;
    $("#view").innerHTML = html;
    if (!force) window.scrollTo(0, y);
    $("#crumbs").innerHTML = `${TITLES[ui.view]}${ui.id && ui.view !== "overview" ? ` <span>/ ${esc(ui.id)}</span>` : ""}`;
  } catch (e) {
    $("#view").innerHTML = `<div class="card"><div class="empty">Could not load: ${esc(e.message)}</div></div>`;
  }
  header();
}

async function header() {
  try {
    const [s, h] = await Promise.all([api("/api/summary"), ui.cache.health || api("/api/health")]);
    ui.cache.health = h;
    const urgent = s.by_severity.P1 + s.by_severity.P2;
    $("#nav-inc").textContent = urgent || "";
    $("#nav-chg").textContent = s.changes_active ? `${s.changes_active} live` : s.changes_pending || "";
    $("#oncall-mini").innerHTML = `On-call <b>${esc(s.oncall.primary)}</b> · ${esc(s.oncall.shift.name)}`;
    $("#mode-chip").textContent = s.mode === "lab" ? "LIVE LAB (NETCONF)" : "mock network";
    $("#mode-chip").classList.toggle("live", s.mode === "lab");
    $("#ai-chip").textContent = h.ai_provider === "mock" ? "AI: offline writer" : `AI: ${h.ai_model}`;
  } catch { /* header is best-effort */ }
}

/* ------------------------------------------------------------------ actions */
document.addEventListener("click", async (ev) => {
  const simBtn = ev.target.closest("#sim-btn");
  if (simBtn) { $("#sim-menu").hidden = !$("#sim-menu").hidden; return; }
  const fault = ev.target.closest("[data-fault]");
  if (fault) {
    $("#sim-menu").hidden = true;
    try { const r = await post(`/api/simulate/${fault.dataset.fault}`); toast(r.text); } catch (e) { toast(e.message, true); }
    ui.verify = {};
    return render(true);
  }
  if (!ev.target.closest(".sim")) $("#sim-menu").hidden = true;
  const el = ev.target.closest("[data-act]");
  if (!el || el.tagName === "SELECT") return;
  const { act, id, a } = el.dataset;
  const run = async (fn, msg) => {
    ui.busy = true;
    el.disabled = true;
    try { const r = await fn(); if (msg) toast(typeof msg === "function" ? msg(r) : msg); } catch (e) { toast(e.message, true); }
    ui.busy = false;
    render(true);
  };
  if (act === "incident") location.hash = `#incidents/${id}`;
  else if (act === "device") location.hash = `#devices/${id}`;
  else if (act === "change") { ui.newChange = false; location.hash = `#changes/${id}`; }
  else if (act === "filter") { ui.filter = id; render(true); }
  else if (act === "dtab") { ui.deviceTab = id; render(true); }
  else if (act === "auditdev") { ui.auditDevice = id; render(true); }
  else if (act === "analyze") { el.textContent = "Analysing…"; run(() => post(`/api/incidents/${id}/analyze`), "AI analysis ready"); }
  else if (act === "verify") { el.textContent = "Running…"; run(async () => { ui.verify[id] = await post(`/api/incidents/${id}/verify`); }); }
  else if (act === "ack") run(() => post(`/api/incidents/${id}/ack`), (r) => `Acknowledged by ${r.acked_by}: escalation stopped`);
  else if (act === "carrier") run(() => post(`/api/incidents/${id}/carrier-ticket`), (r) => `Fault raised with ${r.carrier}: ${r.reference}`);
  else if (act === "ticket") run(() => post(`/api/incidents/${id}/ticket`, { title: $("#t-title").value, body: $("#t-body").value }), (r) => `${r.key} opened`);
  else if (act === "clirun") cli(ui.id, id);
  else if (act === "cliclear") { ui.cli[ui.id] = []; render(true); }
  else if (act === "newchange") { ui.newChange = true; ui.form = null; render(true); }
  else if (act === "temop") { const dev = ui.id; ui.pendingNew = true; ui.form = { template: "bgp_te", device: dev }; location.hash = "#changes"; }
  else if (act === "cancelchange") { ui.newChange = false; render(true); }
  else if (act === "chg") run(() => post(`/api/changes/${id}/${a}`), (r) => `${r.id}: ${r.history[r.history.length - 1].text}`);
  else if (act === "checks") {
    el.textContent = "Running…";
    run(async () => {
      const c = (await api("/api/changes")).find((x) => x.id === id);
      const list = a === "pre" ? c.mop.pre_checks : c.mop.post_checks;
      ui.checks[`${id}:${a}`] = await Promise.all(list.map(async (x) => ({ ...x, output: (await post("/api/cli", { device: x.device, command: x.cmd })).output })));
    });
  } else if (act === "auditfix") {
    run(async () => { const c = await post(`/api/audit/${encodeURIComponent(id)}/fix`); location.hash = `#changes/${c.id}`; return c; }, (c) => `${c.id} drafted from the audit`);
  }
});

document.addEventListener("change", (ev) => {
  const el = ev.target.closest("[data-act='formchg']");
  if (!el) return;
  const f = el.form;
  ui.form = { template: f.template.value, device: el.name === "template" ? null : f.device.value };
  render(true);
});

document.addEventListener("submit", async (ev) => {
  const form = ev.target.closest("[data-form]");
  if (!form) return;
  ev.preventDefault();
  if (form.dataset.form === "cli") {
    const cmd = $("#cli-in").value.trim();
    if (cmd) await cli(ui.id, cmd);
  } else if (form.dataset.form === "change") {
    const params = { device: form.device.value };
    if (form.peer) params.peer = form.peer.value;
    if (form.interface) params.interface = form.interface.value;
    if (form.action) { params.action = form.action.value; params.value = Number(form.value.value); }
    try {
      const c = await post("/api/changes", { template: form.template.value, params });
      ui.newChange = false;
      toast(`${c.id} drafted: review the MOP, then get it approved`);
      location.hash = `#changes/${c.id}`;
    } catch (e) { toast(e.message, true); }
  }
});

async function cli(host, cmd) {
  try {
    const r = await post("/api/cli", { device: host, command: cmd });
    (ui.cli[host] = ui.cli[host] || []).push({ cmd, out: r.output });
    ui.cli[host] = ui.cli[host].slice(-12);
  } catch (e) { toast(e.message, true); }
  ui.deviceTab = "cli";
  await render(true);
  const i = $("#cli-in");
  if (i) i.focus();
}

$("#theme").addEventListener("click", () => {
  const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("cw-theme", t); } catch { /* private mode */ }
});
try { const t = localStorage.getItem("cw-theme"); if (t) document.documentElement.dataset.theme = t; } catch { /* ignore */ }

setInterval(() => { $("#clock").textContent = new Date().toISOString().slice(0, 19).replace("T", " ") + " UTC"; }, 1000);
window.addEventListener("hashchange", route);
setInterval(() => render(false), 4000);
route();
