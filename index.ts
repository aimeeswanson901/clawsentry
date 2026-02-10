import type { OpenClawPluginApi } from "openclaw/plugin-sdk";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { exec } from "node:child_process";
import { createSkillFence } from "./src/skillfence";

export default function register(api: OpenClawPluginApi) {
  const fence = createSkillFence(api);

  api.on("session_start", (event, ctx) => {
    fence.log({
      event: "session_start",
      sessionId: event.sessionId,
      agentId: ctx.agentId,
      payload: { resumedFrom: event.resumedFrom ?? null },
    });
  });

  api.on("session_end", (event, ctx) => {
    fence.log({
      event: "session_end",
      sessionId: event.sessionId,
      agentId: ctx.agentId,
      payload: { messageCount: event.messageCount, durationMs: event.durationMs },
    });
  });

  api.on("before_tool_call", (event, ctx) => {
    const policy = fence.evaluatePolicy({ tool: ctx.toolName, payload: { params: event.params } });

    fence.log({
      event: "tool_call",
      sessionId: ctx.sessionKey,
      agentId: ctx.agentId,
      tool: ctx.toolName,
      payload: { params: event.params },
      findings: policy.reasons,
      severity: policy.reasons.length > 0 ? "high" : undefined,
    });

    if (policy.enforce && policy.reasons.length > 0) {
      fence.log({
        event: "policy_block",
        sessionId: ctx.sessionKey,
        agentId: ctx.agentId,
        tool: ctx.toolName,
        findings: policy.reasons,
        severity: "high",
        payload: { params: event.params },
      });
      return { block: true, blockReason: `ClawSentry policy blocked tool: ${policy.reasons.join(", ")}` };
    }
  });

  api.on("after_tool_call", (event, ctx) => {
    fence.log({
      event: "tool_result",
      sessionId: ctx.sessionKey,
      agentId: ctx.agentId,
      tool: ctx.toolName,
      payload: {
        params: event.params,
        result: event.result,
        error: event.error ?? null,
        durationMs: event.durationMs ?? null,
      },
      status: event.error ? "error" : "ok",
    });
  });

  const cfg = (api.pluginConfig ?? {}) as {
    processMonitor?: { enabled?: boolean; intervalSec?: number };
    networkMonitor?: { enabled?: boolean; intervalSec?: number };
  };

  api.registerService({
    id: "clawsentry-process-monitor",
    start: () => {
      if (!cfg.processMonitor?.enabled) return;
      const interval = Math.max(10, cfg.processMonitor?.intervalSec ?? 60) * 1000;
      const scan = () => {
        exec("ps -eo pid,comm,args", (err, stdout) => {
          if (err) return;
          const lines = stdout.split("\n").slice(1);
          const hits: string[] = [];
          for (const line of lines) {
            const lower = line.toLowerCase();
            if (/(nc -e|bash -i|powershell -enc)/.test(lower)) hits.push("reverse_shell_pattern");
            if (/(xmrig|minerd|cpuminer)/.test(lower)) hits.push("crypto_miner");
            if (/(curl .*\| .*sh|wget .*\| .*sh)/.test(lower)) hits.push("pipe_to_shell");
          }
          if (hits.length > 0) {
            fence.log({
              event: "process_scan",
              findings: Array.from(new Set(hits)),
              severity: "high",
              payload: { matchCount: hits.length },
            });
          }
        });
      };
      scan();
      const timer = setInterval(scan, interval);
      (api as any).__clawsentryProcessTimer = timer;
    },
    stop: () => {
      const timer = (api as any).__clawsentryProcessTimer;
      if (timer) clearInterval(timer);
    },
  });

  api.registerService({
    id: "clawsentry-network-monitor",
    start: () => {
      if (!cfg.networkMonitor?.enabled) return;
      const interval = Math.max(10, cfg.networkMonitor?.intervalSec ?? 60) * 1000;
      const scan = () => {
        exec("netstat -an", (err, stdout) => {
          if (err) return;
          const lines = stdout.split("\n");
          const hits: string[] = [];
          for (const line of lines) {
            const lower = line.toLowerCase();
            if (/(\d+\.\d+\.\d+\.\d+):(\d{4,5})/.test(lower)) hits.push("raw_ip_connection");
            if (/:([0-9]{4,5})\s+.*established/.test(lower)) hits.push("custom_port_connection");
          }
          if (hits.length > 0) {
            fence.log({
              event: "network_scan",
              findings: Array.from(new Set(hits)),
              severity: "high",
              payload: { matchCount: hits.length },
            });
          }
        });
      };
      scan();
      const timer = setInterval(scan, interval);
      (api as any).__clawsentryNetworkTimer = timer;
    },
    stop: () => {
      const timer = (api as any).__clawsentryNetworkTimer;
      if (timer) clearInterval(timer);
    },
  });

  const DANGEROUS_CMD = /\b(curl|wget)\b[^\n]*\|\s*(sh|bash)|\bbash\s+-c\b|\bpowershell\s+-enc\b/gi;
  const BASE64_EXEC = /base64\s+(-d|--decode)|\batob\(|\bfrombase64\b/gi;
  const SENSITIVE_PATH = /\b(\.env|openclaw\.json|\.ssh\/|id_rsa|id_ed25519|credentials|aws\/credentials|config\.json)\b/gi;

  const workspaceDirs = new Set<string>();
  const defaultsWorkspace = (api.config as any)?.agents?.defaults?.workspace;
  if (defaultsWorkspace) workspaceDirs.add(defaultsWorkspace);
  const list = (api.config as any)?.agents?.list ?? [];
  for (const entry of list) {
    if (entry?.workspace) workspaceDirs.add(entry.workspace);
  }
  const runtimeWorkspace = (api as any)?.workspaceDir;
  if (runtimeWorkspace) workspaceDirs.add(runtimeWorkspace);

  const skillDirs = [
    path.join(os.homedir(), ".openclaw", "skills"),
    path.join(os.homedir(), "clawd", "skills"),
    ...Array.from(workspaceDirs).map((w) => path.join(w, "skills")),
  ];

  function scanFileContent(content: string) {
    const findings: string[] = [];
    if (DANGEROUS_CMD.test(content)) findings.push("dangerous_shell_pipeline");
    if (BASE64_EXEC.test(content)) findings.push("base64_decode_exec");
    if (SENSITIVE_PATH.test(content)) findings.push("sensitive_file_access");
    return Array.from(new Set(findings));
  }

  function scanSkillDir(dir: string) {
    const report: Array<{ file: string; findings: string[] }> = [];
    if (!fs.existsSync(dir)) return report;
    const walk = (p: string) => {
      const stats = fs.statSync(p);
      if (stats.isDirectory()) {
        for (const entry of fs.readdirSync(p)) {
          walk(path.join(p, entry));
        }
      } else if (stats.isFile()) {
        if (stats.size > 200_000) return;
        const raw = fs.readFileSync(p, "utf8");
        const findings = scanFileContent(raw);
        if (findings.length > 0) report.push({ file: p, findings });
      }
    };
    walk(dir);
    return report;
  }

  let lastScanResults: Record<string, any> = {};

  function scanAllSkills() {
    const results: Record<string, any> = {};
    for (const base of skillDirs) {
      if (!fs.existsSync(base)) continue;
      const entries = fs.readdirSync(base);
      for (const name of entries) {
        const full = path.join(base, name);
        if (fs.existsSync(full) && fs.statSync(full).isDirectory()) {
          results[name] = scanSkillDir(full);
        }
      }
    }
    lastScanResults = results;
    return results;
  }

  api.registerHttpRoute({
    path: "/clawsentry",
    handler: (_req, res) => {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ClawSentry</title>
  <style>
    :root {
      --bg:#0b0f10; --panel:#0f1416; --border:#1f2a2e;
      --text:#c9f2c7; --muted:#7aa07a;
      --cyan:#59f2e6; --red:#ff5f56; --yellow:#fcd34d; --purple:#b794f4;
    }
    * { box-sizing: border-box; }
    body {
      margin:0; background:var(--bg); color:var(--text);
      font-family:"JetBrains Mono","Fira Code",monospace;
      font-size:14px; line-height:1.5;
    }
    .dashboard{display:grid;grid-template-rows:44px 1fr 38px;grid-template-columns:220px 1fr;grid-template-areas:"top top" "side main" "bottom bottom";min-height:100vh}
    .topbar{grid-area:top;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;padding:0 12px;background:var(--panel)}
    .sidebar{grid-area:side;border-right:1px solid var(--border);padding:12px;background:var(--panel)}
    .main{grid-area:main;padding:12px;overflow:auto}
    .bottombar{grid-area:bottom;border-top:1px solid var(--border);padding:8px 12px;background:#0a0d0e;display:flex;gap:8px;align-items:center}
    .panel{border:1px solid var(--border);padding:10px;margin-bottom:12px;background:rgba(15,20,22,0.6)}
    .panel h3{margin:0 0 8px;font-size:12px;color:var(--cyan);text-transform:uppercase;letter-spacing:.08em}
    .muted{color:var(--muted)}
    label{font-size:11px;color:var(--muted);display:block;margin-bottom:4px}
    input,select{width:100%;padding:6px 8px;font-size:13px;color:var(--text);background:#0c1113;border:1px solid var(--border)}
    button{padding:6px 10px;font-size:12px;color:var(--text);background:#12202a;border:1px solid var(--border);cursor:pointer}
    button:hover{border-color:var(--cyan);color:var(--cyan)}
    table{width:100%;border-collapse:collapse;margin-top:8px}
    th,td{text-align:left;padding:6px;border-bottom:1px solid var(--border);font-size:12px}
    .badge{display:inline-block;padding:2px 6px;border:1px solid var(--border);color:var(--cyan)}
    .badge.low{color:#7CFC9A} .badge.medium{color:var(--yellow)} .badge.high{color:var(--red)} .badge.critical{color:var(--purple)}
    .prompt{color:var(--cyan)} .cmd{background:transparent;border:none;color:var(--text);width:85%;font-family:inherit}
    .nav-item{padding:6px 4px;color:var(--muted);cursor:pointer}
    .nav-item.active{color:var(--cyan)}
    .page{display:none} .page.active{display:block}
    .chart-card{position:relative;padding:14px;border:1px solid var(--border);background:#0c1113}
    .hover-chip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--border);color:var(--text);font-size:12px;padding:6px 8px;border-radius:8px;opacity:0;transform:translateY(6px);transition:.12s ease}
    .chart-card:hover .hover-chip{opacity:1;transform:translateY(0)}
    .scanlines::after{content:"";pointer-events:none;position:fixed;inset:0;background:repeating-linear-gradient(to bottom,rgba(255,255,255,.03),rgba(255,255,255,.03) 1px,transparent 1px,transparent 3px);mix-blend-mode:soft-light;opacity:.25}
    @media (max-width: 1000px){.dashboard{grid-template-columns:1fr;grid-template-areas:"top" "main" "bottom";grid-template-rows:44px auto 38px}.sidebar{display:none}}
  
  </style>
</head>
<body class="scanlines">
  <div class="dashboard">
    <div class="topbar">
      <strong>ClawSentry</strong>
      <span class="badge">ONLINE</span>
      <span class="muted">localhost</span>
      <span id="clock" class="muted"></span>
    </div>

    <div class="sidebar">
      <div class="panel">
        <h3>Nav</h3>
        <div class="nav-item active" data-page="overview">Overview</div>
        <div class="nav-item" data-page="sessions">Sessions</div>
        <div class="nav-item" data-page="policy">Policy</div>
        <div class="nav-item" data-page="scans">Scans</div>
      </div>
      <div class="panel">
        <h3>Status</h3>
        <div class="muted">Security + observability</div>
        <div>Mode: observe‑only</div>
      </div>
    </div>

    <div class="main">
      <div class="page active" id="page-overview">
        <div class="panel">
          <h3>Summary</h3>
          <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:8px;">
            <div class="panel" style="margin:0;">
              <div class="muted">Total (latest)</div>
              <div id="sumTotal">0</div>
            </div>
            <div class="panel" style="margin:0;">
              <div class="muted">High/Critical</div>
              <div id="sumHigh">0</div>
            </div>
            <div class="panel" style="margin:0;">
              <div class="muted">Medium</div>
              <div id="sumMedium">0</div>
            </div>
            <div class="panel" style="margin:0;">
              <div class="muted">Low</div>
              <div id="sumLow">0</div>
            </div>
          </div>
          <div style="margin-top:10px;">
            <div class="muted" style="margin-bottom:6px;">Severity trend (last 60 min)</div>
            <div class="chart-card" id="severityCard"><svg id="severityChart" width="100%" height="80" viewBox="0 0 600 80"></svg><div class="hover-chip" id="severityChip"></div></div>
          </div>
        </div>

        <div class="panel">
          <h3>Filters</h3>
          <div style="display:grid; grid-template-columns: repeat(4, 1fr); gap:10px;">
            <div>
              <label>Severity</label>
              <select id="severity">
                <option value="">All</option>
                <option value="low">low</option>
                <option value="medium">medium</option>
                <option value="high">high</option>
                <option value="critical">critical</option>
              </select>
            </div>
            <div>
              <label>Tool</label>
              <input id="tool" placeholder="exec, browser, web_fetch" />
            </div>
            <div>
              <label>Last minutes</label>
              <input id="minutes" type="number" min="1" placeholder="60" />
            </div>
            <div style="display:flex; gap:8px; align-items:end;">
              <button id="apply">Apply</button>
              <button id="clear">Clear</button>
            </div>
          </div>
          <div style="display:flex; gap:8px; margin-top:8px;">
            <button id="exportJson">Export JSON</button>
            <button id="exportCsv">Export CSV</button>
          </div>
        </div>

        <div class="panel">
          <h3>Alerts</h3>
          <div class="muted">High/Critical events (last 60 min)</div>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Tool</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody id="alertRows"></tbody>
          </table>
        </div>

        <div class="panel">
          <h3>Latest events</h3>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Agent</th>
                <th>Tool</th>
                <th>Severity</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody id="rows"></tbody>
          </table>
          <div style="display:flex; gap:8px; margin-top:8px; align-items:center;">
            <button id="prevPage">Prev</button>
            <div class="muted" id="pageInfo">Page 1</div>
            <button id="nextPage">Next</button>
          </div>
        </div>
      </div>

      <div class="page" id="page-policy">
        <div class="panel">
          <h3>Policy (observe‑only)</h3>
          <div class="muted">Rules won’t block yet. They add policy_* findings.</div>
          <div style="display:grid; gap:8px; margin-top:8px;">
            <div>
              <label>Deny tools</label>
              <input id="denyTools" placeholder="exec, browser" />
            </div>
            <div>
              <label>Allow tools</label>
              <input id="allowTools" placeholder="web_fetch" />
            </div>
            <div>
              <label>Deny findings</label>
              <input id="denyFindings" placeholder="dangerous_shell_pipeline" />
            </div>
            <div>
              <label>Enforce blocking</label>
              <select id="enforce">
                <option value="false">false</option>
                <option value="true">true</option>
              </select>
            </div>
            <div>
              <button id="savePolicy">Save policy</button>
            </div>
          </div>
        </div>

        <div class="panel">
          <h3>Config (read‑only)</h3>
          <div class="muted">Edit in openclaw.json. This view shows current values and provides a copyable snippet.</div>
          <div style="display:grid; gap:8px; margin-top:8px;">
            <div>
              <label>Log dir</label>
              <input id="cfgLogDir" readonly />
            </div>
            <div>
              <label>Redact</label>
              <input id="cfgRedact" readonly />
            </div>
            <div>
              <label>Max payload bytes</label>
              <input id="cfgMaxPayload" readonly />
            </div>
            <div>
              <label>Process monitor</label>
              <input id="cfgProcess" readonly />
            </div>
            <div>
              <label>Network monitor</label>
              <input id="cfgNetwork" readonly />
            </div>
            <div>
              <label>Anomaly detection</label>
              <input id="cfgAnomaly" readonly />
            </div>
            <div>
              <button id="copyConfig">Copy config snippet</button>
            </div>
          </div>
          <pre id="configOut" style="white-space:pre-wrap; margin-top:8px;"></pre>
        </div>
      </div>

      <div class="page" id="page-sessions">
        <div class="panel">
          <h3>Sessions</h3>
          <div class="muted">Select a session to view timeline.</div>
          <table>
            <thead>
              <tr>
                <th>Session</th>
                <th>Events</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody id="sessions"></tbody>
          </table>
        </div>

        <div class="panel">
          <h3>Incident report</h3>
          <div class="muted">Generate a one‑page summary for a session.</div>
          <div style="display:flex; gap:8px; align-items:center; margin-top:8px;">
            <input id="incidentSession" placeholder="session id" />
            <button id="genIncident">Generate</button>
          </div>
          <pre id="incidentOut" style="white-space:pre-wrap; margin-top:8px;"></pre>
        </div>

        <div class="panel">
          <h3>Session timeline</h3>
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Event</th>
                <th>Tool</th>
                <th>Severity</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody id="timeline"></tbody>
          </table>
        </div>
      </div>

      <div class="page" id="page-scans">
        <div class="panel">
          <h3>Security scans</h3>
          <div class="muted">Pre‑install scan a skill or run full system scan.</div>
          <div style="display:flex; gap:8px; align-items:center; margin-top:8px;">
            <input id="scanSkill" placeholder="skill name" />
            <button id="scanSkillBtn">Scan skill</button>
            <button id="scanAllBtn">Full scan</button>
          </div>
          <div class="muted" style="margin-top:8px;">Results appear below.</div>
        </div>

        <div class="panel">
          <h3>Scan results</h3>
          <div class="muted">Latest scan summary by skill.</div>
          <table>
            <thead>
              <tr>
                <th>Skill</th>
                <th>Status</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody id="scanTable"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="bottombar">
      <span class="prompt">claw@host:~$</span>
      <input class="cmd" value="tail --events" readonly />
    </div>
  </div>

  <script>
    function buildQuery() {
      const severity = document.getElementById('severity').value;
      const tool = document.getElementById('tool').value.trim();
      const minutes = document.getElementById('minutes').value;
      const params = new URLSearchParams();
      if (severity) params.set('severity', severity);
      if (tool) params.set('tool', tool);
      if (minutes) params.set('minutes', minutes);
      return params.toString();
    }

    function updateClock() {
      const el = document.getElementById('clock');
      if (!el) return;
      el.textContent = new Date().toLocaleTimeString();
    }

    async function loadPolicy() {
      const res = await fetch('/clawsentry/policy');
      const data = await res.json();
      const p = data.policy || {};
      document.getElementById('denyTools').value = (p.denyTools || []).join(', ');
      document.getElementById('allowTools').value = (p.allowTools || []).join(', ');
      document.getElementById('denyFindings').value = (p.denyFindings || []).join(', ');
      document.getElementById('enforce').value = String(Boolean(p.enforce));
    }

    async function loadConfig() {
      const res = await fetch('/clawsentry/config');
      const data = await res.json();
      const cfg = data.config || {};
      document.getElementById('cfgLogDir').value = cfg.logDir || '';
      document.getElementById('cfgRedact').value = String(cfg.redact ?? true);
      document.getElementById('cfgMaxPayload').value = String(cfg.maxPayloadBytes ?? 4096);
      document.getElementById('cfgProcess').value = JSON.stringify(cfg.processMonitor || {});
      document.getElementById('cfgNetwork').value = JSON.stringify(cfg.networkMonitor || {});
      document.getElementById('cfgAnomaly').value = JSON.stringify(cfg.anomaly || {});
      const out = {
        plugins: {
          entries: {
            clawsentry: { enabled: true, config: cfg }
          }
        }
      };
      document.getElementById('configOut').textContent = JSON.stringify(out, null, 2);
    }

    let currentPage = 1;
    const pageSize = 20;
    let lastData = [];

    function renderPage(data) {
      const rows = document.getElementById('rows');
      const start = (currentPage - 1) * pageSize;
      const page = data.slice(start, start + pageSize);
      rows.innerHTML = page.map(r => {
        const sev = r.severity || 'low';
        const findings = (r.findings || []).join(', ');
        return '<tr>' +
          '<td>' + new Date(r.ts).toLocaleString() + '</td>' +
          '<td>' + r.event + '</td>' +
          '<td>' + (r.agentId || '') + '</td>' +
          '<td>' + (r.tool || '') + '</td>' +
          '<td><span class="badge ' + sev + '">' + sev + '</span></td>' +
          '<td>' + findings + '</td>' +
        '</tr>';
      }).join('');
      const pageInfo = document.getElementById('pageInfo');
      if (pageInfo) {
        const maxPage = Math.max(1, Math.ceil(data.length / pageSize));
        pageInfo.textContent = 'Page ' + currentPage + ' / ' + maxPage;
      }
    }

    async function load() {
      const qs = buildQuery();
      const res = await fetch('/clawsentry/logs' + (qs ? '?' + qs : ''));
      const data = await res.json();
      lastData = data;
      currentPage = 1;
      renderPage(data);

      const alerts = data.filter(r => (r.severity === 'high' || r.severity === 'critical')).slice(0, 10);
      const alertRows = document.getElementById('alertRows');
      if (alertRows) {
        alertRows.innerHTML = alerts.map(r => {
          const sev = r.severity || 'high';
          return '<tr>' +
            '<td>' + new Date(r.ts).toLocaleString() + '</td>' +
            '<td>' + r.event + '</td>' +
            '<td>' + (r.tool || '') + '</td>' +
            '<td><span class=\"badge ' + sev + '\">' + sev + '</span></td>' +
          '</tr>';
        }).join('');
      }

      const total = data.length;
      const high = data.filter(r => (r.severity === 'high' || r.severity === 'critical')).length;
      const medium = data.filter(r => r.severity === 'medium').length;
      const low = data.filter(r => !r.severity || r.severity === 'low').length;
      document.getElementById('sumTotal').textContent = String(total);
      document.getElementById('sumHigh').textContent = String(high);
      document.getElementById('sumMedium').textContent = String(medium);
      document.getElementById('sumLow').textContent = String(low);
      
      const sevHigh = data.filter(r => (r.severity === 'high' || r.severity === 'critical')).length;
      const card=document.getElementById('severityCard');
      if(card){card.dataset.series='High/Critical';card.dataset.value=String(sevHigh);card.dataset.trend='last 60 min';}
      drawSeverityChart(data);
    }

    async function loadSessions() {
      const res = await fetch('/clawsentry/sessions');
      const data = await res.json();
      const rows = document.getElementById('sessions');
      rows.innerHTML = data.map(s => {
        return '<tr>' +
          '<td>' + s.sessionId + '</td>' +
          '<td>' + s.count + '</td>' +
          '<td><button data-session=\"' + s.sessionId + '\">View</button></td>' +
        '</tr>';
      }).join('');
      rows.querySelectorAll('button').forEach(btn => {
        btn.addEventListener('click', () => {
          const sessionId = btn.getAttribute('data-session');
          loadTimeline(sessionId);
          const input = document.getElementById('incidentSession');
          if (input) input.value = sessionId || '';
        });
      });
    }

    async function loadTimeline(sessionId) {
      if (!sessionId) return;
      const res = await fetch('/clawsentry/session?sessionId=' + encodeURIComponent(sessionId));
      const data = await res.json();
      const rows = document.getElementById('timeline');
      rows.innerHTML = data.map(r => {
        const sev = r.severity || 'low';
        const findings = (r.findings || []).join(', ');
        return '<tr>' +
          '<td>' + new Date(r.ts).toLocaleString() + '</td>' +
          '<td>' + r.event + '</td>' +
          '<td>' + (r.tool || '') + '</td>' +
          '<td><span class=\"badge ' + sev + '\">' + sev + '</span></td>' +
          '<td>' + findings + '</td>' +
        '</tr>';
      }).join('');
    }

    function wireHoverChips(){
      const card=document.getElementById('severityCard');
      const chip=document.getElementById('severityChip');
      if(!card||!chip) return;
      card.addEventListener('mousemove',e=>{
        const r=card.getBoundingClientRect();
        chip.style.left=(e.clientX-r.left+8)+'px';
        chip.style.top=(e.clientY-r.top+8)+'px';
        chip.textContent=card.dataset.series?card.dataset.series+': '+card.dataset.value+' ('+card.dataset.trend+')':'';
      });
    }

    function drawSeverityChart(data) {
      const svg = document.getElementById('severityChart');
      if (!svg) return;
      const buckets = 12;
      const now = Date.now();
      const bucketMs = 5 * 60 * 1000;
      const series = new Array(buckets).fill(0).map(() => ({ high:0, medium:0, low:0 }));
      data.forEach(r => {
        const ts = Date.parse(r.ts || '');
        if (!Number.isFinite(ts)) return;
        const age = now - ts;
        if (age < 0 || age > buckets * bucketMs) return;
        const idx = Math.min(buckets - 1, Math.floor(age / bucketMs));
        const sev = r.severity || 'low';
        if (sev === 'high' || sev === 'critical') series[idx].high++;
        else if (sev === 'medium') series[idx].medium++;
        else series[idx].low++;
      });
      const maxVal = Math.max(1, ...series.map(b => b.high + b.medium + b.low));
      const width = 600;
      const height = 80;
      const barW = width / buckets;
      let bars = '';
      for (let i = 0; i < buckets; i++) {
        const x = width - (i + 1) * barW;
        let y = height;
        const hHigh = (series[i].high / maxVal) * (height - 10);
        const hMed = (series[i].medium / maxVal) * (height - 10);
        const hLow = (series[i].low / maxVal) * (height - 10);
        y -= hLow; bars += '<rect x=\"' + (x+2) + '\" y=\"' + y + '\" width=\"' + (barW-4) + '\" height=\"' + hLow + '\" fill=\"#7CFC9A\" />';
        y -= hMed; bars += '<rect x=\"' + (x+2) + '\" y=\"' + y + '\" width=\"' + (barW-4) + '\" height=\"' + hMed + '\" fill=\"#fcd34d\" />';
        y -= hHigh; bars += '<rect x=\"' + (x+2) + '\" y=\"' + y + '\" width=\"' + (barW-4) + '\" height=\"' + hHigh + '\" fill=\"#ff5f56\" />';
      }
      svg.innerHTML = bars;
    }

    function renderScanTable(results) {
      const rows = document.getElementById('scanTable');
      if (!rows) return;
      const entries = Object.entries(results || {});
      rows.innerHTML = entries.map(([skill, files]) => {
        const count = Array.isArray(files) ? files.length : 0;
        const status = count === 0 ? 'clean' : 'suspicious';
        const badge = '<span class=\"badge ' + (status === 'clean' ? 'low' : 'high') + '\">' + status + '</span>';
        return '<tr>' +
          '<td>' + skill + '</td>' +
          '<td>' + badge + '</td>' +
          '<td>' + count + '</td>' +
        '</tr>';
      }).join('');
    }

    async function loadLastScan() {
      const res = await fetch('/clawsentry/scan-last');
      const data = await res.json();
      renderScanTable(data.results || {});
    }

    async function generateIncident(sessionId) {
      if (!sessionId) return;
      const res = await fetch('/clawsentry/incident?sessionId=' + encodeURIComponent(sessionId));
      const data = await res.json();
      const out = document.getElementById('incidentOut');
      out.textContent = data.report || 'No report';
    }

    document.getElementById('apply').addEventListener('click', load);
    document.getElementById('clear').addEventListener('click', () => {
      document.getElementById('severity').value = '';
      document.getElementById('tool').value = '';
      document.getElementById('minutes').value = '';
      load();
    });
    document.getElementById('prevPage').addEventListener('click', () => {
      if (currentPage > 1) { currentPage--; renderPage(lastData); }
    });
    document.getElementById('nextPage').addEventListener('click', () => {
      const maxPage = Math.max(1, Math.ceil(lastData.length / pageSize));
      if (currentPage < maxPage) { currentPage++; renderPage(lastData); }
    });

    document.getElementById('exportJson').addEventListener('click', () => {
      const qs = buildQuery();
      window.open('/clawsentry/export.json' + (qs ? '?' + qs : ''), '_blank');
    });
    document.getElementById('exportCsv').addEventListener('click', () => {
      const qs = buildQuery();
      window.open('/clawsentry/export.csv' + (qs ? '?' + qs : ''), '_blank');
    });

    document.getElementById('savePolicy').addEventListener('click', async () => {
      const denyTools = document.getElementById('denyTools').value.split(',').map(s => s.trim()).filter(Boolean);
      const allowTools = document.getElementById('allowTools').value.split(',').map(s => s.trim()).filter(Boolean);
      const denyFindings = document.getElementById('denyFindings').value.split(',').map(s => s.trim()).filter(Boolean);
      const enforce = document.getElementById('enforce').value === 'true';
      await fetch('/clawsentry/policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ denyTools, allowTools, denyFindings, enforce })
      });
      load();
    });

    document.getElementById('genIncident').addEventListener('click', () => {
      const sessionId = document.getElementById('incidentSession').value.trim();
      generateIncident(sessionId);
    });

    document.getElementById('scanSkillBtn').addEventListener('click', async () => {
      const name = document.getElementById('scanSkill').value.trim();
      const res = await fetch('/clawsentry/scan-skill?name=' + encodeURIComponent(name));
      const data = await res.json();
      renderScanTable({ [data.skill || name]: data.results || [] });
    });
    document.getElementById('scanAllBtn').addEventListener('click', async () => {
      const res = await fetch('/clawsentry/scan');
      const data = await res.json();
      renderScanTable(data.results || {});
    });

    document.getElementById('copyConfig').addEventListener('click', async () => {
      await loadConfig();
      const text = document.getElementById('configOut').textContent || '';
      navigator.clipboard.writeText(text);
    });

    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        const page = item.getAttribute('data-page');
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        item.classList.add('active');
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('page-' + page);
        if (target) target.classList.add('active');
      });
    });

    load();
    loadSessions();
    loadPolicy();
    loadConfig();
    loadLastScan();
    wireHoverChips();
    updateClock();
    setInterval(load, 5000);
    setInterval(loadSessions, 10000);
    setInterval(updateClock, 1000);
  </script>
</body>
</html>`);
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/logs",
    handler: (req, res) => {
      try {
        const url = new URL(req.url ?? "/clawsentry/logs", "http://localhost");
        const severity = url.searchParams.get("severity") || undefined;
        const tool = url.searchParams.get("tool") || undefined;
        const minutes = url.searchParams.get("minutes");
        const since = minutes ? Date.now() - Number(minutes) * 60_000 : undefined;
        const entries = fence.readLatest(200, { severity, tool, since });
        res.setHeader("Content-Type", "application/json; charset=utf-8");
        res.end(JSON.stringify(entries));
      } catch (err) {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: String(err) }));
      }
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/sessions",
    handler: (_req, res) => {
      const entries = fence.readLatest(400, {});
      const counts = new Map<string, number>();
      for (const e of entries) {
        if (!e.sessionId) continue;
        counts.set(e.sessionId, (counts.get(e.sessionId) ?? 0) + 1);
      }
      const list = Array.from(counts.entries()).map(([sessionId, count]) => ({ sessionId, count }));
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(list));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/session",
    handler: (req, res) => {
      const url = new URL(req.url ?? "/clawsentry/session", "http://localhost");
      const sessionId = url.searchParams.get("sessionId") || undefined;
      const entries = fence.readLatest(400, { sessionId });
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify(entries));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/incident",
    handler: (req, res) => {
      const url = new URL(req.url ?? "/clawsentry/incident", "http://localhost");
      const sessionId = url.searchParams.get("sessionId") || undefined;
      const entries = fence.readLatest(400, { sessionId });
      const findings = new Map<string, number>();
      let high = 0, medium = 0, low = 0;
      for (const e of entries) {
        const sev = e.severity || "low";
        if (sev === "high" || sev === "critical") high++;
        else if (sev === "medium") medium++;
        else low++;
        (e.findings || []).forEach((f: string) => findings.set(f, (findings.get(f) ?? 0) + 1));
      }
      const topFindings = Array.from(findings.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([f, n]) => `- ${f} (${n})`)
        .join("\n");
      const report = `Incident Report\nSession: ${sessionId}\n\nSummary:\n- High/Critical: ${high}\n- Medium: ${medium}\n- Low: ${low}\n\nTop findings:\n${topFindings || "- none"}\n\nRecommendations:\n- Review tool calls with high severity\n- Validate sensitive file access findings\n- Tighten policy rules if needed`;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ report }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/scan",
    handler: (_req, res) => {
      const results = scanAllSkills();
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ results }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/scan-last",
    handler: (_req, res) => {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ results: lastScanResults }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/scan-skill",
    handler: (req, res) => {
      const url = new URL(req.url ?? "/clawsentry/scan-skill", "http://localhost");
      const name = url.searchParams.get("name") || "";
      let found: string | null = null;
      for (const base of skillDirs) {
        const p = path.join(base, name);
        if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
          found = p;
          break;
        }
      }
      const results = found ? scanSkillDir(found) : [];
      lastScanResults = { [name]: results };
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ skill: name, path: found, results }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/policy",
    handler: async (req, res) => {
      if (req.method === "POST") {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const parsed = JSON.parse(body || "{}");
            fence.setPolicy(parsed);
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            res.end(JSON.stringify({ ok: true, policy: fence.getPolicy() }));
          } catch (err) {
            res.statusCode = 400;
            res.end(JSON.stringify({ ok: false, error: String(err) }));
          }
        });
        return;
      }

      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ policy: fence.getPolicy() }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/config",
    handler: (_req, res) => {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ config: api.pluginConfig ?? {} }));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/export.json",
    handler: (req, res) => {
      const url = new URL(req.url ?? "/clawsentry/export.json", "http://localhost");
      const severity = url.searchParams.get("severity") || undefined;
      const tool = url.searchParams.get("tool") || undefined;
      const minutes = url.searchParams.get("minutes");
      const since = minutes ? Date.now() - Number(minutes) * 60_000 : undefined;
      const entries = fence.readLatest(200, { severity, tool, since });
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", "attachment; filename=clawsentry.json");
      res.end(JSON.stringify(entries, null, 2));
    },
  });

  api.registerHttpRoute({
    path: "/clawsentry/export.csv",
    handler: (req, res) => {
      const url = new URL(req.url ?? "/clawsentry/export.csv", "http://localhost");
      const severity = url.searchParams.get("severity") || undefined;
      const tool = url.searchParams.get("tool") || undefined;
      const minutes = url.searchParams.get("minutes");
      const since = minutes ? Date.now() - Number(minutes) * 60_000 : undefined;
      const entries = fence.readLatest(200, { severity, tool, since });
      const header = ["ts","event","tool","severity","findings"].join(",") + "\n";
      const lines = entries.map((e: any) => {
        const findings = Array.isArray(e.findings) ? e.findings.join("|") : "";
        return [e.ts, e.event, e.tool ?? "", e.severity ?? "", findings]
          .map((v) => `"${String(v ?? "").replace(/"/g, '""')}"`)
          .join(",");
      });
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", "attachment; filename=clawsentry.csv");
      res.end(header + lines.join("\n"));
    },
  });
}
