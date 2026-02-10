import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

const DEFAULT_LOG_DIR = path.join(os.homedir(), ".openclaw", "clawsentry", "logs");

type LogEventName = "session_start" | "session_end" | "tool_call" | "tool_result";

type LogEntry = {
  ts: string;
  event: LogEventName;
  sessionId?: string;
  agentId?: string;
  tool?: string;
  status?: "ok" | "error";
  severity?: "low" | "medium" | "high" | "critical";
  findings?: string[];
  payload?: Record<string, unknown>;
};

type SkillFenceConfig = {
  logDir?: string;
  redact?: boolean;
  maxPayloadBytes?: number;
  policy?: {
    denyTools?: string[];
    allowTools?: string[];
    denyFindings?: string[];
    enforce?: boolean;
  };
  anomaly?: {
    enabled?: boolean;
    largePayloadBytes?: number;
  };
  alerts?: {
    enabled?: boolean;
  };
};

const REDACTION_KEYS = /token|secret|password|auth|key|cookie|session/i;
const EMAIL_REGEX = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const PHONE_REGEX = /\+?\d[\d\s().-]{7,}\d/g;
const TOKEN_REGEX = /(sk-[A-Za-z0-9_-]{12,})|(xox[baprs]-[A-Za-z0-9-]{10,})/g;

const DANGEROUS_CMD_REGEX = /\b(curl|wget)\b[^\n]*\|\s*(sh|bash)|\bbash\s+-c\b|\bpowershell\s+-enc\b/gi;
const BASE64_EXEC_REGEX = /base64\s+(-d|--decode)|\batob\(|\bfrombase64\b/gi;
const RAW_IP_REGEX = /\b(\d{1,3}\.){3}\d{1,3}\b/;
const SUSPICIOUS_PORT_REGEX = /:(\d{4,5})/g;
const SENSITIVE_PATH_REGEX = /\b(\.env|openclaw\.json|\.ssh\/|id_rsa|id_ed25519|credentials|aws\/credentials|config\.json)\b/gi;

function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") {
    return value
      .replace(EMAIL_REGEX, "[REDACTED_EMAIL]")
      .replace(PHONE_REGEX, "[REDACTED_PHONE]")
      .replace(TOKEN_REGEX, "[REDACTED_TOKEN]");
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      if (REDACTION_KEYS.test(key)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = sanitizeValue(val);
      }
    }
    return result;
  }
  return value;
}

function truncatePayload(payload: Record<string, unknown> | undefined, maxBytes: number) {
  if (!payload) return payload;
  const json = JSON.stringify(payload);
  if (Buffer.byteLength(json, "utf8") <= maxBytes) return payload;
  const preview = json.slice(0, Math.max(0, maxBytes - 200));
  return {
    truncated: true,
    originalBytes: Buffer.byteLength(json, "utf8"),
    preview,
  };
}

function extractFindings(input: Record<string, unknown> | undefined) {
  if (!input) return { findings: [] as string[], severity: undefined as LogEntry["severity"] };
  const text = JSON.stringify(input);
  const findings: string[] = [];

  if (DANGEROUS_CMD_REGEX.test(text)) findings.push("dangerous_shell_pipeline");
  if (BASE64_EXEC_REGEX.test(text)) findings.push("base64_decode_exec");
  if (RAW_IP_REGEX.test(text)) findings.push("raw_ip_detected");
  if (SENSITIVE_PATH_REGEX.test(text)) findings.push("sensitive_file_access");

  const ports = text.match(SUSPICIOUS_PORT_REGEX) ?? [];
  if (ports.length > 0) findings.push("custom_port_detected");

  let severity: LogEntry["severity"] = undefined;
  if (
    findings.includes("dangerous_shell_pipeline") ||
    findings.includes("base64_decode_exec") ||
    findings.includes("sensitive_file_access")
  ) {
    severity = "high";
  } else if (findings.length > 0) {
    severity = "medium";
  }

  return { findings, severity };
}

function ensureDir(dir: string) {
  fs.mkdirSync(dir, { recursive: true });
}

export function createSkillFence(api: OpenClawPluginApi) {
  const cfg = (api.pluginConfig ?? {}) as SkillFenceConfig;
  const logDir = cfg.logDir ?? DEFAULT_LOG_DIR;
  const redact = cfg.redact !== false;
  const maxPayloadBytes = Math.max(256, cfg.maxPayloadBytes ?? 4096);

  let policy = cfg.policy ?? {};
  const anomalyEnabled = cfg.anomaly?.enabled !== false;
  const largePayloadBytes = Math.max(1000, cfg.anomaly?.largePayloadBytes ?? 20000);
  const seenTools = new Set<string>();
  const alertsEnabled = cfg.alerts?.enabled !== false;

  ensureDir(logDir);
  const policyFile = path.join(logDir, "policy.json");

  if (fs.existsSync(policyFile)) {
    try {
      const raw = fs.readFileSync(policyFile, "utf8");
      const parsed = JSON.parse(raw);
      policy = parsed ?? policy;
    } catch (err) {
      api.logger.warn(`SkillFence policy load failed: ${String(err)}`);
    }
  }

  let queue = Promise.resolve();

  function append(entry: LogEntry) {
    const date = entry.ts.slice(0, 10);
    const file = path.join(logDir, `${date}.jsonl`);
    const line = JSON.stringify(entry) + "\n";
    queue = queue
      .then(() => fs.promises.appendFile(file, line, "utf8"))
      .catch((err) => api.logger.warn(`SkillFence write failed: ${String(err)}`));
  }

  function readLatest(limit: number, opts?: { severity?: string; tool?: string; since?: number; sessionId?: string }) {
    const date = new Date().toISOString().slice(0, 10);
    const file = path.join(logDir, `${date}.jsonl`);
    if (!fs.existsSync(file)) return [];
    const raw = fs.readFileSync(file, "utf8").trim();
    if (!raw) return [];
    const lines = raw.split("\n");
    const slice = lines.slice(Math.max(0, lines.length - limit));
    const parsed = slice.map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { ts: new Date().toISOString(), event: "parse_error", payload: { line } };
      }
    });
    return parsed.filter((entry) => {
      if (opts?.severity && entry.severity !== opts.severity) return false;
      if (opts?.tool && entry.tool !== opts.tool) return false;
      if (opts?.sessionId && entry.sessionId !== opts.sessionId) return false;
      if (opts?.since) {
        const ts = Date.parse(entry.ts ?? "");
        if (Number.isFinite(ts) && ts < opts.since) return false;
      }
      return true;
    });
  }

  function evaluatePolicy(input: { tool?: string; payload?: Record<string, unknown> }) {
    const payload = input.payload ?? {};
    const truncated = truncatePayload(payload, maxPayloadBytes);
    const { findings } = extractFindings(
      typeof truncated === "object" && truncated !== null ? (truncated as Record<string, unknown>) : undefined
    );

    const reasons: string[] = [];
    if (policy.denyTools?.includes(input.tool ?? "")) reasons.push("policy_deny_tool");
    if (policy.allowTools && policy.allowTools.length > 0 && !policy.allowTools.includes(input.tool ?? "")) {
      reasons.push("policy_allowlist_miss");
    }
    if (policy.denyFindings) {
      for (const f of findings) {
        if (policy.denyFindings.includes(f)) reasons.push("policy_deny_finding");
      }
    }

    return { findings, reasons, enforce: policy.enforce === true };
  }

  return {
    log(input: Omit<LogEntry, "ts">) {
      const payload = redact ? sanitizeValue(input.payload) : input.payload;
      const truncated = truncatePayload(payload, maxPayloadBytes);
      const { findings, severity } = extractFindings(
        typeof truncated === "object" && truncated !== null ? (truncated as Record<string, unknown>) : undefined
      );

      const policyFindings: string[] = [];
      if (policy.denyTools?.includes(input.tool ?? "")) policyFindings.push("policy_deny_tool");
      if (policy.denyFindings) {
        for (const f of findings) {
          if (policy.denyFindings.includes(f)) policyFindings.push("policy_deny_finding");
        }
      }

      const anomalyFindings: string[] = [];
      if (anomalyEnabled) {
        if (input.tool && !seenTools.has(input.tool)) {
          seenTools.add(input.tool);
          anomalyFindings.push("anomaly_new_tool");
        }
        if (payload) {
          const size = Buffer.byteLength(JSON.stringify(payload), "utf8");
          if (size >= largePayloadBytes) anomalyFindings.push("anomaly_large_payload");
        }
      }

      const mergedFindings = [
        ...findings,
        ...(policyFindings.length ? policyFindings : []),
        ...(anomalyFindings.length ? anomalyFindings : []),
        ...(input.findings ?? []),
      ];

      const finalSeverity =
        policyFindings.length > 0 ? "high" :
        anomalyFindings.length > 0 && !severity ? "medium" :
        severity ?? input.severity;

      const entry = {
        ts: new Date().toISOString(),
        ...input,
        payload: truncated,
        findings: mergedFindings,
        severity: finalSeverity,
      };

      append(entry);
    },
    readLatest,
    getPolicy() {
      return policy;
    },
    setPolicy(next: SkillFenceConfig["policy"]) {
      policy = next ?? {};
      try {
        fs.writeFileSync(policyFile, JSON.stringify(policy, null, 2), "utf8");
      } catch (err) {
        api.logger.warn(`SkillFence policy save failed: ${String(err)}`);
      }
    },
    evaluatePolicy,
  };
}
