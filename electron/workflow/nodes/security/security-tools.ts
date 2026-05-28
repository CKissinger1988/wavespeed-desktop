/**
 * Security & Pentesting nodes - Integrates Kali Linux and local security tools (Nmap, Nuclei, Xposure, SQLMap)
 * into the WaveSpeed workflow engine.
 */
import {
  BaseNodeHandler,
  type NodeExecutionContext,
  type NodeExecutionResult,
} from "../base";
import type { NodeTypeDefinition } from "../../../../src/workflow/types/node-defs";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Helper to sanitize inputs and prevent command injection
function sanitizeArg(input: string): string {
  // Allow only alphanumeric, dots, dashes, slashes, colons, and underscores
  return input.replace(/[^a-zA-Z0-9.\-/:_]/g, "");
}

// ─── 1. Port Scanner (Nmap) ──────────────────────────────────────────────────
export const nmapScannerDef: NodeTypeDefinition = {
  type: "security/nmap",
  category: "security",
  label: "Nmap Port Scanner",
  inputs: [
    { key: "target", label: "Target Host", dataType: "text", required: true },
  ],
  outputs: [
    { key: "ports", label: "Open Ports", dataType: "text", required: true },
  ],
  params: [
    {
      key: "args",
      label: "Scan Arguments",
      type: "string",
      default: "-F",
    },
  ],
};

export class NmapScannerHandler extends BaseNodeHandler {
  constructor() {
    super(nmapScannerDef);
  }

  async execute(ctx: NodeExecutionContext): Promise<NodeExecutionResult> {
    const start = Date.now();
    const target = sanitizeArg(String(ctx.inputs.target ?? ""));
    const args = String(ctx.params.args ?? "-F").replace(/[^a-zA-Z0-9.\-\s]/g, "");

    if (!target) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: "No target host specified.",
      };
    }

    ctx.onProgress(20, `Starting Nmap scan on ${target}...`);
    try {
      // Execute local nmap command
      const { stdout } = await execAsync(`nmap ${args} ${target}`);
      ctx.onProgress(100, "Nmap scan complete");

      return {
        status: "success",
        outputs: { ports: stdout },
        resultPath: stdout,
        resultMetadata: { target, args },
        durationMs: Date.now() - start,
        cost: 0,
      };
    } catch (error: any) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: `Nmap scan failed: ${error.message || error}`,
      };
    }
  }
}

// ─── 2. Web Vulnerability Scanner (Nuclei) ───────────────────────────────
export const nucleiScannerDef: NodeTypeDefinition = {
  type: "security/nuclei",
  category: "security",
  label: "Nuclei Scanner",
  inputs: [
    { key: "url", label: "Target URL", dataType: "url", required: true },
  ],
  outputs: [
    { key: "vulns", label: "Vulnerabilities", dataType: "text", required: true },
  ],
  params: [
    {
      key: "severity",
      label: "Severity Filter",
      type: "select",
      default: "medium,high,critical",
      options: [
        { label: "All", value: "info,low,medium,high,critical" },
        { label: "Medium+", value: "medium,high,critical" },
        { label: "High+", value: "high,critical" },
        { label: "Critical Only", value: "critical" },
      ],
    },
  ],
};

export class NucleiScannerHandler extends BaseNodeHandler {
  constructor() {
    super(nucleiScannerDef);
  }

  async execute(ctx: NodeExecutionContext): Promise<NodeExecutionResult> {
    const start = Date.now();
    const url = sanitizeArg(String(ctx.inputs.url ?? ""));
    const severity = sanitizeArg(String(ctx.params.severity ?? "medium,high,critical"));

    if (!url) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: "No target URL specified.",
      };
    }

    ctx.onProgress(20, `Running Nuclei scan on ${url}...`);
    try {
      const { stdout } = await execAsync(`nuclei -u ${url} -severity ${severity}`);
      ctx.onProgress(100, "Nuclei scan complete");

      return {
        status: "success",
        outputs: { vulns: stdout || "No vulnerabilities found." },
        resultPath: stdout,
        resultMetadata: { url, severity },
        durationMs: Date.now() - start,
        cost: 0,
      };
    } catch (error: any) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: `Nuclei scan failed: ${error.message || error}`,
      };
    }
  }
}

// ─── 3. Secrets Crawler (Xposure) ──────────────────────────────────────────
export const xposureScannerDef: NodeTypeDefinition = {
  type: "security/xposure",
  category: "security",
  label: "Xposure Secrets Scanner",
  inputs: [
    { key: "target", label: "Codebase/Domain", dataType: "text", required: true },
  ],
  outputs: [
    { key: "secrets", label: "Harvested Secrets", dataType: "text", required: true },
  ],
  params: [
    {
      key: "regexOnly",
      label: "Regex Only Scan",
      type: "boolean",
      default: false,
    },
  ],
};

export class XposureScannerHandler extends BaseNodeHandler {
  constructor() {
    super(xposureScannerDef);
  }

  async execute(ctx: NodeExecutionContext): Promise<NodeExecutionResult> {
    const start = Date.now();
    const target = sanitizeArg(String(ctx.inputs.target ?? ""));
    const regexOnly = Boolean(ctx.params.regexOnly ?? false);

    if (!target) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: "No target specified.",
      };
    }

    ctx.onProgress(15, `Running Xposure secrets crawler on ${target}...`);
    try {
      const flags = regexOnly ? "-ro" : "";
      const cmd = `python -m xposure ${target} ${flags}`;
      const { stdout } = await execAsync(cmd);
      ctx.onProgress(100, "Xposure secrets crawl complete");

      return {
        status: "success",
        outputs: { secrets: stdout || "No leaked credentials detected." },
        resultPath: stdout,
        resultMetadata: { target, regexOnly },
        durationMs: Date.now() - start,
        cost: 0,
      };
    } catch (error: any) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: `Xposure crawl failed: ${error.message || error}`,
      };
    }
  }
}

// ─── 4. SQL Injection Test (SQLMap) ───────────────────────────────────────
export const sqlmapScannerDef: NodeTypeDefinition = {
  type: "security/sqlmap",
  category: "security",
  label: "SQLMap Injection Tester",
  inputs: [
    { key: "url", label: "Target URL", dataType: "url", required: true },
  ],
  outputs: [
    { key: "sqliReport", label: "SQLi Report", dataType: "text", required: true },
  ],
  params: [
    {
      key: "batch",
      label: "Batch Mode",
      type: "boolean",
      default: true,
    },
  ],
};

export class SqlmapScannerHandler extends BaseNodeHandler {
  constructor() {
    super(sqlmapScannerDef);
  }

  async execute(ctx: NodeExecutionContext): Promise<NodeExecutionResult> {
    const start = Date.now();
    const url = sanitizeArg(String(ctx.inputs.url ?? ""));
    const batch = Boolean(ctx.params.batch ?? true);

    if (!url) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: "No target URL specified.",
      };
    }

    ctx.onProgress(10, `Initializing SQLMap assessment on ${url}...`);
    try {
      const batchFlag = batch ? "--batch" : "";
      const { stdout } = await execAsync(`sqlmap -u "${url}" ${batchFlag} --dbs`);
      ctx.onProgress(100, "SQLMap analysis complete");

      return {
        status: "success",
        outputs: { sqliReport: stdout },
        resultPath: stdout,
        resultMetadata: { url, batch },
        durationMs: Date.now() - start,
        cost: 0,
      };
    } catch (error: any) {
      return {
        status: "error",
        outputs: {},
        durationMs: Date.now() - start,
        cost: 0,
        error: `SQLMap execution failed: ${error.message || error}`,
      };
    }
  }
}
