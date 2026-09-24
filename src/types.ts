/**
 * Shared types for SkillGuard findings and reports.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Order used for sorting/severity comparisons, highest risk first. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export type FindingCategory =
  | "process-execution"
  | "dynamic-code-execution"
  | "filesystem-access"
  | "network-access"
  | "credential-access"
  | "possible-exfiltration"
  | "install-script"
  | "prompt-injection"
  | "manifest";

export interface Finding {
  /** Stable machine-readable rule id, e.g. "JS001". */
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  /** Path to the offending file, relative to the audited skill directory. */
  file: string;
  /** 1-based line number, when known. */
  line?: number;
  /** 1-based column number, when known. */
  column?: number;
  /** Short human-readable title. */
  title: string;
  /** Plain-English explanation of the risk and why it was flagged. */
  message: string;
  /** The offending source excerpt, when available. */
  snippet?: string;
}

export interface FileScanResult {
  file: string;
  findings: Finding[];
  /** Set when the file could not be parsed/scanned at all. */
  error?: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface AuditReport {
  tool: "skillguard";
  toolVersion: string;
  /** Absolute path that was audited, for local reference only (not shipped in digest-sensitive contexts). */
  target: string;
  scannedAt: string;
  filesScanned: number;
  filesSkipped: string[];
  findings: Finding[];
  summary: AuditSummary;
  /**
   * Content digest of this report. This is a SHA-256 hash of the report's
   * JSON contents (everything above this field), NOT a cryptographic
   * signature tied to any identity or key. It only proves the report was
   * not altered after generation -- it does not prove who generated it.
   */
  digest: {
    algorithm: "sha256";
    value: string;
    note: string;
  };
}
