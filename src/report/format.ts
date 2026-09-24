import chalk from "chalk";
import { AuditReport, Finding, Severity } from "../types";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function colorFor(severity: Severity, text: string, color: boolean): string {
  if (!color) return text;
  switch (severity) {
    case "critical":
      return chalk.bgRed.white.bold(text);
    case "high":
      return chalk.red.bold(text);
    case "medium":
      return chalk.yellow(text);
    case "low":
      return chalk.cyan(text);
    case "info":
      return chalk.gray(text);
    default:
      return text;
  }
}

function formatFinding(f: Finding, color: boolean): string {
  const location = f.line ? `${f.file}:${f.line}${f.column ? `:${f.column}` : ""}` : f.file;
  const badge = colorFor(f.severity, `[${SEVERITY_LABEL[f.severity]}]`, color);
  const lines = [`${badge} ${location} -- ${f.title}`, `    rule: ${f.ruleId} (${f.category})`, `    ${f.message}`];
  if (f.snippet) {
    lines.push(`    > ${f.snippet}`);
  }
  return lines.join("\n");
}

/**
 * Render an AuditReport as a human-readable, terminal-friendly summary.
 */
export function formatHumanReport(report: AuditReport, opts: { color?: boolean; quiet?: boolean } = {}): string {
  const color = opts.color ?? true;
  const quiet = opts.quiet ?? false;
  const out: string[] = [];

  out.push(color ? chalk.bold("SkillGuard audit report") : "SkillGuard audit report");
  out.push(`target:      ${report.target}`);
  out.push(`scanned at:  ${report.scannedAt}`);
  out.push(`files:       ${report.filesScanned} scanned, ${report.filesSkipped.length} skipped`);
  out.push("");

  const s = report.summary;
  out.push(
    [
      colorFor("critical", `critical: ${s.critical}`, color),
      colorFor("high", `high: ${s.high}`, color),
      colorFor("medium", `medium: ${s.medium}`, color),
      colorFor("low", `low: ${s.low}`, color),
      colorFor("info", `info: ${s.info}`, color),
    ].join("   "),
  );
  out.push("");

  if (report.findings.length === 0) {
    out.push("No findings. (Static analysis has limits -- see README 'Limitations'. This is not a guarantee of safety.)");
  } else if (!quiet) {
    out.push("Findings (highest severity first):");
    out.push("");
    for (const f of report.findings) {
      out.push(formatFinding(f, color));
      out.push("");
    }
  }

  out.push(`report digest (sha256): ${report.digest.value}`);
  out.push(`  ^ ${report.digest.note}`);

  return out.join("\n");
}
