import * as fs from "fs";
import * as path from "path";
import { AuditReport, AuditSummary, Finding, severityRank } from "./types";
import { walkDirectory, toRelative } from "./utils/walk";
import { sha256Hex } from "./utils/hash";
import { analyzeJsFile } from "./analyzers/jsAnalyzer";
import { analyzePyFile } from "./analyzers/pyAnalyzer";
import { analyzeTextFile } from "./analyzers/textAnalyzer";
import { analyzeManifest } from "./analyzers/manifestAnalyzer";
import { VERSION } from "./version";

const JS_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const TEXT_EXTENSIONS = new Set([".md", ".markdown", ".mdx", ".yml", ".yaml", ".txt"]);
const PY_EXTENSIONS = new Set([".py"]);

const MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5MB guard against pathological inputs

function computeSummary(findings: Finding[]): AuditSummary {
  const summary: AuditSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  for (const f of findings) {
    summary[f.severity] += 1;
  }
  return summary;
}

/**
 * Run a full SkillGuard audit against a skill package directory and return
 * a structured, tamper-evident report. This is the library entry point
 * used by both the CLI and the test suite.
 */
export function runAudit(targetDirAbs: string): AuditReport {
  const stat = fs.statSync(targetDirAbs);
  if (!stat.isDirectory()) {
    throw new Error(`Audit target is not a directory: ${targetDirAbs}`);
  }

  const { files, skipped } = walkDirectory(targetDirAbs);
  const findings: Finding[] = [...analyzeManifest(targetDirAbs)];
  let filesScanned = 0;

  for (const absFile of files) {
    const rel = toRelative(targetDirAbs, absFile);
    const ext = path.extname(absFile).toLowerCase();

    if (!JS_EXTENSIONS.has(ext) && !TEXT_EXTENSIONS.has(ext) && !PY_EXTENSIONS.has(ext)) {
      continue; // not a source type SkillGuard currently analyzes (assets, lockfiles, binaries, etc.)
    }

    let fileStat: fs.Stats;
    try {
      fileStat = fs.statSync(absFile);
    } catch (err) {
      skipped.push(`${rel} (unreadable: ${(err as Error).message})`);
      continue;
    }
    if (fileStat.size > MAX_FILE_SIZE_BYTES) {
      skipped.push(`${rel} (skipped: file exceeds ${MAX_FILE_SIZE_BYTES} byte scan limit)`);
      continue;
    }

    let source: string;
    try {
      source = fs.readFileSync(absFile, "utf8");
    } catch (err) {
      skipped.push(`${rel} (unreadable: ${(err as Error).message})`);
      continue;
    }

    filesScanned++;

    if (JS_EXTENSIONS.has(ext)) {
      const { findings: f } = analyzeJsFile(rel, source);
      findings.push(...f);
    } else if (PY_EXTENSIONS.has(ext)) {
      findings.push(...analyzePyFile(rel, source));
    } else if (TEXT_EXTENSIONS.has(ext)) {
      findings.push(...analyzeTextFile(rel, source));
    }
  }

  findings.sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byFile = a.file.localeCompare(b.file);
    if (byFile !== 0) return byFile;
    return (a.line ?? 0) - (b.line ?? 0);
  });

  const summary = computeSummary(findings);

  const partial = {
    tool: "skillguard" as const,
    toolVersion: VERSION,
    target: targetDirAbs,
    scannedAt: new Date().toISOString(),
    filesScanned,
    filesSkipped: skipped,
    findings,
    summary,
  };

  const canonical = JSON.stringify(partial);
  const digestValue = sha256Hex(canonical);

  const report: AuditReport = {
    ...partial,
    digest: {
      algorithm: "sha256",
      value: digestValue,
      note:
        "SHA-256 digest of this report's JSON contents (every field above `digest`), for tamper-evidence only. " +
        "This is NOT a cryptographic signature: it does not prove who generated the report or attest to any " +
        "identity/key, it only lets you detect whether these exact report contents were altered after generation.",
    },
  };

  return report;
}

/** True if the report contains at least one high or critical severity finding. */
export function hasBlockingFindings(report: AuditReport): boolean {
  return report.summary.critical > 0 || report.summary.high > 0;
}
