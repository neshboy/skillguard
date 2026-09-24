import * as fs from "fs";
import * as path from "path";
import { Finding } from "../types";

const KNOWN_MANIFEST_FILES = ["SKILL.md", "skill.md", "manifest.json", "plugin.json"];

const INSTALL_SCRIPT_KEYS = ["preinstall", "install", "postinstall"];

/**
 * Inspect the top level of a skill directory for manifest/metadata risk
 * signals: npm lifecycle scripts (a well-known supply-chain attack vector,
 * since npm runs them automatically on `npm install`) and whether any
 * recognizable skill manifest is present at all.
 */
export function analyzeManifest(rootDir: string): Finding[] {
  const findings: Finding[] = [];

  const packageJsonPath = path.join(rootDir, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    try {
      const raw = fs.readFileSync(packageJsonPath, "utf8");
      const pkg = JSON.parse(raw);
      const scripts = pkg.scripts ?? {};
      for (const key of INSTALL_SCRIPT_KEYS) {
        if (typeof scripts[key] === "string" && scripts[key].trim().length > 0) {
          findings.push({
            ruleId: "MAN001",
            category: "install-script",
            severity: "high",
            file: "package.json",
            title: `Auto-executing npm lifecycle script ("${key}")`,
            message: `package.json defines a "${key}" script ("${scripts[key]}"). npm/pnpm/yarn run this automatically during install with no prompt, which is one of the most common real-world supply-chain attack vectors -- malicious packages use lifecycle scripts to run arbitrary code the moment they're installed, before any of the skill's own code is even invoked. Review this command carefully.`,
          });
        }
      }
    } catch (err) {
      findings.push({
        ruleId: "MAN002",
        category: "manifest",
        severity: "info",
        file: "package.json",
        title: "package.json could not be parsed",
        message: `Found a package.json but it is not valid JSON (${(err as Error).message}). Lifecycle-script checks were skipped for this file.`,
      });
    }
  }

  const hasKnownManifest = KNOWN_MANIFEST_FILES.some((name) => fs.existsSync(path.join(rootDir, name)));
  if (!hasKnownManifest) {
    findings.push({
      ruleId: "MAN010",
      category: "manifest",
      severity: "info",
      file: ".",
      title: "No recognized skill manifest found",
      message: `SkillGuard did not find a SKILL.md, manifest.json, or plugin.json at the top level of "${rootDir}". SkillGuard still scanned all source files it found, but double-check this is actually the root of a skill package.`,
    });
  }

  return findings;
}
