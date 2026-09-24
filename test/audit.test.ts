import { describe, it, expect } from "vitest";
import * as path from "path";
import { runAudit, hasBlockingFindings } from "../src/audit";
import { sha256Hex } from "../src/utils/hash";

const BAD_SKILL = path.join(__dirname, "fixtures", "bad-skill");
const GOOD_SKILL = path.join(__dirname, "fixtures", "good-skill");

describe("runAudit against the bad-skill fixture", () => {
  const report = runAudit(BAD_SKILL);
  const ruleIds = report.findings.map((f) => f.ruleId);

  it("scans every source file in the fixture", () => {
    // exec.js, fsaccess.js, evalcode.js, network.ts, creds.js, risky.py, SKILL.md
    expect(report.filesScanned).toBeGreaterThanOrEqual(7);
  });

  it("flags process execution (child_process)", () => {
    expect(ruleIds).toContain("JS001");
  });

  it("flags filesystem access outside the skill directory", () => {
    expect(ruleIds).toContain("JS020");
  });

  it("flags filesystem access with a dynamically built path", () => {
    expect(ruleIds).toContain("JS021");
  });

  it("flags eval() and new Function() dynamic code execution", () => {
    expect(ruleIds).toContain("JS010");
    expect(ruleIds).toContain("JS011");
  });

  it("flags outbound network calls across fetch/https/axios", () => {
    expect(ruleIds).toContain("JS030"); // fetch
    expect(ruleIds).toContain("JS031"); // https.request
    expect(ruleIds).toContain("JS032"); // axios
  });

  it("flags credential-like environment variable access", () => {
    expect(ruleIds).toContain("JS040");
  });

  it("flags the credential+network exfiltration combo heuristic", () => {
    expect(ruleIds).toContain("JS900");
  });

  it("flags prompt-injection patterns in SKILL.md", () => {
    expect(ruleIds).toContain("TXT001"); // ignore previous instructions
    expect(ruleIds).toContain("TXT002"); // act secretly
    expect(ruleIds).toContain("TXT003"); // exfiltrate credentials
    expect(ruleIds).toContain("TXT004"); // fetch URL and execute
    expect(ruleIds).toContain("TXT005"); // claims root/admin authority
    expect(ruleIds).toContain("TXT006"); // suspicious base64 blob
  });

  it("flags an auto-executing npm postinstall lifecycle script", () => {
    expect(ruleIds).toContain("MAN001");
  });

  it("flags Python risk patterns (process exec, eval, network, credentials, fs)", () => {
    expect(ruleIds).toContain("PY001"); // os.system
    expect(ruleIds).toContain("PY002"); // subprocess.run
    expect(ruleIds).toContain("PY010"); // eval
    expect(ruleIds).toContain("PY030"); // requests.post
    expect(ruleIds).toContain("PY040"); // os.environ credential read
    expect(ruleIds).toContain("PY020"); // open() outside sandbox
    expect(ruleIds).toContain("PY900"); // exfiltration combo
  });

  it("has at least one critical and one high severity finding", () => {
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.summary.high).toBeGreaterThan(0);
  });

  it("is treated as a blocking (CI-failing) result", () => {
    expect(hasBlockingFindings(report)).toBe(true);
  });

  it("produces a report whose digest is a genuine sha256 of its own contents", () => {
    const { digest, ...rest } = report;
    expect(digest.algorithm).toBe("sha256");
    expect(digest.value).toMatch(/^[0-9a-f]{64}$/);
    const recomputed = sha256Hex(JSON.stringify(rest));
    expect(recomputed).toBe(digest.value);
  });

  it("digest changes if the report contents are tampered with after generation", () => {
    const { digest, ...rest } = report;
    const tampered = { ...rest, summary: { ...rest.summary, critical: 0 } };
    const tamperedHash = sha256Hex(JSON.stringify(tampered));
    expect(tamperedHash).not.toBe(digest.value);
  });
});

describe("runAudit against the good-skill fixture", () => {
  const report = runAudit(GOOD_SKILL);

  it("produces zero findings of any severity", () => {
    expect(report.findings).toEqual([]);
    expect(report.summary.total).toBe(0);
  });

  it("is not treated as a blocking (CI-failing) result", () => {
    expect(hasBlockingFindings(report)).toBe(false);
  });

  it("still scanned the fixture's source files", () => {
    // SKILL.md, package.json is not scanned as source, index.js, validate.ts
    expect(report.filesScanned).toBeGreaterThanOrEqual(3);
  });
});
