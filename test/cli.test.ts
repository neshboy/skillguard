import { describe, it, expect } from "vitest";
import * as path from "path";
import { execFileSync } from "child_process";
import * as fs from "fs";

const CLI = path.join(__dirname, "..", "dist", "cli.js");
const BAD_SKILL = path.join(__dirname, "fixtures", "bad-skill");
const GOOD_SKILL = path.join(__dirname, "fixtures", "good-skill");

function runCli(args: string[]): { status: number; stdout: string } {
  try {
    const stdout = execFileSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
    return { status: 0, stdout };
  } catch (err) {
    const e = err as { status: number; stdout: string };
    return { status: e.status, stdout: e.stdout };
  }
}

describe("compiled CLI binary (dist/cli.js)", () => {
  it("the build actually produced dist/cli.js", () => {
    expect(fs.existsSync(CLI)).toBe(true);
  });

  it("exits non-zero and prints JSON findings for the bad-skill fixture", () => {
    const { status, stdout } = runCli(["audit", BAD_SKILL, "--json", "--no-color"]);
    expect(status).toBe(1);
    const report = JSON.parse(stdout);
    expect(report.summary.critical).toBeGreaterThan(0);
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("exits zero for the good-skill fixture", () => {
    const { status, stdout } = runCli(["audit", GOOD_SKILL, "--json", "--no-color"]);
    expect(status).toBe(0);
    const report = JSON.parse(stdout);
    expect(report.summary.critical).toBe(0);
    expect(report.summary.high).toBe(0);
  });

  it("exits with code 2 for a non-existent path", () => {
    const { status } = runCli(["audit", path.join(__dirname, "no-such-directory")]);
    expect(status).toBe(2);
  });
});
