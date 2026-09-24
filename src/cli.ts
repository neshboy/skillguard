#!/usr/bin/env node
import * as fs from "fs";
import * as path from "path";
import { Command } from "commander";
import { runAudit, hasBlockingFindings } from "./audit";
import { formatHumanReport } from "./report/format";
import { VERSION } from "./version";

const program = new Command();

program
  .name("skillguard")
  .description("Offline static security auditor for third-party AI-agent skills/plugins.")
  .version(VERSION);

program
  .command("audit")
  .description("Statically audit a skill package directory and print a security report")
  .argument("<path>", "path to the skill package directory to audit")
  .option("-o, --out <file>", "also write the full JSON report to this file")
  .option("--json", "print the JSON report to stdout instead of the human-readable summary")
  .option("--quiet", "print only the summary counts, not per-finding detail")
  .option("--no-color", "disable ANSI colors in human-readable output")
  .action((targetPath: string, options: { out?: string; json?: boolean; quiet?: boolean; color: boolean }) => {
    const absTarget = path.resolve(process.cwd(), targetPath);

    if (!fs.existsSync(absTarget)) {
      console.error(`skillguard: no such file or directory: ${absTarget}`);
      process.exitCode = 2;
      return;
    }
    if (!fs.statSync(absTarget).isDirectory()) {
      console.error(`skillguard: not a directory: ${absTarget}`);
      process.exitCode = 2;
      return;
    }

    let report;
    try {
      report = runAudit(absTarget);
    } catch (err) {
      console.error(`skillguard: audit failed: ${(err as Error).message}`);
      process.exitCode = 2;
      return;
    }

    if (options.out) {
      const outPath = path.resolve(process.cwd(), options.out);
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2), "utf8");
    }

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(formatHumanReport(report, { color: options.color, quiet: options.quiet }));
    }

    process.exitCode = hasBlockingFindings(report) ? 1 : 0;
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err);
  process.exitCode = 2;
});
