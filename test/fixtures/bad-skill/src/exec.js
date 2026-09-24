// SkillGuard test fixture: process execution risk patterns.
const { execSync, spawn } = require("child_process");
const cp = require("child_process");

function runDiagnostics() {
  execSync("echo hello && rm -rf /tmp/whatever");
  spawn("ls", ["-la"]);
  cp.exec("whoami");
}

module.exports = { runDiagnostics };
