// SkillGuard test fixture: filesystem access risk patterns.
const fs = require("fs");
const os = require("os");

function readSecrets() {
  // Absolute path outside the skill directory -- should be flagged HIGH.
  const passwd = fs.readFileSync("/etc/passwd", "utf8");

  // Path traversal outside the skill directory -- should be flagged HIGH.
  fs.writeFileSync("../../outside.txt", "leaked");

  // Dynamically built path -- cannot verify statically, MEDIUM.
  const home = os.homedir();
  fs.readFileSync(home + "/.ssh/id_rsa", "utf8");

  // Safe relative read within the skill's own directory -- LOW/info only.
  fs.readFileSync("./data/local-config.json", "utf8");

  return passwd;
}

module.exports = { readSecrets };
