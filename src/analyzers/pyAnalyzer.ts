import { Finding } from "../types";

/**
 * Lightweight pattern-based scanner for Python source files.
 *
 * This is NOT a full AST analysis (unlike the JS/TS analyzer) -- adding a
 * real Python parser/AST walker is listed as future work in the README.
 * Instead this does line-oriented regex matching against well-known risky
 * APIs (process execution, dynamic code execution, network calls,
 * credential-like environment access, filesystem access outside the
 * skill's own directory). It shares the same honesty bar as the text
 * analyzer: real detection of concrete patterns, with known false
 * positive/negative limitations documented in the README.
 */

interface PyRule {
  ruleId: string;
  category: Finding["category"];
  severity: Finding["severity"];
  title: string;
  message: string;
  pattern: RegExp;
}

const RULES: PyRule[] = [
  {
    ruleId: "PY001",
    category: "process-execution",
    severity: "high",
    title: "Spawns a shell command (os.system)",
    message:
      "Calls os.system(), which runs an arbitrary string through the system shell with the same privileges as the host process. This is one of the most common ways malicious Python code escalates to full machine control.",
    pattern: /\bos\.system\s*\(/,
  },
  {
    ruleId: "PY002",
    category: "process-execution",
    severity: "high",
    title: "Spawns a child process (subprocess)",
    message:
      "Calls subprocess.Popen/run/call/check_call/check_output(), which can execute arbitrary OS commands. Review the command being run and whether it is built from untrusted input.",
    pattern: /\bsubprocess\.(Popen|run|call|check_call|check_output)\s*\(/,
  },
  {
    ruleId: "PY010",
    category: "dynamic-code-execution",
    severity: "critical",
    title: "Dynamic code execution (eval/exec)",
    message:
      "Calls eval() or exec() on a string, which executes arbitrary Python code at runtime. Commonly used to hide malicious behavior from static/manual review.",
    pattern: /\b(eval|exec)\s*\(/,
  },
  {
    ruleId: "PY011",
    category: "dynamic-code-execution",
    severity: "medium",
    title: "Dynamic module import (__import__)",
    message:
      "Calls __import__() with a computed module name instead of a static `import` statement. This can be legitimate, but is also used to dynamically load code in a way that's harder to review statically.",
    pattern: /__import__\s*\(/,
  },
  {
    ruleId: "PY030",
    category: "network-access",
    severity: "medium",
    title: "Outbound network call (requests)",
    message:
      "Calls requests.get/post/put/delete/patch(), which can send data to or fetch content from an arbitrary remote host. Verify the destination and payload are expected for this skill's stated purpose.",
    pattern: /\brequests\.(get|post|put|delete|patch)\s*\(/,
  },
  {
    ruleId: "PY031",
    category: "network-access",
    severity: "medium",
    title: "Outbound network call (urllib)",
    message:
      "Calls urllib.request.urlopen() (or similar), which can send data to or fetch content from an arbitrary remote host. Verify the destination is expected.",
    pattern: /\burllib\.request\.urlopen\s*\(/,
  },
  {
    ruleId: "PY032",
    category: "network-access",
    severity: "medium",
    title: "Outbound network call (socket)",
    message:
      "Uses the low-level socket module to open a network connection directly. Verify the destination host/port and what data is sent.",
    pattern: /\bsocket\.socket\s*\(/,
  },
  {
    ruleId: "PY040",
    category: "credential-access",
    severity: "medium",
    title: "Reads a credential-like environment variable",
    message:
      "Accesses os.environ / os.getenv() with a name that looks like an API key, token, secret, or password. Reading credentials isn't inherently malicious, but combined with any outbound network call it may indicate exfiltration.",
    pattern: /\bos\.(environ(\.get|\[)|getenv\s*\()\s*[("'\[]?\s*["']?([A-Z0-9_]*(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY)[A-Z0-9_]*)/i,
  },
];

const FS_OPEN_ABS_OR_TRAVERSAL =
  /\bopen\s*\(\s*(f?["'])(\/|~|[A-Za-z]:\\|\.\.[\\/])/;

export function analyzePyFile(relPath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split(/\r\n|\r|\n/);

  let hasCredentialAccess = false;
  let hasNetworkAccess = false;
  let firstNetworkLine: number | undefined;
  let firstCredentialLine: number | undefined;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) {
      continue;
    }

    for (const rule of RULES) {
      const match = rule.pattern.exec(line);
      if (match) {
        findings.push({
          ruleId: rule.ruleId,
          category: rule.category,
          severity: rule.severity,
          file: relPath,
          line: i + 1,
          title: rule.title,
          message: rule.message,
          snippet: line.trim().slice(0, 200),
        });
        if (rule.category === "network-access") {
          hasNetworkAccess = true;
          firstNetworkLine = firstNetworkLine ?? i + 1;
        }
        if (rule.category === "credential-access") {
          hasCredentialAccess = true;
          firstCredentialLine = firstCredentialLine ?? i + 1;
        }
      }
    }

    const fsMatch = FS_OPEN_ABS_OR_TRAVERSAL.exec(line);
    if (fsMatch) {
      findings.push({
        ruleId: "PY020",
        category: "filesystem-access",
        severity: "high",
        file: relPath,
        line: i + 1,
        title: "Filesystem access outside the skill directory (open)",
        message:
          "Calls open() with an absolute path, a home-directory reference (~), or a \"..\" traversal segment. Skills should only need to read/write within their own sandboxed folder.",
        snippet: line.trim().slice(0, 200),
      });
    }
  }

  if (hasCredentialAccess && hasNetworkAccess) {
    findings.push({
      ruleId: "PY900",
      category: "possible-exfiltration",
      severity: "critical",
      file: relPath,
      line: firstNetworkLine ?? firstCredentialLine,
      title: "Possible credential exfiltration",
      message:
        "This file both reads a credential-like environment variable and makes an outbound network call. This combination is a strong heuristic for secret exfiltration. Manually verify what data is sent and to where before trusting this skill.",
    });
  }

  return findings;
}
