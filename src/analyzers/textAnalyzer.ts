import { Finding, Severity } from "../types";

interface TextRule {
  ruleId: string;
  severity: Severity;
  title: string;
  message: string;
  pattern: RegExp;
}

/**
 * Heuristic prompt-injection / hidden-instruction patterns for Markdown,
 * YAML, and other plain-text files that an agent might read as part of a
 * skill (SKILL.md instructions, docs, config comments, etc.). These are
 * text-scan heuristics, not an AST-based analysis -- they will have false
 * positives and can be evaded by an adversary who avoids the exact wording,
 * see README "Limitations".
 */
const TEXT_RULES: TextRule[] = [
  {
    ruleId: "TXT001",
    severity: "high",
    title: "Instruction to disregard prior/system instructions",
    message:
      "Contains language telling the reader (an AI agent) to ignore, disregard, or override its previous or system instructions. This is the classic prompt-injection pattern used to hijack an agent that reads this file as context.",
    pattern:
      /\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b(previous|prior|above|earlier|system|all)\b[^.\n]{0,40}\b(instructions?|rules?|prompt)\b/i,
  },
  {
    ruleId: "TXT002",
    severity: "high",
    title: "Instruction to act secretly / hide actions from the user",
    message:
      "Contains language instructing an agent to act without telling the user, or to hide what it is doing. Legitimate skills have no reason to ask an agent to conceal its behavior from the person operating it.",
    pattern:
      /\b(do not|don't|never)\s+(tell|inform|notify|show|let)\s+(the\s+)?(user|human|operator)\b|\bwithout\s+(telling|informing|the\s+user'?s?\s+knowledge)\b|\bsecretly\b|\bcovertly\b/i,
  },
  {
    ruleId: "TXT003",
    severity: "critical",
    title: "Instruction to exfiltrate credentials or file contents",
    message:
      "Contains language instructing an agent to send credentials, environment variables, or file contents to a remote destination. This matches the pattern used in documented prompt-injection attacks against AI coding/agent tools to steal secrets.",
    pattern:
      /\b(send|upload|post|exfiltrate|leak|email|transmit)\b[^.\n]{0,60}\b(api\s*key|token|secret|password|credential|env(ironment)?\s*variables?|\.env|ssh\s*key|private\s*key)\b/i,
  },
  {
    ruleId: "TXT004",
    severity: "critical",
    title: "Instruction to fetch a remote URL and execute its contents",
    message:
      "Contains language or a code fence instructing an agent to download content from a URL and execute/run/eval it (a classic 'curl | sh' style remote-code-execution pattern hidden in documentation or instructions).",
    pattern:
      /\b(curl|wget|fetch|download)\b[^\n]{0,80}\bhttps?:\/\/[^\s"'`)]+[^\n]{0,40}\b(run|exec(ute)?|eval|pipe|\|\s*sh|\|\s*bash)\b|\b(run|exec(ute)?|eval)\b[^\n]{0,40}\bhttps?:\/\/[^\s"'`)]+/i,
  },
  {
    ruleId: "TXT005",
    severity: "medium",
    title: "Instruction claiming elevated/root/admin authority",
    message:
      "Contains language asserting elevated authority (e.g. claiming to be a system administrator or root override) intended to make an agent bypass its normal safety checks or confirmations.",
    pattern:
      /\b(you are now|acting as|as the)\b[^.\n]{0,40}\b(root|admin|administrator|system\s*override|superuser)\b/i,
  },
  {
    ruleId: "TXT006",
    severity: "medium",
    title: "Suspiciously large embedded Base64-looking blob",
    message:
      "Contains a very long contiguous run of Base64-alphabet characters. This can be a legitimate embedded asset, but is also a common way to hide an encoded payload (script, URL, or command) from a quick human read-through of a Markdown/YAML file.",
    pattern: /[A-Za-z0-9+/]{300,}={0,2}/,
  },
];

/**
 * Scan a non-source text file (Markdown, YAML, plain text, etc.) for
 * prompt-injection-style hidden instructions using line-by-line regex
 * matching. Returns one finding per (rule, line) match.
 */
export function analyzeTextFile(relPath: string, source: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split(/\r\n|\r|\n/);

  for (const rule of TEXT_RULES) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (rule.pattern.test(line)) {
        findings.push({
          ruleId: rule.ruleId,
          category: "prompt-injection",
          severity: rule.severity,
          file: relPath,
          line: i + 1,
          title: rule.title,
          message: rule.message,
          snippet: line.trim().slice(0, 200),
        });
      }
      // Reset stateful regex lastIndex is not needed here since patterns
      // are not created with the global flag, but guard anyway:
      rule.pattern.lastIndex = 0;
    }
  }

  return findings;
}
