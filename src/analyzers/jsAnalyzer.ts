import * as path from "path";
import { parse } from "@typescript-eslint/typescript-estree";
import { walkAst, AstNode } from "../utils/astWalk";
import { Finding } from "../types";

const PROCESS_EXEC_MEMBERS = new Set([
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "fork",
  "execFile",
  "execFileSync",
]);

const FS_READ_MEMBERS = new Set([
  "readFile",
  "readFileSync",
  "appendFile",
  "appendFileSync",
  "createReadStream",
]);

const FS_WRITE_MEMBERS = new Set([
  "writeFile",
  "writeFileSync",
  "unlink",
  "unlinkSync",
  "rm",
  "rmSync",
  "rmdir",
  "rmdirSync",
  "rename",
  "renameSync",
  "createWriteStream",
  "chmod",
  "chmodSync",
]);

const FS_MEMBERS = new Set([...FS_READ_MEMBERS, ...FS_WRITE_MEMBERS]);

const HTTP_MODULES = new Set(["http", "https"]);
const HTTP_REQUEST_MEMBERS = new Set(["request", "get"]);
const AXIOS_MEMBERS = new Set([
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "request",
  "head",
  "options",
]);

const CREDENTIAL_NAME_PATTERN =
  /(API_?KEY|ACCESS_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_?KEY)/i;

interface ModuleBindings {
  /** local identifier -> module specifier, for whole-module bindings (require/import default/namespace). */
  aliasToModule: Map<string, string>;
  /** local identifier -> { module, member }, for named/destructured bindings. */
  namedToModuleMember: Map<string, { module: string; member: string }>;
}

function literalStringValue(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (node.type === "Literal" && typeof (node as any).value === "string") {
    return (node as any).value as string;
  }
  if (node.type === "TemplateLiteral") {
    const expressions = (node as any).expressions as unknown[];
    if (Array.isArray(expressions) && expressions.length === 0) {
      const quasis = (node as any).quasis as Array<{ value: { cooked: string } }>;
      return quasis.map((q) => q.value.cooked).join("");
    }
  }
  return undefined;
}

function collectModuleBindings(ast: AstNode): ModuleBindings {
  const aliasToModule = new Map<string, string>();
  const namedToModuleMember = new Map<string, { module: string; member: string }>();

  walkAst(ast, (node) => {
    // ESM: import ... from '<module>'
    if (node.type === "ImportDeclaration") {
      const source = (node as any).source;
      const moduleName = literalStringValue(source);
      if (!moduleName) return;
      const specifiers = ((node as any).specifiers ?? []) as AstNode[];
      for (const spec of specifiers) {
        if (spec.type === "ImportDefaultSpecifier" || spec.type === "ImportNamespaceSpecifier") {
          const local = (spec as any).local?.name;
          if (local) aliasToModule.set(local, moduleName);
        } else if (spec.type === "ImportSpecifier") {
          const imported = (spec as any).imported?.name;
          const local = (spec as any).local?.name;
          if (imported && local) {
            namedToModuleMember.set(local, { module: moduleName, member: imported });
          }
        }
      }
      return;
    }

    // CommonJS: const x = require('<module>'); const { a, b } = require('<module>');
    if (node.type === "VariableDeclarator") {
      const init = (node as any).init as AstNode | undefined;
      if (
        init &&
        init.type === "CallExpression" &&
        (init as any).callee?.type === "Identifier" &&
        (init as any).callee?.name === "require"
      ) {
        const args = (init as any).arguments as AstNode[];
        const moduleName = literalStringValue(args?.[0]);
        if (!moduleName) return;
        const id = (node as any).id as AstNode;
        if (id.type === "Identifier") {
          aliasToModule.set((id as any).name, moduleName);
        } else if (id.type === "ObjectPattern") {
          for (const prop of (id as any).properties as AstNode[]) {
            if (prop.type !== "Property") continue;
            const key = (prop as any).key;
            const value = (prop as any).value;
            const memberName = key?.type === "Identifier" ? key.name : undefined;
            const localName = value?.type === "Identifier" ? value.name : undefined;
            if (memberName && localName) {
              namedToModuleMember.set(localName, { module: moduleName, member: memberName });
            }
          }
        }
      }
    }
  });

  return { aliasToModule, namedToModuleMember };
}

/** Resolve `require('module')` used inline as a call expression's object, e.g. require('fs').readFileSync(...) */
function resolveInlineRequireModule(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  if (
    node.type === "CallExpression" &&
    (node as any).callee?.type === "Identifier" &&
    (node as any).callee?.name === "require"
  ) {
    return literalStringValue((node as any).arguments?.[0]);
  }
  return undefined;
}

function resolveModuleForExpression(node: AstNode | undefined, bindings: ModuleBindings): string | undefined {
  if (!node) return undefined;
  if (node.type === "Identifier") {
    return bindings.aliasToModule.get((node as any).name);
  }
  return resolveInlineRequireModule(node);
}

interface CallSite {
  module?: string;
  member?: string;
  calleeName?: string;
  node: AstNode;
}

/** Describe a CallExpression/NewExpression's callee in terms of (module, member) when resolvable. */
function describeCallee(callee: AstNode, bindings: ModuleBindings): CallSite {
  if (callee.type === "Identifier") {
    const name = (callee as any).name as string;
    const named = bindings.namedToModuleMember.get(name);
    if (named) {
      return { module: named.module, member: named.member, calleeName: name, node: callee };
    }
    return { calleeName: name, node: callee };
  }
  if (callee.type === "MemberExpression" && !(callee as any).computed) {
    const object = (callee as any).object as AstNode;
    const property = (callee as any).property as AstNode;
    const memberName = property?.type === "Identifier" ? (property as any).name : undefined;
    const module = resolveModuleForExpression(object, bindings);
    return { module, member: memberName, node: callee };
  }
  if (callee.type === "MemberExpression" && (callee as any).computed) {
    const object = (callee as any).object as AstNode;
    const property = (callee as any).property as AstNode;
    const memberName = literalStringValue(property);
    const module = resolveModuleForExpression(object, bindings);
    return { module, member: memberName, node: callee };
  }
  return { node: callee };
}

function loc(node: AstNode): { line: number; column: number } {
  const l = (node as any).loc;
  if (l?.start) {
    return { line: l.start.line, column: l.start.column + 1 };
  }
  return { line: 0, column: 0 };
}

function snippetForLine(lines: string[], line: number): string | undefined {
  if (line <= 0 || line > lines.length) return undefined;
  return lines[line - 1].trim().slice(0, 200);
}

function classifyPathArgument(
  argNode: AstNode | undefined,
): { kind: "static-safe" | "static-outside" | "dynamic"; value?: string } {
  const literal = literalStringValue(argNode);
  if (literal === undefined) {
    return { kind: "dynamic" };
  }
  if (path.isAbsolute(literal)) {
    return { kind: "static-outside", value: literal };
  }
  const normalized = path.normalize(literal);
  if (normalized.split(/[\\/]/).some((seg) => seg === "..")) {
    return { kind: "static-outside", value: literal };
  }
  return { kind: "static-safe", value: literal };
}

/**
 * Statically analyze a single JavaScript/TypeScript source file for
 * concrete risk patterns: process execution, dynamic code execution,
 * filesystem access outside the skill directory, outbound network calls,
 * and credential-like environment variable access.
 */
export function analyzeJsFile(relPath: string, source: string): { findings: Finding[]; error?: string } {
  const findings: Finding[] = [];
  const lines = source.split(/\r\n|\r|\n/);

  let ast: AstNode;
  try {
    ast = parse(source, {
      loc: true,
      range: false,
      comment: false,
      jsx: true,
      errorOnUnknownASTType: false,
      allowInvalidAST: true,
    }) as unknown as AstNode;
  } catch (err) {
    const message = (err as Error).message;
    findings.push({
      ruleId: "JS000",
      category: "manifest",
      severity: "info",
      file: relPath,
      title: "File could not be parsed",
      message: `SkillGuard could not parse this file as JavaScript/TypeScript (${message}). It was skipped for AST-based checks. This can happen with unsupported syntax, or with deliberately obfuscated/minified code -- treat unscannable files with extra suspicion.`,
    });
    return { findings, error: message };
  }

  const bindings = collectModuleBindings(ast);
  let hasCredentialAccess = false;
  let hasNetworkAccess = false;
  let firstCredentialLine: number | undefined;
  let firstNetworkLine: number | undefined;

  walkAst(ast, (node) => {
    // eval(...)
    if (node.type === "CallExpression") {
      const callee = (node as any).callee as AstNode;
      if (callee?.type === "Identifier" && (callee as any).name === "eval") {
        const { line, column } = loc(node);
        findings.push({
          ruleId: "JS010",
          category: "dynamic-code-execution",
          severity: "critical",
          file: relPath,
          line,
          column,
          title: "Dynamic code execution via eval()",
          message:
            "Calls eval() on a string, which executes arbitrary code at runtime. This is a common technique to hide malicious behavior from static review and evade simple string scanning.",
          snippet: snippetForLine(lines, line),
        });
      }

      // fetch(...)
      if (callee?.type === "Identifier" && (callee as any).name === "fetch") {
        const { line, column } = loc(node);
        hasNetworkAccess = true;
        firstNetworkLine = firstNetworkLine ?? line;
        findings.push({
          ruleId: "JS030",
          category: "network-access",
          severity: "medium",
          file: relPath,
          line,
          column,
          title: "Outbound network call (fetch)",
          message:
            "Calls the global fetch() API, which can send data to or retrieve code from an arbitrary remote host. Verify the destination and payload are expected for this skill's stated purpose.",
          snippet: snippetForLine(lines, line),
        });
      }
    }

    // new Function(...)
    if (node.type === "NewExpression") {
      const callee = (node as any).callee as AstNode;
      if (callee?.type === "Identifier" && (callee as any).name === "Function") {
        const { line, column } = loc(node);
        findings.push({
          ruleId: "JS011",
          category: "dynamic-code-execution",
          severity: "critical",
          file: relPath,
          line,
          column,
          title: "Dynamic code execution via new Function()",
          message:
            "Constructs a function from a string at runtime with `new Function(...)`. Like eval(), this executes arbitrary code and is a common obfuscation/evasion technique.",
          snippet: snippetForLine(lines, line),
        });
      }
    }

    // Resolved module member calls: child_process, fs, http/https, axios
    if (node.type === "CallExpression") {
      const callee = (node as any).callee as AstNode;
      if (!callee) return;
      const site = describeCallee(callee, bindings);
      const { line, column } = loc(node);
      const args = ((node as any).arguments ?? []) as AstNode[];

      if (site.module === "child_process" && site.member && PROCESS_EXEC_MEMBERS.has(site.member)) {
        findings.push({
          ruleId: "JS001",
          category: "process-execution",
          severity: "high",
          file: relPath,
          line,
          column,
          title: `Spawns a child process (child_process.${site.member})`,
          message: `Calls child_process.${site.member}(), which can run arbitrary OS commands with the same privileges as the host process. Skills that need to shell out should be reviewed carefully -- this is the single most common way a malicious package escalates from "reads files" to "controls the machine".`,
          snippet: snippetForLine(lines, line),
        });
      }

      if ((site.module === "fs" || site.module === "fs/promises" || site.module === "node:fs") && site.member && FS_MEMBERS.has(site.member)) {
        const pathArg = args[0];
        const classification = classifyPathArgument(pathArg);
        if (classification.kind === "static-outside") {
          findings.push({
            ruleId: "JS020",
            category: "filesystem-access",
            severity: "high",
            file: relPath,
            line,
            column,
            title: `Filesystem access outside the skill directory (fs.${site.member})`,
            message: `Calls fs.${site.member}("${classification.value}"), which resolves to an absolute path or uses ".." to escape the skill's own directory. Skills should only need to read/write within their own sandboxed folder; access elsewhere may be reading secrets or tampering with unrelated files.`,
            snippet: snippetForLine(lines, line),
          });
        } else if (classification.kind === "dynamic") {
          findings.push({
            ruleId: "JS021",
            category: "filesystem-access",
            severity: "medium",
            file: relPath,
            line,
            column,
            title: `Filesystem access with a dynamically built path (fs.${site.member})`,
            message: `Calls fs.${site.member}() with a path that is not a static string literal, so SkillGuard cannot verify statically whether the target stays inside the skill's own directory. Review where this value comes from.`,
            snippet: snippetForLine(lines, line),
          });
        } else {
          findings.push({
            ruleId: "JS022",
            category: "filesystem-access",
            severity: "low",
            file: relPath,
            line,
            column,
            title: `Filesystem access within the skill directory (fs.${site.member})`,
            message: `Calls fs.${site.member}("${classification.value}"). This looks like it stays within the skill's own relative directory, which is lower risk, but is still listed for transparency.`,
            snippet: snippetForLine(lines, line),
          });
        }
      }

      if (site.module && HTTP_MODULES.has(site.module) && site.member && HTTP_REQUEST_MEMBERS.has(site.member)) {
        hasNetworkAccess = true;
        firstNetworkLine = firstNetworkLine ?? line;
        findings.push({
          ruleId: "JS031",
          category: "network-access",
          severity: "medium",
          file: relPath,
          line,
          column,
          title: `Outbound network call (${site.module}.${site.member})`,
          message: `Calls ${site.module}.${site.member}(), which can send data to or fetch content from an arbitrary remote host. Verify the destination and payload are expected.`,
          snippet: snippetForLine(lines, line),
        });
      }

      // axios.get/post/... or axios(...) directly
      const axiosAlias = [...bindings.aliasToModule.entries()].find(([, mod]) => mod === "axios")?.[0];
      if (axiosAlias) {
        if (callee.type === "Identifier" && (callee as any).name === axiosAlias) {
          hasNetworkAccess = true;
          firstNetworkLine = firstNetworkLine ?? line;
          findings.push({
            ruleId: "JS032",
            category: "network-access",
            severity: "medium",
            file: relPath,
            line,
            column,
            title: "Outbound network call (axios)",
            message: "Calls axios(...) directly to make an HTTP request. Verify the destination and payload are expected for this skill's stated purpose.",
            snippet: snippetForLine(lines, line),
          });
        } else if (
          callee.type === "MemberExpression" &&
          !(callee as any).computed &&
          (callee as any).object?.type === "Identifier" &&
          (callee as any).object?.name === axiosAlias &&
          (callee as any).property?.type === "Identifier" &&
          AXIOS_MEMBERS.has((callee as any).property.name)
        ) {
          hasNetworkAccess = true;
          firstNetworkLine = firstNetworkLine ?? line;
          findings.push({
            ruleId: "JS032",
            category: "network-access",
            severity: "medium",
            file: relPath,
            line,
            column,
            title: `Outbound network call (axios.${(callee as any).property.name})`,
            message: `Calls axios.${(callee as any).property.name}(...) to make an HTTP request. Verify the destination and payload are expected for this skill's stated purpose.`,
            snippet: snippetForLine(lines, line),
          });
        }
      }
    }

    // process.env.SOMETHING_KEY / process.env["SOMETHING_TOKEN"]
    if (node.type === "MemberExpression") {
      const object = (node as any).object as AstNode;
      const property = (node as any).property as AstNode;
      const isProcessEnv =
        object?.type === "MemberExpression" &&
        !(object as any).computed &&
        (object as any).object?.type === "Identifier" &&
        (object as any).object?.name === "process" &&
        (object as any).property?.type === "Identifier" &&
        (object as any).property?.name === "env";

      if (isProcessEnv) {
        const propName = (node as any).computed ? literalStringValue(property) : (property as any)?.name;
        if (propName && CREDENTIAL_NAME_PATTERN.test(propName)) {
          const { line, column } = loc(node);
          hasCredentialAccess = true;
          firstCredentialLine = firstCredentialLine ?? line;
          findings.push({
            ruleId: "JS040",
            category: "credential-access",
            severity: "medium",
            file: relPath,
            line,
            column,
            title: `Reads a credential-like environment variable (process.env.${propName})`,
            message: `Accesses process.env.${propName}, whose name suggests it holds an API key, token, secret, or password. Reading credentials isn't inherently malicious, but combined with any outbound network call it may indicate exfiltration -- check where this value goes.`,
            snippet: snippetForLine(lines, line),
          });
        }
      }
    }
  });

  if (hasCredentialAccess && hasNetworkAccess) {
    findings.push({
      ruleId: "JS900",
      category: "possible-exfiltration",
      severity: "critical",
      file: relPath,
      line: firstNetworkLine ?? firstCredentialLine,
      title: "Possible credential exfiltration",
      message:
        "This file both reads a credential-like environment variable and makes an outbound network call. This combination is a strong heuristic for secret exfiltration (e.g. sending an API key to a remote server). Manually verify what data is sent and to where before trusting this skill.",
    });
  }

  return { findings };
}
