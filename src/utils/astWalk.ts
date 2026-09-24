/**
 * Minimal generic AST visitor for ESTree-shaped trees (what
 * @typescript-eslint/typescript-estree produces for both JS and TS source).
 * We avoid pulling in a full traversal library (e.g. estraverse) and instead
 * walk every own-enumerable property of each node, skipping a small set of
 * keys that either don't contain AST nodes or would create cycles.
 */

const SKIP_KEYS = new Set(["loc", "range", "parent", "tokens", "comments"]);

export type AstNode = { type: string; [key: string]: unknown };

export function walkAst(root: unknown, visit: (node: AstNode) => void): void {
  const seen = new Set<unknown>();

  function recurse(node: unknown): void {
    if (node === null || typeof node !== "object") {
      return;
    }
    if (seen.has(node)) {
      return;
    }
    seen.add(node);

    if (Array.isArray(node)) {
      for (const item of node) {
        recurse(item);
      }
      return;
    }

    const obj = node as Record<string, unknown>;
    if (typeof obj.type === "string") {
      visit(obj as AstNode);
    }

    for (const key of Object.keys(obj)) {
      if (SKIP_KEYS.has(key)) {
        continue;
      }
      const value = obj[key];
      if (value && typeof value === "object") {
        recurse(value);
      }
    }
  }

  recurse(root);
}
