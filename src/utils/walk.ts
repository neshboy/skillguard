import * as fs from "fs";
import * as path from "path";

/** Directories we never descend into when scanning a skill package. */
const IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  "coverage",
  ".venv",
  "venv",
  "__pycache__",
]);

export interface WalkResult {
  /** Absolute paths of every regular file found. */
  files: string[];
  /** Relative (posix-style) paths that were skipped, with a reason. */
  skipped: string[];
}

/**
 * Recursively walk a directory, returning all regular files while skipping
 * common vendored/build directories so audits stay focused on the skill's
 * own source.
 */
export function walkDirectory(root: string): WalkResult {
  const files: string[] = [];
  const skipped: string[] = [];

  function recurse(dir: string): void {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      skipped.push(`${toRelative(root, dir)} (unreadable directory: ${(err as Error).message})`);
      return;
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        skipped.push(`${toRelative(root, full)} (symlink, not followed)`);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) {
          continue;
        }
        recurse(full);
      } else if (entry.isFile()) {
        files.push(full);
      }
    }
  }

  const rootStat = fs.statSync(root);
  if (!rootStat.isDirectory()) {
    throw new Error(`Not a directory: ${root}`);
  }
  recurse(root);
  return { files, skipped };
}

export function toRelative(root: string, absolute: string): string {
  return path.relative(root, absolute).split(path.sep).join("/");
}
