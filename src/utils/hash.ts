import { createHash } from "crypto";

/** Compute a hex-encoded SHA-256 digest of a UTF-8 string. */
export function sha256Hex(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}
