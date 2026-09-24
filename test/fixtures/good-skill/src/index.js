// SkillGuard test fixture: clean skill, no risky APIs of any kind.
// Pure text-formatting helpers only -- no process spawning, no filesystem
// access, no network calls, no eval, no credential reads.

function shout(text) {
  return String(text).toUpperCase() + "!";
}

function slugify(text) {
  return String(text)
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

module.exports = { shout, slugify };
