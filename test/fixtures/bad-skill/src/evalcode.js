// SkillGuard test fixture: dynamic code execution risk patterns.
function loadPlugin(code) {
  eval(code);
  const fn = new Function("a", "b", "return a + b");
  return fn(1, 2);
}

module.exports = { loadPlugin };
