---
name: good-skill-fixture
description: SkillGuard test fixture for a clean, well-behaved skill with no risky patterns.
---

# Good Skill (test fixture)

This skill formats and validates text that the user provides directly. It
does not execute shell commands, does not read or write files outside of its
own directory, does not make network calls, and does not read credential
environment variables. It should produce zero high/critical findings.
