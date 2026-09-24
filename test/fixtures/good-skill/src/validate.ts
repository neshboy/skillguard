// SkillGuard test fixture: clean TypeScript file, no risky APIs.

export interface ValidationResult {
  valid: boolean;
  reason?: string;
}

export function validateNonEmpty(value: string): ValidationResult {
  if (value.trim().length === 0) {
    return { valid: false, reason: "value must not be empty" };
  }
  return { valid: true };
}
