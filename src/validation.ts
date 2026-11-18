const MAX_EMAIL_LENGTH = 254;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;
const CODE_PATTERN = /^[0-9]{6}$/;

export function normalizeEmail(email: string): string {
	return email.trim().toLowerCase();
}

export function isValidEmail(value: unknown): value is string {
	return typeof value === 'string'
		&& value.length <= MAX_EMAIL_LENGTH
		&& EMAIL_PATTERN.test(value.trim());
}

export function isValidCode(value: unknown): value is string {
	return typeof value === 'string' && CODE_PATTERN.test(value);
}
