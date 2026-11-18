import type { OtpManagerConfig } from './types.js';

export interface OtpEndpointConfig extends OtpManagerConfig {
	/** Required when autoRegister is on, null otherwise. */
	autoRegisterRole: string | null;
}

type Env = Record<string, unknown>;

function readInt(env: Env, name: string, defaultValue: number, { allowZero }: { allowZero: boolean }): number {
	const parsed = parseInt(String(env[name] ?? ''), 10);
	if (Number.isNaN(parsed) || parsed < 0 || (parsed === 0 && !allowZero)) {
		return defaultValue;
	}
	return parsed;
}

function readBool(env: Env, name: string): boolean {
	return ['true', '1', 'yes'].includes(String(env[name] ?? '').trim().toLowerCase());
}

function readList(env: Env, name: string): string[] {
	return String(env[name] ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

export function readOtpConfig(env: Env): OtpEndpointConfig {
	const codeSecret = String(env['SECRET'] ?? '').trim();
	if (!codeSecret) {
		throw new Error('otp-auth: SECRET is not set; refusing to start (needed to hash codes and sign tokens).');
	}

	const autoRegisterRole = String(env['OTP_AUTO_REGISTER_ROLE'] ?? '').trim() || null;
	const autoRegister = readBool(env, 'OTP_AUTO_REGISTER');
	if (autoRegister && !autoRegisterRole) {
		throw new Error('otp-auth: OTP_AUTO_REGISTER=true requires OTP_AUTO_REGISTER_ROLE (no fallback to the public registration role); refusing to start.');
	}
	const allowedRoles = readList(env, 'OTP_ALLOWED_ROLES');
	// A restricted list must not lock out the role that auto-registration hands out.
	if (allowedRoles.length > 0 && autoRegisterRole && !allowedRoles.includes(autoRegisterRole)) {
		allowedRoles.push(autoRegisterRole);
	}

	return {
		codeTtlMinutes: readInt(env, 'OTP_CODE_TTL_MINUTES', 10, { allowZero: false }),
		maxAttempts: readInt(env, 'OTP_MAX_ATTEMPTS', 3, { allowZero: false }),
		rateLimitSeconds: readInt(env, 'OTP_RATE_LIMIT_SECONDS', 60, { allowZero: false }),
		codeSecret,
		autoRegister,
		autoRegisterRole,
		allowedRoles,
		allowPrivilegedAccounts: readBool(env, 'OTP_ALLOW_PRIVILEGED_ACCOUNTS'),
		ipWindowSeconds: readInt(env, 'OTP_IP_WINDOW_SECONDS', 900, { allowZero: false }),
		ipRequestLimit: readInt(env, 'OTP_IP_REQUEST_LIMIT', 10, { allowZero: true }),
		ipVerifyLimit: readInt(env, 'OTP_IP_VERIFY_LIMIT', 20, { allowZero: true }),
		maxCodesPerEmailPerDay: readInt(env, 'OTP_MAX_CODES_PER_EMAIL_PER_DAY', 10, { allowZero: true }),
		verifyFailureLimit: readInt(env, 'OTP_VERIFY_FAILURE_LIMIT', 10, { allowZero: true }),
		verifyFailureWindowSeconds: readInt(env, 'OTP_VERIFY_FAILURE_WINDOW_SECONDS', 3600, { allowZero: false }),
		globalRequestHourlyLimit: readInt(env, 'OTP_GLOBAL_REQUEST_HOURLY_LIMIT', 0, { allowZero: true }),
	};
}
