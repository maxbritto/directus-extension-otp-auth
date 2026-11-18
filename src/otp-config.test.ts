import { readOtpConfig } from './otp-config';

describe('readOtpConfig', () => {
	it('applies safe defaults', () => {
		expect(readOtpConfig({ SECRET: 's3cret' })).toEqual({
			codeTtlMinutes: 10,
			maxAttempts: 3,
			rateLimitSeconds: 60,
			codeSecret: 's3cret',
			autoRegister: false,
			allowedRoles: [],
			allowPrivilegedAccounts: false,
			autoRegisterRole: null,
			ipWindowSeconds: 900,
			ipRequestLimit: 10,
			ipVerifyLimit: 20,
			maxCodesPerEmailPerDay: 10,
			verifyFailureLimit: 10,
			verifyFailureWindowSeconds: 3600,
			globalRequestHourlyLimit: 0,
		});
	});

	it('refuses to run without SECRET (code hashing and JWT signing need it)', () => {
		expect(() => readOtpConfig({})).toThrow(/SECRET/);
		expect(() => readOtpConfig({ SECRET: '  ' })).toThrow(/SECRET/);
	});

	it('reads every OTP_* setting', () => {
		const config = readOtpConfig({
			SECRET: 's',
			OTP_CODE_TTL_MINUTES: '5',
			OTP_MAX_ATTEMPTS: '4',
			OTP_RATE_LIMIT_SECONDS: '30',
			OTP_AUTO_REGISTER: 'true',
			OTP_AUTO_REGISTER_ROLE: 'role-1',
			OTP_ALLOWED_ROLES: 'role-2, role-3 ,',
			OTP_IP_WINDOW_SECONDS: '60',
			OTP_IP_REQUEST_LIMIT: '5',
			OTP_IP_VERIFY_LIMIT: '7',
			OTP_MAX_CODES_PER_EMAIL_PER_DAY: '3',
			OTP_VERIFY_FAILURE_LIMIT: '6',
			OTP_VERIFY_FAILURE_WINDOW_SECONDS: '120',
			OTP_GLOBAL_REQUEST_HOURLY_LIMIT: '100',
		});

		expect(config).toMatchObject({
			codeTtlMinutes: 5, maxAttempts: 4, rateLimitSeconds: 30, autoRegister: true, autoRegisterRole: 'role-1',
			ipWindowSeconds: 60, ipRequestLimit: 5, ipVerifyLimit: 7, maxCodesPerEmailPerDay: 3,
			verifyFailureLimit: 6, verifyFailureWindowSeconds: 120, globalRequestHourlyLimit: 100,
		});
		expect(config.allowedRoles).toEqual(['role-2', 'role-3', 'role-1']);
	});

	it.each(['true', 'TRUE', '1', 'yes'])('enables auto-register for %p', (value) => {
		expect(readOtpConfig({ SECRET: 's', OTP_AUTO_REGISTER: value, OTP_AUTO_REGISTER_ROLE: 'r' }).autoRegister).toBe(true);
	});

	it.each(['false', '0', '', 'nope', undefined])('keeps auto-register off for %p', (value) => {
		expect(readOtpConfig({ SECRET: 's', OTP_AUTO_REGISTER: value }).autoRegister).toBe(false);
	});

	it('accepts 0 to disable a limit but falls back to the default on garbage or negatives', () => {
		const config = readOtpConfig({ SECRET: 's', OTP_IP_REQUEST_LIMIT: '0', OTP_IP_VERIFY_LIMIT: 'abc', OTP_VERIFY_FAILURE_LIMIT: '-3' });
		expect(config.ipRequestLimit).toBe(0);
		expect(config.ipVerifyLimit).toBe(20);
		expect(config.verifyFailureLimit).toBe(10);
	});

	it.each(['true', 'TRUE', '1', 'yes'])('allows privileged accounts for %p', (value) => {
		expect(readOtpConfig({ SECRET: 's', OTP_ALLOW_PRIVILEGED_ACCOUNTS: value }).allowPrivilegedAccounts).toBe(true);
	});

	it.each(['false', '0', '', 'nope', undefined])('keeps privileged accounts refused for %p', (value) => {
		expect(readOtpConfig({ SECRET: 's', OTP_ALLOW_PRIVILEGED_ACCOUNTS: value }).allowPrivilegedAccounts).toBe(false);
	});

	it('keeps the auto-register role check independent of OTP_ALLOW_PRIVILEGED_ACCOUNTS', () => {
		expect(readOtpConfig({ SECRET: 's', OTP_ALLOW_PRIVILEGED_ACCOUNTS: 'true', OTP_AUTO_REGISTER: 'true', OTP_AUTO_REGISTER_ROLE: 'r' })).toMatchObject({ allowPrivilegedAccounts: true, autoRegisterRole: 'r' });
	});

	it('refuses to start with auto-register on and no role (no fallback to the public registration role)', () => {
		expect(() => readOtpConfig({ SECRET: 's', OTP_AUTO_REGISTER: 'true' })).toThrow(/OTP_AUTO_REGISTER_ROLE/);
		expect(() => readOtpConfig({ SECRET: 's', OTP_AUTO_REGISTER: 'true', OTP_AUTO_REGISTER_ROLE: '  ' })).toThrow(/OTP_AUTO_REGISTER_ROLE/);
	});

	it('keeps the allowed-role list empty (any non-privileged role) unless one is configured', () => {
		expect(readOtpConfig({ SECRET: 's', OTP_AUTO_REGISTER: 'true', OTP_AUTO_REGISTER_ROLE: 'r' }).allowedRoles).toEqual([]);
	});
});
