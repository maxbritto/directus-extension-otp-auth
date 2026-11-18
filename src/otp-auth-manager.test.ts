import { OtpAuthManager, type OtpAuthDeps } from './otp-auth-manager';
import { hashOtpCode } from './otp-crypto';
import type {
	IOtpDelivery, IOtpLogger, IOtpStore, IRateLimiter, ITokenGenerator, IUserLookup, IUserProvisioner,
	IssueCodeOutcome, IssueCodeRequest, OtpCode, OtpManagerConfig, OtpUser, OtpUserLookupResult, RequestInfo,
} from './types';

const SECRET = 'test-secret';

const DEFAULT_CONFIG: OtpManagerConfig = {
	codeTtlMinutes: 10,
	maxAttempts: 3,
	rateLimitSeconds: 60,
	codeSecret: SECRET,
	autoRegister: false,
	allowedRoles: [],
	allowPrivilegedAccounts: false,
	ipWindowSeconds: 900,
	ipRequestLimit: 10,
	ipVerifyLimit: 20,
	maxCodesPerEmailPerDay: 10,
	verifyFailureLimit: 10,
	verifyFailureWindowSeconds: 3600,
	globalRequestHourlyLimit: 0,
};

const REQUEST_INFO: RequestInfo = { ip: '127.0.0.1', userAgent: 'test-agent', origin: 'http://localhost' };

const PLAYER: OtpUser = { id: 'user-1', role: 'player-role', status: 'active', hasTfa: false, privileged: false };

function hashFor(email: string, code: string): string {
	return hashOtpCode(SECRET, email, code);
}

function makeOtpCode(overrides?: Partial<OtpCode>): OtpCode {
	const email = overrides?.email ?? 'user@example.com';
	return {
		id: 'test-id',
		email,
		codeHash: hashFor(email, '123456'),
		expires_at: new Date(Date.now() + 10 * 60 * 1000),
		attempts: 0,
		used: false,
		created_at: new Date(),
		...overrides,
	};
}

/** In-memory store whose conditional updates are atomic, like the SQL they stand for. */
class InMemoryStore implements IOtpStore {
	codes: OtpCode[] = [];
	comparisonsAllowed = 0;

	async issueCode({ id, email, codeHash, expiresAt, minIntervalSeconds, maxPerDay }: IssueCodeRequest): Promise<IssueCodeOutcome> {
		// Synchronous body after one yield: like the SQL transaction, check-then-insert cannot interleave.
		await Promise.resolve();
		const own = this.codes.filter((c) => c.email === email);
		if (minIntervalSeconds > 0 && own.some((c) => c.created_at.getTime() > Date.now() - minIntervalSeconds * 1000)) return 'throttled';
		if (maxPerDay > 0 && own.filter((c) => c.created_at.getTime() > Date.now() - 24 * 60 * 60 * 1000).length >= maxPerDay) return 'capped';
		own.forEach((c) => { c.used = true; });
		this.codes.push({ id, email, codeHash, expires_at: expiresAt, attempts: 0, used: false, created_at: new Date() });
		return 'issued';
	}
	async findLatestValidCode(email: string) {
		await Promise.resolve();
		const valid = this.codes.filter((c) => c.email === email && !c.used && c.expires_at > new Date());
		const latest = valid.at(-1);
		return latest ? { ...latest } : null;
	}
	async consumeAttempt(id: string, maxAttempts: number) {
		await Promise.resolve();
		const code = this.codes.find((c) => c.id === id);
		if (!code || code.used || code.attempts >= maxAttempts || code.expires_at <= new Date()) return false;
		code.attempts += 1;
		this.comparisonsAllowed += 1;
		return true;
	}
	async markAsUsed(id: string) {
		await Promise.resolve();
		const code = this.codes.find((c) => c.id === id);
		if (!code || code.used) return false;
		code.used = true;
		return true;
	}
	async invalidateAllForEmail(email: string) {
		this.codes.filter((c) => c.email === email).forEach((c) => { c.used = true; });
	}
}

class InMemoryRateLimiter implements IRateLimiter {
	events = new Map<string, number[]>();
	async hit(key: string, windowSeconds: number) {
		this.events.set(key, [...(this.events.get(key) ?? []), Date.now()]);
		return this.count(key, windowSeconds);
	}
	async count(key: string, windowSeconds: number) {
		const cutoff = Date.now() - windowSeconds * 1000;
		return (this.events.get(key) ?? []).filter((t) => t > cutoff).length;
	}
}

function firstOf<T>(items: readonly T[]): T {
	const [first] = items;
	if (first === undefined) {
		throw new Error('expected at least one item');
	}
	return first;
}

function silentLogger(): jest.Mocked<IOtpLogger> {
	return { info: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

interface Harness {
	manager: OtpAuthManager;
	store: InMemoryStore;
	limiter: InMemoryRateLimiter;
	userLookup: { findByEmail: jest.Mock<Promise<OtpUserLookupResult>, [string]> };
	provisioner: { isAvailable: jest.Mock<Promise<boolean>, []>; create: jest.Mock<Promise<OtpUser | null>, [string]> };
	delivery: { deliver: jest.Mock<Promise<void>, [string, string, number]> };
	tokenGenerator: { generateTokens: jest.Mock };
	logger: jest.Mocked<IOtpLogger>;
}

function createHarness(options?: { config?: Partial<OtpManagerConfig>; user?: OtpUserLookupResult }): Harness {
	const store = new InMemoryStore();
	const limiter = new InMemoryRateLimiter();
	const userLookup = {
		findByEmail: jest.fn<Promise<OtpUserLookupResult>, [string]>().mockResolvedValue(options?.user ?? { kind: 'none' }),
	};
	const provisioner = {
		isAvailable: jest.fn<Promise<boolean>, []>().mockResolvedValue(true),
		create: jest.fn<Promise<OtpUser | null>, [string]>().mockResolvedValue({ ...PLAYER, id: 'new-user' }),
	};
	const delivery = { deliver: jest.fn<Promise<void>, [string, string, number]>().mockResolvedValue(undefined) };
	const tokenGenerator = {
		generateTokens: jest.fn().mockResolvedValue({ access_token: 'access', refresh_token: 'refresh', expires: 900000 }),
	};
	const logger = silentLogger();
	const deps: OtpAuthDeps = {
		store,
		userLookup: userLookup as IUserLookup,
		provisioner: provisioner as IUserProvisioner,
		delivery: delivery as IOtpDelivery,
		tokenGenerator: tokenGenerator as ITokenGenerator,
		rateLimiter: limiter,
		logger,
		config: { ...DEFAULT_CONFIG, ...options?.config },
	};
	return { manager: new OtpAuthManager(deps), store, limiter, userLookup, provisioner, delivery, tokenGenerator, logger };
}

const found = (user: Partial<OtpUser> = {}): OtpUserLookupResult => ({ kind: 'found', user: { ...PLAYER, ...user } });

describe('OtpAuthManager', () => {
	describe('requestOtp', () => {
		it('creates, stores (hashed) and delivers a code for an active user', async () => {
			const h = createHarness({ user: found() });

			const result = await h.manager.requestOtp('user@example.com', '1.1.1.1');

			expect(result).toEqual({ success: true });
			expect(h.delivery.deliver).toHaveBeenCalledTimes(1);
			const [email, code, ttl] = firstOf(h.delivery.deliver.mock.calls);
			expect(email).toBe('user@example.com');
			expect(code).toMatch(/^\d{6}$/);
			expect(ttl).toBe(10);
			expect(h.store.codes).toHaveLength(1);
			expect(firstOf(h.store.codes).codeHash).toBe(hashFor('user@example.com', code));
			expect(JSON.stringify(h.store.codes)).not.toContain(code);
			expect(firstOf(h.store.codes).expires_at.getTime()).toBeGreaterThan(Date.now() + 9 * 60 * 1000);
		});

		it('normalizes the e-mail before lookup and storage', async () => {
			const h = createHarness({ user: found() });

			await h.manager.requestOtp('  User@Example.COM ', '1.1.1.1');

			expect(h.userLookup.findByEmail).toHaveBeenCalledWith('user@example.com');
			expect(firstOf(h.store.codes).email).toBe('user@example.com');
			expect(firstOf(h.delivery.deliver.mock.calls)[0]).toBe('user@example.com');
		});

		it('invalidates previous codes for the e-mail', async () => {
			const h = createHarness({ user: found(), config: { rateLimitSeconds: 0 } });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			const first = firstOf(h.store.codes);

			await h.manager.requestOtp('user@example.com', '1.1.1.1');

			expect(first.used).toBe(true);
			expect(h.store.codes.filter((c) => !c.used)).toHaveLength(1);
		});

		it('sends nothing and still succeeds for an unknown e-mail when auto-register is off', async () => {
			const h = createHarness();

			expect(await h.manager.requestOtp('nobody@example.com', '1.1.1.1')).toEqual({ success: true });
			expect(h.delivery.deliver).not.toHaveBeenCalled();
			expect(h.store.codes).toHaveLength(0);
			expect(h.provisioner.create).not.toHaveBeenCalled();
		});

		it('sends a code to an unknown e-mail when auto-register is on, without creating the user', async () => {
			const h = createHarness({ config: { autoRegister: true } });

			expect(await h.manager.requestOtp('Nobody@Example.com', '1.1.1.1')).toEqual({ success: true });
			expect(h.delivery.deliver).toHaveBeenCalledTimes(1);
			expect(firstOf(h.store.codes).email).toBe('nobody@example.com');
			expect(h.provisioner.create).not.toHaveBeenCalled();
		});

		it('sends nothing to an unknown e-mail when auto-register has no safe role', async () => {
			const h = createHarness({ config: { autoRegister: true } });
			h.provisioner.isAvailable.mockResolvedValue(false);

			expect(await h.manager.requestOtp('nobody@example.com', '1.1.1.1')).toEqual({ success: true });
			expect(h.delivery.deliver).not.toHaveBeenCalled();
		});

		it('refuses ambiguous (case-only duplicate) accounts without creating a third one', async () => {
			const h = createHarness({ user: { kind: 'ambiguous' }, config: { autoRegister: true } });

			expect(await h.manager.requestOtp('dup@example.com', '1.1.1.1')).toEqual({ success: true });
			expect(h.delivery.deliver).not.toHaveBeenCalled();
			expect(h.logger.warn).toHaveBeenCalled();
		});

		it.each(['suspended', 'archived', 'draft', 'invited', 'unverified', ''])('sends no code to a %p account, with the usual response', async (status) => {
			const h = createHarness({ user: found({ status }), config: { autoRegister: true } });

			expect(await h.manager.requestOtp('user@example.com', '1.1.1.1')).toEqual({ success: true });
			expect(h.delivery.deliver).not.toHaveBeenCalled();
			expect(h.store.codes).toHaveLength(0);
		});

		it('sends no code to an account with a TOTP secret', async () => {
			const h = createHarness({ user: found({ hasTfa: true }) });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(h.delivery.deliver).not.toHaveBeenCalled();
		});

		it('sends no code to a privileged (app/admin access) account', async () => {
			const h = createHarness({ user: found({ privileged: true }) });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(h.delivery.deliver).not.toHaveBeenCalled();
		});

		it('sends a code to a privileged (admin/Studio) account when OTP_ALLOW_PRIVILEGED_ACCOUNTS is on', async () => {
			const h = createHarness({ user: found({ privileged: true }), config: { allowPrivilegedAccounts: true } });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(h.delivery.deliver).toHaveBeenCalledTimes(1);
		});

		it('still sends no code to a privileged account with a TOTP secret, even when privileged accounts are allowed', async () => {
			const h = createHarness({ user: found({ privileged: true, hasTfa: true }), config: { allowPrivilegedAccounts: true } });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(h.delivery.deliver).not.toHaveBeenCalled();
		});

		it('still sends no code to a suspended privileged account, even when privileged accounts are allowed', async () => {
			const h = createHarness({ user: found({ privileged: true, status: 'suspended' }), config: { allowPrivilegedAccounts: true } });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(h.delivery.deliver).not.toHaveBeenCalled();
		});

		it('only serves allowed roles when a role list is configured', async () => {
			const refused = createHarness({ user: found({ role: 'other-role' }), config: { allowedRoles: ['player-role'] } });
			await refused.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(refused.delivery.deliver).not.toHaveBeenCalled();

			const accepted = createHarness({ user: found(), config: { allowedRoles: ['player-role'] } });
			await accepted.manager.requestOtp('user@example.com', '1.1.1.1');
			expect(accepted.delivery.deliver).toHaveBeenCalledTimes(1);
		});

		it('silently succeeds when a code was created within the rate-limit window', async () => {
			const h = createHarness({ user: found() });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');

			expect(await h.manager.requestOtp('user@example.com', '1.1.1.2')).toEqual({ success: true });
			expect(h.delivery.deliver).toHaveBeenCalledTimes(1);
		});

		it('sends a single code and a single e-mail for parallel requests on the same address', async () => {
			const h = createHarness({ user: found() });

			await Promise.all(Array.from({ length: 10 }, (_, i) => h.manager.requestOtp('user@example.com', `1.1.1.${i}`)));

			expect(h.store.codes).toHaveLength(1);
			expect(h.delivery.deliver).toHaveBeenCalledTimes(1);
		});

		it('respects the daily cap under parallel requests', async () => {
			const h = createHarness({ user: found(), config: { maxCodesPerEmailPerDay: 2, rateLimitSeconds: 0 } });

			await Promise.all(Array.from({ length: 10 }, (_, i) => h.manager.requestOtp('user@example.com', `1.1.1.${i}`)));

			expect(h.delivery.deliver).toHaveBeenCalledTimes(2);
		});

		it('stops sending once the daily cap of codes per e-mail is reached', async () => {
			const h = createHarness({ user: found(), config: { maxCodesPerEmailPerDay: 2, rateLimitSeconds: 0 } });

			for (let i = 0; i < 4; i++) {
				expect(await h.manager.requestOtp('user@example.com', '1.1.1.1')).toEqual({ success: true });
			}
			expect(h.delivery.deliver).toHaveBeenCalledTimes(2);
		});

		it('rate-limits /request per IP with a generic limit error, not per account', async () => {
			const h = createHarness({ config: { ipRequestLimit: 3 } });

			for (let i = 0; i < 3; i++) {
				expect(await h.manager.requestOtp(`u${i}@example.com`, '9.9.9.9')).toEqual({ success: true });
			}
			expect(await h.manager.requestOtp('u4@example.com', '9.9.9.9')).toEqual({ success: false, error: 'rate_limited' });
			expect(await h.manager.requestOtp('u4@example.com', '8.8.8.8')).toEqual({ success: true });
		});

		it('applies the global hourly cap across IPs', async () => {
			const h = createHarness({ config: { globalRequestHourlyLimit: 2 } });

			await h.manager.requestOtp('a@example.com', '1.1.1.1');
			await h.manager.requestOtp('b@example.com', '2.2.2.2');
			expect(await h.manager.requestOtp('c@example.com', '3.3.3.3')).toEqual({ success: false, error: 'rate_limited' });
			expect(h.logger.warn).toHaveBeenCalledWith(expect.objectContaining({ reason: 'global' }), 'otp.request.rate_limited');
		});

		it('treats a limit of 0 as disabled', async () => {
			const h = createHarness({ config: { ipRequestLimit: 0, maxCodesPerEmailPerDay: 0, rateLimitSeconds: 0 }, user: found() });
			for (let i = 0; i < 15; i++) {
				expect(await h.manager.requestOtp('user@example.com', '1.1.1.1')).toEqual({ success: true });
			}
		});

		it('does not wait for delivery (same latency for every account state)', async () => {
			const h = createHarness({ user: found() });
			h.delivery.deliver.mockReturnValue(new Promise(() => undefined));

			await expect(h.manager.requestOtp('user@example.com', '1.1.1.1')).resolves.toEqual({ success: true });
		});

		it('logs, and does not surface, a delivery failure', async () => {
			const h = createHarness({ user: found() });
			const failure = new Error('smtp down');
			h.delivery.deliver.mockRejectedValue(failure);

			await expect(h.manager.requestOtp('user@example.com', '1.1.1.1')).resolves.toEqual({ success: true });
			await new Promise((resolve) => setImmediate(resolve));
			expect(h.logger.error).toHaveBeenCalledWith(failure, expect.any(String));
		});

		it('never logs the code', async () => {
			const h = createHarness({ user: found() });
			await h.manager.requestOtp('user@example.com', '1.1.1.1');
			const code = firstOf(h.delivery.deliver.mock.calls)[1];
			const logged = JSON.stringify([h.logger.info.mock.calls, h.logger.warn.mock.calls]);
			expect(logged).not.toContain(code);
			expect(logged).not.toContain('user@example.com');
		});
	});

	describe('verifyOtp', () => {
		async function seedCode(h: Harness, email = 'user@example.com', code = '123456', overrides?: Partial<OtpCode>) {
			h.store.codes.push(makeOtpCode({ email, codeHash: hashFor(email, code), ...overrides }));
		}

		it('returns tokens for a valid code of an active user and marks the code used', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h);

			const result = await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO);

			expect(result).toEqual({ success: true, access_token: 'access', refresh_token: 'refresh', expires: 900000, userId: 'user-1', created: false });
			expect(h.tokenGenerator.generateTokens).toHaveBeenCalledWith('user-1', REQUEST_INFO);
			expect(firstOf(h.store.codes).used).toBe(true);
			expect(h.provisioner.create).not.toHaveBeenCalled();
		});

		it('normalizes the e-mail before looking the code up', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h);

			const result = await h.manager.verifyOtp('  USER@Example.com ', '123456', REQUEST_INFO);

			expect(result.success).toBe(true);
			expect(h.userLookup.findByEmail).toHaveBeenCalledWith('user@example.com');
		});

		it('fails without a valid code', async () => {
			const h = createHarness({ user: found() });
			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
		});

		it('fails on an expired code', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h, undefined, undefined, { expires_at: new Date(Date.now() - 1000) });
			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
		});

		it('fails on a wrong code and spends an attempt', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h);

			expect(await h.manager.verifyOtp('user@example.com', '000000', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			expect(firstOf(h.store.codes).attempts).toBe(1);
			expect(firstOf(h.store.codes).used).toBe(false);
			expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
		});

		it('locks the code after max attempts, even for the right code', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h);

			for (let i = 0; i < 3; i++) await h.manager.verifyOtp('user@example.com', '000000', REQUEST_INFO);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'too_many_attempts' });
			expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
		});

		it('cannot reuse a code', async () => {
			const h = createHarness({ user: found() });
			await seedCode(h);
			await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
		});

		it('refuses tokens when the account is no longer active', async () => {
			const h = createHarness({ user: found({ status: 'suspended' }) });
			await seedCode(h);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
			expect(h.provisioner.create).not.toHaveBeenCalled();
		});

		it.each([
			['TOTP', { hasTfa: true }],
			['privileged', { privileged: true }],
		])('refuses tokens for a %s account', async (_label, user) => {
			const h = createHarness({ user: found(user) });
			await seedCode(h);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
		});

		it('issues tokens to a privileged (admin/Studio) account when OTP_ALLOW_PRIVILEGED_ACCOUNTS is on', async () => {
			const h = createHarness({ user: found({ privileged: true }), config: { allowPrivilegedAccounts: true } });
			await seedCode(h);

			const result = await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO);
			expect(result).toMatchObject({ success: true, created: false });
			expect(h.tokenGenerator.generateTokens).toHaveBeenCalledTimes(1);
		});

		it.each([
			['TOTP', { hasTfa: true, privileged: true }],
			['suspended', { status: 'suspended', privileged: true }],
		])('refuses tokens for a privileged %s account even when privileged accounts are allowed', async (_label, user) => {
			const h = createHarness({ user: found(user), config: { allowPrivilegedAccounts: true } });
			await seedCode(h);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
		});

		it('refuses ambiguous accounts instead of creating one', async () => {
			const h = createHarness({ user: { kind: 'ambiguous' }, config: { autoRegister: true } });
			await seedCode(h);

			expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			expect(h.provisioner.create).not.toHaveBeenCalled();
		});

		describe('auto-register', () => {
			it('creates the user only after a valid code, then issues tokens', async () => {
				const h = createHarness({ config: { autoRegister: true } });
				await seedCode(h, 'new@example.com', '654321');

				const result = await h.manager.verifyOtp('New@Example.com', '654321', REQUEST_INFO);

				expect(h.provisioner.create).toHaveBeenCalledWith('new@example.com');
				expect(h.tokenGenerator.generateTokens).toHaveBeenCalledWith('new-user', REQUEST_INFO);
				expect(result).toMatchObject({ success: true, userId: 'new-user', created: true });
			});

			it('never creates a user on a wrong code', async () => {
				const h = createHarness({ config: { autoRegister: true } });
				await seedCode(h, 'new@example.com', '654321');

				expect(await h.manager.verifyOtp('new@example.com', '000000', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
				expect(h.provisioner.create).not.toHaveBeenCalled();
			});

			it('does not create users when auto-register is off', async () => {
				const h = createHarness();
				await seedCode(h, 'new@example.com', '654321');

				expect(await h.manager.verifyOtp('new@example.com', '654321', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
				expect(h.provisioner.create).not.toHaveBeenCalled();
			});

			it('fails cleanly when the provisioner refuses', async () => {
				const h = createHarness({ config: { autoRegister: true } });
				h.provisioner.create.mockResolvedValue(null);
				await seedCode(h, 'new@example.com', '654321');

				expect(await h.manager.verifyOtp('new@example.com', '654321', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
				expect(h.tokenGenerator.generateTokens).not.toHaveBeenCalled();
			});

			it('re-checks the eligibility of the user the provisioner returns (concurrent creation)', async () => {
				const h = createHarness({ config: { autoRegister: true } });
				h.provisioner.create.mockResolvedValue({ ...PLAYER, status: 'suspended' });
				await seedCode(h, 'new@example.com', '654321');

				expect(await h.manager.verifyOtp('new@example.com', '654321', REQUEST_INFO)).toEqual({ success: false, error: 'invalid_code' });
			});
		});

		describe('concurrency', () => {
			it('spends at most maxAttempts comparisons under parallel wrong guesses', async () => {
				const h = createHarness({ user: found() });
				await seedCode(h);

				const results = await Promise.all(
					Array.from({ length: 25 }, (_, i) => h.manager.verifyOtp('user@example.com', String(i).padStart(6, '0'), REQUEST_INFO)),
				);

				expect(h.store.comparisonsAllowed).toBeLessThanOrEqual(3);
				expect(results.every((r) => !r.success)).toBe(true);
			});

			it('issues a single session and creates a single user for parallel correct verifications', async () => {
				const h = createHarness({ config: { autoRegister: true } });
				await seedCode(h, 'new@example.com', '654321');

				const results = await Promise.all(
					Array.from({ length: 10 }, () => h.manager.verifyOtp('new@example.com', '654321', REQUEST_INFO)),
				);

				expect(results.filter((r) => r.success)).toHaveLength(1);
				expect(h.tokenGenerator.generateTokens).toHaveBeenCalledTimes(1);
				expect(h.provisioner.create).toHaveBeenCalledTimes(1);
			});
		});

		describe('abuse limits', () => {
			it('rate-limits /verify per IP before touching any code', async () => {
				const h = createHarness({ user: found(), config: { ipVerifyLimit: 2 } });
				await seedCode(h);
				const info = { ...REQUEST_INFO, ip: '7.7.7.7' };

				await h.manager.verifyOtp('user@example.com', '000000', info);
				await h.manager.verifyOtp('user@example.com', '000001', info);
				const before = h.store.comparisonsAllowed;

				expect(await h.manager.verifyOtp('user@example.com', '123456', info)).toEqual({ success: false, error: 'rate_limited' });
				expect(h.store.comparisonsAllowed).toBe(before);
				expect((await h.manager.verifyOtp('user@example.com', '123456', { ...REQUEST_INFO, ip: '6.6.6.6' })).success).toBe(true);
			});

			it('caps cumulative failures per e-mail across code generations, even for the right code', async () => {
				const h = createHarness({ user: found(), config: { verifyFailureLimit: 4, maxAttempts: 3, rateLimitSeconds: 0 } });
				for (let generation = 0; generation < 2; generation++) {
					await seedCode(h, undefined, undefined, { id: `c${generation}` });
					for (let i = 0; i < 2; i++) await h.manager.verifyOtp('user@example.com', '000000', REQUEST_INFO);
					await h.store.invalidateAllForEmail('user@example.com');
				}
				await seedCode(h, undefined, undefined, { id: 'c-final' });

				expect(await h.manager.verifyOtp('user@example.com', '123456', REQUEST_INFO)).toEqual({ success: false, error: 'rate_limited' });
			});

			it('counts failures for unknown e-mails too, so the cap does not reveal accounts', async () => {
				const h = createHarness({ config: { verifyFailureLimit: 2 } });

				await h.manager.verifyOtp('ghost@example.com', '000000', REQUEST_INFO);
				await h.manager.verifyOtp('ghost@example.com', '000000', REQUEST_INFO);

				expect(await h.manager.verifyOtp('ghost@example.com', '000000', REQUEST_INFO)).toEqual({ success: false, error: 'rate_limited' });
			});

			it('treats a missing IP as one shared bucket instead of skipping the limit', async () => {
				const h = createHarness({ config: { ipVerifyLimit: 1 } });
				const info = { ...REQUEST_INFO, ip: null };

				await h.manager.verifyOtp('a@example.com', '000000', info);
				expect(await h.manager.verifyOtp('b@example.com', '000000', info)).toEqual({ success: false, error: 'rate_limited' });
			});
		});
	});
});
