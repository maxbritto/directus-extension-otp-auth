import { OtpAuthManager } from './otp-auth-manager';
import type { IOtpStore, IUserLookup, IOtpDelivery, ITokenGenerator, OtpCode, OtpConfig, RequestInfo } from './types';

function createMockStore(): jest.Mocked<IOtpStore> {
	return {
		createCode: jest.fn().mockResolvedValue(undefined),
		findLatestValidCode: jest.fn().mockResolvedValue(null),
		findRecentCode: jest.fn().mockResolvedValue(null),
		incrementAttempts: jest.fn().mockResolvedValue(undefined),
		markAsUsed: jest.fn().mockResolvedValue(undefined),
		invalidateAllForEmail: jest.fn().mockResolvedValue(undefined),
	};
}

function createMockUserLookup(): jest.Mocked<IUserLookup> {
	return {
		findByEmail: jest.fn().mockResolvedValue(null),
	};
}

function createMockDelivery(): jest.Mocked<IOtpDelivery> {
	return {
		deliver: jest.fn().mockResolvedValue(undefined),
	};
}

function createMockTokenGenerator(): jest.Mocked<ITokenGenerator> {
	return {
		generateTokens: jest.fn().mockResolvedValue({
			access_token: 'test-access-token',
			refresh_token: 'test-refresh-token',
			expires: 900000,
		}),
	};
}

const DEFAULT_CONFIG: OtpConfig = {
	codeTtlMinutes: 10,
	maxAttempts: 3,
	rateLimitSeconds: 60,
};

const DEFAULT_REQUEST_INFO: RequestInfo = {
	ip: '127.0.0.1',
	userAgent: 'test-agent',
	origin: 'http://localhost',
};

function createManager(overrides?: {
	store?: jest.Mocked<IOtpStore>;
	userLookup?: jest.Mocked<IUserLookup>;
	delivery?: jest.Mocked<IOtpDelivery>;
	tokenGenerator?: jest.Mocked<ITokenGenerator>;
	config?: OtpConfig;
}) {
	const store = overrides?.store ?? createMockStore();
	const userLookup = overrides?.userLookup ?? createMockUserLookup();
	const delivery = overrides?.delivery ?? createMockDelivery();
	const tokenGenerator = overrides?.tokenGenerator ?? createMockTokenGenerator();
	const config = overrides?.config ?? DEFAULT_CONFIG;
	const manager = new OtpAuthManager(store, userLookup, delivery, tokenGenerator, config);
	return { manager, store, userLookup, delivery, tokenGenerator };
}

function makeOtpCode(overrides?: Partial<OtpCode>): OtpCode {
	return {
		id: 'test-id',
		email: 'user@example.com',
		code: '123456',
		expires_at: new Date(Date.now() + 10 * 60 * 1000),
		attempts: 0,
		used: false,
		created_at: new Date(),
		...overrides,
	};
}

describe('OtpAuthManager', () => {

	describe('requestOtp', () => {

		it('should return success true when user exists and no recent code', async () => {
			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager, store, delivery } = createManager({ userLookup });

			const result = await manager.requestOtp('user@example.com');

			expect(result).toEqual({ success: true });
			expect(store.invalidateAllForEmail).toHaveBeenCalledWith('user@example.com');
			expect(store.createCode).toHaveBeenCalledTimes(1);
			expect(delivery.deliver).toHaveBeenCalledTimes(1);
			expect(delivery.deliver).toHaveBeenCalledWith(
				'user@example.com',
				expect.stringMatching(/^\d{6}$/),
				10
			);
		});

		it('should generate a 6-digit code', async () => {
			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager, store } = createManager({ userLookup });

			await manager.requestOtp('user@example.com');

			const createdCode = store.createCode.mock.calls[0]?.[2];
			expect(createdCode).toBeDefined();
			expect(createdCode).toMatch(/^\d{6}$/);
			const codeNum = parseInt(createdCode!, 10);
			expect(codeNum).toBeGreaterThanOrEqual(100000);
			expect(codeNum).toBeLessThanOrEqual(999999);
		});

		it('should set expiration based on config codeTtlMinutes', async () => {
			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const config: OtpConfig = { ...DEFAULT_CONFIG, codeTtlMinutes: 5 };
			const { manager, store } = createManager({ userLookup, config });

			const before = Date.now();
			await manager.requestOtp('user@example.com');
			const after = Date.now();

			const expiresAt = store.createCode.mock.calls[0]?.[3] as Date;
			expect(expiresAt).toBeDefined();
			// Expiry should be ~5 minutes from now
			expect(expiresAt.getTime()).toBeGreaterThanOrEqual(before + 5 * 60 * 1000);
			expect(expiresAt.getTime()).toBeLessThanOrEqual(after + 5 * 60 * 1000);
		});

		it('should normalize email to lowercase and trim', async () => {
			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager, store, delivery } = createManager({ userLookup });

			await manager.requestOtp('  User@Example.COM  ');

			expect(userLookup.findByEmail).toHaveBeenCalledWith('user@example.com');
			expect(store.invalidateAllForEmail).toHaveBeenCalledWith('user@example.com');
			expect(delivery.deliver).toHaveBeenCalledWith(
				'user@example.com',
				expect.any(String),
				10
			);
		});

		it('should return success true when user does not exist (no enumeration)', async () => {
			const { manager, store, delivery } = createManager();

			const result = await manager.requestOtp('unknown@example.com');

			expect(result).toEqual({ success: true });
			expect(store.createCode).not.toHaveBeenCalled();
			expect(delivery.deliver).not.toHaveBeenCalled();
		});

		it('should return success true and skip when rate limited', async () => {
			const store = createMockStore();
			store.findRecentCode.mockResolvedValue(makeOtpCode());

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager, delivery } = createManager({ store, userLookup });

			const result = await manager.requestOtp('user@example.com');

			expect(result).toEqual({ success: true });
			// Should not look up user, create code, or send email when rate limited
			expect(userLookup.findByEmail).not.toHaveBeenCalled();
			expect(store.createCode).not.toHaveBeenCalled();
			expect(delivery.deliver).not.toHaveBeenCalled();
		});

		it('should use rateLimitSeconds from config', async () => {
			const store = createMockStore();
			const config: OtpConfig = { ...DEFAULT_CONFIG, rateLimitSeconds: 120 };
			const { manager } = createManager({ store, config });

			await manager.requestOtp('user@example.com');

			expect(store.findRecentCode).toHaveBeenCalledWith('user@example.com', 120);
		});

		it('should invalidate previous codes before creating a new one', async () => {
			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const store = createMockStore();
			const callOrder: string[] = [];
			store.invalidateAllForEmail.mockImplementation(async () => { callOrder.push('invalidate'); });
			store.createCode.mockImplementation(async () => { callOrder.push('create'); });

			const { manager } = createManager({ store, userLookup });

			await manager.requestOtp('user@example.com');

			expect(callOrder).toEqual(['invalidate', 'create']);
		});
	});

	describe('verifyOtp', () => {

		it('should return tokens on valid code', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(makeOtpCode({ code: '654321' }));

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager, tokenGenerator } = createManager({ store, userLookup });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({
				success: true,
				access_token: 'test-access-token',
				refresh_token: 'test-refresh-token',
				expires: 900000,
			});
			expect(store.markAsUsed).toHaveBeenCalledWith('test-id');
			expect(tokenGenerator.generateTokens).toHaveBeenCalledWith('user-1', DEFAULT_REQUEST_INFO);
		});

		it('should normalize email to lowercase and trim when verifying', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(makeOtpCode({ code: '654321' }));

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const { manager } = createManager({ store, userLookup });

			await manager.verifyOtp('  User@Example.COM  ', '654321', DEFAULT_REQUEST_INFO);

			expect(store.findLatestValidCode).toHaveBeenCalledWith('user@example.com');
			expect(userLookup.findByEmail).toHaveBeenCalledWith('user@example.com');
		});

		it('should return invalid_code when no valid code found', async () => {
			const { manager } = createManager();

			const result = await manager.verifyOtp('user@example.com', '123456', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'invalid_code' });
		});

		it('should return too_many_attempts when max attempts reached', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 3 })
			);

			const { manager } = createManager({ store });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'too_many_attempts' });
			expect(store.incrementAttempts).not.toHaveBeenCalled();
		});

		it('should return too_many_attempts when attempts exceed max', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 5 })
			);

			const { manager } = createManager({ store });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'too_many_attempts' });
		});

		it('should increment attempts and return invalid_code on wrong code', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 0 })
			);

			const { manager } = createManager({ store });

			const result = await manager.verifyOtp('user@example.com', '999999', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'invalid_code' });
			expect(store.incrementAttempts).toHaveBeenCalledWith('test-id');
		});

		it('should increment attempts on second wrong attempt', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 1 })
			);

			const { manager } = createManager({ store });

			const result = await manager.verifyOtp('user@example.com', '111111', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'invalid_code' });
			expect(store.incrementAttempts).toHaveBeenCalledWith('test-id');
		});

		it('should return invalid_code if user not found during verification', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(makeOtpCode({ code: '654321' }));

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue(null);

			const { manager } = createManager({ store, userLookup });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'invalid_code' });
			expect(store.markAsUsed).toHaveBeenCalledWith('test-id');
		});

		it('should respect custom maxAttempts config', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 5 })
			);

			const config: OtpConfig = { ...DEFAULT_CONFIG, maxAttempts: 5 };
			const { manager } = createManager({ store, config });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({ success: false, error: 'too_many_attempts' });
		});

		it('should allow verification when attempts are below custom maxAttempts', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(
				makeOtpCode({ code: '654321', attempts: 4 })
			);

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const config: OtpConfig = { ...DEFAULT_CONFIG, maxAttempts: 5 };
			const { manager } = createManager({ store, userLookup, config });

			const result = await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(result).toEqual({
				success: true,
				access_token: 'test-access-token',
				refresh_token: 'test-refresh-token',
				expires: 900000,
			});
		});

		it('should forward requestInfo to token generator', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(makeOtpCode({ code: '654321' }));

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const tokenGenerator = createMockTokenGenerator();
			const { manager } = createManager({ store, userLookup, tokenGenerator });

			const customRequestInfo: RequestInfo = {
				ip: '192.168.1.1',
				userAgent: 'Custom-Agent/1.0',
				origin: 'https://example.com',
			};

			await manager.verifyOtp('user@example.com', '654321', customRequestInfo);

			expect(tokenGenerator.generateTokens).toHaveBeenCalledWith('user-1', customRequestInfo);
		});

		it('should mark code as used before generating tokens', async () => {
			const store = createMockStore();
			store.findLatestValidCode.mockResolvedValue(makeOtpCode({ code: '654321' }));

			const userLookup = createMockUserLookup();
			userLookup.findByEmail.mockResolvedValue({
				id: 'user-1',
				role: 'role-1',
			});

			const tokenGenerator = createMockTokenGenerator();
			const callOrder: string[] = [];
			store.markAsUsed.mockImplementation(async () => { callOrder.push('markAsUsed'); });
			tokenGenerator.generateTokens.mockImplementation(async () => {
				callOrder.push('generateTokens');
				return { access_token: 'tok', refresh_token: 'ref', expires: 900000 };
			});

			const { manager } = createManager({ store, userLookup, tokenGenerator });

			await manager.verifyOtp('user@example.com', '654321', DEFAULT_REQUEST_INFO);

			expect(callOrder).toEqual(['markAsUsed', 'generateTokens']);
		});
	});
});
