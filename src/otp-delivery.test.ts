import { createOtpDelivery, type OtpDeliveryDeps } from './otp-delivery';
import type { OtpDeliveryPayload, OtpConfig } from './types';

const DEFAULT_CONFIG: OtpConfig = {
	codeTtlMinutes: 10,
	maxAttempts: 3,
	rateLimitSeconds: 60,
};

function createMockMailService() {
	return {
		send: jest.fn().mockResolvedValue(undefined),
	};
}

function createMockDeps(overrides?: Partial<OtpDeliveryDeps>): { deps: OtpDeliveryDeps; mockMailService: ReturnType<typeof createMockMailService> } {
	const mockMailService = createMockMailService();
	const MailServiceClass = jest.fn().mockImplementation(() => mockMailService);

	const deps: OtpDeliveryDeps = {
		emitter: {
			emitFilter: jest.fn().mockImplementation(async (_event: string, payload: OtpDeliveryPayload) => payload),
		},
		database: {},
		services: { MailService: MailServiceClass },
		getSchema: jest.fn().mockResolvedValue({ test: true }),
		env: {},
		config: DEFAULT_CONFIG,
		logger: { error: jest.fn() },
		...overrides,
	};

	return { deps, mockMailService };
}

describe('createOtpDelivery', () => {

	it('should send built-in email when no filter handler sets delivered to true', async () => {
		const { deps, mockMailService } = createMockDeps();
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 10);

		expect(deps.emitter.emitFilter).toHaveBeenCalledTimes(1);
		expect(mockMailService.send).toHaveBeenCalledTimes(1);
		expect(mockMailService.send).toHaveBeenCalledWith(
			expect.objectContaining({
				to: 'user@example.com',
				subject: 'Your login code',
			})
		);
	});

	it('should skip built-in email when filter handler sets delivered to true', async () => {
		const { deps, mockMailService } = createMockDeps({
			emitter: {
				emitFilter: jest.fn().mockImplementation(async (_event: string, payload: OtpDeliveryPayload) => ({
					...payload,
					delivered: true,
				})),
			},
		});
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 10);

		expect(deps.emitter.emitFilter).toHaveBeenCalledTimes(1);
		expect(mockMailService.send).not.toHaveBeenCalled();
	});

	it('should emit filter with correct payload shape', async () => {
		const { deps } = createMockDeps();
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '654321', 5);

		expect(deps.emitter.emitFilter).toHaveBeenCalledWith(
			'otp-auth.deliver',
			{
				email: 'user@example.com',
				code: '654321',
				expiresInMinutes: 5,
				delivered: false,
			},
			{ services: deps.services },
			{ database: deps.database, schema: { test: true } }
		);
	});

	it('should use custom email subject from env', async () => {
		const { deps, mockMailService } = createMockDeps({
			env: { OTP_EMAIL_SUBJECT: 'Custom Subject' },
		});
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 10);

		expect(mockMailService.send).toHaveBeenCalledWith(
			expect.objectContaining({
				subject: 'Custom Subject',
			})
		);
	});

	it('should use custom template when OTP_EMAIL_TEMPLATE is set', async () => {
		const { deps, mockMailService } = createMockDeps({
			env: { OTP_EMAIL_TEMPLATE: 'my-otp-template' },
		});
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 10);

		expect(mockMailService.send).toHaveBeenCalledWith(
			expect.objectContaining({
				template: {
					name: 'my-otp-template',
					data: {
						code: '123456',
						expiry_minutes: 10,
					},
				},
			})
		);
	});

	it('should send default HTML email when no template is configured', async () => {
		const { deps, mockMailService } = createMockDeps();
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 10);

		expect(mockMailService.send).toHaveBeenCalledWith(
			expect.objectContaining({
				html: expect.stringContaining('123456'),
			})
		);
	});

	it('should propagate errors from filter handlers', async () => {
		const filterError = new Error('Handler failed');
		const { deps } = createMockDeps({
			emitter: {
				emitFilter: jest.fn().mockRejectedValue(filterError),
			},
		});
		const delivery = createOtpDelivery(deps);

		await expect(delivery.deliver('user@example.com', '123456', 10)).rejects.toThrow('Handler failed');
		expect(deps.logger.error).toHaveBeenCalledWith(filterError, 'Error in otp-auth.deliver filter handler');
	});

	it('should include expiry minutes in default HTML email', async () => {
		const config: OtpConfig = { ...DEFAULT_CONFIG, codeTtlMinutes: 15 };
		const { deps, mockMailService } = createMockDeps({ config });
		const delivery = createOtpDelivery(deps);

		await delivery.deliver('user@example.com', '123456', 15);

		expect(mockMailService.send).toHaveBeenCalledWith(
			expect.objectContaining({
				html: expect.stringContaining('15 minutes'),
			})
		);
	});
});
