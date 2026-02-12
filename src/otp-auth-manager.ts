import { randomInt, randomUUID } from 'crypto';
import type { IOtpStore, IUserLookup, IMailSender, ITokenGenerator, OtpVerifyResult, OtpConfig } from './types.js';

export class OtpAuthManager {
	private readonly store: IOtpStore;
	private readonly userLookup: IUserLookup;
	private readonly mailSender: IMailSender;
	private readonly tokenGenerator: ITokenGenerator;
	private readonly config: OtpConfig;

	constructor(
		store: IOtpStore,
		userLookup: IUserLookup,
		mailSender: IMailSender,
		tokenGenerator: ITokenGenerator,
		config: OtpConfig
	) {
		this.store = store;
		this.userLookup = userLookup;
		this.mailSender = mailSender;
		this.tokenGenerator = tokenGenerator;
		this.config = config;
	}

	async requestOtp(email: string): Promise<{ success: boolean }> {
		const normalizedEmail = email.toLowerCase().trim();

		// Rate limit: if a code was created recently, silently succeed
		const recentCode = await this.store.findRecentCode(normalizedEmail, this.config.rateLimitSeconds);
		if (recentCode) {
			return { success: true };
		}

		// Look up user — if not found, silently succeed (no enumeration)
		const user = await this.userLookup.findByEmail(normalizedEmail);
		if (!user) {
			return { success: true };
		}

		// Invalidate all previous codes for this email
		await this.store.invalidateAllForEmail(normalizedEmail);

		// Generate 6-digit code
		const code = randomInt(100000, 999999).toString();
		const id = randomUUID();
		const expiresAt = new Date(Date.now() + this.config.codeTtlMinutes * 60 * 1000);

		// Store the code
		await this.store.createCode(id, normalizedEmail, code, expiresAt);

		// Send email
		await this.mailSender.sendOtpEmail(normalizedEmail, code);

		return { success: true };
	}

	async verifyOtp(email: string, code: string): Promise<OtpVerifyResult> {
		const normalizedEmail = email.toLowerCase().trim();

		// Find latest valid (unused + unexpired) code
		const otpCode = await this.store.findLatestValidCode(normalizedEmail);
		if (!otpCode) {
			return { success: false, error: 'invalid_code' };
		}

		// Check max attempts
		if (otpCode.attempts >= this.config.maxAttempts) {
			return { success: false, error: 'too_many_attempts' };
		}

		// Check code match
		if (otpCode.code !== code) {
			await this.store.incrementAttempts(otpCode.id);
			return { success: false, error: 'invalid_code' };
		}

		// Code is valid — mark as used
		await this.store.markAsUsed(otpCode.id);

		// Look up user to generate tokens
		const user = await this.userLookup.findByEmail(normalizedEmail);
		if (!user) {
			return { success: false, error: 'invalid_code' };
		}

		// Generate tokens
		const tokens = await this.tokenGenerator.generateTokens(user.id);

		return {
			success: true,
			access_token: tokens.access_token,
			refresh_token: tokens.refresh_token,
			expires: tokens.expires,
		};
	}
}
