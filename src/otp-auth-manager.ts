import { randomUUID } from 'crypto';
import { fingerprintEmail, generateCode, hashOtpCode, safeEqualHex } from './otp-crypto.js';
import { normalizeEmail } from './validation.js';
import type {
	IOtpDelivery, IOtpLogger, IOtpStore, IRateLimiter, ITokenGenerator, IUserLookup, IUserProvisioner,
	OtpManagerConfig, OtpRequestResult, OtpUser, OtpVerifyFailure, OtpVerifyResult, RequestInfo,
} from './types.js';

const ACTIVE_STATUS = 'active';
const HOUR_SECONDS = 3600;
const GLOBAL_REQUEST_KEY = 'request:global';
const UNKNOWN_IP = 'unknown';

export interface OtpAuthDeps {
	store: IOtpStore;
	userLookup: IUserLookup;
	provisioner: IUserProvisioner;
	delivery: IOtpDelivery;
	tokenGenerator: ITokenGenerator;
	rateLimiter: IRateLimiter;
	logger: IOtpLogger;
	config: OtpManagerConfig;
}

const invalidCode: OtpVerifyFailure = { success: false, error: 'invalid_code' };
const rateLimited = { success: false, error: 'rate_limited' } as const;

export class OtpAuthManager {
	private readonly deps: OtpAuthDeps;

	constructor(deps: OtpAuthDeps) {
		this.deps = deps;
	}

	/**
	 * Always resolves with the same shape whatever the state of the account
	 * (unknown, suspended, rate-limited per e-mail): only account-independent
	 * per-IP / global limits answer differently.
	 */
	async requestOtp(email: string, ip: string | null): Promise<OtpRequestResult> {
		const { store, config } = this.deps;
		const normalizedEmail = normalizeEmail(email);

		const exceeded = await this.exceededRequestLimit(ip);
		if (exceeded) {
			this.deps.logger.warn({ ip, reason: exceeded }, 'otp.request.rate_limited');
			return rateLimited;
		}

		if (!(await this.canReceiveCode(normalizedEmail))) {
			return { success: true };
		}

		const code = generateCode();
		const outcome = await store.issueCode({
			id: randomUUID(),
			email: normalizedEmail,
			codeHash: hashOtpCode(config.codeSecret, normalizedEmail, code),
			expiresAt: new Date(Date.now() + config.codeTtlMinutes * 60 * 1000),
			minIntervalSeconds: config.rateLimitSeconds,
			maxPerDay: config.maxCodesPerEmailPerDay,
		});

		if (outcome === 'capped') {
			this.deps.logger.warn({ email: this.fingerprint(normalizedEmail) }, 'otp.request.daily_cap');
		} else if (outcome === 'issued') {
			this.deliverInBackground(normalizedEmail, code);
			this.deps.logger.info({ email: this.fingerprint(normalizedEmail), ip }, 'otp.request');
		}
		return { success: true };
	}

	async verifyOtp(email: string, code: string, requestInfo: RequestInfo): Promise<OtpVerifyResult> {
		const { rateLimiter, config, logger } = this.deps;
		const normalizedEmail = normalizeEmail(email);
		const failureKey = `verify-fail:${normalizedEmail}`;

		if (config.ipVerifyLimit > 0) {
			const hits = await rateLimiter.hit(`verify:ip:${requestInfo.ip ?? UNKNOWN_IP}`, config.ipWindowSeconds);
			if (hits > config.ipVerifyLimit) {
				logger.warn({ ip: requestInfo.ip }, 'otp.verify.rate_limited');
				return rateLimited;
			}
		}

		if (config.verifyFailureLimit > 0) {
			const failures = await rateLimiter.count(failureKey, config.verifyFailureWindowSeconds);
			if (failures >= config.verifyFailureLimit) {
				logger.warn({ email: this.fingerprint(normalizedEmail), ip: requestInfo.ip }, 'otp.locked');
				return rateLimited;
			}
		}

		const result = await this.checkCodeAndIssueTokens(normalizedEmail, code, requestInfo);

		if (!result.success) {
			await rateLimiter.hit(failureKey, config.verifyFailureWindowSeconds);
			logger.warn({ email: this.fingerprint(normalizedEmail), ip: requestInfo.ip, reason: result.error }, 'otp.verify.fail');
		}
		return result;
	}

	private async checkCodeAndIssueTokens(email: string, code: string, requestInfo: RequestInfo): Promise<OtpVerifyResult> {
		const { store, config, tokenGenerator } = this.deps;

		const otpCode = await store.findLatestValidCode(email);
		if (!otpCode) {
			return invalidCode;
		}
		if (otpCode.attempts >= config.maxAttempts) {
			return { success: false, error: 'too_many_attempts' };
		}

		// Spend the attempt before comparing: parallel guesses cannot exceed maxAttempts.
		if (!(await store.consumeAttempt(otpCode.id, config.maxAttempts))) {
			return invalidCode;
		}
		if (!safeEqualHex(otpCode.codeHash, hashOtpCode(config.codeSecret, email, code))) {
			return invalidCode;
		}
		// Only the caller that claims the code goes on to open a session / create the user.
		if (!(await store.markAsUsed(otpCode.id))) {
			return invalidCode;
		}

		const resolved = await this.resolveUser(email);
		if (!resolved) {
			return invalidCode;
		}

		const tokens = await tokenGenerator.generateTokens(resolved.user.id, requestInfo);
		this.deps.logger.info({ email: this.fingerprint(email), ip: requestInfo.ip }, resolved.created ? 'otp.autoregister' : 'otp.verify.ok');

		return {
			success: true,
			access_token: tokens.access_token,
			refresh_token: tokens.refresh_token,
			expires: tokens.expires,
			userId: resolved.user.id,
			created: resolved.created,
		};
	}

	private async resolveUser(email: string): Promise<{ user: OtpUser; created: boolean } | null> {
		const { userLookup, provisioner, config, logger } = this.deps;
		const lookup = await userLookup.findByEmail(email);
		let result: { user: OtpUser; created: boolean } | null = null;

		if (lookup.kind === 'ambiguous') {
			logger.warn({ email: this.fingerprint(email) }, 'otp.account.ambiguous');
		} else if (lookup.kind === 'found') {
			result = this.isEligible(lookup.user) ? { user: lookup.user, created: false } : null;
		} else if (config.autoRegister) {
			const user = await provisioner.create(email);
			result = user && this.isEligible(user) ? { user, created: true } : null;
		}

		return result;
	}

	private async canReceiveCode(email: string): Promise<boolean> {
		const { userLookup, provisioner, config, logger } = this.deps;
		const lookup = await userLookup.findByEmail(email);
		let canReceive = false;

		if (lookup.kind === 'ambiguous') {
			logger.warn({ email: this.fingerprint(email) }, 'otp.account.ambiguous');
		} else if (lookup.kind === 'found') {
			canReceive = this.isEligible(lookup.user);
		} else {
			canReceive = config.autoRegister && (await provisioner.isAvailable());
		}

		return canReceive;
	}

	private isEligible(user: OtpUser): boolean {
		const { allowedRoles, allowPrivilegedAccounts } = this.deps.config;
		const roleAllowed = allowedRoles.length === 0 || (user.role !== null && allowedRoles.includes(user.role));
		return user.status === ACTIVE_STATUS && !user.hasTfa && (allowPrivilegedAccounts || !user.privileged) && roleAllowed;
	}

	/** Which account-independent limit the request exceeds, if any. */
	private async exceededRequestLimit(ip: string | null): Promise<'ip' | 'global' | null> {
		const { rateLimiter, config } = this.deps;

		if (config.ipRequestLimit > 0) {
			const hits = await rateLimiter.hit(`request:ip:${ip ?? UNKNOWN_IP}`, config.ipWindowSeconds);
			if (hits > config.ipRequestLimit) {
				return 'ip';
			}
		}
		if (config.globalRequestHourlyLimit > 0) {
			const hits = await rateLimiter.hit(GLOBAL_REQUEST_KEY, HOUR_SECONDS);
			if (hits > config.globalRequestHourlyLimit) {
				return 'global';
			}
		}
		return null;
	}

	private fingerprint(email: string): string {
		return fingerprintEmail(this.deps.config.codeSecret, email);
	}

	/** Fire and forget: response time must not reveal whether a mail was sent. */
	private deliverInBackground(email: string, code: string): void {
		const { delivery, config, logger } = this.deps;
		delivery.deliver(email, code, config.codeTtlMinutes).catch((error: unknown) => {
			logger.error(error, 'otp.deliver.failed');
		});
	}
}
