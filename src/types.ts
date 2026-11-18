export interface OtpCode {
	id: string;
	email: string;
	/** HMAC of the code (see otp-crypto), never the plain code. */
	codeHash: string;
	expires_at: Date;
	attempts: number;
	used: boolean;
	created_at: Date;
}

export interface OtpUser {
	id: string;
	role: string | null;
	status: string;
	/** True when the account has a TOTP secret (second factor must not be bypassed). */
	hasTfa: boolean;
	/** True when the account's policies grant app_access or admin_access. */
	privileged: boolean;
}

export type OtpUserLookupResult =
	| { kind: 'none' }
	| { kind: 'ambiguous' }
	| { kind: 'found'; user: OtpUser };

export interface IOtpStore {
	/**
	 * Atomically, for one e-mail: refuses when a code was created less than `minIntervalSeconds` ago
	 * ('throttled') or when `maxPerDay` codes were created in the last 24 h ('capped'; 0 = no cap),
	 * otherwise closes the open codes and stores the new one ('issued').
	 */
	issueCode(request: IssueCodeRequest): Promise<IssueCodeOutcome>;
	findLatestValidCode(email: string): Promise<OtpCode | null>;
	/** Atomically spends one attempt; false when the code is used, expired or already out of attempts. */
	consumeAttempt(id: string, maxAttempts: number): Promise<boolean>;
	/** Atomically marks the code as used; true only for the single caller that claimed it. */
	markAsUsed(id: string): Promise<boolean>;
}

export interface IssueCodeRequest {
	id: string;
	email: string;
	codeHash: string;
	expiresAt: Date;
	minIntervalSeconds: number;
	maxPerDay: number;
}

export type IssueCodeOutcome = 'issued' | 'throttled' | 'capped';

export interface IUserLookup {
	findByEmail(email: string): Promise<OtpUserLookupResult>;
}

export interface IUserProvisioner {
	/** False when no safe role is configured: no code is sent to unknown e-mails. */
	isAvailable(): Promise<boolean>;
	/** Creates the user, or returns the concurrently created one. Null when creation is refused. */
	create(email: string): Promise<OtpUser | null>;
}

export interface IRateLimiter {
	/** Records one event under `key` and returns the number of events inside the sliding window. */
	hit(key: string, windowSeconds: number): Promise<number>;
	count(key: string, windowSeconds: number): Promise<number>;
}

export interface IOtpLogger {
	info(fields: Record<string, unknown>, message: string): void;
	warn(fields: Record<string, unknown>, message: string): void;
	error(error: unknown, message: string): void;
}

export interface IOtpDelivery {
	deliver(email: string, code: string, expiresInMinutes: number): Promise<void>;
}

export interface OtpDeliveryPayload {
	email: string;
	code: string;
	expiresInMinutes: number;
	delivered: boolean;
}

export interface RequestInfo {
	ip: string | null;
	userAgent: string | null;
	origin: string | null;
}

export interface ITokenGenerator {
	generateTokens(userId: string, requestInfo: RequestInfo): Promise<{ access_token: string; refresh_token: string; expires: number }>;
}

export type OtpRequestResult =
	| { success: true }
	| { success: false; error: 'rate_limited' };

export interface OtpVerifySuccess {
	success: true;
	access_token: string;
	refresh_token: string;
	expires: number;
	userId: string;
	created: boolean;
}

export interface OtpVerifyFailure {
	success: false;
	error: 'invalid_code' | 'too_many_attempts' | 'rate_limited';
}

export type OtpVerifyResult = OtpVerifySuccess | OtpVerifyFailure;

export interface OtpConfig {
	codeTtlMinutes: number;
	maxAttempts: number;
	rateLimitSeconds: number;
}

/** A limit of 0 disables that limit. */
export interface OtpManagerConfig extends OtpConfig {
	codeSecret: string;
	autoRegister: boolean;
	/** Empty = any role (TOTP accounts are always refused; admin/Studio accounts only when allowPrivilegedAccounts is on). */
	allowedRoles: string[];
	/** OTP_ALLOW_PRIVILEGED_ACCOUNTS: let existing active admin/Studio accounts log in by code. Never affects the role given to auto-registered accounts. */
	allowPrivilegedAccounts: boolean;
	ipWindowSeconds: number;
	ipRequestLimit: number;
	ipVerifyLimit: number;
	maxCodesPerEmailPerDay: number;
	verifyFailureLimit: number;
	verifyFailureWindowSeconds: number;
	globalRequestHourlyLimit: number;
}
