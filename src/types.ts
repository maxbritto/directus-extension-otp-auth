export interface OtpCode {
	id: string;
	email: string;
	code: string;
	expires_at: Date;
	attempts: number;
	used: boolean;
	created_at: Date;
}

export interface DirectusUser {
	id: string;
	role: string;
}

export interface IOtpStore {
	createCode(id: string, email: string, code: string, expiresAt: Date): Promise<void>;
	findLatestValidCode(email: string): Promise<OtpCode | null>;
	findRecentCode(email: string, withinSeconds: number): Promise<OtpCode | null>;
	incrementAttempts(id: string): Promise<void>;
	markAsUsed(id: string): Promise<void>;
	invalidateAllForEmail(email: string): Promise<void>;
}

export interface IUserLookup {
	findByEmail(email: string): Promise<DirectusUser | null>;
}

export interface IMailSender {
	sendOtpEmail(email: string, code: string): Promise<void>;
}

export interface RequestInfo {
	ip: string | null;
	userAgent: string | null;
	origin: string | null;
}

export interface ITokenGenerator {
	generateTokens(userId: string, requestInfo: RequestInfo): Promise<{ access_token: string; refresh_token: string; expires: number }>;
}

export interface OtpVerifySuccess {
	success: true;
	access_token: string;
	refresh_token: string;
	expires: number;
}

export interface OtpVerifyFailure {
	success: false;
	error: 'invalid_code' | 'too_many_attempts';
}

export type OtpVerifyResult = OtpVerifySuccess | OtpVerifyFailure;

export interface OtpConfig {
	codeTtlMinutes: number;
	maxAttempts: number;
	rateLimitSeconds: number;
}
