import { createHmac, randomInt, timingSafeEqual } from 'crypto';

export const CODE_HASH_LENGTH = 64;

type RandomIntFn = (min: number, max: number) => number;

export function generateCode(rand: RandomIntFn = randomInt): string {
	return rand(0, 1_000_000).toString().padStart(6, '0');
}

/** HMAC-SHA256(secret, "email|code") as hex: the code is never stored in clear. */
export function hashOtpCode(secret: string, email: string, code: string): string {
	return createHmac('sha256', secret).update(`${email}|${code}`).digest('hex');
}

/** Constant-time comparison; false (never throws) when lengths differ. */
export function safeEqualHex(a: string, b: string): boolean {
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	return left.length === right.length && timingSafeEqual(left, right);
}

/** Short tag to correlate log lines without writing the e-mail address; keyed, so a dictionary of known addresses cannot reverse it. */
export function fingerprintEmail(secret: string, email: string): string {
	return createHmac('sha256', secret).update(`fingerprint|${email}`).digest('hex').slice(0, 12);
}
