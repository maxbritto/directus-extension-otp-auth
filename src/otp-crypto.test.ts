import { createHash } from 'crypto';
import { fingerprintEmail, generateCode, hashOtpCode, safeEqualHex } from './otp-crypto';

describe('generateCode', () => {
	it('draws from the full 000000-999999 space', () => {
		const rand = jest.fn().mockReturnValue(0);
		expect(generateCode(rand)).toBe('000000');
		expect(rand).toHaveBeenCalledWith(0, 1_000_000);
	});

	it('can return 999999', () => {
		expect(generateCode(() => 999999)).toBe('999999');
	});

	it('pads to 6 digits', () => {
		expect(generateCode(() => 4521)).toBe('004521');
	});

	it('produces 6-digit strings with the real generator', () => {
		for (let i = 0; i < 50; i++) {
			expect(generateCode()).toMatch(/^\d{6}$/);
		}
	});
});

describe('hashOtpCode', () => {
	it('is a 64-char hex digest, deterministic for the same inputs', () => {
		const hash = hashOtpCode('secret', 'a@b.fr', '123456');
		expect(hash).toMatch(/^[0-9a-f]{64}$/);
		expect(hashOtpCode('secret', 'a@b.fr', '123456')).toBe(hash);
	});

	it('depends on secret, e-mail and code', () => {
		const hash = hashOtpCode('secret', 'a@b.fr', '123456');
		expect(hashOtpCode('other', 'a@b.fr', '123456')).not.toBe(hash);
		expect(hashOtpCode('secret', 'c@d.fr', '123456')).not.toBe(hash);
		expect(hashOtpCode('secret', 'a@b.fr', '123457')).not.toBe(hash);
	});

	it('does not contain the plain code', () => {
		expect(hashOtpCode('secret', 'a@b.fr', '123456')).not.toContain('123456');
	});
});

describe('fingerprintEmail', () => {
	it('is stable, short and keyed by the secret', () => {
		const tag = fingerprintEmail('secret', 'a@b.fr');
		expect(tag).toMatch(/^[0-9a-f]{12}$/);
		expect(fingerprintEmail('secret', 'a@b.fr')).toBe(tag);
		expect(fingerprintEmail('other', 'a@b.fr')).not.toBe(tag);
		expect(fingerprintEmail('secret', 'c@d.fr')).not.toBe(tag);
	});

	it('does not match an unkeyed SHA-256 prefix', () => {
		const unkeyed = createHash('sha256').update('a@b.fr').digest('hex').slice(0, 12);
		expect(fingerprintEmail('secret', 'a@b.fr')).not.toBe(unkeyed);
	});
});

describe('safeEqualHex', () => {
	it('matches equal values and rejects different ones', () => {
		const a = hashOtpCode('s', 'a@b.fr', '111111');
		expect(safeEqualHex(a, a)).toBe(true);
		expect(safeEqualHex(a, hashOtpCode('s', 'a@b.fr', '222222'))).toBe(false);
	});

	it('returns false (never throws) on length mismatch or garbage', () => {
		expect(safeEqualHex('abcd', 'abcdef')).toBe(false);
		expect(safeEqualHex('', 'abcd')).toBe(false);
		expect(safeEqualHex('zz', 'zz')).toBe(true);
	});
});
