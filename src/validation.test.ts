import { isValidCode, isValidEmail, normalizeEmail } from './validation';

describe('normalizeEmail', () => {
	it('trims and lowercases', () => {
		expect(normalizeEmail('  Foo.Bar@Example.COM ')).toBe('foo.bar@example.com');
	});
});

describe('isValidEmail', () => {
	it.each(['a@b.fr', 'first.last+tag@sub.example.com', 'Foo@Example.com'])('accepts %p', (email) => {
		expect(isValidEmail(email)).toBe(true);
	});

	it.each([
		'', 'plain', 'a@', '@b.fr', 'a@b', 'a b@c.fr', 'a@b@c.fr', 'a@@b.fr',
		`${'a'.repeat(250)}@b.fr`, 'a@b.fr\nbcc:x@y.fr',
	])('rejects %p', (email) => {
		expect(isValidEmail(email)).toBe(false);
	});

	it.each([undefined, null, 42, ['a@b.fr'], { email: 'a@b.fr' }, true])('rejects non-string %p', (value) => {
		expect(isValidEmail(value)).toBe(false);
	});
});

describe('isValidCode', () => {
	it.each(['000000', '123456', '999999'])('accepts %p', (code) => {
		expect(isValidCode(code)).toBe(true);
	});

	it.each(['12345', '1234567', '12345a', ' 12345', '123 456', '', '１２３４５６'])('rejects %p', (code) => {
		expect(isValidCode(code)).toBe(false);
	});

	it.each([123456, undefined, null, ['123456']])('rejects non-string %p', (value) => {
		expect(isValidCode(value)).toBe(false);
	});
});
