import { parseDuration } from './duration';

const DAY = 24 * 60 * 60 * 1000;

describe('parseDuration', () => {
	it.each([
		['365d', 365 * DAY],
		['90d', 90 * DAY],
		['1y', 365.25 * DAY],
		['52w', 52 * 7 * DAY],
		['2 weeks', 14 * DAY],
		['90 days', 90 * DAY],
		['15m', 15 * 60 * 1000],
		['15 min', 15 * 60 * 1000],
		['1h', 60 * 60 * 1000],
		['45s', 45 * 1000],
		['250ms', 250],
		['1.5d', 1.5 * DAY],
		['900000', 900000],
		[900000, 900000],
	])('parses %p like the ms library used by Directus', (input, expected) => {
		expect(parseDuration(input, 1)).toBe(expected);
	});

	it.each([[''], ['   '], ['soon'], ['-5d'], [undefined], [null], [NaN]])('falls back to the default for %p', (input) => {
		expect(parseDuration(input as unknown as string, 4242)).toBe(4242);
	});
});
