const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const UNIT_MS: Record<string, number> = {
	ms: 1, msec: 1, msecs: 1, millisecond: 1, milliseconds: 1,
	s: SECOND, sec: SECOND, secs: SECOND, second: SECOND, seconds: SECOND,
	m: MINUTE, min: MINUTE, mins: MINUTE, minute: MINUTE, minutes: MINUTE,
	h: HOUR, hr: HOUR, hrs: HOUR, hour: HOUR, hours: HOUR,
	d: DAY, day: DAY, days: DAY,
	w: 7 * DAY, week: 7 * DAY, weeks: 7 * DAY,
	y: 365.25 * DAY, yr: 365.25 * DAY, yrs: 365.25 * DAY, year: 365.25 * DAY, years: 365.25 * DAY,
};

const DURATION_PATTERN = /^(\d*\.?\d+) *([a-z]+)?$/i;

/**
 * Parses a Directus TTL the way Directus does (it uses the `ms` library):
 * "365d", "1y", "52w", "90 days", "15m", or a bare number of milliseconds.
 * Returns `fallbackMs` for missing, malformed or non-positive values.
 */
export function parseDuration(value: unknown, fallbackMs: number): number {
	if (typeof value === 'number') {
		return Number.isFinite(value) && value > 0 ? value : fallbackMs;
	}
	if (typeof value !== 'string') {
		return fallbackMs;
	}

	const match = DURATION_PATTERN.exec(value.trim());
	if (!match) {
		return fallbackMs;
	}

	const [, amountText = '', unitText = 'ms'] = match;
	const amount = parseFloat(amountText);
	const unit = unitText.toLowerCase();
	const unitMs = UNIT_MS[unit];
	if (unitMs === undefined || amount <= 0) {
		return fallbackMs;
	}
	return amount * unitMs;
}
