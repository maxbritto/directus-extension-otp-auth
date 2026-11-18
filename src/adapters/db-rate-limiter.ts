import type { Knex } from 'knex';
import type { IRateLimiter } from '../types.js';

export const RATE_EVENTS_TABLE = 'otp_rate_events';

/**
 * Sliding window kept in the database so every Directus instance shares it
 * and it survives restarts. The event is recorded before counting, so
 * concurrent requests cannot all slip under the limit.
 */
export function createDbRateLimiter(database: Knex): IRateLimiter {
	async function count(key: string, windowSeconds: number): Promise<number> {
		const since = new Date(Date.now() - windowSeconds * 1000);
		const row = await database(RATE_EVENTS_TABLE)
			.where('bucket', key)
			.where('created_at', '>', since)
			.count({ total: '*' })
			.first();
		return Number(row?.['total'] ?? 0);
	}

	return {
		async hit(key, windowSeconds) {
			await database(RATE_EVENTS_TABLE).insert({ bucket: key, created_at: new Date() });
			return count(key, windowSeconds);
		},
		count,
	};
}
