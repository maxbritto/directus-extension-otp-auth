import type { Knex } from 'knex';
import type { IOtpStore, IssueCodeOutcome, OtpCode } from '../types.js';

interface OtpCodeRow {
	id: string;
	email: string;
	code: string;
	expires_at: Date;
	attempts: number;
	used: boolean | number;
	created_at: Date;
}

const DAY_MS = 24 * 60 * 60 * 1000;

function toOtpCode(row: OtpCodeRow): OtpCode {
	return {
		id: row.id,
		email: row.email,
		codeHash: row.code,
		expires_at: new Date(row.expires_at),
		attempts: Number(row.attempts),
		used: Boolean(row.used),
		created_at: new Date(row.created_at),
	};
}

/** Attempt and usage changes are single conditional UPDATEs; issuing a code is one transaction locked per e-mail. All stay atomic across instances. */
export function createOtpStore(database: Knex): IOtpStore {
	return {
		async issueCode({ id, email, codeHash, expiresAt, minIntervalSeconds, maxPerDay }) {
			return database.transaction(async (trx): Promise<IssueCodeOutcome> => {
				// Serialises concurrent requests for the same e-mail (PostgreSQL); other engines rely on the transaction.
				if (database.client.dialect === 'postgresql') {
					await trx.raw('SELECT pg_advisory_xact_lock(hashtext(?))', [email]);
				}

				const now = new Date();
				if (minIntervalSeconds > 0) {
					const recent = await trx('otp_codes')
						.where('email', email)
						.where('created_at', '>', new Date(now.getTime() - minIntervalSeconds * 1000))
						.first();
					if (recent) {
						return 'throttled';
					}
				}
				if (maxPerDay > 0) {
					const row = await trx('otp_codes')
						.where('email', email)
						.where('created_at', '>', new Date(now.getTime() - DAY_MS))
						.count({ total: '*' })
						.first();
					if (Number(row?.['total'] ?? 0) >= maxPerDay) {
						return 'capped';
					}
				}

				await trx('otp_codes').where('email', email).where('used', false).update({ used: true });
				await trx('otp_codes').insert({
					id, email, code: codeHash, expires_at: expiresAt, attempts: 0, used: false, created_at: now,
				});
				return 'issued';
			});
		},

		async findLatestValidCode(email) {
			const row = await database('otp_codes')
				.where('email', email)
				.where('used', false)
				.where('expires_at', '>', new Date())
				.orderBy('created_at', 'desc')
				.first();
			return row ? toOtpCode(row) : null;
		},

		async consumeAttempt(id, maxAttempts) {
			const updated = await database('otp_codes')
				.where('id', id)
				.where('used', false)
				.where('attempts', '<', maxAttempts)
				.where('expires_at', '>', new Date())
				.update({ attempts: database.raw('attempts + 1') });
			return updated === 1;
		},

		async markAsUsed(id) {
			const updated = await database('otp_codes')
				.where('id', id)
				.where('used', false)
				.update({ used: true });
			return updated === 1;
		},
	};
}
