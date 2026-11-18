import type { Knex } from 'knex';
import { RATE_EVENTS_TABLE } from './adapters/db-rate-limiter.js';
import { CODE_HASH_LENGTH } from './otp-crypto.js';

interface Logger {
	info(message: string): void;
}

const RETENTION_MS = 48 * 60 * 60 * 1000;

export async function ensureOtpSchema(database: Knex, logger: Logger): Promise<void> {
	if (!(await database.schema.hasTable('otp_codes'))) {
		logger.info('Creating otp_codes table...');
		await database.schema.createTable('otp_codes', (table) => {
			table.uuid('id').primary();
			table.string('email', 255).notNullable();
			table.string('code', CODE_HASH_LENGTH).notNullable();
			table.datetime('expires_at').notNullable();
			table.integer('attempts').defaultTo(0);
			table.boolean('used').defaultTo(false);
			table.datetime('created_at').defaultTo(database.fn.now());
			table.index(['email']);
		});
		logger.info('otp_codes table created successfully');
	} else {
		await migrateCodeColumn(database, logger);
	}

	if (!(await database.schema.hasTable(RATE_EVENTS_TABLE))) {
		logger.info(`Creating ${RATE_EVENTS_TABLE} table...`);
		await database.schema.createTable(RATE_EVENTS_TABLE, (table) => {
			table.increments('id');
			table.string('bucket', 255).notNullable();
			table.datetime('created_at').notNullable();
			table.index(['bucket', 'created_at']);
		});
	}
}

/** Pre-hash installs stored 6 plain digits: close those codes and widen the column to hold a digest. */
async function migrateCodeColumn(database: Knex, logger: Logger): Promise<void> {
	const info = await database('otp_codes').columnInfo('code');
	const length = Number((info as { maxLength?: number | null }).maxLength ?? 0);
	if (length >= CODE_HASH_LENGTH) {
		return;
	}

	logger.info('Migrating otp_codes.code to hashed storage; open codes are invalidated.');
	await database('otp_codes').where('used', false).update({ used: true });
	await database.schema.alterTable('otp_codes', (table) => {
		table.string('code', CODE_HASH_LENGTH).notNullable().alter();
	});
}

/** Expired codes hold e-mails of non-users (auto-register): do not keep them. */
export async function purgeOtpData(database: Knex, now: Date = new Date()): Promise<void> {
	const cutoff = new Date(now.getTime() - RETENTION_MS);
	await database('otp_codes').where('created_at', '<', cutoff).delete();
	await database(RATE_EVENTS_TABLE).where('created_at', '<', cutoff).delete();
}
