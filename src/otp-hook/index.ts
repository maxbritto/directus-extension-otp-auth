import { defineHook } from '@directus/extensions-sdk';

export default defineHook(({ init }, { database, logger }) => {
	init('app.after', async () => {
		const hasTable = await database.schema.hasTable('otp_codes');
		if (!hasTable) {
			logger.info('Creating otp_codes table...');
			await database.schema.createTable('otp_codes', (table) => {
				table.uuid('id').primary();
				table.string('email', 255).notNullable();
				table.string('code', 6).notNullable();
				table.datetime('expires_at').notNullable();
				table.integer('attempts').defaultTo(0);
				table.boolean('used').defaultTo(false);
				table.datetime('created_at').defaultTo(database.fn.now());
				table.index(['email']);
			});
			logger.info('otp_codes table created successfully');
		}
	});
});
