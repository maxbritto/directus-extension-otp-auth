import { defineHook } from '@directus/extensions-sdk';
import { ensureOtpSchema, purgeOtpData } from '../otp-schema.js';

const HOURLY_AT_MINUTE_17 = '17 * * * *';

export default defineHook(({ init, schedule }, { database, logger }) => {
	init('app.after', async () => {
		await ensureOtpSchema(database, logger);
	});

	schedule(HOURLY_AT_MINUTE_17, async () => {
		try {
			await purgeOtpData(database);
		} catch (error) {
			logger.error(error, 'OTP purge failed');
		}
	});
});
