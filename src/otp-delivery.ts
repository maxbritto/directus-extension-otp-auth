import type { IOtpDelivery, OtpDeliveryPayload, OtpConfig } from './types.js';

export interface OtpDeliveryDeps {
	emitter: {
		emitFilter<T>(event: string, payload: T, meta: Record<string, unknown>, context: Record<string, unknown>): Promise<T>;
	};
	database: unknown;
	services: Record<string, unknown>;
	getSchema: () => Promise<unknown>;
	env: Record<string, unknown>;
	config: OtpConfig;
	logger: { error(obj: unknown, msg?: string): void };
}

function sendBuiltInEmail(
	services: Record<string, unknown>,
	getSchema: () => Promise<unknown>,
	env: Record<string, unknown>,
	config: OtpConfig,
): (email: string, code: string) => Promise<void> {
	return async (email: string, code: string): Promise<void> => {
		const schema = await getSchema();
		const MailService = services['MailService'] as new (opts: { schema: unknown }) => { send(opts: Record<string, unknown>): Promise<void> };
		const mailService = new MailService({ schema });

		const subject = (env['OTP_EMAIL_SUBJECT'] as string) || 'Your login code';
		const templateName = env['OTP_EMAIL_TEMPLATE'] as string | undefined;

		if (templateName) {
			await mailService.send({
				to: email,
				subject,
				template: {
					name: templateName,
					data: {
						code,
						expiry_minutes: config.codeTtlMinutes,
					},
				},
			});
		} else {
			await mailService.send({
				to: email,
				subject,
				html: `
						<div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; text-align: center;">
							<h2>Your login code</h2>
							<p style="font-size: 32px; font-weight: bold; letter-spacing: 8px; margin: 24px 0; font-family: monospace;">${code}</p>
							<p>This code expires in ${config.codeTtlMinutes} minutes.</p>
							<p style="color: #888; font-size: 12px; margin-top: 24px;">If you didn't request this code, you can safely ignore this email.</p>
						</div>
					`,
			});
		}
	};
}

export function createOtpDelivery(deps: OtpDeliveryDeps): IOtpDelivery {
	const fallbackEmail = sendBuiltInEmail(deps.services, deps.getSchema, deps.env, deps.config);

	return {
		async deliver(email: string, code: string, expiresInMinutes: number): Promise<void> {
			const payload: OtpDeliveryPayload = {
				email,
				code,
				expiresInMinutes,
				delivered: false,
			};

			const meta = { services: deps.services };
			const context = { database: deps.database, schema: await deps.getSchema() };

			let result: OtpDeliveryPayload;
			try {
				result = await deps.emitter.emitFilter('otp-auth.deliver', payload, meta, context);
			} catch (error) {
				deps.logger.error(error, 'Error in otp-auth.deliver filter handler');
				throw error;
			}

			if (!result.delivered) {
				await fallbackEmail(email, code);
			}
		},
	};
}
