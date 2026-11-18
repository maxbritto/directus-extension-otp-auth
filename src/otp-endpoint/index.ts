import { defineEndpoint } from '@directus/extensions-sdk';
import type { Response } from 'express';
import { createDbRateLimiter } from '../adapters/db-rate-limiter.js';
import { checkAutoRegisterRole, createUserLookup, createUserProvisioner } from '../adapters/directus-users.js';
import { createOtpStore } from '../adapters/otp-store.js';
import { createTokenGenerator } from '../adapters/token-generator.js';
import { OtpAuthManager } from '../otp-auth-manager.js';
import { readOtpConfig } from '../otp-config.js';
import { createOtpDelivery } from '../otp-delivery.js';
import type { RequestInfo } from '../types.js';
import { isValidCode, isValidEmail } from '../validation.js';

/** Floor on /request latency, so a refused account (admin, suspended, ambiguous) cannot be told apart by timing. */
const MIN_REQUEST_DURATION_MS = 150;

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function sendError(res: Response, status: number, code: string, message: string): void {
	res.status(status).json({ errors: [{ message, extensions: { code } }] });
}

export default defineEndpoint({
	id: 'otp-auth',
	handler: (router, context) => {
		const { database, env, services, getSchema, logger, emitter } = context;

		const config = readOtpConfig(env);
		const userLookup = createUserLookup(database);
		const manager = new OtpAuthManager({
			store: createOtpStore(database),
			userLookup,
			provisioner: createUserProvisioner({
				database, services, getSchema, logger, userLookup, configuredRole: config.autoRegisterRole,
			}),
			delivery: createOtpDelivery({ emitter, database, services, getSchema, env, config, logger }),
			tokenGenerator: createTokenGenerator(database, env),
			rateLimiter: createDbRateLimiter(database),
			logger,
			config,
		});

		// Fail closed: until the auto-registration role is proven safe, every route answers 503.
		let ready = !config.autoRegister;
		if (config.autoRegister && config.autoRegisterRole) {
			const role = config.autoRegisterRole;
			checkAutoRegisterRole(database, role)
				.then((check) => {
					if (check.ok) {
						ready = true;
					} else {
						logger.error({ role }, `otp-auth: OTP_AUTO_REGISTER_ROLE is unusable (${check.reason}: it must exist and grant neither admin nor Studio access); OTP endpoints stay disabled.`);
					}
				})
				.catch((error) => logger.error(error, 'otp-auth: could not check OTP_AUTO_REGISTER_ROLE; OTP endpoints stay disabled.'));
		}
		router.use((_req, res, next) => {
			if (ready) {
				next();
			} else {
				sendError(res, 503, 'SERVICE_UNAVAILABLE', 'OTP login is unavailable.');
			}
		});

		router.post('/request', async (req, res) => {
			try {
				const { email } = (req.body ?? {}) as { email?: unknown };
				if (!isValidEmail(email)) {
					sendError(res, 400, 'INVALID_PAYLOAD', 'A valid email is required.');
					return;
				}

				const [result] = await Promise.all([manager.requestOtp(email, req.ip ?? null), sleep(MIN_REQUEST_DURATION_MS)]);
				if (!result.success) {
					sendError(res, 429, 'REQUESTS_EXCEEDED', 'Too many requests.');
					return;
				}
				res.status(200).json(result);
			} catch (error) {
				logger.error(error, 'OTP request error');
				sendError(res, 500, 'INTERNAL_SERVER_ERROR', 'Internal server error.');
			}
		});

		router.post('/verify', async (req, res) => {
			try {
				const { email, code } = (req.body ?? {}) as { email?: unknown; code?: unknown };
				if (!isValidEmail(email) || !isValidCode(code)) {
					sendError(res, 400, 'INVALID_PAYLOAD', 'A valid email and a 6-digit code are required.');
					return;
				}

				const requestInfo: RequestInfo = {
					ip: req.ip ?? null,
					userAgent: req.get('user-agent') ?? null,
					origin: req.get('origin') ?? null,
				};

				const result = await manager.verifyOtp(email, code, requestInfo);
				if (!result.success) {
					if (result.error === 'rate_limited') {
						sendError(res, 429, 'REQUESTS_EXCEEDED', 'Too many requests.');
					} else if (result.error === 'too_many_attempts') {
						sendError(res, 401, 'REQUESTS_EXCEEDED', 'Too many attempts.');
					} else {
						sendError(res, 401, 'INVALID_OTP', 'Invalid OTP code.');
					}
					return;
				}

				const schema = await getSchema();
				const activityService = new services['ActivityService']({ schema, knex: database });
				await activityService.createOne({
					action: 'login',
					user: result.userId,
					ip: requestInfo.ip,
					user_agent: requestInfo.userAgent,
					origin: requestInfo.origin,
					collection: 'directus_users',
					item: result.userId,
				});

				await database('directus_users').update({ last_access: new Date() }).where('id', result.userId);
				await database('directus_sessions').delete().where('expires', '<', new Date());

				res.status(200).json({
					data: {
						access_token: result.access_token,
						expires: result.expires,
						refresh_token: result.refresh_token,
					},
				});
			} catch (error) {
				logger.error(error, 'OTP verify error');
				sendError(res, 500, 'INTERNAL_SERVER_ERROR', 'Internal server error.');
			}
		});
	},
});
