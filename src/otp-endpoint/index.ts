import { defineEndpoint } from '@directus/extensions-sdk';
import jwt from 'jsonwebtoken';
import { OtpAuthManager } from '../otp-auth-manager.js';
import { createOtpDelivery } from '../otp-delivery.js';
import type { IOtpStore, IUserLookup, ITokenGenerator, OtpCode, DirectusUser, OtpConfig, RequestInfo } from '../types.js';
import type { Knex } from 'knex';

function parseMilliseconds(value: string, defaultMs: number): number {
	const trimmed = value.trim().toLowerCase();
	const num = parseInt(trimmed, 10);
	if (isNaN(num)) {
		return defaultMs;
	}
	if (trimmed.endsWith('ms')) {
		return num;
	}
	if (trimmed.endsWith('s')) {
		return num * 1000;
	}
	if (trimmed.endsWith('m')) {
		return num * 60 * 1000;
	}
	if (trimmed.endsWith('h')) {
		return num * 60 * 60 * 1000;
	}
	if (trimmed.endsWith('d')) {
		return num * 24 * 60 * 60 * 1000;
	}
	// If just a number, treat as milliseconds
	return num;
}

function createOtpStore(database: Knex): IOtpStore {
	return {
		async createCode(id: string, email: string, code: string, expiresAt: Date): Promise<void> {
			await database('otp_codes').insert({
				id,
				email,
				code,
				expires_at: expiresAt,
				attempts: 0,
				used: false,
				created_at: new Date(),
			});
		},

		async findLatestValidCode(email: string): Promise<OtpCode | null> {
			const row = await database('otp_codes')
				.where('email', email)
				.where('used', false)
				.where('expires_at', '>', new Date())
				.orderBy('created_at', 'desc')
				.first();
			return row ?? null;
		},

		async findRecentCode(email: string, withinSeconds: number): Promise<OtpCode | null> {
			const cutoff = new Date(Date.now() - withinSeconds * 1000);
			const row = await database('otp_codes')
				.where('email', email)
				.where('created_at', '>', cutoff)
				.orderBy('created_at', 'desc')
				.first();
			return row ?? null;
		},

		async incrementAttempts(id: string): Promise<void> {
			await database('otp_codes')
				.where('id', id)
				.increment('attempts', 1);
		},

		async markAsUsed(id: string): Promise<void> {
			await database('otp_codes')
				.where('id', id)
				.update({ used: true });
		},

		async invalidateAllForEmail(email: string): Promise<void> {
			await database('otp_codes')
				.where('email', email)
				.where('used', false)
				.update({ used: true });
		},
	};
}

function createUserLookup(services: Record<string, any>, getSchema: () => Promise<any>): IUserLookup {
	return {
		async findByEmail(email: string): Promise<DirectusUser | null> {
			const schema = await getSchema();
			const usersService = new services.UsersService({
				schema,
				accountability: { admin: true },
			});

			const users = await usersService.readByQuery({
				filter: { email: { _eq: email } },
				fields: ['id', 'role'],
				limit: 1,
			});

			if (!users || users.length === 0) {
				return null;
			}

			return users[0] as DirectusUser;
		},
	};
}

function createTokenGenerator(
	database: Knex,
	env: Record<string, any>,
): ITokenGenerator {
	return {
		async generateTokens(userId: string, requestInfo: RequestInfo): Promise<{ access_token: string; refresh_token: string; expires: number }> {
			const secret = env['SECRET'] as string;
			const accessTokenTtl = (env['ACCESS_TOKEN_TTL'] as string) || '15m';
			const refreshTokenTtl = (env['REFRESH_TOKEN_TTL'] as string) || '7d';

			const accessTokenMs = parseMilliseconds(accessTokenTtl, 15 * 60 * 1000);
			const refreshTokenMs = parseMilliseconds(refreshTokenTtl, 7 * 24 * 60 * 60 * 1000);

			const userRow = await database('directus_users')
				.where('id', userId)
				.select('id', 'role')
				.first();

			// Resolve app_access / admin_access from directus_policies via directus_access.
			// This matches the logic in Directus 11.9.0's fetchGlobalAccessForQuery:
			// access is granted by policies linked to the user directly OR via their role.
			// NOTE: This does not walk the role hierarchy (parent roles). All our roles
			// currently have parent: NULL. If role hierarchy is added later, ancestor
			// roles must be included in the query.
			const accessRows = await database('directus_access')
				.leftJoin('directus_policies', 'directus_policies.id', 'directus_access.policy')
				.where(function () {
					this.where('directus_access.user', userId)
						.orWhere('directus_access.role', userRow?.role ?? null);
				})
				.select('directus_policies.app_access', 'directus_policies.admin_access');

			let adminAccess = false;
			let appAccess = false;
			for (const row of accessRows) {
				adminAccess = adminAccess || !!row.admin_access;
				appAccess = appAccess || adminAccess || !!row.app_access;
			}

			const payload = {
				id: userId,
				role: userRow?.role ?? null,
				app_access: appAccess,
				admin_access: adminAccess,
			};

			const accessToken = jwt.sign(payload, secret, {
				expiresIn: Math.floor(accessTokenMs / 1000),
				issuer: 'directus',
			});

			const { nanoid } = await import('nanoid');
			const refreshToken = nanoid(64);

			// Insert session in directus_sessions
			await database('directus_sessions').insert({
				token: refreshToken,
				user: userId,
				expires: new Date(Date.now() + refreshTokenMs),
				ip: requestInfo.ip,
				user_agent: requestInfo.userAgent,
				origin: requestInfo.origin,
			});

			return {
				access_token: accessToken,
				refresh_token: refreshToken,
				expires: accessTokenMs,
			};
		},
	};
}

export default defineEndpoint({
	id: 'otp-auth',
	handler: (router, context) => {
		const { database, env, services, getSchema, logger, emitter } = context;

		const config: OtpConfig = {
			codeTtlMinutes: parseInt(env['OTP_CODE_TTL_MINUTES'] as string, 10) || 10,
			maxAttempts: parseInt(env['OTP_MAX_ATTEMPTS'] as string, 10) || 3,
			rateLimitSeconds: parseInt(env['OTP_RATE_LIMIT_SECONDS'] as string, 10) || 60,
		};

		const store = createOtpStore(database);
		const userLookup = createUserLookup(services, getSchema);
		const delivery = createOtpDelivery({ emitter, database, services, getSchema, env, config, logger });
		const tokenGenerator = createTokenGenerator(database, env);
		const manager = new OtpAuthManager(store, userLookup, delivery, tokenGenerator, config);

		router.post('/request', async (req, res) => {
			try {
				const { email } = req.body as { email?: string };
				if (!email) {
					res.status(400).json({
						errors: [{ message: 'Email is required.', extensions: { code: 'INVALID_PAYLOAD' } }],
					});
					return;
				}

				const result = await manager.requestOtp(email);
				res.status(200).json(result);
			} catch (error) {
				logger.error(error, 'OTP request error');
				res.status(500).json({
					errors: [{ message: 'Internal server error.', extensions: { code: 'INTERNAL_SERVER_ERROR' } }],
				});
			}
		});

		router.post('/verify', async (req, res) => {
			try {
				const { email, code } = req.body as { email?: string; code?: string };
				if (!email || !code) {
					res.status(400).json({
						errors: [{ message: 'Email and code are required.', extensions: { code: 'INVALID_PAYLOAD' } }],
					});
					return;
				}

				const requestInfo: RequestInfo = {
					ip: req.ip ?? null,
					userAgent: req.get('user-agent') ?? null,
					origin: req.get('origin') ?? null,
				};

				const result = await manager.verifyOtp(email, code, requestInfo);
				if (result.success) {
					// Activity log
					const schema = await getSchema();
					const activityService = new services.ActivityService({ schema, knex: database });
					const decoded = jwt.decode(result.access_token) as { id: string } | null;
					const userId = decoded?.id ?? null;
					if (userId) {
						await activityService.createOne({
							action: 'login',
							user: userId,
							ip: requestInfo.ip,
							user_agent: requestInfo.userAgent,
							origin: requestInfo.origin,
							collection: 'directus_users',
							item: userId,
						});

						// Update last_access
						await database('directus_users').update({ last_access: new Date() }).where('id', userId);
					}

					// Clean up expired sessions
					await database('directus_sessions').delete().where('expires', '<', new Date());

					res.status(200).json({
						data: {
							access_token: result.access_token,
							expires: result.expires,
							refresh_token: result.refresh_token,
						},
					});
				} else {
					if (result.error === 'too_many_attempts') {
						res.status(401).json({
							errors: [{ message: 'Too many attempts.', extensions: { code: 'REQUESTS_EXCEEDED' } }],
						});
					} else {
						res.status(401).json({
							errors: [{ message: 'Invalid OTP code.', extensions: { code: 'INVALID_OTP' } }],
						});
					}
				}
			} catch (error) {
				logger.error(error, 'OTP verify error');
				res.status(500).json({
					errors: [{ message: 'Internal server error.', extensions: { code: 'INTERNAL_SERVER_ERROR' } }],
				});
			}
		});
	},
});
