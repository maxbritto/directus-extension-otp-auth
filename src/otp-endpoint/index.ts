import { defineEndpoint } from '@directus/extensions-sdk';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { OtpAuthManager } from '../otp-auth-manager.js';
import type { IOtpStore, IUserLookup, IMailSender, ITokenGenerator, OtpCode, DirectusUser, OtpConfig } from '../types.js';
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
				accountability: null,
			});

			const users = await usersService.readByQuery({
				filter: { email: { _eq: email } },
				fields: ['id', 'role', 'app_access', 'admin_access'],
				limit: 1,
			});

			if (!users || users.length === 0) {
				return null;
			}

			return users[0] as DirectusUser;
		},
	};
}

function createMailSender(
	services: Record<string, any>,
	getSchema: () => Promise<any>,
	env: Record<string, any>,
	config: OtpConfig
): IMailSender {
	return {
		async sendOtpEmail(email: string, code: string): Promise<void> {
			const schema = await getSchema();
			const mailService = new services.MailService({ schema });

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
		},
	};
}

function createTokenGenerator(
	database: Knex,
	env: Record<string, any>,
): ITokenGenerator {
	return {
		async generateTokens(userId: string): Promise<{ access_token: string; refresh_token: string; expires: number }> {
			const secret = env['SECRET'] as string;
			const accessTokenTtl = (env['ACCESS_TOKEN_TTL'] as string) || '15m';
			const refreshTokenTtl = (env['REFRESH_TOKEN_TTL'] as string) || '7d';

			const accessTokenMs = parseMilliseconds(accessTokenTtl, 15 * 60 * 1000);
			const refreshTokenMs = parseMilliseconds(refreshTokenTtl, 7 * 24 * 60 * 60 * 1000);

			const userRow = await database('directus_users')
				.where('id', userId)
				.select('id', 'role', 'app_access', 'admin_access')
				.first();

			const payload = {
				id: userId,
				role: userRow?.role ?? null,
				app_access: userRow?.app_access ?? false,
				admin_access: userRow?.admin_access ?? false,
				iss: 'directus',
			};

			const accessToken = jwt.sign(payload, secret, {
				expiresIn: Math.floor(accessTokenMs / 1000),
				issuer: 'directus',
			});

			const refreshToken = randomUUID();

			// Insert session in directus_sessions
			await database('directus_sessions').insert({
				token: refreshToken,
				user: userId,
				expires: new Date(Date.now() + refreshTokenMs),
				ip: null,
				user_agent: 'otp-auth',
				share: null,
				origin: null,
				next_token: null,
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
		const { database, env, services, getSchema, logger } = context;

		const config: OtpConfig = {
			codeTtlMinutes: parseInt(env['OTP_CODE_TTL_MINUTES'] as string, 10) || 10,
			maxAttempts: parseInt(env['OTP_MAX_ATTEMPTS'] as string, 10) || 3,
			rateLimitSeconds: parseInt(env['OTP_RATE_LIMIT_SECONDS'] as string, 10) || 60,
		};

		const store = createOtpStore(database);
		const userLookup = createUserLookup(services, getSchema);
		const mailSender = createMailSender(services, getSchema, env, config);
		const tokenGenerator = createTokenGenerator(database, env);
		const manager = new OtpAuthManager(store, userLookup, mailSender, tokenGenerator, config);

		router.post('/request', async (req, res) => {
			try {
				const { email } = req.body as { email?: string };
				if (!email) {
					res.status(400).json({ error: 'Email is required' });
					return;
				}

				const result = await manager.requestOtp(email);
				res.status(200).json(result);
			} catch (error) {
				logger.error('OTP request error:', error);
				res.status(500).json({ error: 'Internal server error' });
			}
		});

		router.post('/verify', async (req, res) => {
			try {
				const { email, code } = req.body as { email?: string; code?: string };
				if (!email || !code) {
					res.status(400).json({ error: 'Email and code are required' });
					return;
				}

				const result = await manager.verifyOtp(email, code);
				if (result.success) {
					res.status(200).json({
						access_token: result.access_token,
						refresh_token: result.refresh_token,
						expires: result.expires,
					});
				} else {
					res.status(401).json({ error: result.error });
				}
			} catch (error) {
				logger.error('OTP verify error:', error);
				res.status(500).json({ error: 'Internal server error' });
			}
		});
	},
});
