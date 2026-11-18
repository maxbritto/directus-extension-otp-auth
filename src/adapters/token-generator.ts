import jwt from 'jsonwebtoken';
import type { Knex } from 'knex';
import { parseDuration } from '../duration.js';
import type { ITokenGenerator, RequestInfo } from '../types.js';
import { resolvePolicyAccess } from './directus-access.js';

const DEFAULT_ACCESS_TOKEN_MS = 15 * 60 * 1000;
const DEFAULT_REFRESH_TOKEN_MS = 7 * 24 * 60 * 60 * 1000;

export function createTokenGenerator(database: Knex, env: Record<string, any>): ITokenGenerator {
	return {
		async generateTokens(userId: string, requestInfo: RequestInfo) {
			const secret = env['SECRET'] as string;
			const accessTokenMs = parseDuration(env['ACCESS_TOKEN_TTL'] ?? '15m', DEFAULT_ACCESS_TOKEN_MS);
			const refreshTokenMs = parseDuration(env['REFRESH_TOKEN_TTL'] ?? '7d', DEFAULT_REFRESH_TOKEN_MS);

			const userRow = await database('directus_users').where('id', userId).select('id', 'role').first();
			const role: string | null = userRow?.role ?? null;
			const access = await resolvePolicyAccess(database, userId, role);

			const payload = {
				id: userId,
				role,
				app_access: access.appAccess,
				admin_access: access.adminAccess,
			};

			const accessToken = jwt.sign(payload, secret, {
				expiresIn: Math.floor(accessTokenMs / 1000),
				issuer: 'directus',
			});

			const { nanoid } = await import('nanoid');
			const refreshToken = nanoid(64);

			await database('directus_sessions').insert({
				token: refreshToken,
				user: userId,
				expires: new Date(Date.now() + refreshTokenMs),
				ip: requestInfo.ip,
				user_agent: requestInfo.userAgent,
				origin: requestInfo.origin,
			});

			return { access_token: accessToken, refresh_token: refreshToken, expires: accessTokenMs };
		},
	};
}
