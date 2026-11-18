import type { Knex } from 'knex';
import type { IOtpLogger, IUserLookup, IUserProvisioner, OtpUser, OtpUserLookupResult } from '../types.js';
import { resolvePolicyAccess } from './directus-access.js';

interface UserRow {
	id: string;
	role: string | null;
	status: string | null;
	tfa_secret: string | null;
}

async function toOtpUser(database: Knex, row: UserRow): Promise<OtpUser> {
	const access = await resolvePolicyAccess(database, row.id, row.role);
	return {
		id: row.id,
		role: row.role,
		status: row.status ?? '',
		hasTfa: Boolean(row.tfa_secret),
		privileged: access.appAccess || access.adminAccess,
	};
}

/** Directus may store mixed-case e-mails: match on LOWER(email), not on `_eq`. */
export function createUserLookup(database: Knex): IUserLookup {
	return {
		async findByEmail(email): Promise<OtpUserLookupResult> {
			const rows: UserRow[] = await database('directus_users')
				.whereRaw('LOWER(email) = ?', [email])
				.select('id', 'role', 'status', 'tfa_secret')
				.limit(2);

			const [row, otherRow] = rows;
			if (row === undefined) {
				return { kind: 'none' };
			}
			if (otherRow !== undefined) {
				return { kind: 'ambiguous' };
			}
			return { kind: 'found', user: await toOtpUser(database, row) };
		},
	};
}

export type AutoRegisterRoleCheck = { ok: true } | { ok: false; reason: 'role_missing' | 'role_privileged' };

/** The auto-registration role must exist and must grant neither app (Studio) nor admin access. */
export async function checkAutoRegisterRole(database: Knex, role: string): Promise<AutoRegisterRoleCheck> {
	const exists = await database('directus_roles').where('id', role).first();
	if (!exists) {
		return { ok: false, reason: 'role_missing' };
	}
	const access = await resolvePolicyAccess(database, null, role);
	if (access.appAccess || access.adminAccess) {
		return { ok: false, reason: 'role_privileged' };
	}
	return { ok: true };
}

export interface UserProvisionerDeps {
	database: Knex;
	services: Record<string, any>;
	getSchema: () => Promise<any>;
	logger: IOtpLogger;
	userLookup: IUserLookup;
	/** OTP_AUTO_REGISTER_ROLE; null when auto-registration is off. */
	configuredRole: string | null;
}

export function createUserProvisioner(deps: UserProvisionerDeps): IUserProvisioner {
	const { database, services, getSchema, logger, userLookup, configuredRole } = deps;

	async function resolveSafeRole(): Promise<string | null> {
		if (!configuredRole) {
			return null;
		}
		const check = await checkAutoRegisterRole(database, configuredRole);
		if (!check.ok) {
			logger.warn({ role: configuredRole }, `otp.autoregister.${check.reason}`);
			return null;
		}
		return configuredRole;
	}

	return {
		async isAvailable() {
			return (await resolveSafeRole()) !== null;
		},

		async create(email) {
			const role = await resolveSafeRole();
			if (!role) {
				return null;
			}

			let concurrentUser: OtpUser | null = null;
			try {
				const usersService = new services['UsersService']({ schema: await getSchema(), accountability: { admin: true } });
				await usersService.createOne({ email, role, status: 'active' });
			} catch (error) {
				// A concurrent verification may have created the same user first.
				const lookup = await userLookup.findByEmail(email);
				if (lookup.kind !== 'found') {
					throw error;
				}
				concurrentUser = lookup.user;
			}

			let user = concurrentUser;
			if (!user) {
				const lookup = await userLookup.findByEmail(email);
				user = lookup.kind === 'found' ? lookup.user : null;
			}
			return user;
		},
	};
}
