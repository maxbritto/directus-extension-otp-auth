import type { Knex } from 'knex';

/**
 * Resolves app_access / admin_access from directus_policies via directus_access
 * (same rule as Directus 11 fetchGlobalAccess): policies linked to the user
 * directly or to their role.
 * NOTE: this does not walk the role hierarchy (parent roles). All our roles
 * currently have parent: NULL. If role hierarchy is added later, ancestor
 * roles must be included in the query.
 */
export async function resolvePolicyAccess(
	database: Knex,
	userId: string | null,
	roleId: string | null,
): Promise<{ appAccess: boolean; adminAccess: boolean }> {
	if (userId === null && roleId === null) {
		return { appAccess: false, adminAccess: false };
	}

	const rows = await database('directus_access')
		.leftJoin('directus_policies', 'directus_policies.id', 'directus_access.policy')
		.where(function () {
			if (userId !== null) {
				this.orWhere('directus_access.user', userId);
			}
			if (roleId !== null) {
				this.orWhere('directus_access.role', roleId);
			}
		})
		.select('directus_policies.app_access', 'directus_policies.admin_access');

	let adminAccess = false;
	let appAccess = false;
	for (const row of rows) {
		adminAccess = adminAccess || Boolean(row.admin_access);
		appAccess = appAccess || adminAccess || Boolean(row.app_access);
	}
	return { appAccess, adminAccess };
}
