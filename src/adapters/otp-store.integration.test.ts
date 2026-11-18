import knex, { type Knex } from 'knex';
import { ensureOtpSchema } from '../otp-schema';
import type { IssueCodeRequest } from '../types';
import { createOtpStore } from './otp-store';

const DATABASE_URL = process.env['OTP_TEST_DATABASE_URL'];
const describeWithDatabase = DATABASE_URL ? describe : describe.skip;

const noopLogger = { info: () => undefined };

function request(email: string, overrides?: Partial<IssueCodeRequest>): IssueCodeRequest {
	return {
		id: crypto.randomUUID(),
		email,
		codeHash: 'a'.repeat(64),
		expiresAt: new Date(Date.now() + 10 * 60 * 1000),
		minIntervalSeconds: 60,
		maxPerDay: 10,
		...overrides,
	};
}

describeWithDatabase('createOtpStore.issueCode (real PostgreSQL, OTP_TEST_DATABASE_URL)', () => {
	let database: Knex;

	beforeAll(async () => {
		database = knex({ client: 'pg', connection: DATABASE_URL, pool: { min: 10, max: 20 } });
		await ensureOtpSchema(database, noopLogger);
	});

	beforeEach(async () => {
		await database('otp_codes').delete();
	});

	afterAll(async () => {
		await database.destroy();
	});

	it('issues a single code when many requests hit the same e-mail at once', async () => {
		const store = createOtpStore(database);

		const outcomes = await Promise.all(Array.from({ length: 30 }, () => store.issueCode(request('same@example.com'))));

		expect(outcomes.filter((o) => o === 'issued')).toHaveLength(1);
		expect(outcomes.filter((o) => o === 'throttled')).toHaveLength(29);
		expect(await database('otp_codes').where('email', 'same@example.com').count({ total: '*' }).first()).toEqual({ total: '1' });
	});

	it('never exceeds the daily cap under concurrent requests', async () => {
		const store = createOtpStore(database);

		const outcomes = await Promise.all(
			Array.from({ length: 30 }, () => store.issueCode(request('cap@example.com', { minIntervalSeconds: 0, maxPerDay: 3 }))),
		);

		expect(outcomes.filter((o) => o === 'issued')).toHaveLength(3);
		expect(outcomes.filter((o) => o === 'capped')).toHaveLength(27);
	});

	it('keeps different e-mails independent and closes the previous open code', async () => {
		const store = createOtpStore(database);

		const [first, other] = await Promise.all([store.issueCode(request('a@example.com')), store.issueCode(request('b@example.com'))]);
		const again = await store.issueCode(request('a@example.com', { minIntervalSeconds: 0 }));

		expect([first, other, again]).toEqual(['issued', 'issued', 'issued']);
		expect(await database('otp_codes').where({ email: 'a@example.com', used: false }).count({ total: '*' }).first()).toEqual({ total: '1' });
		expect(await database('otp_codes').where({ email: 'b@example.com', used: false }).count({ total: '*' }).first()).toEqual({ total: '1' });
	});
});
