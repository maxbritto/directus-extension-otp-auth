# directus-extension-otp-auth

A Directus extension that adds passwordless email OTP (One-Time Password) authentication. Users receive a 6-digit code by email and exchange it for standard Directus access/refresh tokens.

## Compatibility

Declared for Directus `^11.6.1` (`directus:extension.host`). The extension only uses the database handle (knex), `UsersService`, `MailService`, `ActivityService`, `emitter.emitFilter`, `getSchema`, `env` and `logger`, which exist in 11.6.x; it does not rely on 11.9-only APIs. App/admin access is resolved from `directus_access` / `directus_policies`, as in Directus 11.

## Installation

1. Copy or clone this extension into your Directus `extensions/` directory:

```
extensions/
  directus-extension-otp-auth/
```

2. Install dependencies and build:

```bash
cd extensions/directus-extension-otp-auth
npm install
npm run build
```

3. Restart Directus. The extension automatically creates the `otp_codes` table on first startup.

## API Endpoints

All endpoints are available under `/otp-auth/`.

### POST `/otp-auth/request`

Request a one-time code be sent to the user's email.

**Request body:**

```json
{
  "email": "user@example.com"
}
```

**Response (200):**

```json
{
  "success": true
}
```

The response is always `{ "success": true }` whatever the state of the account (unknown, suspended, archived, draft, invited, with a TOTP secret, with admin/app access, …): no code is sent when the account is not eligible, and the answer and its timing are the same (the e-mail is sent in the background). This prevents user enumeration.

With `OTP_AUTO_REGISTER=true`, an unknown e-mail receives a code too. **No user is created at this stage.**

Only account-independent limits answer differently: `429` with `REQUESTS_EXCEEDED` when the per-IP (or global) limit is exceeded. A malformed e-mail gets `400` `INVALID_PAYLOAD`.

### POST `/otp-auth/verify`

Verify the OTP code and receive authentication tokens.

**Request body:**

```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

**Success response (200):**

```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1...",
    "expires": 900000,
    "refresh_token": "V1StGXR8_Z5jdHi6B-myT..."
  }
}
```

With `OTP_AUTO_REGISTER=true`, when the e-mail has no account, the user is created **only now, after a valid code** (see [Account creation](#account-creation-on-the-fly)).

`code` must be a string of exactly 6 digits, otherwise `400` `INVALID_PAYLOAD`.

**Error responses:**

`429` (per-IP limit or too many failures for this e-mail, see [Abuse limits](#abuse-limits)):

```json
{
  "errors": [{ "message": "Too many requests.", "extensions": { "code": "REQUESTS_EXCEEDED" } }]
}
```

**Error responses (401):**

```json
{
  "errors": [{ "message": "Invalid OTP code.", "extensions": { "code": "INVALID_OTP" } }]
}
```

```json
{
  "errors": [{ "message": "Too many attempts.", "extensions": { "code": "REQUESTS_EXCEEDED" } }]
}
```

## Configuration

Configure the extension via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `OTP_CODE_TTL_MINUTES` | `10` | How long a code remains valid (minutes) |
| `OTP_MAX_ATTEMPTS` | `3` | Max verification attempts before a code is locked |
| `OTP_RATE_LIMIT_SECONDS` | `60` | Minimum delay between code requests for the same email |
| `OTP_EMAIL_SUBJECT` | `Your login code` | Subject line of the OTP email |
| `OTP_EMAIL_TEMPLATE` | _(none)_ | Custom Directus email template name (optional) |
| `OTP_AUTO_REGISTER` | `false` | Create the account on the fly after a valid code (see below) |
| `OTP_AUTO_REGISTER_ROLE` | _(none)_ | Role id given to auto-registered users. **Required** when `OTP_AUTO_REGISTER=true` (no fallback to `public_registration_role`); the extension refuses to load without it, and its endpoints answer 503 (error logged) if the role does not exist or grants admin or Studio access |
| `OTP_ALLOW_PRIVILEGED_ACCOUNTS` | `false` | `true`/`1`/`yes`: existing active admin/Studio accounts may log in with a code (see « Allowing admin/Studio accounts » for the risk). TOTP and non-active accounts stay refused; auto-registered accounts stay non-privileged |
| `OTP_ALLOWED_ROLES` | _(empty)_ | Comma-separated role ids allowed to use OTP login. Empty = any role (admin/Studio ones only if `OTP_ALLOW_PRIVILEGED_ACCOUNTS=true`). `OTP_AUTO_REGISTER_ROLE` is added automatically when the list is set |
| `OTP_IP_WINDOW_SECONDS` | `900` | Sliding window of the per-IP limits |
| `OTP_IP_REQUEST_LIMIT` | `10` | Max `/request` calls per IP per window (`0` = off) |
| `OTP_IP_VERIFY_LIMIT` | `20` | Max `/verify` calls per IP per window (`0` = off) |
| `OTP_MAX_CODES_PER_EMAIL_PER_DAY` | `10` | Max codes sent per e-mail per rolling 24 h (`0` = off) |
| `OTP_VERIFY_FAILURE_LIMIT` | `10` | Max failed `/verify` per e-mail, all codes combined (`0` = off) |
| `OTP_VERIFY_FAILURE_WINDOW_SECONDS` | `3600` | Window of the failure cap above |
| `OTP_GLOBAL_REQUEST_HOURLY_LIMIT` | `0` (off) | Max `/request` calls per hour over all IPs, to protect the SMTP reputation |

Values are read at startup. `OTP_*` numbers that are not positive integers fall back to their default (limits accept `0` to disable).

The extension also respects standard Directus variables:

| Variable | Usage |
|----------|-------|
| `SECRET` | Signs JWT access tokens and keys the hash of the stored codes. **Required**: the extension refuses to load without it |
| `ACCESS_TOKEN_TTL` | Access token lifetime (e.g. `15m`) |
| `REFRESH_TOKEN_TTL` | Session lifetime stored in `directus_sessions` (e.g. `7d`, `365d`, `1y`) |
| `IP_TRUST_PROXY` | Express `trust proxy` setting. Set it to the single hop in front of Directus (e.g. your reverse proxy), otherwise a forged `X-Forwarded-For` can dodge the per-IP limits |

`ACCESS_TOKEN_TTL` and `REFRESH_TOKEN_TTL` are parsed like Directus does (the `ms` syntax: `365d`, `1y`, `52w`, `90 days`, `15m`, a bare number = milliseconds). An unparsable value falls back to 15 min / 7 days.

### Custom Email Template

Set `OTP_EMAIL_TEMPLATE` to use a custom Directus Liquid email template. The template receives:

- `code` — the 6-digit OTP code
- `expiry_minutes` — the TTL in minutes

If no template is set, a default HTML email is sent.

## Account creation on the fly

Disabled by default. With `OTP_AUTO_REGISTER=true`:

1. `/request` also sends a code to an unknown e-mail (same `{ "success": true }` response). Nothing is created.
2. `/verify` creates the user **only after a valid code**, through Directus' `UsersService` (admin accountability, so `users.create` hooks and activity run), with `status: active`, the **normalized (lower-case, trimmed) e-mail**, and the role `OTP_AUTO_REGISTER_ROLE`.
3. If no role is configured, if the role does not exist, or if it carries `app_access` / `admin_access`, nothing is created and no code is sent to unknown e-mails (refused cleanly, logged).
4. Concurrent verifications of the same code issue one session and create one user; if another process created the same e-mail first, that user is used instead of failing with a 500.

Directus' `public_registration_email_filter` setting is **not** applied to this auto-registration: the role check above is the only guard.

Existing accounts are found case-insensitively (`LOWER(email)`), so `Foo@x.fr` stored with capitals is never duplicated. If two accounts differ only by case, OTP refuses both (and logs a warning) rather than picking one.

## Which accounts can log in with a code

An e-mailed code is a single factor, so it is restricted. A code is neither sent nor accepted (same generic answer as for an unknown e-mail) when the account:

- is not `active` (`suspended`, `archived`, `draft`, `invited`, …);
- has a TOTP secret (`tfa_secret`): the code must not bypass two-factor authentication;
- has `app_access` or `admin_access` through its policies (Studio users and administrators), **unless `OTP_ALLOW_PRIVILEGED_ACCOUNTS=true`** (see below);
- is outside `OTP_ALLOWED_ROLES`, when that list is set;
- is one of several accounts that only differ by letter case.

The status is re-checked at `/verify`, so an account suspended after the code was sent gets nothing.

### Allowing admin/Studio accounts (`OTP_ALLOW_PRIVILEGED_ACCOUNTS`)

Default `false` (safe): administrators and Studio users cannot log in with a code. Set `OTP_ALLOW_PRIVILEGED_ACCOUNTS=true` to let an **existing, active** admin or Studio account receive a code and get a session like any other user.

**Risk, to accept knowingly**: whoever can read the mailbox of such an account gets its admin/Studio rights, with no password and no second factor. Accounts with a TOTP secret, and non-active accounts, stay refused whatever this setting says. It never changes the role of an account created by auto-registration: that role must still carry neither admin nor Studio access, otherwise the extension refuses to create accounts.

## Custom Delivery (SMS, Push, etc.)

By default, OTP codes are delivered via Directus's built-in email service. You can intercept delivery to use any channel (SMS, push notifications, webhooks) by registering a Directus filter hook for the `otp-auth.deliver` event.

### How It Works

1. When an OTP is requested, the extension emits a `otp-auth.deliver` filter event
2. The filter payload contains `{ email, code, expiresInMinutes, delivered: false }`
3. If any handler sets `delivered: true`, the built-in email is skipped
4. If no handler modifies `delivered`, the built-in email sends as before

### Creating a Custom Delivery Hook

Create a separate Directus hook extension (or add to an existing one):

```typescript
import { defineHook } from '@directus/extensions-sdk';

export default defineHook(({ filter }, { services }) => {
    filter('otp-auth.deliver', async (payload, meta, context) => {
        // context.database and context.schema are available for DB lookups
        const phone = await lookupPhone(payload.email, context.database);
        await sendSms(phone, `Your code: ${payload.code}`);
        return { ...payload, delivered: true };
    });
});
```

### Payload Reference

| Field | Type | Description |
|-------|------|-------------|
| `email` | `string` | The user's email address |
| `code` | `string` | The 6-digit OTP code |
| `expiresInMinutes` | `number` | How long the code is valid |
| `delivered` | `boolean` | Set to `true` to skip built-in email |

### Context Reference

The filter handler receives the standard Directus event context:

| Object | Field | Description |
|--------|-------|-------------|
| `meta` | `services` | Directus services (MailService, UsersService, etc.) |
| `context` | `database` | Knex database instance |
| `context` | `schema` | Current Directus schema |

### Notes

- Multiple handlers can chain (e.g., send SMS + log to audit table)
- The `delivered` flag only controls the built-in email; all external handlers always run
- Errors thrown by handlers propagate back to the caller (the OTP request will fail)
- Handlers receive full Directus context, so they can query the database or use Directus services

## Database

The extension auto-creates two tables on startup. `otp_rate_events` (`id`, `bucket`, `created_at`, index on `bucket, created_at`) holds the sliding windows of the abuse limits, in the database so that several Directus instances share them.

`otp_codes`:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `email` | VARCHAR(255) | User email (indexed) |
| `code` | VARCHAR(64) | `HMAC-SHA256(SECRET, "email\|code")` as hex. **The code itself is never stored** |
| `expires_at` | DATETIME | Expiration timestamp |
| `attempts` | INTEGER | Number of verification attempts |
| `used` | BOOLEAN | Whether the code has been consumed |
| `created_at` | DATETIME | Creation timestamp |

**Upgrading from a version that stored plain codes:** at startup the `code` column is widened to 64 characters and every code still open is invalidated (users just ask for a new one).

An hourly job deletes `otp_codes` and `otp_rate_events` rows older than 48 h (they can contain the e-mail addresses of people who never had an account). Keep every `*_WINDOW_SECONDS` under 48 h.

## Security

- **No user enumeration**: `/request` answers `{ "success": true }` and `/verify` answers `INVALID_OTP` whether the e-mail is unknown, suspended, TOTP-protected, privileged or ambiguous. The mail is sent in the background so the response time does not depend on the account.
- **Eligible accounts only**: see [Which accounts can log in with a code](#which-accounts-can-log-in-with-a-code).
- **Codes**: 6 digits drawn uniformly from `000000`–`999999` with `crypto.randomInt()`, stored as a keyed hash, compared in constant time (`crypto.timingSafeEqual`), single use, TTL `OTP_CODE_TTL_MINUTES`. Requesting a new code invalidates the previous ones.
- **Atomic attempt counting**: an attempt is spent with a conditional `UPDATE` *before* the comparison and a code is claimed with `UPDATE … WHERE used = false`. Parallel requests cannot exceed `OTP_MAX_ATTEMPTS`, and a code opens at most one session (and creates at most one user).
- **Atomic code issuing**: `/request` stores a code in one transaction guarded by a per-e-mail lock (`pg_advisory_xact_lock` on PostgreSQL), which checks the `OTP_RATE_LIMIT_SECONDS` delay and the daily cap, closes the open codes and inserts the new one. N parallel requests for one address send one code and one e-mail. On other engines the guarantee relies on the transaction isolation only.
- **Request timing**: `/request` always takes at least 150 ms, so a refused account (admin, suspended, ambiguous) cannot be told apart by response time.
- **Input validation**: `email` and `code` must be strings; e-mail format and length (≤ 254) and a 6-digit code are checked before any database access.
- <a name="abuse-limits"></a>**Abuse limits** (all shared through the database, sliding windows):
  - per IP: `OTP_IP_REQUEST_LIMIT` / `OTP_IP_VERIFY_LIMIT` per `OTP_IP_WINDOW_SECONDS` → `429`;
  - per e-mail: one code per `OTP_RATE_LIMIT_SECONDS`, at most `OTP_MAX_CODES_PER_EMAIL_PER_DAY` codes per 24 h (silent: same `{ "success": true }`);
  - per e-mail, failed `/verify` over all codes: `OTP_VERIFY_FAILURE_LIMIT` per `OTP_VERIFY_FAILURE_WINDOW_SECONDS` → `429`. Failures are counted for unknown e-mails too, so the cap reveals nothing. Trade-off: someone who knows an address can lock that person out of OTP login for up to one window; the short window (1 h) keeps this tolerable, and without it code rotation allows roughly 4 000 guesses per day per account;
  - optional global hourly cap `OTP_GLOBAL_REQUEST_HOURLY_LIMIT` against mail bombing through many addresses; a request refused by it is logged as `otp.request.rate_limited` with `reason: "global"` (`"ip"` for the per-IP limit), which an alert can match.
- **Proxy**: per-IP limits use `req.ip`. Behind a reverse proxy set `IP_TRUST_PROXY` to the trusted hop only. A missing IP shares one bucket.
- **Logging**: `otp.request`, `otp.verify.ok`, `otp.verify.fail`, `otp.locked`, `otp.autoregister`, `otp.request.rate_limited`, … with a keyed (HMAC) truncated fingerprint of the e-mail and the IP; never the code or the e-mail.
- **Standard tokens**: the same JWT access + refresh token pair as Directus native auth (a `directus_sessions` row, so `/auth/refresh` works). The native `auth.login` action and `auth.jwt` filter events are *not* emitted; an `login` activity row is written.
- **Revocation**: suspending an account stops new codes and token issuance; sessions already issued are cleared by Directus itself when an account is set to a non-`active` status (native `UsersService` behaviour in 11.6.1, which also covers an account deleted as `status: archived`); otherwise they stay valid until they expire or are deleted from `directus_sessions`.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Run tests
npm test

# Also run the store tests against a real PostgreSQL (concurrent /request); skipped when the variable is unset
OTP_TEST_DATABASE_URL=postgres://user:password@127.0.0.1:5432/database npm test
```

## License

MIT
