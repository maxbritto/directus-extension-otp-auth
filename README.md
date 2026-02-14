# directus-extension-otp-auth

A Directus extension that adds passwordless email OTP (One-Time Password) authentication. Users receive a 6-digit code by email and exchange it for standard Directus access/refresh tokens.

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

The response is always `{ "success": true }` regardless of whether the email exists. This prevents user enumeration.

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

The extension also respects standard Directus variables:

| Variable | Usage |
|----------|-------|
| `SECRET` | Used to sign JWT access tokens |
| `ACCESS_TOKEN_TTL` | Access token lifetime (e.g. `15m`) |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime (e.g. `7d`) |

### Custom Email Template

Set `OTP_EMAIL_TEMPLATE` to use a custom Directus Liquid email template. The template receives:

- `code` — the 6-digit OTP code
- `expiry_minutes` — the TTL in minutes

If no template is set, a default HTML email is sent.

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

The extension auto-creates an `otp_codes` table on startup with the following schema:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `email` | VARCHAR(255) | User email (indexed) |
| `code` | VARCHAR(6) | The 6-digit code |
| `expires_at` | DATETIME | Expiration timestamp |
| `attempts` | INTEGER | Number of verification attempts |
| `used` | BOOLEAN | Whether the code has been consumed |
| `created_at` | DATETIME | Creation timestamp |

## Security

- **No user enumeration**: `/request` always returns `{ "success": true }`, even for unknown emails.
- **Rate limiting**: Only one code can be sent per email within the configured rate limit window.
- **Brute-force protection**: Codes are locked after the configured max attempts.
- **Single use**: Codes are marked as used after successful verification.
- **Code invalidation**: All previous codes for an email are invalidated when a new one is requested.
- **Cryptographic randomness**: Codes are generated using Node.js `crypto.randomInt()`.
- **Standard tokens**: Returns the same JWT access + refresh token pair as Directus native auth.

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
```

## License

MIT
