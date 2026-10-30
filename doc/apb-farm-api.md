# APB Farm API Documentation

The APB Farm is a proxy service that manages multiple APB Servers, automatically distributing build requests to the most appropriate server based on architecture and load.

## Base URL
- Default: `http://localhost:8080`
- Configurable via `--host` and `--port` command line arguments

## Authentication

The APB Farm implements a comprehensive token-based authentication system with role-based access control. Authentication is required for build submissions and certain administrative operations.

### Authentication Overview

- **Token-based**: Uses secure Bearer tokens for authentication
- **Role-based Access Control**: Three user roles with different permissions
- **Secure Storage**: Passwords hashed with PBKDF2, tokens stored securely
- **Token Management**: Automatic expiration, renewal, and cleanup
- **Default Admin**: Creates default admin user on first startup
- **Web Sessions**: The web UI logs in through `POST /login`, which stores the token in an `HttpOnly` `authToken` cookie (see [Web Form Endpoints](#web-form-endpoints))
- **CSRF Protection**: Any non-GET request authenticated by the `authToken` cookie must carry a CSRF token (`csrf_token` form field or `X-CSRF-Token` header); requests with an `Authorization: Bearer` header are exempt
- **Two-Factor Authentication**: TOTP authenticator apps and WebAuthn security keys (YubiKey and other FIDO2/U2F keys), with single-use recovery codes; mandatory for admins, optional for users (see [Two-Factor Authentication](#two-factor-authentication))

### User Roles

#### Guest (Unauthenticated Users)
- View dashboard and farm status
- View public build information (with obfuscated server URLs)
- Download package artifacts
- Download a truncated `build.log` (last 100 lines only)
- No build submission capabilities

#### User (Regular Users)
- All guest permissions
- Submit builds to the farm
- Cancel own builds
- View own build history via `/my/builds`
- Download the full `build.log`
- Access authenticated endpoints
- Update own email address

#### Admin (Administrators)
- All user permissions
- Cancel any user's builds
- View unobfuscated server URLs
- Complete user management (create, delete, change roles)
- Access to user build histories
- Revoke user tokens
- Configure SMTP settings
- Send email notifications
- Manage custom pacman repositories

### Authentication Flow

1. **Registration**: Admins create user accounts with username/password/email
2. **Login**: Users authenticate with credentials to receive token
3. **Second factor**: Users with 2FA receive a short-lived `mfa_token` instead and exchange it for a token with `POST /auth/login/2fa`; admins without 2FA receive a `setup_token` that only allows enrolling a second factor
4. **Token Usage**: Include token in `Authorization: Bearer <token>` header
5. **Auto-renewal**: Tokens automatically renewed on use (10-day expiration)
6. **Logout**: Explicitly revoke tokens when done

### Default Admin Account

On first startup, the farm creates a default admin account:
- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ SECURITY WARNING**: Change this password immediately after first login!
- Admins must use two-factor authentication, so the first login of this account leads to the 2FA enrollment page (`/account/2fa`)

### Two-Factor Authentication

Supported second factors:
- **TOTP**: RFC 6238 authenticator apps (6 digits, 30-second steps, SHA-1). A code is accepted for the previous, current and next time step, and every time step can only be used once per user
- **Security keys**: WebAuthn/FIDO2 credentials, including U2F-only YubiKeys. User verification (PIN) is not required, so a touch is enough. A user can register several keys
- **Recovery codes**: 10 single-use codes of the form `xxxxx-xxxxx`, shown once when the first second factor is enrolled and stored as SHA-256 hashes. Regenerating them invalidates the old set

Rules:
- A user has 2FA enabled as soon as a TOTP authenticator is confirmed or a security key is registered. Removing the last second factor of a regular user disables 2FA and deletes the recovery codes
- Admins must have 2FA. They cannot remove their last second factor, and an admin without a second factor (a new admin, the default `admin` account, or after an admin reset) only receives an enrollment session when logging in
- Promoting a user without 2FA to admin revokes all of that user's tokens, so the next login goes through enrollment
- An admin can reset another user's 2FA with `DELETE /auth/users/{user_id}/2fa`

Token scopes:

| Scope | Issued by | Lifetime | Allows |
|-------|-----------|----------|--------|
| `full` | completed login | 10 days, renewed on use | all authenticated endpoints |
| `mfa_pending` | `POST /auth/login` for users with 2FA | 5 minutes, not renewed, 5 failed attempts | `POST /auth/login/2fa` and `POST /auth/login/2fa/webauthn-options` |
| `mfa_setup` | `POST /auth/login` for admins without 2FA | 15 minutes, not renewed | `/auth/my/2fa` endpoints, `/account/2fa` pages and logout |

WebAuthn requirements:
- The relying party ID is the host name of the configured `farm_url` and the expected origin is the scheme, host and port of `farm_url`. `farm_url` must therefore be the public URL users open in their browser and pass to `apb --farm-url`
- Browsers only offer WebAuthn on HTTPS origins and on `http://localhost`. Serve the farm over HTTPS (for example behind the provided nginx configuration) to use security keys
- Each pending login or session has at most one outstanding WebAuthn challenge (valid for 5 minutes); requesting new options replaces it

### TOTP Key File

TOTP secrets are stored encrypted with AES-256-GCM, bound to the user ID, as `v1:<key_id>:<base64url(nonce || ciphertext)>`. The keys are kept outside `farm.db`, in the file named by `totp_keys_file` in `apb.json` (default `~/.apb/farm-totp.keys`):

```
# comment lines and blank lines are ignored
3f9a1c2e 6Pq...base64url 32-byte key...
b71d04aa Zr1...base64url 32-byte key...
```

- One `<key_id> <base64url key>` per line; the key ID is 1-64 characters of `A-Z a-z 0-9 _ -`. The **last** key is active and used for new secrets
- If the file does not exist, the farm creates it on startup with mode `0600` and one random key. A file readable by group or others is reported as a warning
- Back up the key file separately from `farm.db`: without it, the stored TOTP secrets cannot be decrypted
- On every startup, plaintext secrets (from older versions) are encrypted with the active key, and secrets encrypted with an older key are re-encrypted with it
- **Rotation**: append a new line, for example from `python -c "import secrets,base64;print(secrets.token_hex(4), base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"`, and restart the farm. Old lines can be removed after that restart
- **Missing or broken keys**: if the file cannot be read or parsed, the farm still starts with an error in the log. Authenticator app logins fail and `POST /auth/my/2fa/totp` answers `400 Bad Request`, while security keys and recovery codes keep working. Secrets whose key is no longer in the file are reported at startup; those users sign in with another factor and re-enroll the authenticator app, or an admin resets their 2FA

### Token Security

- **Expiration**: 10-day expiration with automatic renewal on use (`full` tokens only; pending and enrollment tokens have a fixed short lifetime)
- **Secure Hashing**: SHA-256 hashing for token storage
- **Background Cleanup**: Expired tokens automatically removed every hour
- **Revocation**: Individual token or all user tokens can be revoked

## Content Types
- **Request**: `multipart/form-data` for file uploads, `application/json` for JSON requests
- **Response**: `application/json` for API endpoints, `text/html` for web pages

## File Size Limits

The farm implements configurable file size limits inherited from servers:

### Upload Handling
- **Streaming**: Large uploads are streamed to target servers
- **Validation**: Files validated before forwarding to servers
- **Error Handling**: Proper error messages for oversized uploads
- **Server Limits**: Respects individual server file size limits

### Tarball Support
- **Native Support**: Full support for tarball uploads to servers
- **Automatic Detection**: Detects tarball vs individual file uploads
- **Compression**: Supports gzipped tar archives (.tar.gz)
- **Validation**: Validates tarball structure before forwarding

## Configuration
The farm requires a configuration file (`apb.json`) that defines the available servers grouped by architecture:

```json
{
  "servers": {
    "x86_64": [
      "http://server1.example.com:8000",
      "http://server2.example.com:8000"
    ],
    "aarch64": [
      "http://arm-server1.example.com:8000"
    ],
    "powerpc": [
      "http://powerpc-server1.example.com:8000"
    ],
    "powerpc64le": [
      "http://ppc64le-server1.example.com:8000"
    ]
  }
}
```

## Architecture Validation

The farm validates that servers actually support the architectures they are configured for. Each server reports its supported architecture via the `supported_architecture` field in its status endpoint.

### Server Architecture Detection

APB Servers determine their architecture by:
1. **Command-line override**: Using the `--architecture` flag (highest priority)
2. Reading the `Architecture` setting from `/etc/pacman.conf`
3. If `Architecture` is "auto" or not set, mapping from `uname -m` using these rules:
   - `ppc64le` → `powerpc64le`
   - `ppc64` → `powerpc64`
   - `ppc` → `powerpc`
   - Other architectures are used as-is

**Command-line Override Examples:**
```bash
# Espresso server building PowerPC packages
apb-server.py --architecture powerpc

# Cross-compilation scenarios
apb-server.py --architecture aarch64
```

### Architecture Availability

The farm will only queue builds for architectures that have available servers. If a PKGBUILD specifies architectures that don't have servers available, those architectures will be skipped with appropriate logging.

Example scenario:
- PKGBUILD specifies: `arch=('x86_64' 'powerpc64le' 'aarch64')`
- Available servers support: `x86_64`, `powerpc64le`
- Result: Builds queued for `x86_64` and `powerpc64le` only, `aarch64` skipped

## Server Health Monitoring

The farm implements sophisticated server health tracking with the following states:

### Health States

- **HEALTHY**: Server is responding normally and available for builds
- **DEGRADED**: Server has experienced failures but is still operational (reduced priority)
- **UNAVAILABLE**: Server is temporarily unreachable but may recover
- **MISCONFIGURED**: Server has persistent issues and should be investigated

### Health Tracking Logic

- Servers are marked as DEGRADED after 5 consecutive failures
- Servers are marked as UNAVAILABLE after 15 consecutive failures
- HTTP 502 errors are treated specially as they often indicate busy servers
- Architecture mismatches between configuration and server reports are tracked
- Cached server information is used during temporary outages

### Server Status Tracking

Each server maintains:
- Last successful contact timestamp
- Last failed contact timestamp
- Consecutive failure count
- Last known architecture
- Health status (HEALTHY/DEGRADED/UNAVAILABLE/MISCONFIGURED)
- Cached response data for fallback during outages

## Email Notifications

The farm includes an integrated SMTP system for sending email notifications:

### SMTP Configuration
- **Admin Configuration**: Admins can configure SMTP settings via API
- **Flexible Settings**: Supports various SMTP providers (Gmail, SendGrid, etc.)
- **TLS Support**: Configurable TLS encryption
- **Authentication**: Optional SMTP authentication
- **Custom Headers**: Configurable from address and name

### Email Features
- **User Notifications**: Email notifications for user management actions
- **Account Management**: Notifications for account creation, deletion, role changes
- **Test Functionality**: Built-in email testing for configuration validation
- **Error Handling**: Comprehensive error handling for email delivery

### Supported SMTP Providers
- Gmail (smtp.gmail.com:587)
- SendGrid (smtp.sendgrid.net:587)
- Mailgun (smtp.mailgun.org:587)
- Custom SMTP servers

---

## Endpoints

### Farm Information

#### GET /farm
Get farm information and status of all managed servers.

**Request Headers:**
- `Authorization: Bearer <token>` (optional)

**Response:**
```json
{
  "status": "running",
  "version": "2026.10.28",
  "servers": [
    {
      "url": "http://server1.example.com:8000",
      "arch": "x86_64",
      "status": "online",
      "health": "healthy",
      "info": {
        "version": "2026.10.28",
        "supported_architecture": "x86_64",
        "system_info": {
          "architecture": "x86_64",
          "cpu": {
            "cores": 8,
            "usage_percent": 25.5
          },
          "memory": {
            "total": 16777216,
            "used": 8388608,
            "percentage": 50.0
          },
          "uptime": "2 days, 5 hours, 30 minutes"
        },
        "queue_status": {
          "current_builds_count": 1,
          "queued_builds": 2,
          "max_concurrent_builds": 3,
          "buildroot_recreation_count": 0,
          "server_busy_with_buildroot": false
        }
      }
    }
  ],
  "available_architectures": ["x86_64", "powerpc", "powerpc64le"],
  "total_servers": 3,
  "authenticated": true,
  "user_role": "user"
}
```

**Authentication Impact:**
- **Guest**: Server URLs are obfuscated (e.g., `ser---1`)
- **User/Admin**: Different levels of server information visibility
- **Admin**: Full server URLs and detailed information

#### GET /health
Simple health check endpoint for the farm.

**Response:**
```json
{
  "status": "healthy",
  "version": "2026.10.28"
}
```

#### GET /dashboard
Get the comprehensive farm dashboard (HTML page) showing all servers, their current builds, and recent build history.

**Routes:**
- `/dashboard` — Servers by Architecture tab (default)
- `/dashboard/builds` — Recent Builds tab, page 1
- `/dashboard/builds/{page}` — Recent Builds tab, paginated (page ≥ 1)
- `/dashboard/statistics` — Statistics tab (authenticated users only)

Legacy query-string URLs (`?tab=` and `?page=`) redirect to the path-based routes above.

Tabs are plain links to these routes, so the dashboard works without JavaScript (including text browsers such as lynx and w3m). Only the data for the requested tab is queried and rendered. `/dashboard/statistics` falls back to the servers tab for guests.

**Response:** HTML page (rendered from templates in `apb.web`, with all values HTML-escaped) with:

**Servers tab** (`/dashboard`):
- Servers grouped by their actual supported architecture, plus a `misconfigured` group when needed
- A text status badge per server (`online`, `offline`, `misconfigured (N failures)`)
- Current and queued build counts per server, and a buildroot recreation indicator
- Up to 3 currently building packages per server (package link, user, start time) and an "... and N more" line

**Builds tab** (`/dashboard/builds/{page}`):
- Table of recent builds across all servers (20 per page) with package link, status badge, architecture, server, creation time, user and build ID
- Previous/next links; "Next" is only shown when another page exists

**Statistics tab** (`/dashboard/statistics`, authenticated users only):
- Top 10 users by total, successful and failed builds

**Live updates:**
- With JavaScript, the servers tab is refreshed in place every 30 seconds (paused while the browser tab is hidden). Without JavaScript the page is static; reload it manually

**Layout:**
- Shared stylesheet served from `/static/style.css` (system fonts, light and dark color schemes via `prefers-color-scheme`, tables that stack on narrow screens)
- Status is always shown as text, never by color alone

#### GET /admin
Get the comprehensive admin panel (Admin Only).

**Authentication:**
- `Authorization: Bearer <admin_token>` or the dashboard `authToken` cookie (required)
- Not logged in: `303 See Other` to `/login`; logged in without the admin role: HTML error page with status `403`

**Response:** HTML admin panel. The user list is rendered on the server; all other actions use the JSON endpoints below through `/static/admin.js` (ES5, `XMLHttpRequest`), so the admin panel requires JavaScript. A `<noscript>` notice says so. The script sends the page's CSRF token as `X-CSRF-Token`.

Sections (linked from an in-page section menu):

- **Users**: list users with role, email, notification setting, creation date and last login; create users; edit role, email and notifications; delete users (with confirmation)
- **SMTP**: configure the email server (server, port, credentials, TLS, from address and name; the password is never shown), delete the configuration, send a test email
- **Repositories**: list, add, edit, enable/disable and delete custom repositories
- **Cache**: show artifact cache status and trigger a manual cleanup

---

### Build Management

#### POST /build
Submit a build request to the farm (Authentication Required).

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Request Methods:**

**Method 1: Tarball Upload (Recommended)**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `build_tarball` (file, required): Compressed tarball containing PKGBUILD and sources
  - `architectures` (string, optional): Comma-separated list of target architectures
  - `build_timeout` (integer, optional): Build timeout in seconds (300-14400, admin only)

**Method 2: Individual File Upload (Legacy)**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `pkgbuild` (file, required): The PKGBUILD file
  - `sources` (file[], optional): Additional source files
  - `architectures` (string, optional): Comma-separated list of target architectures
  - `build_timeout` (integer, optional): Build timeout in seconds (300-14400, admin only)

**Enhanced Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "status": "queued",
  "message": "Queued 2 build(s) for processing",
  "pkgname": "example-package",
  "target_architectures": ["x86_64", "powerpc"],
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "arch": "x86_64",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0,
      "queue_state": "farm",
      "queue_position": 1,
      "jobs_ahead": 0,
      "farm_queue_size": 2
    },
    {
      "build_id": "7f2a8e9b-1234-5678-9abc-def012345678",
      "arch": "powerpc",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0,
      "queue_state": "farm",
      "queue_position": 2,
      "jobs_ahead": 1,
      "farm_queue_size": 2
    }
  ],
  "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
  "queue_status": {
    "queue_size": 2,
    "builds_queued": 2,
    "message": "Build(s) queued on farm; waiting for server capacity (2 job(s) in farm queue)"
  },
}
```

**Authentication Changes:**
- **Required**: All build submissions require authentication
- **User Tracking**: Builds are associated with the submitting user
- **Permission Checking**: Users can only cancel their own builds (admins can cancel any)

**Build Timeout Configuration:**
- **Default**: 7200 seconds (2 hours)
- **Range**: 300-14400 seconds (5 minutes to 4 hours)
- **Admin Only**: Only admin users can specify custom timeouts
- **Per-Build**: Each build can have a custom timeout

**Enhanced Processing:**
- **Queue-based**: Builds are queued immediately on the farm and processed by background tasks
- **Capacity-aware scheduling**: Builds wait in the farm queue until a server with matching architecture has a free `--max-concurrent` slot
- **Architecture-aware ordering**: When one architecture's servers are full, builds for other architectures can still be assigned
- **Server Assignment**: Builds assigned to servers based on availability and architecture compatibility
- **Consistent Tracking**: Farm passes its build ID to the server, ensuring consistent tracking
- **Retry Logic**: Exponential backoff retry logic for transient submission failures (network/timeouts)

**Architecture Filtering:**
If `architectures` parameter is provided, only those architectures will be built (if they exist in the PKGBUILD and have available servers).

**PKGBUILD `apb_arch_hint` (arch=(any) only):**
When `arch=()` is exactly `(any)`, an optional `apb_arch_hint=powerpc` assignment pins server selection to that architecture. The client still submits `architectures=any`; package artifacts remain `*-any.pkg.tar.*`. If no server supports the hint, the build is not queued on another architecture. The hint is ignored (with a log warning) when `arch=()` lists anything other than `any` alone.

**Error Responses:**
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions (custom timeout without admin role)
- **503 Service Unavailable**: No suitable server available
- **400 Bad Request**: Invalid PKGBUILD file or missing required files
- **413 Payload Too Large**: Upload exceeds server file size limits
- **500 Internal Server Error**: Server error

**Architecture Mismatch Error:**
When no servers are available for the requested architectures:
```json
{
  "error": "No builds queued",
  "message": "No servers available for any of the target architectures",
  "pkgname": "example-package",
  "target_architectures": ["powerpc", "riscv64"],
  "available_architectures": ["x86_64", "powerpc64le"],
  "pkgbuild_architectures": ["powerpc", "riscv64", "x86_64"]
}
```

#### GET /build/{build_id}/status
Get build status. Returns HTML page by default, JSON if `format=json` is specified.

**Parameters:**
- `build_id` (string, required): The build ID
- `format` (string, optional): Response format (`json` or `html`)

**HTML Response:**
One build status page covers every state: not found (404), waiting in the farm queue, submission failed (404), live status from the build server, last cached status while the server is unavailable or unreachable, and server unavailable without cached status (503). It shows:
- **Build Metadata**: Package name, status badge, build ID, architecture, server (obfuscated), user, start and end time, duration, and the farm queue position while queued
- **Artifacts**: Links to packages and logs
- **Cancel**: A plain HTML form posting to `POST /build/{build_id}/cancel` when the logged-in user may cancel a queued or building build
- **Live Updates**: While a build is not finished, the page refreshes. With JavaScript, only the status section is reloaded in place (paused while the browser tab is hidden, backing off on errors, stopping once the build finishes). Without JavaScript, a `<noscript>` meta refresh reloads the page (10 seconds while queued, 30 seconds while building or showing cached status, 60 seconds when the server is unavailable)

**Enhanced JSON Response:**

The JSON response is the shared `BuildStatusResponse` model (`apb.models`). It has the build server's status fields plus optional farm extras: `server_url`, `server_arch`, `artifacts_ready`, `queue_state`, `queue_position`, `jobs_ahead`, `farm_queue_size`, `server_unavailable`, `last_status_update` and `error_message`. Fields without a value are omitted. Times are epoch seconds.

```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": 1642694400.0,
  "end_time": 1642694500.0,
  "duration": 100.0,
  "exit_code": 0,
  "arch": ["x86_64"],
  "server_url": "ser---1",
  "server_arch": "x86_64",
  "created_at": 1642694300.0,
  "build_timeout": 7200,
  "packages": [
    {
      "filename": "example-package-1.0.0-1-x86_64.pkg.tar.xz",
      "size": 1024000,
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example-package-1.0.0-1-x86_64.pkg.tar.xz"
    }
  ],
  "logs": [
    {
      "filename": "build.log",
      "size": 50000,
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/build.log"
    }
  ],
  "artifacts_ready": true
}
```

The `artifacts_ready` field indicates whether the farm has finished caching all packages and logs locally. Clients must wait for `artifacts_ready: true` before downloading artifacts from the farm.

**Farm Queue Response (before server assignment):**
When a build is waiting in the farm queue for server capacity, status JSON includes:
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "queued",
  "server_arch": "x86_64",
  "created_at": 1642694300.0,
  "packages": [],
  "logs": [],
  "artifacts_ready": false,
  "queue_state": "farm",
  "queue_position": 3,
  "jobs_ahead": 2,
  "farm_queue_size": 5
}
```

- `queue_state`: `"farm"` while waiting for a server slot; omitted once assigned to a build server
- `queue_position`: 1-based position in the farm queue
- `jobs_ahead`: Number of farm-queued builds ahead of this one
- `farm_queue_size`: Total builds currently waiting on the farm

**Enhanced Error Handling:**
- **Server Unavailable**: If the assigned server is unavailable, returns cached status with warning
- **Build Not Found**: If build was never submitted through farm, provides detailed error message
- **Submission Failed**: If build failed during submission before server assignment

**Server Unavailable Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "building",
  "server_unavailable": true,
  "last_status_update": 1642694450.0,
  "server_url": "ser---1",
  "error_message": "Server unavailable: Connection timeout"
}
```

**Note:** Server URLs are obfuscated in responses for security (e.g., `server1.example.com` → `ser---1`).

#### GET /build/{build_id}/status-api
Get build status as JSON (alias for `/build/{build_id}/status?format=json`). The build server serves the same path with the same shape, so clients use `status-api` against either.

**Parameters:**
- `build_id` (string, required): The build ID

**Response:** Same as `/build/{build_id}/status` with `format=json`.

#### POST /build/{build_id}/cancel
Cancel a build with comprehensive permission checking.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Parameters:**
- `build_id` (string, required): Build ID

**Response (farm queue):**
```json
{
  "success": true,
  "message": "Build 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3 removed from farm queue"
}
```

**Response (assigned build):**
```json
{
  "success": true,
  "message": "Build 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3 cancelled successfully",
  "server_response": {
    "success": true,
    "message": "Build cancelled successfully"
  }
}
```

Builds still waiting in the farm queue (not yet assigned to a build server) are removed from the queue and marked cancelled without contacting a server.

**Web form submission:**
When the request body is `application/x-www-form-urlencoded` or `multipart/form-data` (the cancel form on the build status page), the farm authenticates with the `authToken` cookie, requires the `csrf_token` form field, and answers with `303 See Other` to `/build/{build_id}/status` instead of JSON. Errors are rendered as an HTML error page with the same status code.

**Permission Rules:**
- **Users**: Can cancel only their own builds
- **Admins**: Can cancel any user's builds
- **Build Ownership**: Permission checked against build database user_id

**Enhanced Error Handling:**
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Not authorized to cancel this build
- **404 Not Found**: Build not found in database
- **503 Service Unavailable**: Server unavailable for cancellation request

#### GET /build/{build_id}/output
Get build output/logs by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `start_index` (integer, optional): Starting line index (default: 0)
- `limit` (integer, optional): Maximum number of lines (default: 50, max: 1000)

**Response:**
```json
{
  "output": [
    "==> Making package: example-package 1.0.0-1 (x86_64)",
    "==> Checking runtime dependencies...",
    "==> Installing missing dependencies...",
    "==> Starting build()...",
    "==> Build completed successfully"
  ],
  "total_lines": 150,
  "start_index": 0,
  "returned_lines": 5
}
```

**Enhanced Features:**
- **Server Forwarding**: Automatically forwards to the correct server
- **Error Handling**: Handles server unavailability gracefully
- **Permission Checking**: Respects build visibility permissions
- **Caching**: Uses cached output when servers are temporarily unavailable

#### GET /build/{build_id}/stream
Stream build output in real-time by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID

**Response:**
- **Content-Type:** `text/event-stream`
- Forwards Server-Sent Events from the target server
- Handles server unavailability with appropriate error responses
- Maintains connection state and error recovery

**Enhanced Streaming Features:**
- **Connection Management**: Proper cleanup and error handling
- **Failover Support**: Handles server disconnections gracefully
- **Authentication**: Respects user permissions for build access
- **Real-time Forwarding**: Low-latency forwarding of server events

---

### File Downloads

#### GET /build/{build_id}/download/{filename}
Download a build artifact from the farm's local artifact cache.

**Parameters:**
- `build_id` (string, required): Build UUID
- `filename` (string, required): The filename to download

**Authentication:**
- Optional. Bearer token (APB client) or dashboard `authToken` cookie.
- For `build.log`:
  - **Unauthenticated**: response body is truncated to the last 100 lines, with a short notice header. Headers include `X-APB-Log-Truncated: true` and `X-APB-Log-Tail-Lines: 100`. `Cache-Control: private, no-store`.
  - **Authenticated** (farm user or admin): full `build.log` is returned. `Cache-Control: private, no-store`.
- Other artifact types are unchanged and do not require authentication.

**Response:** Binary file content with appropriate headers.

**Enhanced Error Handling:**
- **Cache Headers**: Proper caching headers for static package content; build logs are not publicly cached
- **Permission Checking**: Full build logs require authentication

**Error Responses:**
- **404 Not Found**: File not found in the farm cache
- **403 Forbidden**: Insufficient permissions to access build

---

### Custom Repository Management

The APB Farm supports custom pacman repositories that users can request in their PKGBUILD files using the `apb_extra_repos` variable. These repositories are managed by administrators and must be pre-configured with GPG key validation for security.

#### Custom Repository Format

Users can specify custom repositories in their PKGBUILD files using the following format:

```bash
apb_extra_repos=(
  reponame::https://myrepo.example.com
  anotherrepo::https://another.example.com/$arch
)
```

Multi-line and single-line array forms are both accepted. Pacman placeholders `$arch` and `$repo` in repository URLs are preserved (not expanded by the PKGBUILD parser) so they must match the admin-configured URL literally and are expanded by pacman when the custom `pacman.conf` is used. Other bash-style `${var}` references in those URLs are expanded normally.

#### Repository Validation

- All requested repositories must be pre-configured by an administrator
- Repository URLs must match exactly what was configured (including literal `$arch` / `$repo` if used)
- GPG keys must be valid and trusted
- Builds will fail if invalid repositories are requested
- Builds fail immediately if custom repository setup fails (GPG key download or pacman.conf modification)
- Failed builds produce build.log files with detailed error messages for client download
- Custom pacman.conf is created in build directory and mounted via makechrootpkg -d flag instead of modifying buildroot

#### Admin Repository Management

##### GET /admin/repositories
Get all configured custom repositories (admin only).

**Response:**
```json
{
  "repositories": [
    {
      "id": 1,
      "name": "myrepo",
      "url": "https://myrepo.example.com",
      "gpg_key_id": "ABCD1234...",
      "description": "My custom repository",
      "is_active": true,
      "created_at": 1640995200.0,
      "created_by": 1
    }
  ]
}
```

##### POST /admin/repositories
Create a new custom repository (admin only).

**Parameters:**
- `name` (string, required): Repository name
- `url` (string, required): Repository URL
- `gpg_key_id` (string, required): GPG key ID for repository signing
- `description` (string, optional): Repository description

**Response:**
```json
{
  "success": true,
  "message": "Repository 'myrepo' created successfully"
}
```

##### PUT /admin/repositories/{repo_id}
Update an existing custom repository (admin only).

**Parameters:**
- `name` (string, optional): New repository name
- `url` (string, optional): New repository URL
- `gpg_key_id` (string, optional): New GPG key ID
- `description` (string, optional): New description
- `is_active` (boolean, optional): Repository status

##### DELETE /admin/repositories/{repo_id}
Delete a custom repository (admin only).

**Response:**
```json
{
  "success": true,
  "message": "Repository 'myrepo' deleted successfully"
}
```

---

### Build History

Build history endpoints return the same `BuildSummary` / `BuildListResponse` shape as the build server (`apb.models`):

- Each build has `build_id`, `pkgname`, `status`, `start_time`, `end_time`, `created_at` and `duration` (seconds).
- Farm entries add `server_arch`, `server_url` (obfuscated), `display_name` (`pkgname (epoch:pkgver-pkgrel)`) and `username` (`#anon#` for anonymous submissions).
- Timestamps are ISO 8601 UTC strings. Fields without a value are omitted.
- `total` is the number of builds matching the filters, not the number returned.
- Builds are ordered newest first by `created_at`.

#### GET /builds/latest
Get the latest builds across all managed servers.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 20, min: 1, max: 100)
- `status` (string, optional): Filter by status

**Response:**
```json
{
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
      "created_at": "2024-01-20T09:59:50Z",
      "duration": 300.0,
      "server_arch": "x86_64",
      "server_url": "ser---1",
      "display_name": "example-package (1.0.0-1)",
      "username": "builder"
    }
  ],
  "total": 1
}
```

**Enhanced Features:**
- **Multi-server Aggregation**: Combines builds from all servers
- **User Context**: Shows the submitting user's name
- **Status Filtering**: Filter by build status (queued, building, completed, failed, cancelled)

#### GET /builds/pkgname/{pkgname}
Get recent builds for a specific package name as stored by the farm (`pkgbase` when present, otherwise `pkgname`).

**Parameters:**
- `pkgname` (string, required): Package name
- `limit` (integer, optional): Maximum builds to return (default: 20, min: 1, max: 100)
- `status` (string, optional): Filter by status

**Response:**
```json
{
  "pkgname": "example-package",
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
      "created_at": "2024-01-20T09:59:50Z",
      "duration": 300.0,
      "server_arch": "x86_64",
      "server_url": "ser---1",
      "display_name": "example-package (1.0.0-1)",
      "username": "builder"
    }
  ],
  "total": 1
}
```

#### GET /builds/pkgname/{pkgname}/latest
Get the latest build for a package across all architectures.

**Parameters:**
- `pkgname` (string, required): Package name
- `successful_only` (boolean, optional): Only completed builds (default: true)

**Response:** Single build summary (same fields as above). Returns 404 when none found.

#### GET /builds/pkgname/{pkgname}/arch/{arch}/latest
Get the latest build for a package on a specific architecture.

**Parameters:**
- `pkgname` (string, required): Package name
- `arch` (string, required): Target architecture. Use `any` to match the latest completed build regardless of `server_arch` (for `arch=('any')` packages)
- `successful_only` (boolean, optional): Only completed builds (default: true)

**Response:** Single build summary. Returns 404 when none found.

#### GET /builds/pkgname/{pkgname}/latest-by-arch
Get the latest build for each `server_arch` of a package.

**Parameters:**
- `pkgname` (string, required): Package name
- `successful_only` (boolean, optional): Only completed builds (default: true)

**Response:** A build list with one entry per architecture, sorted by `server_arch`; `total` is the number of architectures.
```json
{
  "pkgname": "example-package",
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "server_arch": "aarch64"
    },
    {
      "build_id": "59fb2ef6-a8b4-488f-b8b8-47f637fb8de4",
      "pkgname": "example-package",
      "status": "completed",
      "server_arch": "x86_64"
    }
  ],
  "total": 2
}
```

#### GET /my/builds
Get builds submitted by the current authenticated user.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Parameters:**
- `limit` (integer, optional): Maximum builds to return (default: 20, min: 1, max: 100)
- `status` (string, optional): Filter by status

**Response:** A build list in the shape shown under [GET /builds/latest](#get-buildslatest), limited to the user's builds.
```json
{
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
      "created_at": "2024-01-20T09:59:50Z",
      "duration": 300.0,
      "server_arch": "x86_64",
      "server_url": "ser---1",
      "display_name": "example-package (1.0.0-1)",
      "username": "user1"
    }
  ],
  "total": 1
}
```

**User-specific Features:**
- **Personal History**: Shows only builds submitted by the authenticated user

---

## Authentication Endpoints

### POST /auth/login
Authenticate user and receive access token.

**Request:**
```json
{
  "username": "your_username",
  "password": "your_password"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "username": "your_username",
    "role": "user",
    "created_at": 1642694400.0,
    "last_login": 1642694400.0,
    "email": "user@example.com",
    "email_notifications_enabled": true,
    "mfa_enabled": false
  },
  "expires_in_days": 10
}
```

**Response for users with 2FA** (no session token yet; continue with [POST /auth/login/2fa](#post-authlogin2fa)):
```json
{
  "mfa_required": true,
  "mfa_token": "kq3...",
  "methods": ["totp", "webauthn", "recovery"],
  "expires_in_seconds": 300
}
```

`methods` lists what the user has enrolled: `totp`, `webauthn` (at least one security key) and `recovery` (unused recovery codes left).

**Response for admins without 2FA** (enroll a second factor with the `/auth/my/2fa` endpoints, or in a browser at `setup_url`):
```json
{
  "mfa_setup_required": true,
  "setup_token": "Zt0...",
  "setup_url": "https://apb-farm.example.com/account/2fa",
  "expires_in_seconds": 900
}
```

**Enhanced Features:**
- **Email Support**: User email included in response
- **Last Login Tracking**: Updates last login timestamp
- **Detailed User Info**: Complete user profile information
- **Security Logging**: Login attempts logged for security monitoring

**Error Responses:**
- **401 Unauthorized**: Invalid username or password
- **400 Bad Request**: Missing or invalid request data

### POST /auth/login/2fa/webauthn-options
Start a security key login for a pending 2FA login. Replaces any earlier challenge of the same pending login.

**Request:**
```json
{
  "mfa_token": "kq3..."
}
```

**Response:** WebAuthn `CredentialRequestOptions` in JSON form (binary values are base64url strings), to pass to `navigator.credentials.get()` or a FIDO2 client:
```json
{
  "publicKey": {
    "challenge": "m2V...",
    "rpId": "apb-farm.example.com",
    "allowCredentials": [{"type": "public-key", "id": "AbC..."}],
    "userVerification": "discouraged"
  }
}
```

**Error Responses:**
- **401 Unauthorized**: Invalid or expired 2FA login
- **400 Bad Request**: The user has no security keys

### POST /auth/login/2fa
Finish a pending 2FA login and receive a session token.

**Request:**
```json
{
  "mfa_token": "kq3...",
  "method": "totp",
  "code": "123456"
}
```

- `method`: `totp`, `recovery` or `webauthn`
- `code`: the authenticator code (`totp`) or a recovery code (`recovery`; dashes and case are ignored)
- `credential`: for `webauthn`, the `PublicKeyCredential` returned for the options from `POST /auth/login/2fa/webauthn-options`, in JSON form (`id`, `rawId`, `type` and `response` with base64url `clientDataJSON`, `authenticatorData`, `signature` and `userHandle`)

**Response:** the same `LoginResponse` as a login without 2FA. The pending `mfa_token` is revoked.

**Error Responses:**
- **401 Unauthorized**: Invalid or expired 2FA login, or a wrong code or security key response. After 5 failed attempts the pending login is revoked and the user has to log in with the password again
- **400 Bad Request**: Unsupported or not enrolled `method`, or missing `code`/`credential`

### POST /auth/logout
Logout and revoke current authentication token.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

**Enhanced Features:**
- **Token Revocation**: Immediately invalidates the current token
- **Security Logging**: Logout events logged for audit trail
- **Session Cleanup**: Cleans up any associated session data

### GET /auth/logout
Alternative GET endpoint for logout (for web browser redirects).

**Request Headers:**
- `Authorization: Bearer <token>` (optional)

**Response:** Redirects to dashboard with logout confirmation message.

### GET /auth/me
Get current authenticated user information.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Response:**
```json
{
  "id": 1,
  "username": "your_username",
  "role": "user",
  "created_at": 1642694400.0,
  "last_login": 1642694400.0,
  "email": "user@example.com",
  "email_notifications_enabled": true,
  "mfa_enabled": true
}
```

**Enhanced Features:**
- **Complete Profile**: Full user profile information
- **Role Information**: Current user role and permissions
- **Email Address**: User's email address if configured
- **2FA Status**: `mfa_enabled` is true when the user has a confirmed authenticator or a security key

---

## Two-Factor Management Endpoints

Endpoints for managing the second factors of the logged-in user. They accept a `full` token and the `mfa_setup` token returned to admins without 2FA. Cookie-authenticated requests need a CSRF token as usual.

When a request enrolls the user's first second factor, the response contains `recovery_codes` (shown only once). When it was made with an `mfa_setup` token, the response also contains a new `full` `token` and the setup token is revoked; web requests get the new token as `authToken` cookie instead.

### GET /auth/my/2fa
**Response:**
```json
{
  "enabled": true,
  "required": false,
  "totp_enabled": true,
  "security_keys": [
    {"id": 1, "name": "YubiKey 5C", "created_at": 1642694400.0, "last_used_at": 1642694800.0}
  ],
  "recovery_codes_remaining": 9
}
```

### POST /auth/my/2fa/totp
Start TOTP enrollment. Generates a new secret, replacing an unconfirmed one. The authenticator is not active until it is confirmed.

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "provisioning_uri": "otpauth://totp/APB%20Farm%20%28apb-farm.example.com%29:alice?secret=JBSWY3DPEHPK3PXP&issuer=APB%20Farm%20%28apb-farm.example.com%29"
}
```

**Error Responses:**
- **400 Bad Request**: TOTP is already enabled (remove it first)

### POST /auth/my/2fa/totp/confirm
**Request:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "message": "Authenticator app enabled",
  "recovery_codes": ["3f9a1-0c2d4", "..."],
  "token": null
}
```

**Error Responses:**
- **400 Bad Request**: No pending TOTP enrollment, or a wrong code

### DELETE /auth/my/2fa/totp
**Request:**
```json
{
  "password": "current_password"
}
```

**Response:**
```json
{
  "message": "Authenticator app removed"
}
```

**Error Responses:**
- **400 Bad Request**: Wrong password, TOTP not enabled, or it is the last second factor of an admin

### POST /auth/my/2fa/webauthn/register-options
Start security key registration. Replaces any earlier challenge of the same session.

**Response:** WebAuthn `CredentialCreationOptions` in JSON form (binary values are base64url strings), to pass to `navigator.credentials.create()`. Already registered keys are listed in `excludeCredentials`.

### POST /auth/my/2fa/webauthn
Finish security key registration.

**Request:**
```json
{
  "name": "YubiKey 5C",
  "credential": {
    "id": "AbC...",
    "rawId": "AbC...",
    "type": "public-key",
    "response": {"clientDataJSON": "eyJ...", "attestationObject": "o2N..."}
  }
}
```

- `name`: 1-64 characters

**Response:**
```json
{
  "message": "Security key registered",
  "recovery_codes": null,
  "token": null
}
```

**Error Responses:**
- **400 Bad Request**: No registration in progress, invalid response, or the key is already registered

### DELETE /auth/my/2fa/webauthn/{credential_id}
**Parameters:**
- `credential_id` (integer): `id` from `GET /auth/my/2fa`

**Request:**
```json
{
  "password": "current_password"
}
```

**Response:**
```json
{
  "message": "Security key removed"
}
```

**Error Responses:**
- **404 Not Found**: No such security key for this user
- **400 Bad Request**: Wrong password, or it is the last second factor of an admin

### POST /auth/my/2fa/recovery-codes
Replace all recovery codes with a new set.

**Request:**
```json
{
  "password": "current_password"
}
```

**Response:**
```json
{
  "recovery_codes": ["3f9a1-0c2d4", "..."]
}
```

**Error Responses:**
- **400 Bad Request**: Wrong password, or 2FA is not enabled

---

## Web Form Endpoints

HTML endpoints used by the web UI. They work with plain HTML forms and no JavaScript, so text browsers and very old browsers can log in, log out, change the password and cancel builds. The JSON endpoints above are unchanged and remain the interface for the APB client.

### Web Session and CSRF

- `POST /login` stores the token in an `authToken` cookie with `HttpOnly`, `SameSite=Lax`, `Path=/`, a lifetime of 10 days and `Secure` when the request came in over HTTPS
- Pages rendered for a logged-in user embed a CSRF token, derived from the session token, as a hidden `csrf_token` form field and a `<meta name="csrf-token">` tag
- Every non-GET request authenticated by the `authToken` cookie must send that token as the `csrf_token` form field or the `X-CSRF-Token` header; otherwise the farm answers `403 Forbidden` with `{"detail": "CSRF token missing or invalid"}`
- Requests that send `Authorization: Bearer <token>` (the APB client) do not need a CSRF token

### GET /login
HTML login form. Redirects (`303`) to `/dashboard` when already logged in.

### POST /login
**Content-Type:** `application/x-www-form-urlencoded`

**Form fields:**
- `username` (string, required)
- `password` (string, required)

**Response:**
- Success: `303 See Other` to `/dashboard` and sets the `authToken` cookie
- User with 2FA: `303 See Other` to `/login/2fa` and sets the pending login in an `apbMfa` cookie (`HttpOnly`, `SameSite=Lax`, 5 minutes)
- Admin without 2FA: `303 See Other` to `/account/2fa` and sets the `authToken` cookie to the 15-minute `mfa_setup` token
- Invalid credentials: the login form again with an error message, status `401`

### GET /login/2fa
Second login step: a form for the authenticator or recovery code and, when the user has security keys, a "Use security key" button (needs JavaScript and WebAuthn support). The page embeds fresh WebAuthn request options. Redirects (`303`) to `/login` without a valid `apbMfa` cookie.

### POST /login/2fa
**Content-Type:** `application/x-www-form-urlencoded`

**Form fields:**
- `csrf_token` (string, required; derived from the pending login)
- `method` (string, required): `totp`, `recovery` or `webauthn`
- `code` (string): authenticator or recovery code
- `credential` (string): for `webauthn`, the JSON-encoded `PublicKeyCredential`

**Response:**
- Success: `303 See Other` to `/dashboard`, sets the `authToken` cookie and clears `apbMfa`
- Wrong code or key: the 2FA form again with an error message, status `401`
- Expired pending login or too many attempts: the login form with an error message, status `401`

### GET /account/2fa
Two-factor settings of the logged-in user: enrolled factors, "Set up authenticator app", security key registration and removal, and recovery code regeneration. Also reachable with an `mfa_setup` session. Redirects (`303`) to `/login` when not logged in.

### POST /account/2fa/totp
Start TOTP enrollment (same as `POST /auth/my/2fa/totp`) and answer `303 See Other` to `/account/2fa/totp`.

### GET /account/2fa/totp
QR code (inline SVG), secret and confirmation form of the pending TOTP enrollment. Redirects (`303`) to `/account/2fa` when there is none.

### POST /account/2fa/totp/confirm
**Form fields:** `csrf_token`, `code`. On success renders `/account/2fa` with the recovery codes (first factor only); a setup session is replaced by a full session cookie.

### POST /account/2fa/totp/delete
**Form fields:** `csrf_token`, `password`. Removes the authenticator app.

### POST /account/2fa/webauthn
**Form fields:** `csrf_token`, `name`, `credential` (JSON-encoded `PublicKeyCredential` from `navigator.credentials.create()` with the options embedded in `/account/2fa`). On success renders `/account/2fa` with the recovery codes (first factor only).

### POST /account/2fa/webauthn/{credential_id}/delete
**Form fields:** `csrf_token`, `password`. Removes a security key.

### POST /account/2fa/recovery-codes
**Form fields:** `csrf_token`, `password`. Renders `/account/2fa` with a new set of recovery codes.

All `/account/2fa` form endpoints answer validation errors with the 2FA page and status `400`, and `303 See Other` to `/login` when not logged in.

### POST /logout
**Content-Type:** `application/x-www-form-urlencoded`

**Form fields:**
- `csrf_token` (string, required when logged in)

**Response:** Revokes the session token, clears the `authToken` cookie and answers `303 See Other` to `/dashboard`. A missing or wrong CSRF token returns `403`.

### GET /account
HTML account page for the logged-in user (username, role, email) with a password change form. Redirects (`303`) to `/login` when not logged in.

### POST /account/password
**Content-Type:** `application/x-www-form-urlencoded`

**Form fields:**
- `current_password` (string, required)
- `new_password` (string, required, at least 8 characters)
- `confirm_password` (string, required, must match `new_password`)
- `csrf_token` (string, required)

**Response:**
- Success: revokes all tokens of the user (same as `PUT /auth/change-password`), clears the `authToken` cookie and renders the login form with a confirmation message
- Validation error: the account page again with the error message, status `400`
- Not logged in: `303 See Other` to `/login`

### GET /static/{path}
Stylesheet and scripts for the web UI (`style.css`, `apb.js`, `admin.js`, `webauthn.js`). Pages link them with a `?v=<version>` suffix; responses are sent with `Cache-Control: public, max-age=31536000, immutable`.

---

## User Management Endpoints (Admin Only)

### GET /auth/users
List all users in the system.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Response:**
```json
[
  {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "created_at": 1642694400.0,
    "last_login": 1642694400.0,
    "email": "admin@example.com"
  },
  {
    "id": 2,
    "username": "user1",
    "role": "user",
    "created_at": 1642694500.0,
    "last_login": 1642694600.0,
    "email": "user1@example.com"
  }
]
```

**Enhanced Features:**
- **Complete User Profiles**: Full user information including email
- **Activity Tracking**: Last login timestamps
- **Role Information**: User roles and permissions
- **Account Status**: Active/inactive status indicators

### POST /auth/users
Create a new user account.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Request:**
```json
{
  "username": "newuser",
  "password": "securepassword123",
  "role": "user",
  "email": "newuser@example.com"
}
```

**Response:**
```json
{
  "id": 3,
  "username": "newuser",
  "role": "user",
  "created_at": 1642694700.0,
  "last_login": null,
  "email": "newuser@example.com"
}
```

**Enhanced Features:**
- **Email Support**: Optional email address for notifications
- **Email Notifications**: Automatic email notification to new user (if SMTP configured)
- **Input Validation**: Comprehensive validation of all fields
- **Duplicate Detection**: Prevents duplicate usernames

**Validation Rules:**
- Username: 3-50 characters, unique, alphanumeric and underscore only
- Password: 8-100 characters minimum
- Role: "user" or "admin"
- Email: Valid email format, optional

### DELETE /auth/users/{user_id}
Delete a user account (soft delete - marks as inactive).

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID to delete

**Response:**
```json
{
  "message": "User 3 deleted successfully"
}
```

**Enhanced Features:**
- **Soft Delete**: Marks user as inactive rather than hard delete
- **Token Revocation**: Automatically revokes all user tokens
- **Email Notification**: Sends email notification to user (if configured)
- **Build History Preservation**: Preserves user's build history for audit purposes
- **Self-Protection**: Prevents admin from deleting their own account

### PUT /auth/users/{user_id}/role
Change user role.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID to modify

**Request:**
```json
{
  "role": "admin"
}
```

**Response:**
```json
{
  "message": "User role changed to admin"
}
```

**Enhanced Features:**
- **Email Notification**: Notifies user of role change via email
- **Audit Logging**: Logs role changes for security audit
- **Permission Updates**: Immediately updates user permissions
- **Validation**: Prevents invalid role assignments

### PUT /auth/users/{user_id}/email
Update user email address (Admin Only).

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID to modify

**Request:**
```json
{
  "email": "newemail@example.com"
}
```

**Response:**
```json
{
  "message": "User email updated successfully"
}
```

**Enhanced Features:**
- **Email Validation**: Validates email format
- **Notification**: Sends confirmation to both old and new email addresses
- **Null Support**: Allows setting email to null to remove it

### PUT /auth/my/email
Update own email address (User/Admin).

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "email": "mynewemail@example.com"
}
```

**Response:**
```json
{
  "message": "Email updated successfully"
}
```

**Features:**
- **Self-Service**: Users can update their own email
- **Email Validation**: Validates email format
- **Confirmation**: Sends confirmation to new email address

### DELETE /auth/users/{user_id}/2fa
Reset a user's two-factor authentication: removes the authenticator app, all security keys and recovery codes, and revokes all tokens of the user. A reset admin has to enroll a new second factor at the next login.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID

**Response:**
```json
{
  "message": "Two-factor authentication reset for user 2"
}
```

**Error Responses:**
- **400 Bad Request**: Admins cannot reset their own 2FA (use `/account/2fa`)
- **404 Not Found**: User not found

**Features:**
- **Email Notification**: Notifies the user of the reset (if configured)

### POST /auth/users/{user_id}/revoke-tokens
Revoke all authentication tokens for a user.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID

**Response:**
```json
{
  "message": "Revoked 3 tokens for user 2"
}
```

**Enhanced Features:**
- **Complete Revocation**: Revokes all active tokens for the user
- **Force Logout**: Immediately logs out user from all sessions
- **Security Logging**: Logs token revocation for audit purposes
- **Email Notification**: Notifies user of forced logout

### GET /auth/users/{user_id}/builds
Get build history for a specific user.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID
- `limit` (integer, optional): Maximum builds to return (default: 20, min: 1, max: 100)
- `status` (string, optional): Filter by status

**Response:** A build list in the shape shown under [GET /builds/latest](#get-buildslatest), except that `server_url` is not obfuscated.
```json
{
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
      "created_at": "2024-01-20T09:59:50Z",
      "duration": 300.0,
      "server_arch": "x86_64",
      "server_url": "http://server1.example.com:8000",
      "display_name": "example-package (1.0.0-1)",
      "username": "user1"
    }
  ],
  "total": 1
}
```

**Admin Features:**
- **Full Access**: Admins see unobfuscated server URLs
- **Complete History**: Access to all user builds regardless of status

### PUT /auth/change-password
Change current user's password.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Request:**
```json
{
  "current_password": "currentpass123",
  "new_password": "newpassword456",
  "confirm_password": "newpassword456"
}
```

**Response:**
```json
{
  "message": "Password changed successfully"
}
```

**Enhanced Security Features:**
- **Current Password Verification**: Requires current password for security
- **Password Confirmation**: Requires new password confirmation
- **Token Revocation**: Optionally revokes other tokens after password change
- **Email Notification**: Sends email notification of password change
- **Security Logging**: Logs password changes for security audit

---

## SMTP Configuration Endpoints (Admin Only)

### GET /admin/smtp
Get current SMTP configuration.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Response:**
```json
{
  "id": 1,
  "server": "smtp.gmail.com",
  "port": 587,
  "username": "your-email@gmail.com",
  "use_tls": true,
  "from_email": "noreply@yourcompany.com",
  "from_name": "APB Farm",
  "created_at": 1642694400.0,
  "updated_at": 1642694500.0
}
```

**Security Note:** Password is never returned in API responses.

### POST /admin/smtp
Configure SMTP settings.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Request:**
```json
{
  "server": "smtp.gmail.com",
  "port": 587,
  "username": "your-email@gmail.com",
  "password": "your-app-password",
  "use_tls": true,
  "from_email": "noreply@yourcompany.com",
  "from_name": "APB Farm"
}
```

**Response:**
```json
{
  "id": 1,
  "server": "smtp.gmail.com",
  "port": 587,
  "username": "your-email@gmail.com",
  "use_tls": true,
  "from_email": "noreply@yourcompany.com",
  "from_name": "APB Farm",
  "created_at": 1642694400.0,
  "updated_at": 1642694600.0
}
```

**Enhanced Features:**
- **Password Security**: Passwords are securely encrypted before storage
- **Configuration Validation**: Validates SMTP settings before saving
- **TLS Support**: Configurable TLS encryption
- **Custom Headers**: Configurable from address and display name
- **Update Tracking**: Tracks when configuration was last updated

**Supported SMTP Providers:**
- **Gmail**: smtp.gmail.com:587 (requires app password)
- **SendGrid**: smtp.sendgrid.net:587
- **Mailgun**: smtp.mailgun.org:587
- **Office 365**: smtp.office365.com:587
- **Custom SMTP**: Any standard SMTP server

### DELETE /admin/smtp
Delete SMTP configuration.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Response:**
```json
{
  "message": "SMTP configuration deleted successfully"
}
```

**Features:**
- **Complete Removal**: Removes all SMTP configuration
- **Disables Notifications**: Automatically disables email notifications
- **Security Cleanup**: Securely wipes stored passwords

### POST /admin/smtp/test
Test SMTP configuration by sending a test email.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Request:**
```json
{
  "test_email": "admin@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Test email sent successfully to admin@example.com"
}
```

**Error Response:**
```json
{
  "success": false,
  "error": "SMTP connection failed",
  "detail": "Authentication failed: Invalid credentials"
}
```

**Test Features:**
- **Live Testing**: Actually sends a test email to verify configuration
- **Error Details**: Provides detailed error messages for troubleshooting
- **Connection Validation**: Tests SMTP server connectivity and authentication
- **TLS Testing**: Validates TLS encryption if enabled

---

## Build Database Schema

The farm maintains a comprehensive SQLite database with full build tracking:

### Enhanced Builds Table Schema
```sql
CREATE TABLE builds (
    id TEXT PRIMARY KEY,                -- Build UUID
    server_url TEXT,                   -- Assigned server URL
    server_arch TEXT,                  -- Target architecture
    pkgname TEXT,                      -- Package name from PKGBUILD
    status TEXT,                       -- Current build status
    start_time REAL,                   -- Build start timestamp
    end_time REAL,                     -- Build completion timestamp
    created_at REAL,                   -- Submission timestamp
    queue_position INTEGER,            -- Position in queue when submitted
    submission_group TEXT,             -- Group ID for related builds from same submission
    last_known_status TEXT,            -- Last known status from server
    last_status_update REAL,           -- Last status check timestamp
    server_available BOOLEAN DEFAULT 1, -- Server availability flag
    cached_response TEXT,              -- Cached server response (JSON)
    user_id INTEGER,                   -- User who submitted the build
    build_timeout INTEGER DEFAULT 7200, -- Custom build timeout in seconds
    first_missing_at REAL,             -- When build was first detected as missing from server
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Database indexes for performance
CREATE INDEX idx_builds_user ON builds(user_id);
CREATE INDEX idx_builds_status ON builds(status);
CREATE INDEX idx_builds_created_at ON builds(created_at);
CREATE INDEX idx_builds_submission_group ON builds(submission_group);
CREATE INDEX idx_builds_server_arch ON builds(server_arch);
```

### Database Features
- **Build Tracking**: Complete history of all builds across all servers
- **User Attribution**: Links builds to submitting users
- **Server Availability**: Tracks which servers are currently available
- **Status Caching**: Caches server responses for offline access
- **Submission Grouping**: Links related builds from same PKGBUILD submission
- **Queue Management**: Tracks build queue positions and timing
- **Custom Timeouts**: Stores per-build timeout configurations
- **Missing Build Detection**: Automatically marks builds as failed after 15 minutes if they disappear from their assigned server

---

## Authentication Database Schema

The farm authentication system uses comprehensive database tables:

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,           -- PBKDF2-hashed password with salt
    role TEXT NOT NULL DEFAULT 'user',     -- 'user' or 'admin'
    created_at REAL NOT NULL,              -- Unix timestamp
    last_login REAL,                       -- Unix timestamp
    email TEXT,                            -- User email address
    is_active BOOLEAN DEFAULT 1            -- Soft delete flag
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active);
```

### Tokens Table
```sql
CREATE TABLE tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,       -- SHA-256 hashed token
    user_id INTEGER NOT NULL,              -- Foreign key to users.id
    created_at REAL NOT NULL,              -- Unix timestamp
    last_used_at REAL NOT NULL,            -- Unix timestamp
    expires_at REAL NOT NULL,              -- Unix timestamp
    is_active BOOLEAN DEFAULT 1,           -- Token active flag
    scope TEXT NOT NULL DEFAULT 'full',    -- 'full', 'mfa_pending' or 'mfa_setup'
    attempts INTEGER NOT NULL DEFAULT 0,   -- Failed second-factor attempts (mfa_pending)
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Indexes for performance
CREATE INDEX idx_tokens_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_user ON tokens(user_id);
CREATE INDEX idx_tokens_expires ON tokens(expires_at);
CREATE INDEX idx_tokens_active ON tokens(is_active);
```

### Two-Factor Tables
```sql
CREATE TABLE user_totp (
    user_id INTEGER PRIMARY KEY,           -- Foreign key to users.id
    secret TEXT NOT NULL,                  -- AES-256-GCM encrypted Base32 secret (v1:<key_id>:<data>)
    confirmed BOOLEAN NOT NULL DEFAULT 0,  -- Active once a code was confirmed
    last_used_step INTEGER NOT NULL DEFAULT 0, -- Last accepted time step (replay protection)
    created_at REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE webauthn_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,              -- Foreign key to users.id
    credential_id BLOB UNIQUE NOT NULL,    -- WebAuthn credential ID
    credential_data BLOB NOT NULL,         -- Attested credential data (AAGUID, ID, COSE public key)
    sign_count INTEGER NOT NULL DEFAULT 0, -- Last seen signature counter
    name TEXT NOT NULL,                    -- User-chosen key name
    created_at REAL NOT NULL,
    last_used_at REAL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,              -- Foreign key to users.id
    code_hash TEXT NOT NULL,               -- SHA-256 of the normalized code
    used_at REAL,                          -- Set when the code was used
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE webauthn_challenges (
    token_hash TEXT PRIMARY KEY,           -- Token the ceremony belongs to
    purpose TEXT NOT NULL,                 -- 'register' or 'authenticate'
    state TEXT NOT NULL,                   -- JSON ceremony state (challenge)
    expires_at REAL NOT NULL               -- Unix timestamp
);
```

### SMTP Configuration Table
```sql
CREATE TABLE smtp_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server TEXT NOT NULL,                  -- SMTP server hostname
    port INTEGER NOT NULL,                 -- SMTP server port
    username TEXT,                         -- SMTP username (optional)
    password TEXT,                         -- Encrypted SMTP password (optional)
    use_tls BOOLEAN DEFAULT 1,             -- Use TLS encryption
    from_email TEXT,                       -- From email address
    from_name TEXT,                        -- From display name
    created_at REAL NOT NULL,              -- Unix timestamp
    updated_at REAL NOT NULL               -- Unix timestamp
);
```

### Security Features

- **Password Security**: PBKDF2 with 100,000 iterations and random salt per password
- **Token Security**: SHA-256 hashing for storage, cryptographically secure random generation
- **Second Factors**: TOTP secrets are encrypted with AES-256-GCM using keys from a separate key file (see [TOTP Key File](#totp-key-file)); security keys only store public keys; recovery codes are stored as SHA-256 hashes
- **Email Encryption**: SMTP passwords encrypted before database storage
- **Database Indexes**: Optimized for authentication and query performance
- **Automatic Cleanup**: Background task removes expired tokens every hour
- **Foreign Key Constraints**: Maintains data integrity between users and tokens

---

## Background Tasks

The farm runs several sophisticated background tasks for maintaining system health:

### Process Build Queue
- **Frequency**: Continuous with 5-second intervals when no server slot is available, 1-second when assigning builds
- **Function**: Processes queued builds and assigns them to available servers with free capacity
- **Features**:
  - **Capacity Waiting**: Keeps builds in the farm queue until a matching server has `current_builds < max_concurrent`
  - **Architecture-aware Scanning**: Skips builds blocked by full servers for their architecture and assigns others
  - **Exponential Backoff**: Retry logic with increasing delays for transient submission failures
  - **Server Health**: Checks server availability and health before assignment
  - **Load Balancing**: Distributes builds across available servers
  - **Architecture Validation**: Ensures server supports required architecture
  - **Timeout Handling**: Respects custom build timeouts
  - **Cancellation**: Removes cancelled builds from the farm queue without server contact

### Update Build Status
- **Frequency**: Every 120 seconds for all active builds
- **Function**: Updates status for all active builds from their assigned servers
- **Features**:
  - **Concurrent Processing**: Uses asyncio for parallel status updates
  - **Error Isolation**: One server failure doesn't block updates for other servers
  - **Status Caching**: Caches responses for offline access
  - **Database Updates**: Maintains comprehensive build status in database
  - **Server Health Tracking**: Updates server health based on response patterns

### Discover Builds
- **Frequency**: Every 300 seconds across all configured servers
- **Function**: Discovers builds directly submitted to servers (bypassing farm)
- **Features**:
  - **Automatic Discovery**: Finds builds not submitted through farm
  - **Database Synchronization**: Adds discovered builds to farm database
  - **Historical Data**: Collects historical build data from servers
  - **Architecture Tracking**: Maintains accurate architecture information
  - **Orphan Detection**: Identifies builds without user attribution

### Handle Unavailable Servers
- **Frequency**: Every 120 seconds for health monitoring
- **Function**: Manages builds on servers that become unavailable
- **Features**:
  - **Availability Detection**: Identifies servers that have become unavailable
  - **Final Status Attempts**: Tries to get final status before marking as lost
  - **Automatic Failure**: Marks builds as failed after 30 minutes of server unavailability
  - **Recovery Detection**: Automatically detects when servers come back online
  - **Health State Management**: Updates server health states appropriately

### Cleanup Expired Tokens
- **Frequency**: Every 3600 seconds (1 hour)
- **Function**: Removes expired authentication tokens from database
- **Features**:
  - **Automatic Cleanup**: Removes tokens past their expiration time
  - **Performance Optimization**: Prevents token table from growing indefinitely
  - **Security Maintenance**: Ensures old tokens cannot be used
  - **Database Optimization**: Maintains optimal database performance

---

## Error Handling

The farm provides comprehensive error handling and fallback mechanisms:

### HTTP Status Codes
- **200 OK**: Request successful
- **400 Bad Request**: Invalid request data or malformed parameters
- **401 Unauthorized**: Authentication required or invalid token
- **403 Forbidden**: Insufficient permissions for requested action
- **404 Not Found**: Build not found on any server or resource not found
- **413 Payload Too Large**: Upload exceeds server or farm file size limits
- **503 Service Unavailable**:
  - No suitable server available for architecture
  - All servers for architecture are offline
  - Connection errors to servers
- **500 Internal Server Error**: Farm internal error

### Enhanced Error Response Format
```json
{
  "error": "Build not found",
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' not found on any server",
  "error_type": "build_not_found",
  "timestamp": "2024-01-20T10:00:00Z"
}
```

### Authentication Error Responses
```json
{
  "error": "Authentication required",
  "detail": "This endpoint requires authentication. Please provide a valid Bearer token."
}
```

```json
{
  "error": "Insufficient permissions",
  "detail": "Admin role required to perform this action"
}
```

### Fallback Mechanisms
- **Cached Responses**: Uses cached data when servers are temporarily unavailable
- **Automatic Retry**: Exponential backoff retry logic for server connections
- **Graceful Degradation**: Continues operation when some servers are unavailable
- **Health Recovery**: Automatically detects when servers come back online
- **Error Isolation**: Server failures don't affect other servers or farm operation

### Server Health Error Handling
- **Connection Timeouts**: 30-second timeout for server connections
- **HTTP Error Codes**: Special handling for 502 (server busy) vs other errors
- **Consecutive Failure Tracking**: Marks servers as degraded after 5 failures
- **Architecture Mismatch**: Handles servers reporting wrong architecture
- **Persistent Errors**: Marks servers as MISCONFIGURED for persistent issues

---

## Real-time Updates and Monitoring

The farm provides comprehensive real-time monitoring across all components:

### Enhanced Dashboard Updates
- **In-place refresh**: With JavaScript, the servers tab and unfinished build status pages reload only their status section; requests are sequential (never in parallel), paused while the browser tab is hidden, and back off after errors. Without JavaScript, build status pages use a meta refresh
- **Live Build Display**: Shows currently running builds per server with real-time updates
- **Server Health Indicators**: Visual indicators update in real-time
- **Queue Status**: Real-time queue information and server capacity
- **User Activity**: Real-time display of user submissions and activity

### Build Status Monitoring
- **Real-time Streaming**: Live build output streaming from servers
- **Status Propagation**: Immediate status updates from servers to farm database
- **Progress Tracking**: Real-time progress indicators for active builds
- **Completion Notifications**: Immediate notification when builds complete

### Server Health Monitoring
- **Continuous Monitoring**: Real-time server health and availability tracking
- **Health State Transitions**: Immediate updates when servers change health state
- **Performance Metrics**: Real-time monitoring of server load and capacity
- **Alert Generation**: Automatic alerts for server health issues

### Background Task Monitoring
- **Task Status**: Monitoring of all background task execution
- **Performance Metrics**: Execution time and success rate tracking
- **Error Tracking**: Comprehensive error logging and monitoring
- **Resource Usage**: Monitoring of background task resource consumption

---

## Configuration and Deployment

### Configuration File Locations
The farm searches for configuration files in this order:
1. `./apb.json` (current directory)
2. `/etc/apb/apb.json` (system-wide)
3. `~/.apb/apb.json` (user home)
4. `~/.apb-farm/apb.json` (farm-specific)

### Enhanced Configuration Schema
```json
{
  "servers": {
    "x86_64": [
      "http://server1.example.com:8000",
      "http://server2.example.com:8000"
    ],
    "powerpc": [
      "http://powerpc-server.example.com:8000"
    ],
    "powerpc64le": [
      "http://ppc64le-server.example.com:8000"
    ],
    "aarch64": [
      "http://arm-server.example.com:8000"
    ]
  }
}
```

SMTP settings are managed through the [SMTP configuration endpoints](#smtp-configuration-endpoints-admin-only) and stored in the farm database, not in `apb.json`. Artifact caching is configured under `cache` (see [Cache Configuration](#cache-configuration)).

### Command Line Options
- `--host`: Host address to bind to (default: 0.0.0.0)
- `--port`: Port to listen on (default: 8080)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--config`: Path to specific config file
- `--database`: Path to SQLite database file
- `--no-auth`: Disable authentication (development only)

### Environment Variables
- `APB_FARM_HOST`: Override host setting
- `APB_FARM_PORT`: Override port setting
- `APB_FARM_CONFIG`: Override config file path
- `APB_FARM_DATABASE`: Override database file path
- `APB_FARM_LOG_LEVEL`: Override log level

---

## Security Considerations

### Authentication Security
- **Token-based Authentication**: Secure Bearer token system with automatic expiration
- **Password Security**: PBKDF2 hashing with salt for password storage
- **Role-based Access Control**: Granular permissions based on user roles
- **Token Management**: Automatic cleanup of expired tokens
- **Session Security**: Secure token generation and validation
- **Web Sessions**: The web UI keeps its token in an `HttpOnly`, `SameSite=Lax` cookie that page scripts cannot read
- **CSRF Protection**: Cookie-authenticated non-GET requests require a CSRF token, since older browsers ignore `SameSite`
- **Output Escaping**: All HTML pages are rendered from autoescaped Jinja templates; user-controlled values (usernames, package names, build IDs, repository data) are never inserted as raw HTML or into inline JavaScript

### Server URL Obfuscation
- **URL Protection**: Server URLs are obfuscated in API responses for non-admin users
- **Format**: `{first_3_chars}---{last_char}` (e.g., `ser---1`)
- **Internal Network Protection**: Prevents exposure of internal server addresses
- **Admin Access**: Full URLs visible to admin users only

### Network Security
- **Proxy Architecture**: Farm acts as a secure proxy to individual servers
- **Centralized Access Control**: Single point for authentication and authorization
- **Internal Network Isolation**: Servers can be deployed on internal networks
- **HTTPS Support**: Can be deployed behind HTTPS reverse proxy

### Data Protection
- **Database Encryption**: Sensitive data encrypted before storage
- **Audit Logging**: Comprehensive logging of security-relevant events
- **Input Validation**: All inputs validated to prevent injection attacks
- **Error Information**: Error messages don't leak sensitive information

---

## Monitoring and Observability

### Comprehensive Logging
- **Structured Logging**: JSON-formatted logs with structured data
- **Security Logging**: Authentication, authorization, and security events
- **Performance Logging**: Request timing and performance metrics
- **Error Logging**: Detailed error information with stack traces
- **Audit Logging**: User actions and administrative changes

### Metrics and Analytics
- **Server Health Metrics**: Availability, response time, and error rates
- **Build Metrics**: Build distribution, success rates, and timing
- **User Activity**: Login patterns, build submissions, and usage statistics
- **Performance Metrics**: API response times and throughput
- **System Health**: Database performance and background task execution

### Health Monitoring
- **Endpoint Health**: Individual server health monitoring
- **Farm Health**: Overall farm health and status
- **Database Health**: Database connectivity and performance
- **Background Task Health**: Monitoring of all background processes
- **Resource Monitoring**: Memory, CPU, and disk usage tracking

### Alerting and Notifications
- **Email Notifications**: User management and system events
- **Health Alerts**: Automatic alerts for server health issues
- **Performance Alerts**: Notifications for performance degradation
- **Security Alerts**: Notifications for security-relevant events

---

## Migration and Compatibility

### Backward Compatibility

- **API Compatibility**: All existing endpoints remain functional
- **Guest Access**: Unauthenticated users can still view dashboard and public information
- **Client Compatibility**: Existing clients continue to work without modification
- **Configuration Compatibility**: Existing configuration files remain valid

### Migration Path

1. **Install Updated Farm**: Deploy new farm version with authentication system
2. **Database Migration**: Automatic database schema migration on first startup
3. **Default Admin Setup**: Use default admin account (admin/admin123) for initial setup
4. **User Account Creation**: Create user accounts for team members
5. **Client Migration**: Update client tools with authentication tokens
6. **Security Hardening**: Change default admin password, configure HTTPS

### Deployment Scenarios

#### Development Environment
```bash
# Simple development setup
apb-farm.py --host localhost --port 8080 --log-level DEBUG
```

#### Production Environment
```bash
# Production setup with authentication
apb-farm.py --host 0.0.0.0 --port 8080 --log-level INFO
# Configure nginx/apache for HTTPS termination
# Set up proper firewall rules
# Configure backup procedures for database
```

#### High Availability Setup
```bash
# Multiple farm instances with shared database
apb-farm.py --host 0.0.0.0 --port 8080 --database /shared/apb-farm.db
# Configure load balancer for multiple farm instances
# Set up database replication and backup
# Monitor all instances for health and performance
```

### Client Migration

#### Legacy Clients (No Authentication)
- Continue to work for read-only operations
- Build submission requires authentication

#### Updated Clients (With Authentication)
```bash
# Login to get token
TOKEN=$(curl -X POST http://farm:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"myuser","password":"mypass"}' | jq -r .token)

# Submit build with authentication
curl -X POST http://farm:8080/build \
  -H "Authorization: Bearer $TOKEN" \
  -F "pkgbuild=@PKGBUILD" \
  -F "sources=@source.tar.gz"
```

---

## Artifact Caching

The APB Farm includes a built-in caching system for improved download performance and reliability.

### Cache Features
- **Local Storage**: Built packages and build logs are cached locally on the farm
- **Configurable Retention**: Artifacts are kept for a configurable period (default: 30 days)
- **Automatic Cleanup**: Background task removes expired artifacts
- **Direct Serving**: Downloads are served directly from cache when available
- **Fallback Support**: Falls back to build servers if artifacts aren't cached

### Cache Configuration

Cache settings are configured in `apb.json`:

```json
{
  "cache": {
    "enabled": true,
    "retention_days": 30,
    "directory": "~/.apb/cache",
    "max_size_mb": 10240
  }
}
```

### Cache Management Endpoints

#### Get Cache Status
- **GET** `/admin/cache`
- **Authorization**: Bearer token (admin only)
- Returns cache statistics and configuration
- **Also available**: Through the admin web dashboard under "Admin Functions" tab

**Response:**
```json
{
  "enabled": true,
  "retention_days": 30,
  "directory": "/home/user/.apb/cache",
  "max_size_mb": 10240,
  "total_artifacts": 150,
  "total_size_bytes": 524288000,
  "total_size_mb": 500.0,
  "expired_artifacts": 5,
  "oldest_cache_timestamp": 1672531200.0,
  "oldest_cache_age_days": 15.5
}
```

#### Manual Cache Cleanup
- **POST** `/admin/cache/cleanup`
- **Authorization**: Bearer token (admin only)
- Manually triggers cache cleanup of expired artifacts
- **Also available**: Through the admin web dashboard under "Admin Functions" tab with one-click cleanup

**Response:**
```json
{
  "success": true,
  "artifacts_before": 150,
  "artifacts_after": 145,
  "artifacts_cleaned": 5,
  "message": "Cache cleanup completed. Removed 5 expired artifacts."
}
```

### Cache Behavior

1. **Build Completion**: When a build completes, the farm downloads all artifacts from the build server in the background (with retries)
2. **Status Polling**: Build status responses include `artifacts_ready` while caching is in progress
3. **Download Request**: When a client requests an artifact download from the farm
4. **Cache Hit**: If cached locally, the artifact is served directly from farm storage
5. **Cache Miss**: If not cached yet, the farm returns 404 and does not re-fetch from the build server; clients must wait for `artifacts_ready`
6. **Cache Storage**: Artifacts are stored in build-specific directories
7. **Automatic Cleanup**: Background task runs every 4 hours to remove expired artifacts

### Admin Dashboard Integration

The cache management features are fully integrated into the admin web dashboard:

- **Access**: Navigate to the admin panel and click the "Admin Functions" tab
- **Cache Status**: Real-time display of cache statistics, retention settings, and storage usage
- **Manual Cleanup**: One-click cache cleanup with live status updates
- **Authentication**: Requires admin login through the web interface
- **User-Friendly**: Visual status indicators and success/error messages

#### Proactive Caching

The farm automatically caches all build artifacts (packages and logs) immediately when a build completes successfully:

- **Triggered**: Automatically when build status changes to "completed" or "failed"
- **Background Process**: Caching runs asynchronously without blocking status updates
- **Retries**: Failed server downloads are retried with exponential backoff before giving up
- **All Artifacts**: Both packages (.pkg.tar.xz files) and build logs are cached
- **Error Handling**: Individual artifact caching failures don't affect other artifacts
- **Logging**: Comprehensive logging of caching operations for monitoring

### CDN and Proxy Caching

Build artifact downloads include appropriate headers for optimal caching and user experience:

- **Cache-Control**: `public, max-age=2592000, immutable` (30 days)
- **ETag**: `"{build_id}-{filename}"` for cache validation
- **Content-Disposition**: `attachment; filename={filename}` for proper downloads
- **Content-Length**: File size in bytes for download progress indication

These headers enable:
- **CDN Caching**: Content delivery networks can cache artifacts for 30 days
- **Proxy Caching**: Corporate proxies and ISP caches can store frequently accessed packages
- **Browser Caching**: End-user browsers cache downloads to avoid re-downloading
- **Immutable Content**: The `immutable` directive tells caches the content will never change
- **Download Progress**: Content-Length allows clients to show accurate download progress bars
