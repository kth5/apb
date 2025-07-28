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

### User Roles

#### Guest (Unauthenticated Users)
- View dashboard and farm status
- View public build information (with obfuscated server URLs)
- No build submission capabilities

#### User (Regular Users)
- All guest permissions
- Submit builds to the farm
- Cancel own builds
- View own build history via `/my/builds`
- Access authenticated endpoints

#### Admin (Administrators)
- All user permissions
- Cancel any user's builds
- View unobfuscated server URLs
- Complete user management (create, delete, change roles)
- Access to user build histories
- Revoke user tokens

### Authentication Flow

1. **Registration**: Admins create user accounts with username/password
2. **Login**: Users authenticate with credentials to receive token
3. **Token Usage**: Include token in `Authorization: Bearer <token>` header
4. **Auto-renewal**: Tokens automatically renewed on use (10-day expiration)
5. **Logout**: Explicitly revoke tokens when done

### Default Admin Account

On first startup, the farm creates a default admin account:
- **Username**: `admin`
- **Password**: `admin123`
- **⚠️ SECURITY WARNING**: Change this password immediately after first login!

### Token Security

- **Expiration**: 10-day expiration with automatic renewal on use
- **Secure Hashing**: SHA-256 hashing for token storage
- **Background Cleanup**: Expired tokens automatically removed every hour
- **Revocation**: Individual token or all user tokens can be revoked

## Content Types
- **Request**: `multipart/form-data` for file uploads, `application/json` for JSON requests
- **Response**: `application/json` for API endpoints, `text/html` for web pages

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
    "riscv64": [
      "http://riscv-server1.example.com:8000"
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
- Servers are marked as SEVERELY DEGRADED after 15 consecutive failures
- HTTP 502 errors are treated specially as they often indicate busy servers
- Architecture mismatches between configuration and server reports are tracked
- Cached server information is used during temporary outages

### Server Status Tracking

Each server maintains:
- Last successful contact timestamp
- Last failed contact timestamp
- Consecutive failure count
- Last known architecture
- Cached response data for fallback during outages

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
  "version": "2025-07-16",
  "servers": [
    {
      "url": "http://server1.example.com:8000",
      "arch": "x86_64",
      "status": "online",
      "info": {
        "version": "2025-07-16",
        "supported_architecture": "x86_64",
        "queue_status": {
          "current_builds_count": 1,
          "queued_builds": 2,
          "max_concurrent_builds": 3
        }
      }
    }
  ],
  "available_architectures": ["x86_64", "powerpc64le"],
  "total_servers": 2,
  "authenticated": true,
  "user_role": "user"
}
```

**Authentication Impact:**
- **Guest**: Server URLs are obfuscated (e.g., `ser---1`)
- **User/Admin**: Different levels of server information visibility
- **Admin**: Full server URLs and detailed information

#### GET /health
Health check endpoint for the farm.

**Response:**
```json
{
  "status": "healthy",
  "version": "2025-07-16"
}
```

#### GET /dashboard
Get the farm dashboard (HTML page) showing all servers, their current builds, and recent build history.

**Parameters:**
- `page` (integer, optional): Page number for build history pagination (default: 1)

**Response:** HTML page with:
- **Server Status by Architecture**: Shows each server grouped by architecture
- **Currently Running Builds**: Displays up to 3 currently building packages per server with:
  - Package name (clickable link to build details)
  - Build start time
  - "... and X more" indicator if more than 3 builds are running
- **Server Health Information**: Visual indicators for server status (online/offline/misconfigured)
- **Queue Information**: Current and queued build counts per server
- **Recent Build History**: Paginated list of recent builds across all servers
- **Auto-refresh**: Page refreshes every 10 seconds for real-time updates

**Dashboard Features:**
- **Real-time Status**: Shows live server health and build activity
- **Build Monitoring**: Direct links to build status pages for active builds
- **Architecture Grouping**: Servers organized by their actual supported architecture
- **Degraded Server Handling**: Special display for servers with health issues
- **Responsive Design**: Mobile-friendly layout with proper styling

**CSS Styling includes:**
- Color-coded server status (green=online, red=offline, yellow=misconfigured)
- Styled running builds section with blue accent border
- Responsive build history with status-based color coding
- Pagination controls for build history navigation

---

### Build Management

#### POST /build
Submit a build request to the farm (Authentication Required).

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Request:**
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
  "target_architectures": ["x86_64", "powerpc64le"],
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "arch": "x86_64",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0
    }
  ],
  "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
  "user_id": 2,
  "created_at": 1642694400.0
}
```

**Authentication Changes:**
- **Required**: All build submissions require authentication
- **User Tracking**: Builds are associated with the submitting user
- **Permission Checking**: Users can only cancel their own builds (admins can cancel any)

**Error Responses:**
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions

**Architecture Filtering:**
If `architectures` parameter is provided, only those architectures will be built (if they exist in the PKGBUILD and have available servers).

**Queue-based Processing:**
1. Builds are queued immediately and processed by background tasks
2. Background process redistributes queued builds to available servers
3. Builds are assigned to servers based on availability and architecture compatibility
4. Farm passes its build ID to the server, ensuring consistent tracking
5. Retry logic with exponential backoff for failed submissions

**Error Responses:**
- **503 Service Unavailable**: No suitable server available
- **400 Bad Request**: Invalid PKGBUILD file
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

**Enhanced Error Handling:**
- **Server Unavailable**: If the assigned server is unavailable, returns cached status with warning
- **Build Not Found**: If build was never submitted through farm, provides detailed error message
- **Submission Failed**: If build failed during submission before server assignment

**Response (HTML):**
Forwards to the appropriate server's build status page, or displays cached information with server availability warnings.

**Response (JSON):**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": 1642694400.0,
  "end_time": 1642694500.0,
  "duration": 100.0,
  "server_url": "ser---1",
  "server_arch": "x86_64",
  "packages": [...],
  "logs": [...],
  "server_unavailable": false,
  "last_status_update": 1642694500.0
}
```

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
Get build status as JSON (alias for `/build/{build_id}/status?format=json`).

**Parameters:**
- `build_id` (string, required): The build ID

**Response:** Same as `/build/{build_id}/status` with `format=json`.

#### POST /build/{build_id}/cancel
Cancel a build with permission checking.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Parameters:**
- `build_id` (string, required): Build ID

**Response:**
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

**Permission Rules:**
- **Users**: Can cancel only their own builds
- **Admins**: Can cancel any user's builds

**Error Responses:**
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Not authorized to cancel this build

#### GET /build/{build_id}/output
Get build output/logs by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `start_index` (integer, optional): Starting line index (default: 0)
- `limit` (integer, optional): Maximum number of lines (default: 50)

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
  "returned_lines": 50
}
```

#### GET /build/{build_id}/stream
Stream build output in real-time by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID

**Response:**
- **Content-Type:** `text/event-stream`
- Forwards Server-Sent Events from the target server
- Handles server unavailability with appropriate error responses

---

### File Downloads

#### GET /build/{build_id}/download/{filename}
Download a build artifact by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `filename` (string, required): The filename to download

**Response:** Binary file content with appropriate headers.

**Error Handling:**
- Automatically retries up to 3 times on connection errors
- Handles server unavailability with detailed error messages
- Returns 404 if file not found on any server
- Returns 503 if connection to servers fails

---

### Build History

#### GET /builds/latest
Get the latest builds across all managed servers.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 20, max: 100)
- `status` (string, optional): Filter by status

**Response:**
```json
{
  "builds": [
    {
      "id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "server_url": "ser---1",
      "server_arch": "x86_64",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20 10:00:00 UTC",
      "end_time": "2024-01-20 10:05:00 UTC",
      "created_at": "2024-01-20 10:00:00 UTC"
    }
  ]
}
```

#### GET /my/builds
Get builds submitted by the current authenticated user.

**Request Headers:**
- `Authorization: Bearer <token>` (required)

**Parameters:**
- `limit` (integer, optional): Maximum builds to return (default: 50, max: 200)

**Response:**
```json
{
  "builds": [
    {
      "id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "server_url": "ser---1",
      "server_arch": "x86_64",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": 1642694400.0,
      "end_time": 1642694500.0,
      "created_at": 1642694400.0
    }
  ]
}
```

**Note:** Server URLs are obfuscated for regular users in this endpoint.

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
    "last_login": 1642694400.0
  },
  "expires_in_days": 10
}
```

**Error Responses:**
- **401 Unauthorized**: Invalid username or password

**Usage Example:**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "myuser", "password": "mypassword"}'
```

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

**Note:** This revokes only the current token. User can have multiple active tokens from different sessions.

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
  "last_login": 1642694400.0
}
```

**Error Responses:**
- **401 Unauthorized**: Invalid or expired token

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
    "last_login": 1642694400.0
  },
  {
    "id": 2,
    "username": "user1",
    "role": "user",
    "created_at": 1642694500.0,
    "last_login": 1642694600.0
  }
]
```

**Error Responses:**
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Admin access required

### POST /auth/users
Create a new user account.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Request:**
```json
{
  "username": "newuser",
  "password": "securepassword123",
  "role": "user"
}
```

**Response:**
```json
{
  "id": 3,
  "username": "newuser",
  "role": "user",
  "created_at": 1642694700.0,
  "last_login": null
}
```

**Validation Rules:**
- Username: 3-50 characters, unique
- Password: 8-100 characters minimum
- Role: "user" or "admin"

**Error Responses:**
- **400 Bad Request**: Invalid username, password, or role
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Admin access required

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

**Error Responses:**
- **400 Bad Request**: Cannot delete yourself
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Admin access required
- **404 Not Found**: User not found

**Note:** This performs a soft delete (marks user as inactive) and revokes all user tokens.

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

**Error Responses:**
- **400 Bad Request**: Invalid role
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Admin access required
- **404 Not Found**: User not found

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

### GET /auth/users/{user_id}/builds
Get build history for a specific user.

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Parameters:**
- `user_id` (integer): User ID
- `limit` (integer, optional): Maximum builds to return (default: 50)

**Response:**
```json
{
  "builds": [
    {
      "id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "server_url": "http://server1.example.com:8000",
      "server_arch": "x86_64",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": 1642694400.0,
      "end_time": 1642694500.0,
      "created_at": 1642694400.0
    }
  ]
}
```



#### GET /build/{build_id}/status
Get build status. Returns HTML page by default, JSON if `format=json` is specified.

**Parameters:**
- `build_id` (string, required): The build ID
- `format` (string, optional): Response format (`json` or `html`)

**Enhanced Error Handling:**
- **Server Unavailable**: If the assigned server is unavailable, returns cached status with warning
- **Build Not Found**: If build was never submitted through farm, provides detailed error message
- **Submission Failed**: If build failed during submission before server assignment

**Response (HTML):**
Forwards to the appropriate server's build status page, or displays cached information with server availability warnings.

**Response (JSON):**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": 1642694400.0,
  "end_time": 1642694500.0,
  "duration": 100.0,
  "server_url": "ser---1",
  "server_arch": "x86_64",
  "packages": [...],
  "logs": [...],
  "server_unavailable": false,
  "last_status_update": 1642694500.0
}
```

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
Get build status as JSON (alias for `/build/{build_id}/status?format=json`).

**Parameters:**
- `build_id` (string, required): The build ID

**Response:** Same as `/build/{build_id}/status` with `format=json`.

#### POST /build/{build_id}/cancel
Cancel a build by forwarding the request to the appropriate server.

**Parameters:**
- `build_id` (string, required): The build ID

**Response:**
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

**Enhanced Error Handling:**
- Handles server unavailability gracefully
- Updates local database when cancellation succeeds
- Provides detailed error messages for troubleshooting

#### GET /build/{build_id}/output
Get build output/logs by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `start_index` (integer, optional): Starting line index (default: 0)
- `limit` (integer, optional): Maximum number of lines (default: 50)

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
  "returned_lines": 50
}
```

#### GET /build/{build_id}/stream
Stream build output in real-time by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID

**Response:**
- **Content-Type:** `text/event-stream`
- Forwards Server-Sent Events from the target server
- Handles server unavailability with appropriate error responses

---

### File Downloads

#### GET /build/{build_id}/download/{filename}
Download a build artifact by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `filename` (string, required): The filename to download

**Response:** Binary file content with appropriate headers.

**Error Handling:**
- Automatically retries up to 3 times on connection errors
- Handles server unavailability with detailed error messages
- Returns 404 if file not found on any server
- Returns 503 if connection to servers fails

---

### Build History

#### GET /builds/latest
Get the latest builds across all managed servers.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 20, max: 100)
- `status` (string, optional): Filter by status

**Response:**
```json
{
  "builds": [
    {
      "id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "server_url": "ser---1",
      "server_arch": "x86_64",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20 10:00:00 UTC",
      "end_time": "2024-01-20 10:05:00 UTC",
      "created_at": "2024-01-20 10:00:00 UTC"
    }
  ]
}
```

---

## Build Database Schema

The farm maintains a SQLite database with comprehensive build tracking:

### Builds Table Schema
```sql
CREATE TABLE builds (
    id TEXT PRIMARY KEY,                -- Build UUID
    server_url TEXT,                   -- Assigned server URL
    server_arch TEXT,                  -- Target architecture
    pkgname TEXT,                      -- Package name
    status TEXT,                       -- Current build status
    start_time REAL,                   -- Build start timestamp
    end_time REAL,                     -- Build completion timestamp
    created_at REAL,                   -- Submission timestamp
    queue_position INTEGER,            -- Position in queue when submitted
    submission_group TEXT,             -- Group ID for related builds
    last_known_status TEXT,            -- Last known status from server
    last_status_update REAL,           -- Last status check timestamp
    server_available BOOLEAN DEFAULT 1, -- Server availability flag
    cached_response TEXT               -- Cached server response (JSON)
);
```

### Database Features
- **Build Tracking**: Complete history of all builds across all servers
- **Server Availability**: Tracks which servers are currently available
- **Status Caching**: Caches server responses for offline access
- **Submission Grouping**: Links related builds from same PKGBUILD submission
- **Queue Management**: Tracks build queue positions and timing

---

## Authentication Database Schema

The farm authentication system uses the following database tables:

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,           -- PBKDF2-hashed password
    role TEXT NOT NULL DEFAULT 'user',     -- 'user' or 'admin'
    created_at REAL NOT NULL,              -- Unix timestamp
    last_login REAL,                       -- Unix timestamp
    is_active BOOLEAN DEFAULT 1            -- Soft delete flag
);
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
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Enhanced Builds Table
The existing builds table has been extended with user tracking:
```sql
ALTER TABLE builds ADD COLUMN user_id INTEGER;  -- Links builds to users
CREATE INDEX idx_builds_user ON builds(user_id);
```

### Security Features

- **Password Security**: PBKDF2 with 100,000 iterations and random salt
- **Token Security**: SHA-256 hashing for storage, secure random generation
- **Database Indexes**: Optimized for authentication performance
- **Automatic Cleanup**: Background task removes expired tokens every hour

---

## Background Tasks

The farm runs several background tasks for maintaining system health:

### Process Build Queue
- **Frequency**: Continuous with 5-second intervals
- **Function**: Processes queued builds and assigns them to available servers
- **Features**:
  - Exponential backoff retry logic
  - Server availability checking
  - Load balancing across servers
  - Architecture compatibility validation

### Update Build Status
- **Frequency**: Every 120 seconds
- **Function**: Updates status for all active builds
- **Features**:
  - Concurrent status checking for performance
  - Error isolation to prevent one failure from blocking others
  - Database updates with comprehensive status information

### Discover Builds
- **Frequency**: Every 300 seconds
- **Function**: Discovers builds directly submitted to servers
- **Features**:
  - Automatic discovery of builds not submitted through farm
  - Database synchronization with server build lists
  - Historical build data collection

### Handle Unavailable Servers
- **Frequency**: Every 120 seconds
- **Function**: Manages builds on servers that become unavailable
- **Features**:
  - Detects builds on unavailable servers
  - Attempts final status updates before marking as lost
  - Automatically fails builds on servers unavailable for >30 minutes

---

## Error Handling

The farm provides robust error handling and fallback mechanisms:

### HTTP Status Codes
- **200 OK**: Request successful
- **404 Not Found**: Build not found on any server
- **503 Service Unavailable**:
  - No suitable server available for architecture
  - All servers for architecture are offline
  - Connection errors to servers
- **500 Internal Server Error**: Farm internal error

### Error Response Format
```json
{
  "error": "Build not found",
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' not found on any server"
}
```

### Fallback Mechanisms
- **Cached Responses**: Uses cached data when servers are temporarily unavailable
- **Automatic Retry**: Exponential backoff for server connections
- **Graceful Degradation**: Continues operation when some servers are unavailable
- **Health Recovery**: Automatically detects when servers come back online

### Server Unavailability Handling
- **Temporary Outages**: Uses cached status information
- **Extended Outages**: Marks builds as failed after 30 minutes
- **Partial Failures**: Continues serving available servers while others recover
- **Error Isolation**: Server failures don't affect other servers or farm operation

---

## Real-time Updates

The farm provides real-time monitoring of builds across all servers:

### Background Tasks
- **Server Status Refresh**: Every 90 seconds with enhanced caching
- **Build Status Updates**: Every 120 seconds with concurrent processing
- **Build Discovery**: Every 300 seconds across all servers
- **Server Health Monitoring**: Continuous with failure tracking

### Dashboard Updates
- **Auto-refresh**: Every 10 seconds when viewing active builds
- **Live Build Display**: Shows currently running builds per server
- **Real-time Status**: Updates build and server status indicators
- **Health Indicators**: Visual feedback for server health states

---

## Configuration

### Configuration File Locations
The farm searches for configuration files in this order:
1. `./apb.json` (current directory)
2. `/etc/apb/apb.json` (system-wide)
3. `~/.apb/apb.json` (user home)
4. `~/.apb-farm/apb.json` (farm-specific)

### Configuration Schema
```json
{
  "servers": {
    "architecture_name": [
      "http://server1:port",
      "http://server2:port"
    ]
  }
}
```

### Command Line Options
- `--host`: Host address to bind to (default: 0.0.0.0)
- `--port`: Port to listen on (default: 8080)
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--config`: Path to specific config file

---

## Security Considerations

### Server URL Obfuscation
- Server URLs are obfuscated in API responses
- Format: `{first_3_chars}---{last_char}` (e.g., `ser---1`)
- Prevents exposure of internal server addresses

### Access Control
- No authentication currently implemented
- All endpoints are publicly accessible
- Consider implementing authentication for production deployments

### Network Security
- Farm acts as a proxy, hiding individual server addresses
- Centralizes access control point
- Can be placed behind reverse proxy for additional security

---

## Monitoring and Observability

### Logging
- Comprehensive logging with configurable levels
- Separate log files for different components
- Request/response logging for debugging
- Enhanced server health tracking logs

### Metrics
- Server availability tracking with health states
- Build distribution across servers
- Performance metrics for server selection
- Queue processing performance monitoring

### Health Checks
- Individual server health monitoring with failure tracking
- Farm-level health status
- Automatic server discovery and recovery
- Enhanced error reporting and diagnostics

---

## Migration and Compatibility

### Backward Compatibility

- **Existing Endpoints**: All existing endpoints remain functional
- **Guest Access**: Unauthenticated users can still view dashboard and public information
- **API Compatibility**: No breaking changes to existing API contracts

### Migration Path

1. **Install Updated Farm**: Deploy new farm version with authentication
2. **Default Admin**: Use default admin account (admin/admin123) for initial setup
3. **Create Users**: Create user accounts for team members
4. **Update Clients**: Update client configurations with authentication
5. **Security Hardening**: Change default admin password, configure HTTPS

### Environment-Specific Deployment

#### Development
```bash
# Use default settings with HTTP
apb-farm.py --host localhost --port 8080
```

#### Production
```bash
# Use HTTPS reverse proxy, secure settings
apb-farm.py --host 0.0.0.0 --port 8080
# Configure nginx/apache for HTTPS termination
```
