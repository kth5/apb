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

### Authentication Flow

1. **Registration**: Admins create user accounts with username/password/email
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
  "version": "2025-07-16",
  "servers": [
    {
      "url": "http://server1.example.com:8000",
      "arch": "x86_64",
      "status": "online",
      "health": "healthy",
      "info": {
        "version": "2025-07-16",
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
  "version": "2025-07-16"
}
```

#### GET /dashboard
Get the comprehensive farm dashboard (HTML page) showing all servers, their current builds, and recent build history.

**Parameters:**
- `page` (integer, optional): Page number for build history pagination (default: 1)

**Response:** Enhanced HTML page with:

**Server Status by Architecture**:
- Servers grouped by their actual supported architecture
- Real-time health indicators (green=online, red=offline, yellow=misconfigured)
- Current and queued build counts per server
- Server version information and uptime

**Currently Running Builds**:
- Displays up to 3 currently building packages per server with:
  - Package name (clickable link to build details)
  - Build start time and duration
  - User who submitted the build (for authenticated users)
  - "... and X more" indicator if more than 3 builds are running

**Enhanced Build Monitoring**:
- **Buildroot Recreation Tracking**: Special indicators for builds performing buildroot recreation
- **Build Timeout Information**: Shows custom timeout configurations
- **Architecture-specific Information**: Build architecture clearly displayed
- **User Attribution**: Shows which user submitted each build (with appropriate permissions)

**Recent Build History**:
- Paginated list of recent builds across all servers (20 per page)
- Status-based color coding (green=completed, red=failed, blue=building, gray=cancelled)
- Build timing information and duration
- Package names with direct links to build details
- User information (for authenticated users)

**Advanced Dashboard Features**:
- **Auto-refresh**: Page refreshes every 10 seconds for real-time updates
- **Responsive Design**: Mobile-friendly layout with proper CSS styling
- **Permission-based Display**: Different information levels based on user role
- **Server Health Details**: Extended server information including system stats
- **Queue Status**: Real-time queue information and build distribution

**CSS Styling includes:**
- Modern card-based layout for server information
- Color-coded build status indicators
- Responsive grid layout for different screen sizes
- Interactive elements with hover effects
- Status badges for server health and build states

#### GET /admin
Get the comprehensive admin panel (Admin Only).

**Request Headers:**
- `Authorization: Bearer <admin_token>` (required)

**Response:** Full-featured HTML admin panel with:

**User Management Section**:
- List all users with roles, creation dates, and last login
- Create new users with username, password, role, and email
- Delete users (with confirmation dialogs)
- Change user roles between 'user' and 'admin'
- Revoke user tokens for security purposes
- View user build histories

**SMTP Configuration Section**:
- Configure email server settings (server, port, authentication)
- Test email configuration with test messages
- View current SMTP configuration (passwords hidden)
- Enable/disable TLS encryption
- Set custom from address and display name

**Server Management Section**:
- View detailed server information including health status
- Monitor server performance and resource usage
- View server-specific build statistics
- Access server logs and diagnostic information

**System Statistics**:
- Overall farm statistics and performance metrics
- Build distribution across servers and architectures
- User activity and build submission patterns
- System health monitoring and alerts

**Admin Panel Features**:
- **Role-based Security**: Only accessible to admin users
- **Real-time Updates**: Dynamic content updates without page refresh
- **Input Validation**: Comprehensive form validation with error messages
- **Confirmation Dialogs**: Safety confirmations for destructive actions
- **Mobile Responsive**: Optimized for mobile and tablet access

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
      "user_id": 2
    },
    {
      "build_id": "7f2a8e9b-1234-5678-9abc-def012345678",
      "arch": "powerpc",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0,
      "user_id": 2
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

**Build Timeout Configuration:**
- **Default**: 7200 seconds (2 hours)
- **Range**: 300-14400 seconds (5 minutes to 4 hours)
- **Admin Only**: Only admin users can specify custom timeouts
- **Per-Build**: Each build can have a custom timeout

**Enhanced Processing:**
- **Queue-based**: Builds are queued immediately and processed by background tasks
- **Background Processing**: Background process redistributes queued builds to available servers
- **Server Assignment**: Builds assigned to servers based on availability and architecture compatibility
- **Consistent Tracking**: Farm passes its build ID to the server, ensuring consistent tracking
- **Retry Logic**: Exponential backoff retry logic for failed submissions

**Architecture Filtering:**
If `architectures` parameter is provided, only those architectures will be built (if they exist in the PKGBUILD and have available servers).

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

**Enhanced HTML Response:**
Returns a comprehensive build status page with:
- **Real-time Status**: Live updates of build progress
- **Build Metadata**: Package name, architecture, submission time, user info
- **Server Information**: Assigned server details and health status
- **Live Output Streaming**: Real-time build output with auto-scroll
- **Action Buttons**: Cancel build (if permitted), download artifacts
- **Progress Indicators**: Build phase tracking and timing information
- **Error Handling**: Graceful display of server unavailability

**Enhanced JSON Response:**
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
  "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
  "user_id": 2,
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
  "server_unavailable": false,
  "last_status_update": 1642694500.0
}
```

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
Get build status as JSON (alias for `/build/{build_id}/status?format=json`).

**Parameters:**
- `build_id` (string, required): The build ID

**Response:** Same as `/build/{build_id}/status` with `format=json`.

#### POST /build/{build_id}/cancel
Cancel a build with comprehensive permission checking.

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
Download a build artifact by forwarding to the appropriate server.

**Parameters:**
- `build_id` (string, required): Build UUID
- `filename` (string, required): The filename to download

**Response:** Binary file content with appropriate headers.

**Enhanced Error Handling:**
- **Automatic Retry**: Up to 3 retry attempts on connection errors
- **Server Discovery**: Attempts to find build on alternative servers if needed
- **Cache Headers**: Proper caching headers for static content
- **Range Support**: Passes through range requests for large files
- **Permission Checking**: Respects build visibility permissions

**Error Responses:**
- **404 Not Found**: File not found on any server
- **503 Service Unavailable**: All servers unavailable
- **403 Forbidden**: Insufficient permissions to access build

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
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
      "created_at": "2024-01-20T10:00:00Z",
      "user_id": 2,
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15"
    }
  ],
  "total": 1
}
```

**Enhanced Features:**
- **Multi-server Aggregation**: Combines builds from all servers
- **User Context**: Shows user information where appropriate
- **Submission Grouping**: Groups related builds from same submission
- **Status Filtering**: Filter by build status (queued, building, completed, failed, cancelled)

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
      "created_at": 1642694400.0,
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "build_timeout": 7200
    }
  ],
  "total": 1,
  "user_id": 2
}
```

**User-specific Features:**
- **Personal History**: Shows only builds submitted by the authenticated user
- **Full Permissions**: User can access all details of their own builds
- **Submission Groups**: Groups builds from same PKGBUILD submission
- **Extended Information**: Includes build timeout and detailed timing

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
    "email": "user@example.com"
  },
  "expires_in_days": 10
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
  "email": "user@example.com"
}
```

**Enhanced Features:**
- **Complete Profile**: Full user profile information
- **Role Information**: Current user role and permissions
- **Email Address**: User's email address if configured

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
- `limit` (integer, optional): Maximum builds to return (default: 50)

**Response:**
```json
{
  "user_id": 2,
  "username": "user1",
  "builds": [
    {
      "id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "server_url": "http://server1.example.com:8000",
      "server_arch": "x86_64",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": 1642694400.0,
      "end_time": 1642694500.0,
      "created_at": 1642694400.0,
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15"
    }
  ],
  "total": 1
}
```

**Admin Features:**
- **Full Access**: Admins see unobfuscated server URLs
- **Complete History**: Access to all user builds regardless of status
- **User Context**: Includes username and user information
- **Detailed Information**: Full build metadata and timing

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
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Indexes for performance
CREATE INDEX idx_tokens_hash ON tokens(token_hash);
CREATE INDEX idx_tokens_user ON tokens(user_id);
CREATE INDEX idx_tokens_expires ON tokens(expires_at);
CREATE INDEX idx_tokens_active ON tokens(is_active);
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
- **Email Encryption**: SMTP passwords encrypted before database storage
- **Database Indexes**: Optimized for authentication and query performance
- **Automatic Cleanup**: Background task removes expired tokens every hour
- **Foreign Key Constraints**: Maintains data integrity between users and tokens

---

## Background Tasks

The farm runs several sophisticated background tasks for maintaining system health:

### Process Build Queue
- **Frequency**: Continuous with 5-second intervals when builds are queued
- **Function**: Processes queued builds and assigns them to available servers
- **Features**:
  - **Exponential Backoff**: Retry logic with increasing delays for failed submissions
  - **Server Health**: Checks server availability and health before assignment
  - **Load Balancing**: Distributes builds across available servers
  - **Architecture Validation**: Ensures server supports required architecture
  - **Timeout Handling**: Respects custom build timeouts
  - **Error Recovery**: Handles server failures gracefully

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
- **Auto-refresh**: Every 10 seconds for active build monitoring
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
  },
  "database": {
    "path": "./apb-farm.db",
    "backup_interval": 3600
  },
  "security": {
    "token_expiry_days": 10,
    "max_login_attempts": 5,
    "require_email": false
  },
  "notifications": {
    "smtp_enabled": true,
    "admin_notifications": true
  }
}
```

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
