# APB Farm API Documentation

The APB Farm is a proxy service that manages multiple APB Servers, automatically distributing build requests to the most appropriate server based on architecture and load.

## Base URL
- Default: `http://localhost:8080`
- Configurable via `--host` and `--port` command line arguments

## Authentication
Currently, the APB Farm does not implement authentication. All endpoints are publicly accessible.

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

**Response:**
```json
{
  "status": "running",
  "version": "2025-07-15",
  "servers": [
    {
      "url": "ser---1",
      "arch": "x86_64",
      "status": "online",
      "info": {
        "version": "2025-07-15",
        "supported_architecture": "x86_64",
        "queue_status": {
          "current_builds_count": 1,
          "queued_builds": 2,
          "max_concurrent_builds": 3
        },
        "current_build": {
          "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
          "pkgname": "example-package",
          "status": "building"
        }
      }
    },
    {
      "url": "ser---2",
      "arch": "x86_64",
      "status": "offline",
      "info": null
    }
  ],
  "available_architectures": ["x86_64", "powerpc64le"],
  "total_servers": 2
}
```

#### GET /health
Health check endpoint for the farm.

**Response:**
```json
{
  "status": "healthy",
  "version": "2025-07-15"
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
Submit a build request to the farm, which will automatically select the best server.

**Request:**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `pkgbuild` (file, required): The PKGBUILD file
  - `sources` (file[], optional): Additional source files
  - `architectures` (string, optional): Comma-separated list of target architectures to filter

**Multi-Architecture Processing:**
1. Parse PKGBUILD to determine required architecture(s)
2. Check available server architectures
3. Create separate builds for each available architecture
4. Generate unique build IDs for each architecture-specific build
5. Queue builds with submission group tracking

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "status": "queued",
  "message": "Queued 2 build(s) for processing",
  "pkgname": "example-package",
  "target_architectures": ["x86_64", "powerpc64le"],
  "pkgbuild_architectures": ["x86_64", "powerpc64le", "aarch64"],
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "arch": "x86_64",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0
    },
    {
      "build_id": "7b2c8f1e-9d4a-4567-8901-2345678abcde",
      "arch": "powerpc64le",
      "status": "queued",
      "pkgname": "example-package",
      "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
      "created_at": 1642694400.0
    }
  ],
  "submission_group": "25733701-5546-41bc-957d-d76bbaa09f15",
  "queue_status": {
    "queue_size": 3,
    "builds_queued": 2
  },
  "created_at": 1642694400.0
}
```

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
