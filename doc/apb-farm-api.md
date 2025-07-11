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

---

## Endpoints

### Farm Information

#### GET /farm
Get farm information and status of all managed servers.

**Response:**
```json
{
  "status": "running",
  "version": "2025-07-11",
  "servers": [
    {
      "url": "ser---1",
      "arch": "x86_64",
      "status": "online",
      "info": {
        "version": "2025-07-11",
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
  "version": "2025-07-11"
}
```

#### GET /dashboard
Get the farm dashboard (HTML page) showing all servers and recent builds.

**Parameters:**
- `page` (integer, optional): Page number for build history pagination (default: 1)

**Response:** HTML page with:
- Server status grouped by architecture
- Recent builds across all servers
- Pagination controls

---

### Build Management

#### POST /build
Submit a build request to the farm, which will automatically select the best server.

**Request:**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `pkgbuild` (file, required): The PKGBUILD file
  - `sources` (file[], optional): Additional source files

**Queue-based Processing:**
1. Parse PKGBUILD to determine required architecture(s)
2. Generate unique UUID build ID and queue the build
3. Background process redistributes queued builds to available servers
4. Builds are assigned to servers based on availability and architecture compatibility
5. Farm passes its build ID to the server, ensuring consistent tracking across the system

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "status": "queued",
  "message": "Build has been queued for processing",
  "pkgname": "example-package",
  "target_architectures": ["x86_64"],
  "queue_status": {
    "queue_size": 3,
    "position": 3
  },
  "created_at": 1642694400.0
}
```

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

**Response (HTML):** 
Forwards to the appropriate server's build status page.

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
  "logs": [...]
}
```

**Note:** Server URLs are obfuscated in responses for security (e.g., `server1.example.com` → `ser---1`).

#### GET /build/{build_id}/status-api
Get build status as JSON (alias for `/build/{build_id}/status?format=json`).

**Parameters:**
- `build_id` (string, required): The build ID

**Response:** Same as `/build/{build_id}/status` with `format=json`.

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
- Returns 404 if file not found on any server
- Returns 503 if connection to servers fails

---

### Build History

#### GET /builds/latest
Get the latest builds across all managed servers.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 20)
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

### Server Discovery

The farm automatically discovers and tracks builds from all configured servers. It maintains a local database of build history and continuously monitors server status.

**Server Information Caching:**
- Server information is cached for 60 seconds
- Background tasks refresh server status every 60 seconds
- Build status is checked every 120 seconds

**Build Discovery:**
- Periodically discovers new builds from all servers
- Maintains a local database of all builds
- Tracks build status changes automatically

---

## Build ID Management

The APB Farm implements a unified build ID system to ensure consistent tracking across the entire system:

### Build ID Generation
- **Farm Build ID**: Generated as a UUID (e.g., `25733701-5546-41bc-957d-d76bbaa09f15`)
- **Server Build ID**: Previously generated by servers, now uses the same ID as the farm
- **Database Tracking**: Farm maintains mapping between farm and server build IDs for backwards compatibility

### Build ID Consistency
- When the farm forwards a build to a server, it provides its build ID
- The server uses the farm's build ID instead of generating its own
- This ensures that clients can use the same build ID for all operations:
  - Status checking
  - Build cancellation
  - File downloads
  - Output streaming

### Legacy Build Support
- Builds created before the ID unification are still supported
- Legacy builds where farm and server IDs differ are handled automatically
- The system maintains backward compatibility with existing builds

### Example Build ID Flow
```
1. Client submits build to farm
2. Farm generates UUID: 25733701-5546-41bc-957d-d76bbaa09f15
3. Farm queues build with this ID
4. Farm forwards build to server with build_id parameter
5. Server uses farm's ID instead of generating own
6. Client can use 25733701-5546-41bc-957d-d76bbaa09f15 for:
   - Status checking: GET /build/25733701-5546-41bc-957d-d76bbaa09f15/status
   - Cancellation: POST /build/25733701-5546-41bc-957d-d76bbaa09f15/cancel
   - Downloads: GET /build/25733701-5546-41bc-957d-d76bbaa09f15/download/file.pkg.tar.xz
```

## Architecture-Specific Routing

The farm uses a queue-based system to intelligently distribute builds based on the PKGBUILD architecture field:

### Architecture Types
- **`any`**: Can be built on any architecture - queued for assignment to any available server
- **Specific architecture** (e.g., `x86_64`, `aarch64`): Queued for assignment to servers of that architecture
- **Multiple architectures**: Queued for assignment to servers supporting any of the specified architectures

### Server Assignment Priority (Background Process)
1. **Available servers**: Servers that report as available for new builds
2. **Idle servers**: No current builds and empty queue
3. **Lowest load**: Server with minimal current builds + queued builds
4. **Online status**: Only online servers are considered

### Queue Management
- Builds are processed in FIFO order
- Failed assignments are retried up to 3 times with 30-second delays
- Queue status is continuously monitored and updated

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
- If build not found in farm database, searches all configured servers
- Automatic retry with exponential backoff for server connections
- Graceful degradation when servers are unavailable

---

## Real-time Updates

The farm provides real-time monitoring of builds across all servers:

### Background Tasks
- **Server Status Refresh**: Every 60 seconds
- **Build Status Updates**: Every 120 seconds
- **Build Discovery**: Continuously discovers new builds

### Dashboard Updates
- Auto-refresh every 10 seconds when viewing active builds
- Collapsible architecture sections with session state persistence
- Real-time build status indicators

---

## Configuration

### Configuration File Locations
The farm searches for configuration files in this order:
1. `./apb.json` (current directory)
2. `~/.config/apb.json` (user config directory)
3. `/etc/apb.json` (system-wide config)

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
- `--curses-ui`: Enable terminal UI dashboard

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

### Metrics
- Server availability tracking
- Build distribution across servers
- Performance metrics for server selection

### Health Checks
- Individual server health monitoring
- Farm-level health status
- Automatic server discovery and recovery
