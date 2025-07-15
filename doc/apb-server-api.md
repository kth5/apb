# APB Server API Documentation

The APB Server is the core component that handles package building requests and serves build results back to the farm.

## Base URL
- Default: `http://localhost:8000`
- Configurable via `--host` and `--port` command line arguments

## Authentication
Currently, the APB Server does not implement authentication. All endpoints are publicly accessible.

## Content Types
- **Request**: `multipart/form-data` for file uploads, `application/json` for JSON requests
- **Response**: `application/json` for API endpoints, `text/html` for web pages

## Rate Limiting
No explicit rate limiting is implemented, but the server has a configurable concurrent build limit.

## Request Timeout Middleware

The server implements sophisticated request timeout middleware to prevent hanging requests:

### Timeout Configuration
- **Build submissions**: 300 seconds (5 minutes) for build uploads
- **Streaming endpoints**: No timeout for real-time output streaming
- **Other endpoints**: 30 seconds for general API requests

### Timeout Behavior
- Returns HTTP 408 (Request Timeout) when timeout is exceeded
- Provides detailed error messages for debugging
- Automatically handles cleanup of incomplete requests

### Example Timeout Response
```json
{
  "error": "Request timeout",
  "detail": "Request took too long to process"
}
```

## Resource Monitoring

The server includes comprehensive resource monitoring capabilities:

### System Monitoring
- **CPU Usage**: Real-time CPU load and core utilization
- **Memory Monitoring**: Total, available, and used memory tracking
- **Disk Monitoring**: Build directory space usage and availability
- **Process Tracking**: Individual build process resource consumption

### Background Monitoring
- **Resource Monitor Thread**: Runs continuously in background
- **Cleanup Scheduling**: Automatic cleanup based on resource usage
- **Build Process Management**: Tracks and manages running build processes
- **Garbage Collection**: Automatic memory cleanup during resource pressure

### System Information Response
Enhanced system information includes:
```json
{
  "system_info": {
    "architecture": "x86_64",
    "cpu": {
      "model": "Intel Core i7",
      "cores": 8,
      "load_average": [0.5, 0.7, 0.9]
    },
    "memory": {
      "total": 16777216,
      "available": 8388608,
      "used": 8388608,
      "percentage": 50.0
    },
    "disk": {
      "total": 1000000000,
      "used": 500000000,
      "free": 500000000,
      "percentage": 50.0
    },
    "uptime": "2 days, 5 hours, 30 minutes"
  }
}
```

## Architecture Detection

The APB Server automatically detects and reports its supported architecture to the APB Farm for proper build routing. The detection process follows these steps:

### Architecture Detection Process

1. **Command-line override**: If the `--architecture` flag is provided, this value takes precedence over all other detection methods.
2. **Read `/etc/pacman.conf`**: The server attempts to read the `Architecture` setting from the system's pacman configuration.
3. **Handle "auto" setting**: If `Architecture` is set to "auto" or not specified, the server falls back to machine architecture mapping.
4. **Map machine architecture**: Uses `uname -m` output and applies these mappings for farm compatibility:
   - `ppc64le` → `powerpc64le`
   - `ppc64` → `powerpc64`
   - `ppc` → `powerpc`
   - Other architectures are used as-is (e.g., `x86_64`, `aarch64`)

### Command-line Architecture Override

Use the `--architecture` flag to override the detected architecture:

```bash
# Example: espresso server that produces powerpc packages
apb-server.py --architecture powerpc

# Example: x86_64 server configured to build for a different architecture
apb-server.py --architecture aarch64
```

This is particularly useful when:
- Running cross-compilation environments
- Using emulation for different architectures
- Building packages for embedded systems
- Testing architecture-specific builds

---

## Endpoints

### Server Information

#### GET /
Get comprehensive server information and status.

**Response:**
```json
{
  "status": "running",
  "version": "2025-07-15",
  "supported_architecture": "x86_64",
  "system_info": {
    "architecture": "x86_64",
    "cpu": {
      "model": "Intel Core i7",
      "cores": 8,
      "load_average": [0.5, 0.7, 0.9]
    },
    "memory": {
      "total": 16777216,
      "available": 8388608,
      "used": 8388608,
      "percentage": 50.0
    },
    "disk": {
      "total": 1000000000,
      "used": 500000000,
      "free": 500000000,
      "percentage": 50.0
    },
    "uptime": "2 days, 5 hours, 30 minutes"
  },
  "queue_status": {
    "current_builds_count": 1,
    "queued_builds": 2,
    "max_concurrent_builds": 3
  },
  "current_build": {
    "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
    "pkgname": "example-package",
    "status": "building",
    "start_time": 1642694400.0
  }
}
```

#### GET /health
Simple health check endpoint for monitoring systems.

**Response:**
```json
{
  "status": "healthy",
  "version": "2025-07-15"
}
```

### Build Management

#### POST /build
Submit a new build request.

**Request:**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `pkgbuild` (file, required): The PKGBUILD file
  - `sources` (file[], optional): Additional source files
  - `build_id` (string, optional): Build UUID (provided by APB Farm)

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "status": "queued",
  "message": "Build queued successfully"
}
```

**Build ID Behavior:**
- If `build_id` is provided, the server will use that exact ID
- If `build_id` is not provided, the server generates a timestamp-based ID
- The APB Farm always provides a build ID to ensure consistency across the system

**Enhanced Build Processing:**
- **Input Validation**: Comprehensive PKGBUILD and source file validation
- **Resource Checking**: Verifies sufficient disk space and memory before queuing
- **Queue Management**: Intelligent queuing with priority and resource consideration
- **Process Tracking**: Full lifecycle tracking from submission to completion

**Error Response:**
```json
{
  "error": "Invalid PKGBUILD file",
  "detail": "Missing required fields: pkgname, pkgver"
}
```

#### GET /build/{build_id}/status-api
Get build status as JSON.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": 1642694400.0,
  "end_time": 1642694500.0,
  "duration": 100.0,
  "exit_code": 0,
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
  ]
}
```

**Status Values:**
- `queued`: Build is waiting in queue
- `building`: Build is currently in progress
- `completed`: Build finished successfully
- `failed`: Build failed
- `cancelled`: Build was cancelled

**Enhanced Status Information:**
- **Resource Usage**: Memory and CPU usage during build
- **Progress Indicators**: Build phase tracking when available
- **Error Details**: Detailed error information for failed builds
- **Timing Information**: Comprehensive timing and duration data

#### GET /build/{build_id}
Get detailed build information (HTML or JSON based on Accept header).

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response (HTML):** Comprehensive build status page with:
- Real-time build status updates
- Live output streaming
- Download links for artifacts
- Build metadata and timing information
- Cancel build functionality (for active builds)

**Response (JSON):**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": "2024-01-20 10:00:00 UTC",
  "end_time": "2024-01-20 10:05:00 UTC",
  "duration": 300.0,
  "exit_code": 0,
  "packages": [...],
  "logs": [...],
  "sources": [...]
}
```

#### GET /build/{build_id}/output
Get build output/logs.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
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
  "returned_lines": 50,
  "build_status": "building",
  "last_updated": 1642694450.0
}
```

**Enhanced Output Features:**
- **Streaming Support**: Real-time output as builds progress
- **Pagination**: Efficient handling of large build logs
- **Status Integration**: Build status included with output
- **Filtering**: Support for filtering output by log level or content

#### GET /build/{build_id}/stream
Stream build output in real-time using Server-Sent Events.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:**
- **Content-Type:** `text/event-stream`
- **Events:**
  - `output`: New build output line
  - `status`: Status change
  - `complete`: Build finished

**Example Event Stream:**
```
event: output
data: ==> Making package: example-package 1.0.0-1 (x86_64)

event: output
data: ==> Checking runtime dependencies...

event: status
data: {"status": "building", "progress": 25}

event: complete
data: {"status": "completed", "exit_code": 0}
```

**Enhanced Streaming Features:**
- **Connection Management**: Automatic reconnection handling
- **Resource Efficiency**: Optimized for minimal server resource usage
- **Error Handling**: Graceful handling of connection issues
- **Progress Updates**: Real-time build progress when available

#### POST /build/{build_id}/cancel
Cancel a build.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:**
```json
{
  "success": true,
  "message": "Build cancelled successfully"
}
```

**Enhanced Cancellation:**
- **Process Management**: Properly terminates build processes and cleans up resources
- **State Management**: Updates build status and notifies monitoring systems
- **Resource Cleanup**: Cleans up temporary files and build directories
- **Safety Checks**: Prevents cancellation of builds in critical phases

#### GET /build/{build_id}/confirm-cancel
Get build cancellation confirmation page.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:** HTML confirmation page with:
- Build information and current status
- Confirmation button with safety warnings
- Option to cancel or return to build status

---

### File Downloads

#### GET /build/{build_id}/download/{filename}
Download a build artifact.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
- `filename` (string, required): The filename to download

**Response:** Binary file content with appropriate headers.

**Headers:**
- `Content-Disposition`: `attachment; filename={filename}`
- `Content-Type`: Determined by file extension
- `Content-Length`: File size for download progress

**Enhanced Download Features:**
- **Range Support**: Partial content support for large files
- **Bandwidth Management**: Configurable download speed limiting
- **Security**: Filename validation to prevent directory traversal
- **Caching**: Appropriate cache headers for static content

#### GET /build/{build_id}/view/{filename}
View a text file in the browser.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
- `filename` (string, required): The filename to view

**Response:**
- **Content-Type:** `text/plain` or `text/html`
- File content for viewing with syntax highlighting for supported formats

**Viewing Features:**
- **Syntax Highlighting**: Automatic highlighting for PKGBUILD, log files, and source code
- **Line Numbers**: Configurable line numbering for easier navigation
- **Search**: In-browser search functionality for large files
- **Security**: Safe rendering of text content with XSS protection

#### GET /build/{build_id}/packages
List packages produced by a build.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "packages": [
    {
      "filename": "example-package-1.0.0-1-x86_64.pkg.tar.xz",
      "size": 1024000,
      "created_at": "2024-01-20 10:05:00 UTC",
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example-package-1.0.0-1-x86_64.pkg.tar.xz",
      "checksum": "sha256:a1b2c3d4...",
      "type": "package"
    }
  ],
  "total_packages": 1,
  "total_size": 1024000
}
```

---

### Build History

#### GET /builds/latest
Get the latest builds.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 10, max: 100)
- `status` (string, optional): Filter by status
- `architecture` (string, optional): Filter by architecture

**Response:**
```json
{
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "completed",
      "start_time": "2024-01-20 10:00:00 UTC",
      "end_time": "2024-01-20 10:05:00 UTC",
      "duration": 300.0,
      "architecture": "x86_64"
    }
  ],
  "total": 1,
  "filtered": true
}
```

#### GET /builds/pkgname/{pkgname}
Get builds for a specific package.

**Parameters:**
- `pkgname` (string, required): The package name
- `limit` (integer, optional): Maximum number of builds (default: 5, max: 50)

**Response:**
```json
{
  "pkgname": "example-package",
  "builds": [
    {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "status": "completed",
      "start_time": "2024-01-20 10:00:00 UTC",
      "end_time": "2024-01-20 10:05:00 UTC",
      "duration": 300.0
    }
  ],
  "total": 1
}
```

#### GET /builds/pkgname/{pkgname}/latest
Get the latest build for a specific package.

**Parameters:**
- `pkgname` (string, required): The package name
- `successful_only` (boolean, optional): Only return successful builds (default: true)

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "pkgname": "example-package",
  "status": "completed",
  "start_time": "2024-01-20 10:00:00 UTC",
  "end_time": "2024-01-20 10:05:00 UTC",
  "duration": 300.0,
  "packages": [
    {
      "filename": "example-package-1.0.0-1-x86_64.pkg.tar.xz",
      "size": 1024000,
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example-package-1.0.0-1-x86_64.pkg.tar.xz"
    }
  ]
}
```

#### GET /builds/pkgname/{pkgname}/latest/download/{file_type}
Download the latest build file for a package.

**Parameters:**
- `pkgname` (string, required): The package name
- `file_type` (string, required): Type of file to download
- `successful_only` (boolean, optional): Only consider successful builds (default: true)

**File Types:**
- `package`: Main package file
- `debug`: Debug package file
- `log`: Build log file
- `pkgbuild`: PKGBUILD file

**Response:** Binary file content or redirect to download URL.

---

### Administration

#### GET /admin/cleanup
Get cleanup administration page.

**Response:** HTML page with cleanup options including:
- Disk space usage summary
- Old build cleanup configuration
- Buildroot recreation options
- Cache management controls

#### POST /admin/cleanup
Trigger server cleanup.

**Request:**
- **Content-Type:** `application/json`
- **Parameters:**
  - `cleanup_type` (string, optional): Type of cleanup ("builds", "cache", "buildroot", "all")
  - `older_than_days` (integer, optional): Clean builds older than N days
  - `force` (boolean, optional): Force cleanup even if builds are active

**Response:**
```json
{
  "success": true,
  "message": "Cleanup initiated",
  "cleanup_id": "cleanup_456",
  "estimated_space_freed": "2.5 GB",
  "cleanup_type": "builds"
}
```

**Enhanced Cleanup Features:**
- **Selective Cleanup**: Choose specific cleanup operations
- **Space Estimation**: Preview how much space will be freed
- **Background Processing**: Cleanup runs in background without blocking server
- **Progress Tracking**: Monitor cleanup progress via cleanup_id

---

## Build Process Management

The server implements sophisticated build process management:

### Build Lifecycle

1. **Submission**: Validate PKGBUILD and queue build
2. **Resource Check**: Verify sufficient resources (disk, memory)
3. **Buildroot Preparation**: Ensure clean buildroot environment
4. **Source Management**: Download and validate sources
5. **Build Execution**: Run makechrootpkg in isolated environment
6. **Artifact Collection**: Collect packages and logs
7. **Cleanup**: Clean temporary files and update status

### Process Tracking

- **Running Processes**: Global tracking of active build processes
- **Resource Monitoring**: CPU and memory usage per build
- **Timeout Management**: Automatic build termination after timeout (2 hours default)
- **Graceful Shutdown**: Proper process termination during server shutdown

### Buildroot Management

- **Automatic Recreation**: Configurable buildroot recreation (e.g., every 50 builds)
- **Cache Management**: Intelligent package cache handling
- **Chroot Isolation**: Complete isolation between builds
- **Security**: Proper user/group separation and permissions

### Queue Management

- **Thread Pool**: Configurable worker threads for concurrent builds
- **Priority Queuing**: Build prioritization based on age and resource requirements
- **Resource Limits**: Respect system resource limits and concurrent build count
- **Failure Handling**: Automatic retry logic for transient failures

---

## Error Handling

All endpoints return appropriate HTTP status codes:

- **200 OK**: Request successful
- **400 Bad Request**: Invalid request parameters or malformed data
- **404 Not Found**: Resource not found (build, file, etc.)
- **408 Request Timeout**: Request exceeded timeout limits
- **409 Conflict**: Resource conflict (e.g., duplicate build ID)
- **413 Payload Too Large**: Upload exceeds size limits
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Server maintenance or overloaded

**Enhanced Error Responses:**
```json
{
  "error": "Build not found",
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' does not exist",
  "status_code": 404,
  "timestamp": "2024-01-20T10:00:00Z",
  "request_id": "req_abc123"
}
```

### Error Recovery

- **Automatic Retry**: Transient errors are retried automatically
- **Graceful Degradation**: Service continues with reduced functionality during issues
- **Resource Recovery**: Automatic cleanup of failed builds
- **State Consistency**: Maintains consistent build state even during failures

---

## WebSocket Events

The server supports real-time updates through Server-Sent Events (SSE) for build output streaming:

### Event Types

- **output**: New build output line
- **status**: Build status change
- **progress**: Build progress update (when available)
- **error**: Error during build
- **complete**: Build completion

### Connection Management

- **Automatic Reconnection**: Client-side reconnection handling
- **Connection Limits**: Configurable limits on concurrent SSE connections
- **Resource Efficiency**: Optimized for minimal server overhead
- **Security**: Proper authentication and access control for streams

---

## Configuration

Server behavior can be configured via:
- Command line arguments
- Environment variables
- Configuration files

### Key Configuration Options

#### Command Line Arguments
- `--host`: Server host address (default: localhost)
- `--port`: Server port (default: 8000)
- `--buildroot`: Build root directory (default: ~/.apb/buildroot)
- `--builds-dir`: Build storage directory (default: ~/.apb/builds)
- `--max-concurrent`: Maximum concurrent builds (default: 3)
- `--buildroot-autorecreate`: Auto-recreate buildroot after N builds
- `--architecture`: Override detected architecture
- `--debug`: Enable debug logging

#### Environment Variables
- `APB_HOST`: Override default host
- `APB_PORT`: Override default port
- `APB_BUILDROOT`: Override buildroot location
- `APB_MAX_CONCURRENT`: Override concurrent build limit
- `APB_DEBUG`: Enable debug mode

#### Advanced Configuration
- **Resource Limits**: Configure memory and disk usage limits
- **Timeout Settings**: Customize build and request timeouts
- **Cache Settings**: Configure package cache behavior
- **Security Settings**: User/group permissions and sandboxing options
