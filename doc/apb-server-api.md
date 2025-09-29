# APB Server API Documentation

The APB Server is the core component that handles package building requests and serves build results back to the farm.

## Base URL
- Default: `http://localhost:8000`
- Configurable via `--host` and `--port` command line arguments

## Authentication

The APB Server itself does not implement authentication. All server endpoints are publicly accessible. However, when used in conjunction with APB Farm, authentication is handled at the farm level:

### APB Farm Integration

- **Farm Authentication**: APB Farm implements comprehensive authentication and forwards authenticated requests to servers
- **No Direct Client Authentication**: Clients authenticate with the farm, not individual servers
- **Server Trust**: Servers trust requests forwarded from the farm (farm acts as authentication proxy)
- **Build Ownership**: The farm tracks which user submitted each build and enforces permissions

### Security Model

- **Farm as Gateway**: All authenticated client requests go through the farm
- **Server Isolation**: Individual servers remain publicly accessible but are typically deployed behind firewalls
- **Authentication Proxy**: Farm acts as an authentication proxy for multiple servers
- **Permission Enforcement**: Build cancellation and access control enforced at farm level

### Deployment Recommendations

For production deployments:
- Deploy servers behind firewall/VPN accessible only to farm
- Use APB Farm as the public-facing authentication gateway
- Configure servers to accept requests only from farm instances
- Monitor server access logs for unauthorized direct access attempts

## Content Types
- **Request**: `multipart/form-data` for file uploads, `application/json` for JSON requests
- **Response**: `application/json` for API endpoints, `text/html` for web pages

## File Size Limits

The server implements configurable file size limits to prevent resource exhaustion:

### Default Limits
- **Individual files**: 100MB per file
- **Total request**: 500MB total request size
- **Configurable**: Limits can be adjusted via command-line arguments

### Configuration
```bash
# Set custom file size limits
apb-server.py --max-file-size 209715200    # 200MB per file
apb-server.py --max-request-size 1073741824 # 1GB total request
```

### Streaming Uploads
- **Memory Efficient**: Files are streamed to disk to avoid memory exhaustion
- **Partial Cleanup**: Incomplete uploads are automatically cleaned up
- **Progress Tracking**: Large uploads can be monitored for progress

## Rate Limiting
No explicit rate limiting is implemented, but the server has a configurable concurrent build limit and request timeout middleware.

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

## Global Exception Handling

The server includes comprehensive exception handling to prevent HTTP 502 errors:

### Exception Management
- **Global Handler**: Catches all unhandled exceptions
- **Detailed Logging**: Full exception details and tracebacks
- **Graceful Responses**: Returns structured JSON error responses
- **Resource Cleanup**: Forces garbage collection on errors

### Exception Response Format
```json
{
  "error": "Internal server error",
  "detail": "Specific error message",
  "type": "ExceptionType"
}
```

## Resource Monitoring

The server includes comprehensive resource monitoring capabilities:

### System Monitoring
- **CPU Usage**: Real-time CPU load and core utilization
- **Memory Monitoring**: Total, available, and used memory tracking with 90% threshold
- **Disk Monitoring**: Build directory space usage with 95% threshold
- **Process Tracking**: Individual build process resource consumption
- **Uptime Tracking**: Server uptime and boot time information

### Background Monitoring
- **Resource Monitor Thread**: Runs continuously every 30 seconds
- **Cleanup Scheduling**: Automatic cleanup based on resource usage (hourly)
- **Build Process Management**: Tracks running processes with timeout detection
- **Garbage Collection**: Automatic memory cleanup during resource pressure
- **Hung Process Detection**: Identifies and terminates processes exceeding timeouts

### Build Data Cleanup
- **Memory Management**: Limits build outputs to 10,000 lines per build
- **History Cleanup**: Maintains only 100 most recent builds in memory
- **Old Build Removal**: Automatically removes builds older than 1 hour from memory
- **Disk Cleanup**: Removes build directories older than 7 days

### System Information Response
Enhanced system information includes:
```json
{
  "system_info": {
    "architecture": "x86_64",
    "cpu": {
      "model": "Intel Core i7",
      "cores": 8,
      "usage_percent": 25.5,
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
    "uptime": "2 days, 5 hours, 30 minutes",
    "process_info": {
      "pid": 12345,
      "thread_count": 8,
      "open_files": 25,
      "memory_usage": 104857600
    }
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

### PowerPC Architecture Support

The server includes special support for PowerPC architectures:

#### Automatic ppc32 Prefix
- **Detection**: Automatically detects PowerPC and Espresso architectures
- **Build Command**: Uses `ppc32` prefix for makechrootpkg to ensure 32-bit detection
- **Architecture Mapping**: Maps `espresso` architecture to ensure compatibility

```bash
# PowerPC build command example
sudo ppc32 makechrootpkg -cuT -r /buildroot
```

#### PowerPC Configuration
```bash
# Example: Espresso server configuration
apb-server.py --architecture powerpc --buildroot /data/buildroot
```

---

## Endpoints

### Server Information

#### GET /
Get comprehensive server information and status.

**Response:**
```json
{
  "status": "running",
  "version": "2025-07-28",
  "supported_architecture": "x86_64",
  "system_info": {
    "architecture": "x86_64",
    "cpu": {
      "model": "Intel Core i7",
      "cores": 8,
      "usage_percent": 25.5,
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
    "uptime": "2 days, 5 hours, 30 minutes",
    "process_info": {
      "pid": 12345,
      "thread_count": 8,
      "open_files": 25,
      "memory_usage": 104857600
    }
  },
  "queue_status": {
    "current_builds_count": 1,
    "queued_builds": 2,
    "max_concurrent_builds": 3,
    "current_build": {
      "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
      "pkgname": "example-package",
      "status": "building",
      "start_time": 1642694400.0,
      "buildroot_recreation": false
    },
    "total_active_builds": 3,
    "build_history_count": 25,
    "buildroot_recreation_count": 0,
    "buildroot_recreation_builds": [],
    "server_busy_with_buildroot": false
  }
}
```

#### GET /health
Enhanced health check endpoint that performs comprehensive system testing.

**Response (Healthy):**
```json
{
  "status": "healthy",
  "version": "2025-07-28",
  "timestamp": "2024-01-20T10:00:00Z",
  "response_time_ms": 45.2,
  "checks": {
    "memory": {
      "status": "ok",
      "usage_percent": 45.2,
      "available_mb": 8192
    },
    "disk": {
      "status": "ok",
      "usage_percent": 65.3,
      "free_gb": 125
    },
    "executor": {
      "status": "ok",
      "test_result": "test"
    },
    "build_queue": {
      "status": "ok",
      "queue_size": 2,
      "active_builds": 1,
      "running_processes": 1
    },
    "filesystem": {
      "status": "ok"
    }
  }
}
```

**Response (Degraded):**
```json
{
  "status": "degraded",
  "version": "2025-07-28",
  "timestamp": "2024-01-20T10:00:00Z",
  "response_time_ms": 2500.1,
  "warning": "High response time",
  "checks": {
    "memory": {
      "status": "warning",
      "usage_percent": 92.1,
      "available_mb": 512
    },
    "disk": {
      "status": "error",
      "error": "Disk usage above 95%"
    }
  }
}
```

**Health Status Values:**
- `healthy`: All checks pass
- `warning`: Some checks have warnings but service is functional
- `degraded`: Errors detected or high response time
- `error`: Critical failure (returns 500 status)

### Build Management

#### POST /build
Submit a new build request with support for both tarball and individual file uploads.

**Request Methods:**

**Method 1: Tarball Upload (Recommended)**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `build_tarball` (file, required): Compressed tarball containing PKGBUILD and sources
  - `build_id` (string, required): Build UUID (provided by APB Farm)
  - `build_timeout` (integer, optional): Build timeout in seconds (300-14400)

**Method 2: Individual File Upload (Legacy)**
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `pkgbuild` (file, required): The PKGBUILD file (must be named 'PKGBUILD')
  - `sources` (file[], optional): Additional source files
  - `build_id` (string, required): Build UUID (provided by APB Farm)
  - `build_timeout` (integer, optional): Build timeout in seconds (300-14400)

**Response:**
```json
{
  "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
  "status": "queued",
  "message": "Build queued successfully"
}
```

**Tarball Requirements:**
- **Format**: Gzipped tar archive (.tar.gz)
- **Contents**: Must contain a PKGBUILD file at the root level
- **Size Limit**: Subject to configured maximum request size
- **Extraction**: Automatically extracted to build directory

**Enhanced Build Processing:**
- **Input Validation**: Comprehensive PKGBUILD parsing and validation
- **Resource Checking**: Verifies sufficient disk space and memory before queuing
- **Queue Management**: Intelligent queuing with concurrent build limits
- **Process Tracking**: Full lifecycle tracking from submission to completion
- **Streaming Upload**: Memory-efficient handling of large uploads
- **Partial Cleanup**: Automatic cleanup of failed uploads

**Build Timeout Configuration:**
- **Default**: 7200 seconds (2 hours)
- **Range**: 300-14400 seconds (5 minutes to 4 hours)
- **Per-Build**: Each build can have a custom timeout
- **Enforcement**: Automatic termination after timeout

**Error Responses:**
```json
{
  "error": "Invalid PKGBUILD file",
  "detail": "Missing required fields: pkgname, pkgver"
}
```

```json
{
  "error": "File too large",
  "detail": "Tarball exceeds 500000000 bytes"
}
```

```json
{
  "error": "Build ID already exists",
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' already exists"
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
  "created_at": 1642694300.0,
  "start_time": 1642694400.0,
  "end_time": 1642694500.0,
  "duration": 100.0,
  "exit_code": 0,
  "build_timeout": 7200,
  "arch": ["x86_64"],
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
- **Timing Details**: Separate creation, start, and end times
- **Custom Timeouts**: Shows configured timeout for each build
- **Architecture Info**: Target architecture for the build
- **Build Context**: Additional metadata about build environment

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
  "start_time": "2024-01-20T10:00:00Z",
  "end_time": "2024-01-20T10:05:00Z",
  "duration": 300.0,
  "exit_code": 0,
  "packages": [...],
  "logs": [...],
  "sources": [
    {
      "filename": "example.patch",
      "size": 1024,
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example.patch"
    }
  ]
}
```

#### GET /build/{build_id}/output
Get build output/logs with pagination support.

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
  "returned_lines": 5
}
```

**Enhanced Output Features:**
- **Streaming Support**: Real-time output as builds progress
- **Pagination**: Efficient handling of large build logs (up to 10,000 lines)
- **Memory Management**: Automatic truncation of very large outputs
- **Real-time Updates**: Output updates as build progresses

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
  - `heartbeat`: Connection keepalive (every 30 seconds)

**Example Event Stream:**
```
event: output
data: ==> Making package: example-package 1.0.0-1 (x86_64)

event: output
data: ==> Checking runtime dependencies...

event: status
data: {"status": "building"}

event: heartbeat
data: 1642694450.0

event: complete
data: {"status": "completed", "exit_code": 0}
```

**Enhanced Streaming Features:**
- **Connection Management**: Automatic stream cleanup and resource management
- **Heartbeat Support**: Regular heartbeats prevent connection timeout
- **Resource Efficiency**: Optimized for minimal server resource usage
- **Error Handling**: Graceful handling of connection issues
- **Historical Output**: Sends existing output before streaming new content

#### POST /build/{build_id}/cancel
Cancel a build with proper process management.

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
- **Process Management**: Properly terminates build processes (SIGTERM then SIGKILL)
- **Buildroot Recreation Handling**: Special timeout handling for buildroot recreation (300s vs 10s)
- **Resource Cleanup**: Cleans up temporary files and build directories
- **State Management**: Updates build status and notifies monitoring systems
- **Safety Checks**: Prevents cancellation conflicts and race conditions

#### GET /build/{build_id}/confirm-cancel
Get build cancellation confirmation page.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:** HTML confirmation page with:
- Build information and current status
- Confirmation button with safety warnings
- Option to cancel or return to build status

---

### File Downloads and Viewing

#### GET /build/{build_id}/download/{filename}
Download a build artifact with enhanced features.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
- `filename` (string, required): The filename to download

**Response:** Binary file content with appropriate headers.

**Headers:**
- `Content-Disposition`: `attachment; filename={filename}`
- `Content-Type`: `application/octet-stream`
- `Content-Length`: File size for download progress

**Enhanced Download Features:**
- **Security**: Filename validation to prevent directory traversal attacks
- **File Types**: Supports all build artifacts (packages, logs, sources)
- **Error Handling**: Proper 404 responses for missing files

#### GET /build/{build_id}/view/{filename}
View a text file in the browser with syntax highlighting.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
- `filename` (string, required): The filename to view

**Response:**
- **Content-Type:** `text/html` with embedded content
- File content displayed in formatted HTML with navigation

**Viewing Features:**
- **Text Detection**: Automatic detection of text vs binary files
- **Fallback**: Redirects binary files to download endpoint
- **Navigation**: Links back to build status page
- **UTF-8 Support**: Proper encoding handling for text files

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
      "created_at": "2024-01-20T10:05:00Z",
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example-package-1.0.0-1-x86_64.pkg.tar.xz"
    }
  ]
}
```

---

### Build History

#### GET /builds/latest
Get the latest builds with filtering support.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 10, max: 100)
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
      "duration": 300.0
    }
  ],
  "total": 1
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
      "start_time": "2024-01-20T10:00:00Z",
      "end_time": "2024-01-20T10:05:00Z",
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
  "start_time": "2024-01-20T10:00:00Z",
  "end_time": "2024-01-20T10:05:00Z",
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
- `debug`: Debug package file (excludes -debug packages from main search)
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
- Memory usage and cleanup status
- Manual cleanup triggers

#### POST /admin/cleanup
Trigger server cleanup with detailed results.

**Response:**
```json
{
  "success": true,
  "message": "Cleanup completed: removed 15 old builds",
  "cleanup_id": "cleanup_1642694400"
}
```

**Enhanced Cleanup Features:**
- **Selective Cleanup**: Removes builds older than 7 days
- **Memory Cleanup**: Clears build outputs and history
- **Disk Management**: Removes old build directories
- **Error Handling**: Continues cleanup even if some operations fail
- **Logging**: Detailed logging of cleanup operations

---

## Build Process Management

The server implements sophisticated build process management with enhanced features:

### Build Lifecycle

1. **Submission**: Validate PKGBUILD and queue build
2. **Resource Check**: Verify sufficient disk space and memory
3. **Buildroot Preparation**: Ensure clean buildroot environment
4. **GPG Key Management**: Download and verify GPG keys for source validation
5. **SRCDEST Locking**: Acquire exclusive access to shared source directory
6. **Source Management**: Download and validate sources
7. **Build Execution**: Run makechrootpkg in isolated environment
8. **Artifact Collection**: Collect packages and logs
9. **Cleanup**: Clean temporary files and update status

### GPG Key Support

The server automatically handles GPG key management for package source validation:

#### Automatic Key Download
- **validpgpkeys Parsing**: Extracts GPG keys from PKGBUILD validpgpkeys array
- **Key Retrieval**: Downloads keys using `gpg --recv-keys`
- **Multi-line Support**: Handles both single-line and multi-line validpgpkeys arrays
- **Error Handling**: Continues build even if key download fails (with warnings)

#### GPG Configuration
```bash
# Example PKGBUILD with GPG keys
validpgpkeys=('ABCD1234...' 'EFGH5678...')

# Multi-line format also supported
validpgpkeys=(
    'ABCD1234...'
    'EFGH5678...'
)
```

### Build Timeout Configuration

The server supports configurable output timeouts for build processes to handle hung builds:

#### Output Timeout Control
- **PKGBUILD Variable**: Set `apb_output_timeout=<seconds>` in PKGBUILD to customize timeout
- **Default Behavior**: 30 minutes (1800 seconds) if not specified
- **Validation**: Range limited to 60 seconds minimum, 24 hours (86400 seconds) maximum
- **Hung Build Detection**: Terminates builds that produce no output for the specified duration

#### Configuration Examples
```bash
# Example PKGBUILD with custom output timeout
pkgname=my-package
pkgver=1.0.0
pkgrel=1
apb_output_timeout=3600  # 1 hour timeout instead of default 30 minutes

# For packages with very long compile times without output
apb_output_timeout=7200  # 2 hours for complex builds

# Quick builds that should fail fast
apb_output_timeout=300   # 5 minutes for simple packages
```

#### Validation Rules
- **Minimum**: 60 seconds (prevents accidental immediate timeouts)
- **Maximum**: 86400 seconds (24 hours, prevents indefinite hangs)
- **Invalid Values**: Logged as warnings and ignored, fallback to default
- **Format**: Must be a valid integer value

### SRCDEST Locking

The server implements sophisticated SRCDEST directory locking for concurrent builds:

#### Locking Mechanism
- **Package-specific Locks**: Each package uses a separate lock file (`.apb-{pkgname}.lock`)
- **Exclusive Access**: Prevents concurrent source downloads for the same package in shared SRCDEST
- **Orphan Detection**: Automatically detects and cleans up orphaned locks
- **Timeout Handling**: 10-minute timeout prevents infinite waiting
- **Lock File Management**: Uses fcntl for atomic lock operations

#### Orphan Lock Cleanup
- **Startup Cleanup**: Removes orphaned locks from previous server sessions
- **Process Detection**: Uses `lsof` to verify if locks are actually held
- **Age-based Cleanup**: Removes locks older than 5 minutes if lsof unavailable
- **Graceful Degradation**: Continues build even if locking fails

#### SRCDEST Configuration
```bash
# /etc/makepkg.conf
SRCDEST="/data/sources"  # Shared source directory
CCACHE_DIR="/data/ccache"  # Shared ccache directory
```

### Buildroot Management

Enhanced buildroot management with automatic recreation:

#### Buildroot Recreation
- **Automatic Triggers**: Configurable recreation after N builds
- **Safe Recreation**: Special handling during buildroot recreation builds
- **Extended Timeouts**: 5-minute timeout for buildroot recreation vs 10 seconds for normal builds
- **Process Tracking**: Tracks builds performing buildroot recreation
- **Failure Handling**: Continues with existing buildroot if recreation fails

#### Buildroot Configuration
```bash
# Enable automatic buildroot recreation every 50 builds
apb-server.py --buildroot-autorecreate 50
```

#### Configuration Management
- **Host Configuration**: Copies `/etc/makepkg.conf` and `/etc/pacman.conf` to chroot
- **Dependency Management**: Installs base, base-devel, and ccache packages
- **Permission Handling**: Proper sudo permissions for chroot operations

### Process Tracking

Enhanced tracking of build processes and resources:

#### Running Process Management
- **Global Tracking**: Maintains registry of all running build processes
- **Graceful Termination**: SIGTERM followed by SIGKILL if necessary
- **Timeout Detection**: Monitors processes for timeout and hung state
- **Shutdown Handling**: Proper cleanup during server shutdown
- **Process Groups**: Uses process groups for better cleanup

#### Timeout Management
- **Overall Timeout**: Configurable per-build timeout (default 2 hours)
- **Output Timeout**: Terminates builds with no output for 30 minutes
- **Custom Timeouts**: Per-build timeout configuration
- **Special Handling**: Extended timeouts for buildroot recreation

### Queue Management

Sophisticated queue management with resource awareness:

#### Thread Pool Management
- **Configurable Workers**: Adjustable concurrent build limit
- **Dynamic Scaling**: Thread pool recreated with new worker count during startup
- **Resource Monitoring**: Considers system resources when accepting builds
- **Queue Processing**: Background thread processes build queue continuously

#### Build Prioritization
- **FIFO Processing**: First-in-first-out queue processing
- **Resource Limits**: Respects configured concurrent build limits
- **Failure Handling**: Proper error handling and state management

---

## Error Handling

All endpoints return appropriate HTTP status codes with enhanced error information:

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
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' does not exist"
}
```

```json
{
  "error": "Invalid tarball",
  "detail": "Tarball must contain a PKGBUILD file"
}
```

```json
{
  "error": "File too large",
  "detail": "PKGBUILD exceeds 104857600 bytes"
}
```

### Error Recovery

- **Automatic Cleanup**: Failed uploads and builds are automatically cleaned up
- **Graceful Degradation**: Service continues with reduced functionality during issues
- **Resource Recovery**: Automatic cleanup of failed builds and orphaned processes
- **State Consistency**: Maintains consistent build state even during failures
- **Global Exception Handling**: Prevents HTTP 502 errors through comprehensive exception catching

---

## Server-Sent Events (SSE)

The server supports real-time updates through Server-Sent Events for build output streaming:

### Event Types

- **output**: New build output line
- **status**: Build status change
- **complete**: Build completion with exit code
- **heartbeat**: Connection keepalive (every 30 seconds)

### Connection Management

- **Stream Registry**: Maintains registry of active streams per build
- **Automatic Cleanup**: Removes streams when connections close
- **Resource Efficiency**: Optimized for minimal server overhead
- **Historical Output**: Sends existing output before streaming new content
- **Heartbeat Support**: Regular heartbeats prevent connection timeout

### Example Usage
```javascript
const eventSource = new EventSource('/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/stream');

eventSource.addEventListener('output', function(event) {
    console.log('Build output:', event.data);
});

eventSource.addEventListener('complete', function(event) {
    const result = JSON.parse(event.data);
    console.log('Build completed with exit code:', result.exit_code);
});
```

---

## Configuration

Server behavior can be configured via command line arguments and environment variables:

### Command Line Arguments

#### Basic Configuration
- `--host`: Server host address (default: localhost)
- `--port`: Server port (default: 8000)
- `--buildroot`: Build root directory (default: ~/.apb/buildroot)
- `--builds-dir`: Build storage directory (default: ~/.apb/builds)
- `--debug`: Enable debug logging

#### Build Management
- `--max-concurrent`: Maximum concurrent builds (default: 3)
- `--buildroot-autorecreate`: Auto-recreate buildroot after N builds
- `--build-timeout`: Maximum build time in seconds (default: 7200)

#### Architecture and Platform
- `--architecture`: Override detected architecture (e.g., 'powerpc' for espresso)

#### File Size Limits
- `--max-file-size`: Maximum individual file size in bytes (default: 100MB)
- `--max-request-size`: Maximum total request size in bytes (default: 500MB)

### Example Configurations

#### Standard x86_64 Server
```bash
apb-server.py \
    --host 0.0.0.0 \
    --port 8000 \
    --max-concurrent 4 \
    --buildroot-autorecreate 25
```

#### PowerPC/Espresso Server
```bash
apb-server.py \
    --architecture powerpc \
    --buildroot /data/powerpc-buildroot \
    --builds-dir /data/powerpc-builds \
    --max-concurrent 2
```

#### High-capacity Server
```bash
apb-server.py \
    --max-concurrent 8 \
    --max-file-size 209715200 \
    --max-request-size 1073741824 \
    --build-timeout 10800
```

#### Development Server
```bash
apb-server.py \
    --debug \
    --max-concurrent 1 \
    --buildroot-autorecreate 5
```

### Environment Variables
- `APB_HOST`: Override default host
- `APB_PORT`: Override default port
- `APB_BUILDROOT`: Override buildroot location
- `APB_MAX_CONCURRENT`: Override concurrent build limit
- `APB_DEBUG`: Enable debug mode

### Resource Limits

The server automatically configures system resource limits:

#### Unlimited Resource Settings
- **Address Space**: RLIMIT_AS set to unlimited
- **Data Segment**: RLIMIT_DATA set to unlimited
- **Stack Size**: RLIMIT_STACK set to unlimited
- **File Size**: RLIMIT_FSIZE set to unlimited
- **Open Files**: RLIMIT_NOFILE set to unlimited
- **Processes**: RLIMIT_NPROC set to unlimited

#### Monitoring and Cleanup
- **Memory Monitoring**: Triggers cleanup at 90% memory usage
- **Disk Monitoring**: Triggers cleanup at 95% disk usage
- **Build Output Limits**: Maximum 10,000 lines per build output
- **History Limits**: Maximum 100 builds in memory history
