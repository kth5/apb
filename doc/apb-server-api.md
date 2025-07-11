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
- The server's machine architecture differs from the target package architecture
- Building cross-compiled packages
- Testing server configurations
- Working with specialized build environments like `espresso` → `powerpc`

### Reported Architecture

The detected architecture is included in all server status responses as `supported_architecture`. This allows the APB Farm to:
- Validate server configurations
- Route builds only to compatible servers
- Provide accurate error messages about architecture availability

### Example Configuration

**Standard PowerPC 64-bit little-endian server:**
- `/etc/pacman.conf` contains: `Architecture = powerpc64le`
- Or if set to `Architecture = auto`, maps `ppc64le` → `powerpc64le`
- Server reports: `"supported_architecture": "powerpc64le"`

**Espresso server building PowerPC packages:**
- Machine architecture: `espresso` (from `uname -m`)
- Command line: `apb-server.py --architecture powerpc`
- Server reports: `"supported_architecture": "powerpc"`

**Cross-compilation example:**
- Machine architecture: `x86_64`
- Command line: `apb-server.py --architecture aarch64`
- Server reports: `"supported_architecture": "aarch64"`

The farm uses this information to ensure builds are only sent to servers that can actually handle the target architecture.

## Buildroot creation

The APB server utilizes `marchroot` to install the buildroot into a directory defaulting to ~/.apb/buildroot, or
when `--buildroot` is given a full path on the command-line to that respective path. It always respects the command-line
parameter `--buildroot-autorecreate` with an optional integer that will upon N builds - successful or not - re-created
this buildroot.

APB Server must respect the host's `/etc/makepkg.conf`, ensure that `SRCDEST` defined in makepkg.conf is mounted into
the buildroot when executing `makechrootpkg` later on. The same is true for `CCACHE_DIR` should it be defined.

Example mkarchroot call:
```
sudo mkarchroot <buildroot path>/root base base-devel ccache"
```

A package is built from the current directory the APB Server saved the submitted build files into like so:
```
sudo makechrootpkg -cuT [-d /cacche] [-d /srcdest]
```

### GPG Key Validation

The APB Server automatically handles GPG key validation for source verification. When a PKGBUILD contains a `validpgpkeys=()` array, the server will:

1. Parse the `validpgpkeys` array from the PKGBUILD (supports both single-line and multi-line formats)
2. Download all specified GPG keys using `gpg --recv-keys` before starting the build
3. Log the GPG key download process to the build output
4. Continue with the build process (makechrootpkg will handle source validation)

**Example PKGBUILD with GPG keys:**
```bash
validpgpkeys=(
    'ABCD1234567890ABCDEF1234567890ABCDEF123456'
    'EFGH5678901234EFGH5678901234EFGH567890123'
)
```

The server handles various formats:
- Single-line: `validpgpkeys=('key1' 'key2')`
- Multi-line arrays with proper indentation
- Empty arrays: `validpgpkeys=()`
- Missing validpgpkeys (no action taken)

If GPG key download fails, the server logs a warning but continues with the build, allowing makechrootpkg to handle the validation failure appropriately.

### Notes on SRCDEST directory

The APB Server assumes that the directory is shared between itself and other servers. This can mean that another server
may interfere with a `git clone` operation or file download. The APB Server attempts to lock the `SRCDEST` directory
and all other APB Servers must wait until this log is released before starting the execution of the next build if they
see the `SRCDEST` directory is locked by another server.

## Endpoints

### Server Information

#### GET /
Get server information and status.

**Response:**
```json
{
  "status": "running",
  "version": "2025-07-11",
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
Simple health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "version": "2025-07-11"
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
  - `build_id` (string, required): Build UUID (provided by APB Farm)

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

**Error Response:**
```json
{
  "error": "Invalid PKGBUILD file",
  "detail": "Missing required fields"
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

#### GET /build/{build_id}/output
Get build output/logs.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
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

#### GET /build/{build_id}/confirm-cancel
Get build cancellation confirmation page.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

**Response:** HTML confirmation page.

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

#### GET /build/{build_id}/view/{filename}
View a text file in the browser.

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)
- `filename` (string, required): The filename to view

**Response:** 
- **Content-Type:** `text/plain` or `text/html`
- File content for viewing

---

### Build History

#### GET /builds/latest
Get the latest builds.

**Parameters:**
- `limit` (integer, optional): Maximum number of builds (default: 10)
- `status` (string, optional): Filter by status

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
- `limit` (integer, optional): Maximum number of builds (default: 5)

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

### Build Details

#### GET /build/{build_id}
Get detailed build information (HTML or JSON based on Accept header).

**Parameters:**
- `build_id` (string, required): Build UUID (provided by APB Farm)

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
      "download_url": "/build/48ea1df5-f7f3-477e-a7a7-36e526ea7cd3/download/example-package-1.0.0-1-x86_64.pkg.tar.xz"
    }
  ]
}
```

---

### Administration

#### GET /admin/cleanup
Get cleanup administration page.

**Response:** HTML page with cleanup options.

#### POST /admin/cleanup
Trigger server cleanup.

**Response:**
```json
{
  "success": true,
  "message": "Cleanup initiated",
  "cleanup_id": "cleanup_456"
}
```

---

## Error Handling

All endpoints return appropriate HTTP status codes:

- **200 OK**: Request successful
- **400 Bad Request**: Invalid request parameters
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error
- **503 Service Unavailable**: Server maintenance or overloaded

Error responses include details:
```json
{
  "error": "Build not found",
  "detail": "Build with ID '48ea1df5-f7f3-477e-a7a7-36e526ea7cd3' does not exist",
  "status_code": 404
}
```

---

## WebSocket Events

The server supports real-time updates through Server-Sent Events (SSE) for build output streaming.

## Configuration

Server behavior can be configured via:
- Command line arguments
- Environment variables
- Configuration files

Key configuration options:
- `--host`: Server host address
- `--port`: Server port
- `--buildroot`: Build root directory
- `--max-concurrent-builds`: Maximum concurrent builds
- `--log-level`: Logging level 
