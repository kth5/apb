# APB - Arch Package Builder

APB is a distributed Arch Linux package building system that provides automated, multi-architecture package compilation across multiple build servers. It consists of three main components that work together to efficiently build and distribute pacman packages.

## What is APB?

APB (Arch Package Builder) is designed to solve the challenges of building Arch Linux packages across different architectures and managing build infrastructure at scale. It provides:

- **Distributed Building**: Automatically distribute package builds across multiple servers based on architecture and load
- **Multi-Architecture Support**: Build packages for x86_64, aarch64, powerpc64le, riscv64, and other architectures
- **Architecture-Independent Packages**: `arch=('any')` packages can be routed to any available build server
- **Automated Buildroot Management**: Handles chroot creation, maintenance, and cleanup using `mkarchroot` and `makechrootpkg`
- **Source Management**: Automatic GPG key validation, source dependency handling, and tarball uploads that include source directories
- **Build Monitoring**: Real-time build status tracking and log streaming
- **Artifact Caching**: The farm caches completed build artifacts locally so clients download from the farm without re-fetching from build servers
- **Resource Management**: Intelligent load balancing and concurrent build limiting
- **Authentication & Authorization**: Secure user management with role-based access control
- **Web Dashboard**: Farm dashboard for server health, build history, and administration

APB is particularly useful for:

- Package maintainers building pacman packages for multiple architectures
- Organizations maintaining private package repositories
- Developers needing consistent, isolated build environments
- Projects requiring automated CI/CD package building
- Teams needing secure, multi-user build infrastructure

## Architecture

APB follows a three-tier architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   APB Client    │───▶│    APB Farm     │───▶│   APB Server    │
│                 │    │                 │    │                 │
│ • Submit builds │    │ • Load balancing│    │ • Package builds│
│ • Monitor status│    │ • Architecture  │    │ • Buildroot mgmt│
│ • Download files│    │   routing       │    │ • Resource mgmt │
│ • Build control │    │ • Multi-server  │    │ • File serving  │
│ • Authentication│    │   coordination  │    └─────────────────┘
└─────────────────┘    │ • User management│
                       │ • Access control │
                       │ • Artifact cache │
                       └─────────────────┘
```

### APB Client (`apb`)

The command-line interface and Python library (`apb.client`) for interacting with the build system. It handles:

- Submitting build requests as tarballs of the package directory (PKGBUILD plus sources)
- Monitoring build progress with real-time output streaming
- Waiting for farm artifact caching (`artifacts_ready`) before downloading results
- Downloading completed packages and build artifacts
- Managing multiple architectures and build configurations
- User authentication and session management

### APB Farm (`apb-farm`)

The central coordinator that manages multiple build servers. It provides:

- Automatic server discovery and health monitoring
- Intelligent build routing based on architecture and server load
- Build queue management and prioritization
- Unified API interface for clients
- Build tracking across all servers with cached status when servers are temporarily unavailable
- **User authentication and authorization system**
- **Role-based access control (admin, user, guest)**
- **Secure token-based session management**
- **Web dashboard** at `/dashboard` with path-based URLs (for example `/dashboard/builds/2`)
- **Artifact caching** with configurable retention
- **SMTP notifications** and **custom pacman repository** configuration (admin)

### APB Server (`apb-server`)

The build execution engine that runs on each build machine. It handles:

- Isolated package building using clean chroots
- Buildroot lifecycle management with automatic recreation
- Source caching and GPG key validation
- Concurrent build management and resource limiting
- Build artifact storage and serving

### Package Layout

APB is installed as a Python package under `src/apb/`:

| Module | Purpose |
|--------|---------|
| `apb.client` | CLI, HTTP client, and authentication |
| `apb.farm` | Farm application, routing, and core logic |
| `apb.server` | Server application and build engine |
| `apb.pkgbuild` | PKGBUILD parsing (including bash-style variable substitution) |
| `apb.tarball` | Build directory tarball creation |
| `apb.config` | Shared configuration loading |
| `apb.web` | Jinja2 HTML templates and static assets |

Console entry points are defined in `pyproject.toml`: `apb`, `apb-farm`, and `apb-server`.

## Configuration

The system uses a JSON configuration file (`apb.json`) that defines server topology and optional cache settings:

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
    "any": [
      "http://fallback-server.example.com:8000"
    ]
  },
  "farm_url": "http://farm.example.com:8080",
  "cache": {
    "enabled": true,
    "retention_days": 30,
    "directory": "~/.apb/cache",
    "max_size_mb": 10240
  }
}
```

Servers listed under the `any` group act as fallbacks for `arch=('any')` packages or when load-based selection cannot reach server status endpoints.

### Configuration File Locations

Components look for `apb.json` in the following locations (in order):

1. Current working directory: `./apb.json`
2. System-wide: `/etc/apb/apb.json`
3. User home: `~/.apb/apb.json`
4. Farm-specific: `~/.apb-farm/apb.json`

## Authentication System

APB Farm includes a authentication and authorization system.

### User Roles

- **Admin**: Full system access including user management, can cancel any build, see full server details, configure SMTP and custom repositories
- **User**: Can submit builds, cancel own builds, view own build history via `/my/builds`
- **Guest**: Read-only access to dashboard and build status (no authentication required)

### Security Features

- **Token-based Authentication**: Secure Bearer tokens with 10-day expiration
- **Password Security**: PBKDF2 password hashing with 100,000 iterations
- **Automatic Token Renewal**: Tokens automatically renewed on use
- **Session Management**: Users can revoke tokens and manage active sessions

### Default Admin Account

When the farm starts for the first time, it automatically creates a default admin account:

- **Username**: `admin`
- **Password**: `admin123`

**IMPORTANT**: Change the default admin password immediately after first login.

## Installation

APB requires Python 3.12+ and installs as a Python package with console scripts `apb`, `apb-farm`, and `apb-server`.

```bash
pip install -e .
```

Or install dependencies from `requirements.txt` first:

```bash
pip install -r requirements.txt && pip install -e .
```

On Arch Linux, APB can also be built and installed from the included `PKGBUILD` (requires `devtools` and `arch-install-scripts` on build servers).

For development and unit tests:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -v
```

Use `python -m pytest` so the active virtualenv's interpreter is used. A system-wide `pytest` command may invoke a different Python and fail to import `apb`.

Integration tests spawn farm and server processes and require Linux, Arch build tools, `multipart>=1.3`, and `APB_INTEGRATION=1`:

```bash
./tests/run-integration.sh
```

On Arch Linux, install the distribution package with `pacman -S python-multipart` (PyPI name `multipart`, not Kludex `python-multipart`).

## Getting Started

1. **Set up a build server**:

   ```bash
   apb-server --host 0.0.0.0
   ```

2. **Start the farm**:

   ```bash
   apb-farm --config apb.json
   ```

3. **Login to the farm** (first time setup):

   ```bash
   apb --farm --login --username admin
   # Password: admin123 (change this immediately!)

   apb --farm --auth-status
   ```

4. **Submit a build**:

   ```bash
   apb --farm /path/to/package/
   ```

5. **Open the dashboard** at `http://farm-host:8080/dashboard` to monitor servers and builds.

6. **Create additional users** (admin only) via the farm web interface or API endpoints.

## Running APB Farm

The APB Farm acts as the central coordinator for multiple build servers.

### Basic Usage

```bash
# Start the farm with default settings
apb-farm

# Start on specific host and port
apb-farm --host 0.0.0.0 --port 8080

# Use custom configuration file
apb-farm --config /path/to/custom-apb.json

# Enable debug logging
apb-farm --log-level DEBUG
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `0.0.0.0` | Host interface to bind to |
| `--port` | `8080` | Port to listen on |
| `--log-level` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `--config` | *auto-detect* | Path to configuration file |

## Running APB Server

The APB Server is the build execution engine that should run on each build machine.

### Basic Usage

```bash
# Start server with default settings
apb-server

# Start on specific host and port
apb-server --host 0.0.0.0 --port 8000

# Custom buildroot location
apb-server --buildroot /srv/apb/buildroot

# Custom build storage directory
apb-server --builds-dir /srv/apb/builds

# Limit concurrent builds
apb-server --max-concurrent 2

# Auto-recreate buildroot every 50 builds
apb-server --buildroot-autorecreate 50

# Override architecture detection
apb-server --architecture powerpc

# Custom file size and timeout limits
apb-server --max-file-size 209715200 --max-request-size 1073741824 --build-timeout 7200

# Enable debug logging
apb-server --debug
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `localhost` | Host interface to bind to |
| `--port` | `8000` | Port to listen on |
| `--buildroot` | `~/.apb/buildroot` | Directory for the build chroot |
| `--builds-dir` | `~/.apb/builds` | Directory to store build results |
| `--max-concurrent` | `3` | Maximum number of concurrent builds |
| `--buildroot-autorecreate` | *disabled* | Recreate buildroot after N builds |
| `--architecture` | *auto-detect* | Override detected architecture |
| `--max-file-size` | `100MB` | Maximum individual upload file size |
| `--max-request-size` | `500MB` | Maximum total request size |
| `--build-timeout` | `7200` | Maximum build time in seconds |
| `--debug` | `false` | Enable debug logging |

### Architecture Detection

The server automatically detects its architecture using this process:

1. **Command-line override**: `--architecture` flag takes precedence
2. **Read `/etc/pacman.conf`**: Uses the `Architecture` setting
3. **Machine architecture mapping**: Maps `uname -m` output for compatibility:
   - `ppc64le` → `powerpc64le`
   - `ppc64` → `powerpc64`
   - `ppc` → `powerpc`

### Build Process

The server uses Arch Linux's standard build tools:

1. **Buildroot Creation**: `mkarchroot` creates a clean chroot environment
2. **Package Building**: `makechrootpkg` builds packages in isolation
3. **Source Management**: Automatic handling of `SRCDEST` and `CCACHE_DIR`
4. **GPG Validation**: Downloads GPG keys from `validpgpkeys` arrays

### Server Management

- **Build Monitoring**: View builds at `http://server-host:8000/`
- **Cleanup**: Trigger cleanup at `http://server-host:8000/admin/cleanup`
- **Health Check**: Monitor health at `http://server-host:8000/health`

## Running APB Client

The APB Client is used to submit builds, monitor progress, and download results.

### Authentication

Before submitting builds to an APB Farm, you need to authenticate:

```bash
# Login to farm
apb --farm --login
# or specify username
apb --farm --login --username myuser

# Check authentication status
apb --farm --auth-status

# Logout
apb --farm --logout
```

### Basic Usage

```bash
# Build package in current directory (requires authentication for farm)
apb --farm

# Build specific package directory
apb --farm /path/to/package/

# Build for specific architecture
apb --farm --arch x86_64 /path/to/package/

# Build for multiple architectures
apb --farm --arch x86_64,aarch64,powerpc64le /path/to/package/

# Use specific server (no authentication required)
apb --server http://build-server:8000 /path/to/package/

# Submit build and exit (don't wait)
apb --farm --detach /path/to/package/

# Monitor existing build
apb --farm --monitor 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Download build results by ID
apb --farm --download 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Download latest successful builds for every arch=() from PKGBUILD
apb --farm --download
apb --farm --download /path/to/package/
apb --farm --arch x86_64,aarch64 --download /path/to/package/

# Check build status
apb --farm --status 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Cancel running build (own builds only, unless admin)
apb --farm --cancel 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3
```

### Command-Line Options

#### Basic Options

| Option | Description |
|--------|-------------|
| `pkgbuild_path` | Path to PKGBUILD or package directory (optional if PKGBUILD in current dir) |
| `--server URL` | Server URL |
| `--arch ARCH` | Target architecture(s) (comma-separated) |
| `--config PATH` | Path to configuration file |
| `--verbose` | Enable verbose output |
| `--quiet` | Suppress output except errors |

#### Authentication Options

| Option | Description |
|--------|-------------|
| `--login` | Login to farm |
| `--logout` | Logout from farm |
| `--auth-status` | Show authentication status |
| `--username USER` | Username for login |

#### Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `--output-dir PATH` | `./output` | Output directory for downloaded files |
| `--detach` | `false` | Submit build and exit (don't wait for completion) |
| `--no-download` | `false` | Don't download build results |
| `--force` | `false` | Force rebuild even if package exists |
| `--build-timeout SECS` | *server default* | Build timeout in seconds, 300–14400 (admin only) |

#### Monitoring Options

| Option | Description |
|--------|-------------|
| `--monitor BUILD_ID` | Monitor existing build |
| `--download [BUILD_ID\|PATH]` | Download by build ID, or latest farm builds per PKGBUILD `arch=()` |
| `--status BUILD_ID` | Check build status |
| `--cancel BUILD_ID` | Cancel running build |

#### Advanced Options

| Option | Description |
|--------|-------------|
| `--farm` | Use APB Farm instead of direct server |
| `--list-servers` | List available servers |
| `--cleanup` | Trigger server cleanup |
| `--test-arch` | Test architecture compatibility |

### Client Configuration

Create `~/.apb/apb.json` or specify with `--config`:

```json
{
  "farm_url": "http://farm.example.com:8080",
  "default_server": "http://server.example.com:8000",
  "default_arch": "x86_64",
  "servers": {
    "x86_64": ["http://server1:8000", "http://server2:8000"],
    "aarch64": ["http://arm-server:8000"]
  }
}
```

### Authentication Storage

Authentication tokens are stored in `~/.apb/auth.json` with restrictive permissions (600). The client automatically manages token storage and renewal.

### Build Output

The client automatically organizes downloaded files by architecture:

```
output/
├── x86_64/
│   ├── package-1.0.0-1-x86_64.pkg.tar.zst
│   └── build.log
├── aarch64/
│   ├── package-1.0.0-1-aarch64.pkg.tar.zst
│   └── build.log
├── any/
│   ├── package-1.0.0-1-any.pkg.tar.zst
│   └── build.log
└── powerpc64le/
    ├── package-1.0.0-1-powerpc64le.pkg.tar.zst
    └── build.log
```

Packages with `arch=('any')` in the PKGBUILD are downloaded to the `any/` subdirectory.

### Monitoring Builds

The client provides real-time monitoring capabilities:

- **Progress Tracking**: Live build status updates
- **Output Streaming**: Real-time build log display
- **Artifact Readiness**: Waits for the farm to finish caching artifacts before downloading
- **Server Resilience**: Uses cached status when build servers are temporarily unavailable
- **Completion Notification**: Automatic success/failure reporting

## Security Recommendations

- **Change default password**: Immediately change the default admin password
- **Create user accounts**: Set up individual user accounts instead of sharing admin access
- **Use HTTPS**: Deploy with HTTPS in production environments
- **Firewall configuration**: Restrict access to farm and server ports; deploy servers behind the farm
- **Regular token rotation**: Logout and login periodically to refresh tokens

## Documentation

For detailed API reference, see the documentation in the `doc/` directory:

- [APB Client API](doc/apb-client-api.md)
- [APB Farm API](doc/apb-farm-api.md)
- [APB Server API](doc/apb-server-api.md)
