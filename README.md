# APB - Arch Package Builder

APB is a distributed Arch Linux package building system that provides automated, multi-architecture package compilation across multiple build servers. It consists of three main components that work together to efficiently build and distribute building pacman packages.

## What is APB?

APB (Arch Package Builder) is designed to solve the challenges of building Arch Linux packages across different architectures and managing build infrastructure at scale. It provides:

- **Distributed Building**: Automatically distribute package builds across multiple servers based on architecture and load
- **Multi-Architecture Support**: Build packages for x86_64, aarch64, powerpc64le, riscv64, and other architectures
- **Automated Buildroot Management**: Handles chroot creation, maintenance, and cleanup using `mkarchroot` and `makechrootpkg`
- **Source Management**: Automatic GPG key validation and source dependency handling
- **Build Monitoring**: Real-time build status tracking and log streaming
- **Resource Management**: Intelligent load balancing and concurrent build limiting

APB is particularly useful for:
- package maintainers building pacman packages for multiple architectures
- Organizations maintaining private package repositories
- Developers needing consistent, isolated build environments
- Projects requiring automated CI/CD package building

## Basic Architecture

APB follows a three-tier architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   APB Client    │───▶│    APB Farm     │───▶│   APB Server    │
│                 │    │                 │    │                 │
│ • Submit builds │    │ • Load balancing│    │ • Package builds│
│ • Monitor status│    │ • Architecture  │    │ • Buildroot mgmt│
│ • Download files│    │   routing       │    │ • Resource mgmt │
│ • Build control │    │ • Multi-server  │    │ • File serving  │
└─────────────────┘    │   coordination  │    └─────────────────┘
                       └─────────────────┘
```

### APB Client (`apb.py`)
The command-line interface and Python library for interacting with the build system. It handles:
- Submitting build requests with PKGBUILD and source files
- Monitoring build progress with real-time output streaming
- Downloading completed packages and build artifacts
- Managing multiple architectures and build configurations

### APB Farm (`apb-farm.py`)
The central coordinator that manages multiple build servers. It provides:
- Automatic server discovery and health monitoring
- Intelligent build routing based on architecture and server load
- Build queue management and prioritization
- Unified API interface for clients
- Build tracking across all servers

### APB Server (`apb-server.py`)
The actual build execution engine that runs on each build machine. It handles:
- Isolated package building using clean chroots
- Buildroot lifecycle management with automatic recreation
- Source caching and GPG key validation
- Concurrent build management and resource limiting
- Build artifact storage and serving

### Configuration
The system uses a JSON configuration file (`apb.json`) that defines server topology:

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
    "powerpc64le": [
      "http://power-server1.example.com:8000"
    ]
  }
}
```

## Running APB Farm

The APB Farm acts as the central coordinator for multiple build servers.

### Basic Usage

```bash
# Start the farm with default settings
python3 apb-farm.py

# Start on specific host and port
python3 apb-farm.py --host 0.0.0.0 --port 8080

# Use custom configuration file
python3 apb-farm.py --config /path/to/custom-apb.json

# Enable debug logging
python3 apb-farm.py --log-level DEBUG
```

### Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | `0.0.0.0` | Host interface to bind to |
| `--port` | `8080` | Port to listen on |
| `--log-level` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `--config` | *auto-detect* | Path to configuration file |

### Configuration File Locations

The farm looks for `apb.json` in the following locations (in order):
1. Current working directory: `./apb.json`
2. System-wide: `/etc/apb/apb.json`
3. User home: `~/.apb/apb.json`
4. Farm-specific: `~/.apb-farm/apb.json`

### Farm Features

- **Server Health Monitoring**: Continuously monitors all configured servers
- **Automatic Failover**: Routes builds away from unhealthy servers
- **Architecture Validation**: Ensures servers actually support their configured architectures
- **Load Balancing**: Distributes builds based on server capacity and current load
- **Build Tracking**: Maintains a database of all builds across all servers
- **Web Dashboard**: Provides a web interface at `http://farm-host:8080/dashboard`

## Running APB Server

The APB Server is the build execution engine that should run on each build machine.

### Basic Usage

```bash
# Start server with default settings
python3 apb-server.py

# Start on specific host and port
python3 apb-server.py --host 0.0.0.0 --port 8000

# Custom buildroot location
python3 apb-server.py --buildroot /srv/apb/buildroot

# Custom build storage directory
python3 apb-server.py --builds-dir /srv/apb/builds

# Limit concurrent builds
python3 apb-server.py --max-concurrent 2

# Auto-recreate buildroot every 50 builds
python3 apb-server.py --buildroot-autorecreate 50

# Override architecture detection
python3 apb-server.py --architecture powerpc

# Enable debug logging
python3 apb-server.py --debug
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

### Basic Usage

```bash
# Build package in current directory
python3 apb.py

# Build specific package directory
python3 apb.py /path/to/package/

# Build for specific architecture
python3 apb.py --arch x86_64 /path/to/package/

# Build for multiple architectures
python3 apb.py --arch x86_64,aarch64,powerpc64le /path/to/package/

# Use APB Farm instead of direct server
python3 apb.py --farm /path/to/package/

# Use specific server
python3 apb.py --server http://build-server:8000 /path/to/package/

# Submit build and exit (don't wait)
python3 apb.py --detach /path/to/package/

# Monitor existing build
python3 apb.py --monitor 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Download build results
python3 apb.py --download 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Check build status
python3 apb.py --status 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Cancel running build
python3 apb.py --cancel 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3
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

#### Build Options
| Option | Default | Description |
|--------|---------|-------------|
| `--output-dir PATH` | `./output` | Output directory for downloaded files |
| `--detach` | `false` | Submit build and exit (don't wait for completion) |
| `--no-download` | `false` | Don't download build results |
| `--force` | `false` | Force rebuild even if package exists |

#### Monitoring Options
| Option | Description |
|--------|-------------|
| `--monitor BUILD_ID` | Monitor existing build |
| `--download BUILD_ID` | Download build results |
| `--status BUILD_ID` | Check build status |
| `--cancel BUILD_ID` | Cancel running build |

#### Advanced Options
| Option | Description |
|--------|-------------|
| `--farm` | Use APB Farm instead of direct server |
| `--list-servers` | List available servers |
| `--cleanup` | Trigger server cleanup |
| `--test-arch` | Test architecture compatibility |

### Configuration

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
└── powerpc64le/
    ├── package-1.0.0-1-powerpc64le.pkg.tar.zst
    └── build.log
```

### Monitoring Builds

The client provides real-time monitoring capabilities:
- **Progress Tracking**: Live build status updates
- **Output Streaming**: Real-time build log display
- **Interactive Controls**: Toggle between detailed and summary views
- **Completion Notification**: Automatic success/failure reporting

## Installation

APB requires Python 3.7+ and the following dependencies:

```bash
pip install fastapi uvicorn aiohttp psutil requests
```

For development or testing, see `requirements.txt` for the complete dependency list.

## Getting Started

1. **Set up a build server**:
   ```bash
   python3 apb-server.py --host 0.0.0.0
   ```

2. **Start the farm** (optional, for multi-server setups):
   ```bash
   python3 apb-farm.py --config apb.json
   ```

3. **Submit a build**:
   ```bash
   python3 apb.py /path/to/package/
   ```

For more detailed information, see the documentation in the `doc/` directory.
