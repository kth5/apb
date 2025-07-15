# APB Client API Documentation

The APB Client is a Python library and command-line tool that provides a convenient interface for interacting with APB Servers and APB Farm instances.

## Installation

The APB Client is included in the main APB package. No separate installation is required.

## Usage

### Command Line Interface

```bash
# Basic usage
python apb.py [OPTIONS] [PKGBUILD_PATH]

# Build for specific architecture
python apb.py --arch x86_64 /path/to/package/

# Build for multiple architectures
python apb.py --arch x86_64,aarch64 /path/to/package/

# Build with verbose output
python apb.py --verbose /path/to/package/

# Use APB Farm (recommended for multi-server setups)
python apb.py --farm /path/to/package/

# Monitor existing build
python apb.py --monitor 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Download build results
python apb.py --download 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3 --output-dir ./downloads/

# Check build status
python apb.py --status 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Cancel running build
python apb.py --cancel 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# List and test servers
python apb.py --list-servers
```

### Python Library

```python
from apb import APBotClient

# Create client instance
client = APBotClient("http://localhost:8000")

# Submit build
build_id = client.build_package([Path("PKGBUILD")])

# Monitor build
status = client.get_build_status(build_id)

# Download results
client.download_file(build_id, "package.pkg.tar.xz", Path("./downloads/"))
```

---

## Command Line Options

### Basic Options

- `pkgbuild_path` (positional): Path to PKGBUILD or package directory (optional if PKGBUILD in current dir)
- `--server URL`: Server URL (default: from config or http://localhost:8000)
- `--arch ARCH`: Target architecture(s) (comma-separated)
- `--config PATH`: Path to configuration file
- `--verbose`: Enable verbose output
- `--quiet`: Suppress output except errors

### Build Options

- `--output-dir PATH`: Output directory for downloaded files (default: ./output)
- `--detach`: Submit build and exit (don't wait for completion)
- `--no-download`: Don't download build results
- `--force`: Force rebuild even if package exists

### Monitoring Options

- `--monitor BUILD_ID`: Monitor existing build with real-time output
- `--download BUILD_ID`: Download build results only
- `--status BUILD_ID`: Check build status
- `--cancel BUILD_ID`: Cancel running build

### Advanced Options

- `--farm`: Use APB Farm instead of direct server (recommended)
- `--list-servers`: List and test available servers
- `--cleanup`: Trigger server cleanup
- `--test-arch`: Test architecture compatibility

---

## Enhanced Configuration

### Configuration File Locations

The client searches for configuration files in this order:
1. `./apb.json` (current directory)
2. `~/.config/apb.json` (user config directory)
3. `/etc/apb.json` (system-wide config)

### Configuration Schema

```json
{
  "servers": {
    "x86_64": ["http://server1:8000", "http://server2:8000"],
    "aarch64": ["http://arm-server:8000"],
    "powerpc64le": ["http://power-server:8000"]
  },
  "farm_url": "http://farm.example.com:8080",
  "default_server": "http://localhost:8000",
  "default_arch": "x86_64",
  "output_dir": "./output"
}
```

### Configuration Options

- **`servers`**: Map of architectures to server URLs for direct connections
- **`farm_url`**: APB Farm URL (used with `--farm` flag)
- **`default_server`**: Default server URL when no farm is configured
- **`default_arch`**: Default architecture for builds
- **`output_dir`**: Default output directory for downloaded files

---

## Architecture-Specific Output Organization

The client automatically organizes downloaded files by architecture:

```
output/
├── x86_64/
│   ├── package-1.0.0-1-x86_64.pkg.tar.zst
│   ├── package-debug-1.0.0-1-x86_64.pkg.tar.zst
│   ├── build.log
│   └── PKGBUILD
├── aarch64/
│   ├── package-1.0.0-1-aarch64.pkg.tar.zst
│   └── build.log
└── powerpc64le/
    ├── package-1.0.0-1-powerpc64le.pkg.tar.zst
    └── build.log
```

### Organization Features

- **Architecture Separation**: Each architecture gets its own subdirectory
- **Automatic Detection**: Architecture detected from build status or command line
- **Consistent Naming**: Predictable directory structure for automation
- **Fallback Handling**: Uses default architecture if detection fails

---

## Python Client Library

### Class: APBotClient

The main client class for interacting with APB servers.

#### Constructor

```python
APBotClient(server_url: str)
```

**Parameters:**
- `server_url` (str): Base URL of the APB server or farm

**Example:**
```python
client = APBotClient("http://build-server.example.com:8000")
```

---

### Build Management Methods

#### build_package()

Submit a build request to the server.

```python
def build_package(self, files: List[Path]) -> str
```

**Parameters:**
- `files` (List[Path]): List of file paths to upload (first should be PKGBUILD)

**Returns:**
- `str`: Build UUID

**Raises:**
- `requests.HTTPError`: On HTTP errors
- `requests.RequestException`: On connection errors
- `ValueError`: On invalid response

**Example:**
```python
files = [Path("PKGBUILD"), Path("source.tar.gz")]
build_id = client.build_package(files)
print(f"Build started: {build_id}")
```

#### get_build_status()

Get the current status of a build.

```python
def get_build_status(self, build_id: str) -> Dict
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `Dict`: Build status information

**Example:**
```python
status = client.get_build_status("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3")
print(f"Status: {status['status']}")
print(f"Package: {status['pkgname']}")
```

**Response Format:**
```python
{
    "build_id": "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
    "pkgname": "example-package",
    "status": "completed",  # queued, building, completed, failed, cancelled
    "start_time": 1642694400.0,
    "end_time": 1642694500.0,
    "duration": 100.0,
    "exit_code": 0,
    "packages": [...],
    "logs": [...]
}
```

#### cancel_build()

Cancel a running build.

```python
def cancel_build(self, build_id: str) -> bool
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `bool`: True if cancellation was successful

**Example:**
```python
success = client.cancel_build("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3")
if success:
    print("Build cancelled successfully")
```

---

### File Management Methods

#### download_file()

Download a file from a build.

```python
def download_file(self, build_id: str, filename: str, output_dir: Path) -> bool
```

**Parameters:**
- `build_id` (str): Build UUID
- `filename` (str): Name of the file to download
- `output_dir` (Path): Directory to save the file

**Returns:**
- `bool`: True if download was successful

**Example:**
```python
success = client.download_file(
    "48ea1df5-f7f3-477e-a7a7-36e526ea7cd3",
    "example-package-1.0.0-1-x86_64.pkg.tar.xz",
    Path("./downloads/")
)
```

#### get_build_output()

Get build output/logs.

```python
def get_build_output(self, build_id: str, start_index: int = 0, limit: int = 50) -> Dict
```

**Parameters:**
- `build_id` (str): Build UUID
- `start_index` (int): Starting line index
- `limit` (int): Maximum number of lines

**Returns:**
- `Dict`: Build output with metadata

**Example:**
```python
output = client.get_build_output("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3", start_index=0, limit=100)
for line in output['output']:
    print(line)
```

#### stream_output()

Stream build output in real-time.

```python
def stream_output(self, build_id: str) -> Generator[str, None, None]
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `Generator[str, None, None]`: Generator yielding output lines

**Example:**
```python
for line in client.stream_output("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3"):
    print(line, end='')
```

---

### Enhanced Information Methods

#### get_build_by_id()

Get detailed information about a build.

```python
def get_build_by_id(self, build_id: str) -> Dict
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `Dict`: Detailed build information including packages, logs, and metadata

#### get_builds_by_pkgname()

Get builds for a specific package.

```python
def get_builds_by_pkgname(self, pkgname: str, limit: int = 5) -> Dict
```

**Parameters:**
- `pkgname` (str): Package name
- `limit` (int): Maximum number of builds to return

**Returns:**
- `Dict`: Build history for the package

#### get_latest_build_by_pkgname()

Get the latest build for a specific package.

```python
def get_latest_build_by_pkgname(self, pkgname: str, successful_only: bool = True) -> Dict
```

**Parameters:**
- `pkgname` (str): Package name
- `successful_only` (bool): Only consider successful builds

**Returns:**
- `Dict`: Latest build information

#### download_latest_build_files()

Download all files from the latest build of a package.

```python
def download_latest_build_files(self, pkgname: str, output_dir: Path, successful_only: bool = True) -> bool
```

**Parameters:**
- `pkgname` (str): Package name
- `output_dir` (Path): Directory to save files
- `successful_only` (bool): Only consider successful builds

**Returns:**
- `bool`: True if download was successful

**Example:**
```python
success = client.download_latest_build_files(
    "example-package",
    Path("./downloads/"),
    successful_only=True
)
```

---

### Real-time Monitoring Methods

#### stream_build_updates()

Stream build status updates in real-time.

```python
def stream_build_updates(self, build_id: str) -> Generator[Dict, None, None]
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `Generator[Dict, None, None]`: Generator yielding status updates

**Example:**
```python
for update in client.stream_build_updates("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3"):
    print(f"Status: {update['status']}")
    if update['status'] in ['completed', 'failed', 'cancelled']:
        break
```

#### get_latest_successful_build_id()

Get the build ID of the latest successful build for a package.

```python
def get_latest_successful_build_id(self, is_interactive: bool = True) -> str
```

**Parameters:**
- `is_interactive` (bool): Whether to prompt user for input if multiple packages found

**Returns:**
- `str`: Build ID of the latest successful build

---

### Utility Methods

#### cleanup_server()

Trigger server cleanup.

```python
def cleanup_server(self) -> bool
```

**Returns:**
- `bool`: True if cleanup was triggered successfully

---

## High-Level Functions

### submit_build()

Submit a build to a server with automatic server selection.

```python
def submit_build(server_url: str, pkgbuild_path: Path, source_files: List[Path]) -> Optional[str]
```

**Parameters:**
- `server_url` (str): Server URL
- `pkgbuild_path` (Path): Path to PKGBUILD file
- `source_files` (List[Path]): List of source files

**Returns:**
- `Optional[str]`: Build ID if successful, None otherwise

### monitor_build()

Monitor a build with optional real-time output and automatic downloading.

```python
def monitor_build(build_id: str, client: APBotClient, output_dir: Path = None,
                 verbose: bool = False, allow_toggle: bool = True,
                 status_callback = None, pkgname: str = None) -> bool
```

**Parameters:**
- `build_id` (str): Build ID to monitor
- `client` (APBotClient): Client instance
- `output_dir` (Path, optional): Directory to download results
- `verbose` (bool): Enable verbose output
- `allow_toggle` (bool): Allow toggling output display
- `status_callback` (callable, optional): Callback for status updates
- `pkgname` (str, optional): Package name to display

**Returns:**
- `bool`: True if build was successful

**Enhanced Monitoring Features:**
- **Interactive Controls**: Press 'd' to toggle detailed output, 's' for summary only
- **Real-time Updates**: Live build status and progress tracking
- **Automatic Downloads**: Downloads artifacts when build completes successfully
- **Error Handling**: Graceful handling of connection issues and server unavailability
- **Status Callbacks**: Custom callbacks for build status changes

### build_for_multiple_arches()

Build a package for multiple architectures using available servers.

```python
def build_for_multiple_arches(build_path: Path, output_dir: Path, config: Dict,
                            verbose: bool = False, detach: bool = False,
                            specific_arch: str = None) -> bool
```

**Parameters:**
- `build_path` (Path): Path to package directory
- `output_dir` (Path): Output directory
- `config` (Dict): Configuration dictionary
- `verbose` (bool): Enable verbose output
- `detach` (bool): Don't wait for completion
- `specific_arch` (str, optional): Build for specific architecture only

**Returns:**
- `bool`: True if all builds were successful

**Multi-Architecture Features:**
- **Automatic Server Selection**: Chooses best server for each architecture
- **Parallel Processing**: Handles multiple builds concurrently
- **Progress Tracking**: Shows progress for all builds simultaneously
- **Architecture Filtering**: Can build for specific architectures only
- **Intelligent Fallback**: Falls back to farm if direct servers unavailable

---

## Enhanced PKGBUILD Processing

### parse_pkgbuild_info()

Parse PKGBUILD file to extract package information.

```python
def parse_pkgbuild_info(pkgbuild_path: Path) -> Dict[str, Any]
```

**Parameters:**
- `pkgbuild_path` (Path): Path to PKGBUILD file

**Returns:**
- `Dict`: Package information including name, version, and architectures

**Enhanced Parsing Features:**
- **pkgbase Support**: Prefers pkgbase over pkgname when defined
- **Array Handling**: Properly handles pkgname arrays and architecture arrays
- **Version Detection**: Extracts pkgver and pkgrel information
- **Architecture Analysis**: Parses target architectures for build routing

**Example:**
```python
info = parse_pkgbuild_info(Path("PKGBUILD"))
print(f"Package: {info['pkgname']}")
print(f"Version: {info['pkgver']}-{info['pkgrel']}")
print(f"Architectures: {info['arch']}")
```

---

## Configuration Management

### load_config()

Load configuration from file with fallback handling.

```python
def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]
```

**Parameters:**
- `config_path` (Path, optional): Specific config file path

**Returns:**
- `Dict`: Configuration dictionary with defaults

**Configuration Features:**
- **Multiple Locations**: Searches standard configuration locations
- **Fallback Defaults**: Provides sensible defaults when config is missing
- **Validation**: Validates configuration structure and values
- **Environment Variables**: Supports environment variable overrides

### determine_server_url()

Determine which server URL to use based on configuration and options.

```python
def determine_server_url(args: argparse.Namespace, config: Dict) -> str
```

**Parameters:**
- `args` (argparse.Namespace): Command line arguments
- `config` (Dict): Configuration dictionary

**Returns:**
- `str`: Server URL to use

**Server Selection Logic:**
1. Use `--server` flag if provided
2. Use farm URL if `--farm` flag is provided
3. Use `default_server` from config
4. Fall back to localhost:8000

---

## Error Handling

### Exception Types

The client raises standard `requests` exceptions:

- `requests.HTTPError`: HTTP errors (4xx, 5xx responses)
- `requests.ConnectionError`: Connection errors
- `requests.Timeout`: Request timeouts
- `requests.RequestException`: General request errors

### Enhanced Error Handling

```python
try:
    build_id = client.build_package([Path("PKGBUILD")])
except requests.HTTPError as e:
    if e.response.status_code == 503:
        print("Server unavailable - try again later")
    elif e.response.status_code == 400:
        print("Invalid PKGBUILD or build request")
    else:
        print(f"HTTP Error: {e.response.status_code}")
        print(f"Response: {e.response.text}")
except requests.ConnectionError:
    print("Could not connect to server - check URL and network")
except requests.RequestException as e:
    print(f"Request error: {e}")
```

### Server Unavailability Handling

- **Cached Responses**: Uses cached build status during server outages
- **Graceful Degradation**: Continues operation with limited functionality
- **Retry Logic**: Automatic retries for transient network issues
- **Fallback Mechanisms**: Falls back to alternative servers when available

---

## Examples

### Basic Build Workflow

```python
from pathlib import Path
from apb import APBotClient

# Create client
client = APBotClient("http://build-server.example.com:8000")

# Submit build
files = [Path("PKGBUILD"), Path("source.tar.gz")]
build_id = client.build_package(files)
print(f"Build started: {build_id}")

# Monitor progress
while True:
    status = client.get_build_status(build_id)
    print(f"Status: {status['status']}")

    if status['status'] in ['completed', 'failed', 'cancelled']:
        break

    time.sleep(5)

# Download results if successful
if status['status'] == 'completed':
    for package in status['packages']:
        client.download_file(
            build_id,
            package['filename'],
            Path("./downloads/")
        )
```

### Real-time Build Monitoring

```python
from apb import APBotClient, monitor_build

client = APBotClient("http://build-server.example.com:8000")

# Submit build
build_id = client.build_package([Path("PKGBUILD")])

# Monitor with real-time output and automatic downloading
success = monitor_build(
    build_id,
    client,
    output_dir=Path("./output/x86_64"),
    verbose=True,
    allow_toggle=True
)

if success:
    print("Build completed successfully!")
else:
    print("Build failed or was cancelled")
```

### Multi-Architecture Build

```python
from pathlib import Path
from apb import build_for_multiple_arches, load_config

# Load configuration
config = load_config()

# Build for multiple architectures
success = build_for_multiple_arches(
    build_path=Path("./my-package/"),
    output_dir=Path("./output/"),
    config=config,
    verbose=True,
    specific_arch="x86_64,aarch64"  # Optional: build only these architectures
)

if success:
    print("All builds completed successfully")
else:
    print("Some builds failed")
```

### Using APB Farm

```python
from apb import APBotClient

# Connect to farm instead of individual server
client = APBotClient("http://farm.example.com:8080")

# Farm automatically routes builds to appropriate servers
build_id = client.build_package([Path("PKGBUILD")])

# Monitor as usual - farm handles server unavailability
status = client.get_build_status(build_id)
print(f"Build routed to: {status.get('server_url', 'unknown')}")
```

---

## Best Practices

### Error Handling
- Always wrap API calls in try-except blocks
- Check build status before attempting downloads
- Handle connection errors gracefully
- Use retry logic for transient failures

### Performance
- Use streaming methods for large outputs
- Implement proper timeout handling
- Cache server information when possible
- Use farms for automatic load balancing

### Configuration
- Use configuration files for consistent settings
- Set appropriate default architectures
- Configure output directories for organization
- Use farms for multi-server environments

### Monitoring
- Implement status callbacks for long-running builds
- Use real-time streaming for immediate feedback
- Enable interactive controls for manual monitoring
- Set up automatic downloading for completed builds

### Security
- Use HTTPS in production
- Validate server certificates
- Implement proper authentication if required
- Sanitize file paths and names

### Architecture Management
- Specify target architectures explicitly when needed
- Use farm routing for automatic architecture selection
- Organize output by architecture for clarity
- Test builds on multiple architectures when possible
