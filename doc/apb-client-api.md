# APB Client API Documentation

The APB Client is a Python library and command-line tool that provides a convenient interface for interacting with APB Servers and APB Farm instances.

## Installation

The APB Client is included in the main APB package. No separate installation is required.

## Authentication

The APB Client includes comprehensive authentication support for connecting to APB Farm instances with secure token-based authentication.

### Authentication Overview

- **APB Farm Authentication**: Full authentication support when using `--farm` flag
- **Token Storage**: Secure local storage of authentication tokens
- **Automatic Token Management**: Token renewal and expiration handling
- **Multiple Farm Support**: Store tokens for different farm instances
- **Command Line Integration**: Built-in login/logout commands

### Authentication Configuration

Authentication tokens are stored in `~/.apb/auth.json` with the following structure:

```json
{
  "tokens": {
    "http://farm.example.com:8080": "your_secure_token_here",
    "http://localhost:8080": "another_token_for_dev"
  }
}
```

**Security Features:**
- File permissions set to 600 (read/write for owner only)
- Tokens are automatically renewed on use
- Support for multiple farm instances with separate tokens

### Command Line Authentication

```bash
# Login to farm
python apb.py --farm --login

# Login with specific username
python apb.py --farm --login --username myuser

# Check authentication status
python apb.py --farm --auth-status

# Logout from farm
python apb.py --farm --logout

# Build with authentication (automatic if logged in)
python apb.py --farm /path/to/package/
```

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

# Farm with authentication
python apb.py --farm --login
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
from apb import APBotClient, APBAuthClient

# Create authentication client for farm
auth_client = APBAuthClient("http://farm.example.com:8080")

# Login programmatically
auth_client.login("username", "password")

# Create client instance with authentication
client = APBotClient("http://farm.example.com:8080", auth_client)

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

### Authentication Options

- `--login`: Login to farm (requires `--farm` flag)
- `--logout`: Logout from farm (requires `--farm` flag)
- `--auth-status`: Show authentication status for farm
- `--username USERNAME`: Username for login (optional, will prompt if not provided)

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

## Authentication Workflow

### Initial Setup

1. **Configure Farm URL**: Set `farm_url` in configuration file
2. **Login**: Use `--login` to authenticate with farm
3. **Build**: Submit builds normally - authentication is automatic

```bash
# 1. Configure (optional - can also specify with --server)
echo '{"farm_url": "https://farm.example.com"}' > ~/.apb/apb.json

# 2. Login
python apb.py --farm --login --username myuser

# 3. Build (authentication automatic)
python apb.py --farm ./my-package/
```

### Authentication Commands

#### Login Command

```bash
# Interactive login (prompts for username and password)
python apb.py --farm --login

# Login with specified username (prompts for password)
python apb.py --farm --login --username myuser

# Login with environment variables
FARM_USERNAME=myuser FARM_PASSWORD=mypass python apb.py --farm --login
```

**Example Output:**
```
Username: myuser
Password: [hidden]
Successfully logged in as myuser
Logged in as: myuser (user)
```

#### Authentication Status

```bash
python apb.py --farm --auth-status
```

**Example Output (Authenticated):**
```
Authenticated as: myuser (user)
Farm URL: https://farm.example.com
```

**Example Output (Not Authenticated):**
```
Not authenticated
Farm URL: https://farm.example.com
Use --login to authenticate
```

#### Logout Command

```bash
python apb.py --farm --logout
```

**Example Output:**
```
Successfully logged out
```

### Error Handling

Authentication errors are handled gracefully with clear user messages:

```bash
# Authentication required
python apb.py --farm ./my-package/
# Output: Authentication required. Please login first using: apb --farm --login

# Invalid credentials
python apb.py --farm --login --username wronguser
# Output: Login failed: Invalid username or password

# Token expired
python apb.py --farm ./my-package/
# Output: Authentication token expired. Please login again using: apb --farm --login
```

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
APBotClient(server_url: str, auth_client: Optional[APBAuthClient] = None)
```

**Parameters:**
- `server_url` (str): Base URL of the APB server or farm
- `auth_client` (APBAuthClient, optional): Authentication client for farm connections

**Example:**
```python
# Farm connection with authentication
auth_client = APBAuthClient("https://farm.example.com")
auth_client.login("username", "password")
client = APBotClient("https://farm.example.com", auth_client)

# Direct server connection (no authentication)
client = APBotClient("http://build-server.example.com:8000")
```

#### Authentication Integration

When an APBAuthClient is provided, all requests automatically include authentication headers:

```python
# Authentication headers are automatically added
build_id = client.build_package([Path("PKGBUILD")])

# No manual header management required
status = client.get_build_status(build_id)
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
def submit_build(server_url: str, pkgbuild_path: Path, source_files: List[Path], auth_client: Optional[APBAuthClient] = None) -> Optional[str]
```

**Parameters:**
- `server_url` (str): Server URL
- `pkgbuild_path` (Path): Path to PKGBUILD file
- `source_files` (List[Path]): List of source files
- `auth_client` (APBAuthClient, optional): Authentication client for farm connections

**Returns:**
- `Optional[str]`: Build ID if successful, None otherwise

### submit_build_to_farm()

Submit a build to a farm server with authentication support.

```python
def submit_build_to_farm(server_url: str, pkgbuild_path: Path, source_files: List[Path],
                        architectures: List[str] = None,
                        auth_client: Optional[APBAuthClient] = None) -> Optional[Dict]
```

**Parameters:**
- `server_url` (str): Farm server URL
- `pkgbuild_path` (Path): Path to PKGBUILD file
- `source_files` (List[Path]): List of source files
- `architectures` (List[str], optional): Target architectures
- `auth_client` (APBAuthClient, optional): Authentication client

**Returns:**
- `Optional[Dict]`: Full response dictionary if successful, None otherwise

**Enhanced Features:**
- **Authentication Support**: Automatic authentication header inclusion
- **Error Handling**: Clear authentication error messages
- **Multi-Architecture**: Support for architecture-specific builds

**Example:**
```python
# With authentication
auth_client = APBAuthClient("https://farm.example.com")
auth_client.login("username", "password")

response = submit_build_to_farm(
    "https://farm.example.com",
    Path("PKGBUILD"),
    [Path("source.tar.gz")],
    ["x86_64", "aarch64"],
    auth_client
)
```

### monitor_build()

Monitor a build with optional real-time output and automatic downloading.

```python
def monitor_build(build_id: str, client: APBotClient, output_dir: Path = None,
                 verbose: bool = False, allow_toggle: bool = True,
                 status_callback = None, pkgname: str = None, arch: str = None) -> bool
```

**Parameters:**
- `build_id` (str): Build ID to monitor
- `client` (APBotClient): Client instance
- `output_dir` (Path, optional): Directory to download results
- `verbose` (bool): Enable verbose output
- `allow_toggle` (bool): Allow toggling output display
- `status_callback` (callable, optional): Callback for status updates
- `pkgname` (str, optional): Package name to display
- `arch` (str, optional): Architecture being built (for display purposes)

**Returns:**
- `bool`: True if build was successful

### monitor_farm_builds()

Monitor multiple builds from a farm submission with authentication support.

```python
def monitor_farm_builds(builds: List[Dict], client: APBotClient, output_dir: Path = None,
                       verbose: bool = False, pkgbuild_path: Path = None,
                       auth_client: Optional[APBAuthClient] = None) -> bool
```

**Parameters:**
- `builds` (List[Dict]): List of build information dictionaries
- `client` (APBotClient): Client instance
- `output_dir` (Path, optional): Base output directory
- `verbose` (bool): Enable verbose output
- `pkgbuild_path` (Path, optional): Path to PKGBUILD file
- `auth_client` (APBAuthClient, optional): Authentication client

**Returns:**
- `bool`: True if all builds were successful

**Authentication Features:**
- **Automatic Authentication**: Uses auth_client for all requests
- **Permission Checking**: Respects user permissions for build cancellation
- **Error Handling**: Graceful handling of authentication errors

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
                            specific_arch: str = None, force: bool = False,
                            auth_client: Optional[APBAuthClient] = None) -> bool
```

**Parameters:**
- `build_path` (Path): Path to package directory
- `output_dir` (Path): Output directory
- `config` (Dict): Configuration dictionary
- `verbose` (bool): Enable verbose output
- `detach` (bool): Don't wait for completion
- `specific_arch` (str, optional): Build for specific architecture only
- `force` (bool): Force rebuild even if package exists
- `auth_client` (APBAuthClient, optional): Authentication client

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

### Authentication Workflow

```python
from pathlib import Path
from apb import APBAuthClient, APBotClient

# Setup authentication
auth_client = APBAuthClient("https://farm.example.com")

# Login
if auth_client.login("username", "password"):
    print("Login successful!")

    # Get user info
    user_info = auth_client.get_user_info()
    print(f"Logged in as: {user_info['username']} ({user_info['role']})")

    # Create authenticated client
    client = APBotClient("https://farm.example.com", auth_client)

    # Submit build (authentication automatic)
    build_id = client.build_package([Path("PKGBUILD")])
    print(f"Build submitted: {build_id}")
else:
    print("Login failed")
```

### Farm Build with Authentication

```python
from apb import APBAuthClient, submit_build_to_farm, monitor_farm_builds

# Setup authentication
auth_client = APBAuthClient("https://farm.example.com")
auth_client.login("username", "password")

# Submit build to farm
response = submit_build_to_farm(
    "https://farm.example.com",
    Path("PKGBUILD"),
    [Path("source.tar.gz")],
    ["x86_64", "aarch64"],
    auth_client
)

if response and 'builds' in response:
    # Monitor builds
    client = APBotClient("https://farm.example.com", auth_client)
    success = monitor_farm_builds(
        response['builds'],
        client,
        output_dir=Path("./output/"),
        verbose=True,
        auth_client=auth_client
    )

    if success:
        print("All builds completed successfully!")
else:
    print("Failed to submit builds")
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
from apb import APBotClient, APBAuthClient

# Setup authentication for farm
auth_client = APBAuthClient("http://farm.example.com:8080")
auth_client.login("username", "password")

# Connect to farm with authentication
client = APBotClient("http://farm.example.com:8080", auth_client)

# Farm automatically routes builds to appropriate servers
build_id = client.build_package([Path("PKGBUILD")])

# Monitor as usual - farm handles server unavailability
status = client.get_build_status(build_id)
print(f"Build routed to: {status.get('server_url', 'unknown')}")
```

### Command Line Authentication Examples

```bash
# Complete workflow from scratch
python apb.py --farm --login --username myuser
python apb.py --farm ./my-package/

# Check what user is logged in
python apb.py --farm --auth-status

# Build for specific architectures with authentication
python apb.py --farm --arch x86_64,aarch64 ./my-package/

# Monitor with authentication
python apb.py --farm --monitor 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Logout when done
python apb.py --farm --logout
```

### Environment Variables

You can use environment variables for automated authentication:

```bash
# Set credentials
export APB_FARM_URL="https://farm.example.com"
export APB_USERNAME="myuser"
export APB_PASSWORD="mypassword"

# Login and build
python apb.py --farm --login && python apb.py --farm ./my-package/
```

### Error Handling with Authentication

```python
from apb import APBAuthClient, APBotClient
import requests
import getpass

auth_client = APBAuthClient("https://farm.example.com")
client = APBotClient("https://farm.example.com", auth_client)

try:
    # This will fail if not authenticated
    build_id = client.build_package([Path("PKGBUILD")])
except requests.HTTPError as e:
    if e.response.status_code == 401:
        print("Authentication required - please login")
        # Attempt login
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        if auth_client.login(username, password):
            print("Login successful, retrying build...")
            build_id = client.build_package([Path("PKGBUILD")])
        else:
            print("Login failed")
    elif e.response.status_code == 403:
        print("Access denied - insufficient permissions")
    else:
        print(f"HTTP Error: {e.response.status_code}")
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

## Authentication Classes

### Class: APBAuthClient

Handles authentication for APB Farm connections.

#### Constructor

```python
APBAuthClient(farm_url: str, config_path: Optional[Path] = None)
```

**Parameters:**
- `farm_url` (str): Farm URL for authentication
- `config_path` (Path, optional): Custom path for token storage

**Example:**
```python
auth_client = APBAuthClient("https://farm.example.com:8080")
```

#### Authentication Methods

##### login()

Login with username and password.

```python
def login(self, username: str, password: str) -> bool
```

**Parameters:**
- `username` (str): Username for authentication
- `password` (str): Password for authentication

**Returns:**
- `bool`: True if login successful

**Example:**
```python
success = auth_client.login("myuser", "mypassword")
if success:
    print("Login successful!")
```

##### logout()

Logout and revoke current token.

```python
def logout(self) -> bool
```

**Returns:**
- `bool`: True if logout successful

**Example:**
```python
auth_client.logout()
```

##### is_authenticated()

Check if currently authenticated.

```python
def is_authenticated(self) -> bool
```

**Returns:**
- `bool`: True if authenticated

**Example:**
```python
if auth_client.is_authenticated():
    print("Ready to submit builds")
else:
    print("Please login first")
```

##### get_user_info()

Get current user information.

```python
def get_user_info(self) -> Optional[Dict[str, Any]]
```

**Returns:**
- `Optional[Dict]`: User information or None if not authenticated

**Example:**
```python
user_info = auth_client.get_user_info()
if user_info:
    print(f"Logged in as: {user_info['username']} ({user_info['role']})")
```

##### get_auth_headers()

Get authentication headers for requests.

```python
def get_auth_headers(self) -> Dict[str, str]
```

**Returns:**
- `Dict[str, str]`: Headers for authenticated requests

**Example:**
```python
headers = auth_client.get_auth_headers()
# Returns: {"Authorization": "Bearer <token>"} or {}
```


