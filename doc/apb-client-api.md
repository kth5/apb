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

# Farm: queue only selected PKGBUILD architectures (multi-arch PKGBUILD)
python apb.py --farm --arch powerpc /path/to/package/

# Monitor existing build
python apb.py --monitor 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Download build results
python apb.py --download 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3 --output-dir ./downloads/

# Download latest successful farm builds for every arch=() from PKGBUILD
python apb.py --farm --download
python apb.py --farm --download /path/to/package/
python apb.py --farm --download --arch x86_64,aarch64 /path/to/package/

# Check build status
python apb.py --status 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# Cancel running build
python apb.py --cancel 48ea1df5-f7f3-477e-a7a7-36e526ea7cd3

# List and test servers
python apb.py --list-servers
```

### Python Library

```python
from pathlib import Path

from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient

# Create authentication client for farm
auth_client = APBAuthClient("http://farm.example.com:8080")

# Login programmatically
auth_client.login("username", "password")

# Create client instance with authentication
client = APBotClient("http://farm.example.com:8080", auth_client)

# Submit the package directory (PKGBUILD plus sources)
response = client.build_package(Path("./my-package"))

# Check build status
status = client.get_build_status(response.build_id)

# Download results
client.download_file(response.build_id, "package.pkg.tar.xz", Path("./downloads/"))
```

---

## Command Line Options

### Basic Options

- `pkgbuild_path` (positional): Path to PKGBUILD or package directory (optional if PKGBUILD in current dir)
- `--server URL`: Server URL (default: from config or http://localhost:8000)
- `--arch ARCH`: Target architecture(s) (comma-separated). With `--farm`, only these names from PKGBUILD `arch=()` are queued on matching build servers
- `--config PATH`: Path to configuration file
- `--verbose`: Enable verbose output
- `--quiet`: Suppress output except errors

### Authentication Options

- `--login`: Login to farm (requires `--farm` flag)
- `--logout`: Logout from farm (requires `--farm` flag)
- `--auth-status`: Show authentication status for farm
- `--username USERNAME`: Username for login (optional, will prompt if not provided)
- `--2fa-method {totp,key,recovery}`: Second factor to use when the account has 2FA (optional). Without it, a connected FIDO2 security key is used when the account has one, otherwise the client asks for the authenticator code

### Build Options

- `--output-dir PATH`: Output directory for downloaded files (default: ./output)
- `--detach`: Submit build and exit (don't wait for completion)
- `--no-download`: Don't download build results
- `--force`: Force rebuild even if package exists

### PKGBUILD variables (client / farm)

- **`apb_arch_hint=<arch>`**: Only when `arch=(any)`. Farm and config-based (`apb.json` servers) builds run on servers of that architecture instead of the default lowest-load or first-configured choice. Does not change the package architecture (`any`); artifacts still go under `output/any/`. Ignored with a warning for any other `arch=()` list. Does not replace `--arch`.

### Monitoring Options

- `--monitor BUILD_ID`: Monitor existing build with real-time output
- `--download [BUILD_ID|PATH]`: Download by build ID, or (with `--farm`) latest successful builds for each `arch=()` from a PKGBUILD path / current directory
- `--status BUILD_ID`: Check build status
- `--cancel BUILD_ID`: Cancel running build

### Advanced Options

- `--farm`: Use APB Farm instead of direct server (recommended)
- `--list-servers`: List and test available servers
- `--cleanup`: Trigger in-memory build data cleanup on the server
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

**Two-factor authentication:**

Accounts with 2FA (always the case for admins) need a second factor after the password:
- **Security key**: when the account has a security key and a FIDO2 key (YubiKey etc.) is connected over USB, the client asks you to touch it. The farm must be reached through its public `farm_url` (HTTPS or `localhost`), because the key signs the origin
- **Authenticator app**: the client asks for the 6-digit code
- **Recovery code**: `--2fa-method recovery` asks for one of the single-use recovery codes

Admins without a second factor cannot log in with the CLI; the client prints the `/account/2fa` URL where the second factor can be enrolled in a browser.

```bash
# Use the authenticator app even when a security key is connected
python apb.py --farm --login --2fa-method totp
```

**Example Output:**
```
Username: myuser
Password: [hidden]
Authentication code: [hidden]
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

The client searches for configuration files in this order (`apb.constants.DEFAULT_CONFIG_PATHS`, shared with the farm):
1. `./apb.json` (current directory)
2. `/etc/apb/apb.json` (system-wide config)
3. `~/.apb/apb.json` (user home)
4. `~/.apb-farm/apb.json` (farm-specific)

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
response = client.build_package(Path("./my-package"))

# No manual header management required
status = client.get_build_status(response.build_id)
```

---

### Build Management Methods

#### build_package()

Submit a build to a server or farm. The build directory is packed into one tarball (the PKGBUILD plus sources, without build artifacts or `exclude_paths`) and posted as `build_tarball` to `POST /build`, together with the optional form fields.

```python
def build_package(self, build_path: Path,
                  exclude_paths: Optional[Iterable[Path]] = None,
                  architectures: Optional[List[str]] = None,
                  build_timeout: Optional[int] = None) -> BuildSubmitResponse
```

**Parameters:**
- `build_path` (Path): Directory containing the PKGBUILD and source files
- `exclude_paths` (Iterable[Path], optional): Paths left out of the tarball, such as the output directory
- `architectures` (List[str], optional): PKGBUILD `arch=()` entries the farm should queue (sent as the `architectures` form field)
- `build_timeout` (int, optional): Build timeout in seconds (`BUILD_TIMEOUT_MIN` to `BUILD_TIMEOUT_MAX`; admin only on the farm)

**Returns:**
- `FarmBuildSubmitResponse` when the farm queued per-architecture builds (`builds`, `queue_status`, ...)
- `BuildSubmitResponse` (`build_id`, `status`, `message`) from a build server

**Raises:**
- `httpx.HTTPError`: On HTTP error responses or connection errors
- `apb.client.api.BuildRejectedError`: The farm answered with an `error` payload (for example no servers for the requested architectures); the payload is in `exc.detail`
- `ValueError`: Missing PKGBUILD, invalid `build_timeout` or an invalid response

**Example:**
```python
response = client.build_package(Path("./my-package"), architectures=["x86_64"])
print(f"Build started: {response.build_id}")
```

#### get_build_status()

Get the current status of a build.

```python
def get_build_status(self, build_id: str) -> BuildStatusResponse
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `BuildStatusResponse`: Build status from `GET /build/{build_id}/status-api`. Farm-only fields (`artifacts_ready`, `queue_state`, `queue_position`, `server_unavailable`, ...) are `None` on build servers

**Example:**
```python
status = client.get_build_status("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3")
print(f"Status: {status.status}")
print(f"Package: {status.pkgname}")
for package in status.packages:
    print(package.filename, package.size)
```

#### wait_for_farm_artifacts()

Wait until a finished build's artifacts can be downloaded.

```python
def wait_for_farm_artifacts(self, build_id: str, timeout: float = 300.0,
                            poll_interval: float = 2.0) -> Optional[BuildStatusResponse]
```

The farm caches artifacts from the build server before serving them, and reports `artifacts_ready` once done. Build servers do not report `artifacts_ready`, so their status is returned straight away.

**Returns:**
- `BuildStatusResponse` once artifacts are ready, or `None` on timeout or when the build has not completed or failed

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
def get_build_by_id(self, build_id: str) -> BuildStatusResponse
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `BuildStatusResponse`: Same as `get_build_status()`, including packages, logs, and metadata

#### get_builds_by_pkgname()

Get builds for a specific package.

```python
def get_builds_by_pkgname(self, pkgname: str, limit: int = 20,
                          status: Optional[str] = None) -> BuildListResponse
```

**Parameters:**
- `pkgname` (str): Package name
- `limit` (int): Maximum number of builds to return (1-100)
- `status` (str, optional): Only return builds with this status

**Returns:**
- `BuildListResponse`: `builds` (newest first) and `total` (all matching builds)

**Example:**
```python
history = client.get_builds_by_pkgname("example-package", limit=5)
print(f"{len(history.builds)} of {history.total} builds")
for build in history.builds:
    print(build.build_id, build.status, build.created_at)
```

#### get_latest_build_by_pkgname()

Get the latest build for a specific package.

```python
def get_latest_build_by_pkgname(self, pkgname: str, successful_only: bool = True,
                                arch: Optional[str] = None) -> Optional[BuildSummary]
```

**Parameters:**
- `pkgname` (str): Package name
- `successful_only` (bool): Only consider successful builds
- `arch` (str, optional): Architecture filter. Use `'any'` for `arch=('any')` packages

**Returns:**
- `Optional[BuildSummary]`: Latest build, or `None` if none found

#### get_latest_builds_by_pkgname_per_arch()

Get the latest successful build for each architecture of a package.

```python
def get_latest_builds_by_pkgname_per_arch(self, pkgname: str,
                                          successful_only: bool = True) -> Dict[str, BuildSummary]
```

**Parameters:**
- `pkgname` (str): Package name
- `successful_only` (bool): Only consider successful builds

**Returns:**
- `Dict[str, BuildSummary]`: Mapping of `server_arch` to the latest build

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
def stream_build_updates(self, build_id: str) -> Generator[BuildStatusResponse, None, None]
```

**Parameters:**
- `build_id` (str): Build UUID

**Returns:**
- `Generator[BuildStatusResponse, None, None]`: Status every 5 seconds until the build reaches a terminal state

**Example:**
```python
for update in client.stream_build_updates("48ea1df5-f7f3-477e-a7a7-36e526ea7cd3"):
    print(f"Status: {update.status}")
    if update.queue_state == "farm":
        print(
            f"Farm queue position {update.queue_position}/{update.farm_queue_size} "
            f"({update.jobs_ahead} job(s) ahead)"
        )
```

When a build is waiting in the farm queue, status responses include `queue_state`, `queue_position`, `jobs_ahead`, and `farm_queue_size`. The CLI prints these while monitoring and removes farm-queued builds on interrupt or `--cancel`.

---

### Utility Methods

#### cleanup_server()

Trigger in-memory build data cleanup on the server.

```python
def cleanup_server(self) -> bool
```

**Returns:**
- `bool`: True if cleanup was triggered successfully

---

## High-Level Functions

These live in `apb.client.cli`.

### submit_build()

Submit a build directory to a server or farm. Farm and direct server submissions use the same function; it wraps `APBotClient.build_package()` and prints errors instead of raising them.

```python
def submit_build(server_url: str, build_path: Path,
                 auth_client: Optional[APBAuthClient] = None,
                 exclude_paths: Optional[List[Path]] = None,
                 architectures: Optional[List[str]] = None,
                 build_timeout: Optional[int] = None) -> Optional[BuildSubmitResponse]
```

**Parameters:**
- `server_url` (str): Server or farm URL
- `build_path` (Path): Directory containing the PKGBUILD and source files
- `auth_client` (APBAuthClient, optional): Authentication client for farm connections
- `exclude_paths` (List[Path], optional): Paths left out of the tarball
- `architectures` (List[str], optional): PKGBUILD architectures the farm should queue
- `build_timeout` (int, optional): Build timeout in seconds (admin only on the farm)

**Returns:**
- `FarmBuildSubmitResponse` or `BuildSubmitResponse` (see `build_package()`), or `None` when the submission failed. Authentication (401), permission (403) and farm rejection details are printed

**Example:**
```python
auth_client = APBAuthClient("https://farm.example.com")
auth_client.login("username", "password")

response = submit_build(
    "https://farm.example.com",
    Path("./my-package"),
    auth_client,
    architectures=["x86_64", "aarch64"],
)
```

### monitor_builds()

Monitor submitted builds in parallel, then download their artifacts.

```python
class MonitorTarget(NamedTuple):
    build_id: str
    client: APBotClient
    output_dir: Optional[Path] = None   # None disables downloads
    arch: Optional[str] = None          # used as the "[arch] " output prefix

def monitor_builds(targets: List[MonitorTarget], *, verbose: bool = False) -> Dict[str, Tuple[str, bool]]
```

**Returns:**
- `Dict[str, Tuple[str, bool]]`: Build ID mapped to (final status, is_successful). A build is successful when it completed and its artifacts were downloaded (or downloads are disabled)

**Behaviour:**
- One poll loop for farm and server builds, driven by `BuildStatusResponse` every 5 seconds
- Prints status changes and the farm queue position while a build waits in the farm queue
- Retries HTTP 502/503 and `server_unavailable` responses up to 8 times in a row; a cached terminal status is accepted after that
- Gives up after 5 consecutive other errors (such as 404)
- Waits for the farm's `artifacts_ready` before downloading completed or failed builds into `output_dir`
- Ctrl-C cancels every unfinished build

### monitor_build()

Monitor a single build and download its artifacts. Wraps `monitor_builds()`.

```python
def monitor_build(build_id: str, client: APBotClient, output_dir: Optional[Path] = None,
                  verbose: bool = False, arch: Optional[str] = None) -> bool
```

**Parameters:**
- `build_id` (str): Build ID to monitor
- `client` (APBotClient): Client instance
- `output_dir` (Path, optional): Directory to download results
- `verbose` (bool): Enable verbose output
- `arch` (str, optional): Architecture being built (for display purposes)

**Returns:**
- `bool`: True if the build completed and its artifacts were downloaded

### build_for_multiple_arches()

Build a package for multiple architectures using the per-architecture servers from the configuration. This is what `apb` runs when neither `--server` nor `--farm` is given.

```python
def build_for_multiple_arches(build_path: Path, output_dir: Path, config: Dict,
                              verbose: bool = False, detach: bool = False,
                              specific_arch: Optional[str] = None, force: bool = False,
                              auth_client: Optional[APBAuthClient] = None,
                              build_timeout: Optional[int] = None,
                              download: bool = True) -> bool
```

**Parameters:**
- `build_path` (Path): Path to package directory
- `output_dir` (Path): Output directory; results go to `output_dir/<arch>`
- `config` (Dict): Configuration dictionary
- `verbose` (bool): Enable verbose output
- `detach` (bool): Don't wait for completion
- `specific_arch` (str, optional): Comma-separated architectures to build (default: PKGBUILD `arch=()` entries with configured servers, or `any`)
- `force` (bool): Force rebuild even if package exists
- `auth_client` (APBAuthClient, optional): Authentication client
- `build_timeout` (int, optional): Build timeout in seconds
- `download` (bool): Download build results after completion

**Returns:**
- `bool`: True if every architecture was built (or, with `detach`, submitted) successfully or skipped because its package already exists. Architectures without configured servers count as failed.

**Multi-Architecture Features:**
- **Server Fallback**: Tries each configured server for an architecture until one accepts the build
- **Parallel Monitoring**: All submitted builds are monitored at the same time
- **Architecture Filtering**: Can build for specific architectures only
- **`arch=(any)` Support**: Uses `apb_arch_hint` or the first configured server architecture

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

The client raises `httpx` exceptions, plus `BuildRejectedError` for refused farm submissions:

- `httpx.HTTPStatusError`: HTTP errors (4xx, 5xx responses)
- `httpx.ConnectError`: Connection errors
- `httpx.TimeoutException`: Request timeouts
- `httpx.HTTPError`: Base class of all of the above
- `apb.client.api.BuildRejectedError` (a `ValueError`): The farm answered `POST /build` with an `error` payload

### Enhanced Error Handling

```python
import httpx

from apb.client.api import BuildRejectedError

try:
    build_id = client.build_package(Path("./my-package")).build_id
except BuildRejectedError as e:
    print(f"Farm refused the build: {e}")
    print(e.detail.get("available_architectures"))
except httpx.HTTPStatusError as e:
    if e.response.status_code == 503:
        print("Server unavailable - try again later")
    elif e.response.status_code == 400:
        print("Invalid PKGBUILD or build request")
    else:
        print(f"HTTP Error: {e.response.status_code}")
        print(f"Response: {e.response.text}")
except httpx.ConnectError:
    print("Could not connect to server - check URL and network")
except httpx.HTTPError as e:
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

from apb.client.api import APBotClient

# Create client
client = APBotClient("http://build-server.example.com:8000")

# Submit build
build_id = client.build_package(Path("./my-package")).build_id
print(f"Build started: {build_id}")

# Monitor progress
for status in client.stream_build_updates(build_id):
    print(f"Status: {status.status}")

# Download results if successful
if status.status == "completed":
    for package in status.packages:
        client.download_file(build_id, package.filename, Path("./downloads/"))
```

### Authentication Workflow

```python
from pathlib import Path
from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient

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
    response = client.build_package(Path("./my-package"))
    print(f"Build submitted: {response.build_id}")
else:
    print("Login failed")
```

### Farm Build with Authentication

```python
from pathlib import Path

from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient
from apb.client.cli import MonitorTarget, monitor_builds, submit_build

# Setup authentication
auth_client = APBAuthClient("https://farm.example.com")
auth_client.login("username", "password")

# Submit build to farm
response = submit_build(
    "https://farm.example.com",
    Path("./my-package"),
    auth_client,
    architectures=["x86_64", "aarch64"],
)

if response:
    # Monitor all queued builds in parallel, one output directory per architecture
    client = APBotClient("https://farm.example.com", auth_client)
    results = monitor_builds(
        [MonitorTarget(build.build_id, client, Path("./output") / build.arch, build.arch)
         for build in response.builds],
        verbose=True,
    )

    if all(is_successful for _status, is_successful in results.values()):
        print("All builds completed successfully!")
else:
    print("Failed to submit builds")
```

### Real-time Build Monitoring

```python
from pathlib import Path

from apb.client.api import APBotClient
from apb.client.cli import monitor_build

client = APBotClient("http://build-server.example.com:8000")

# Submit build
build_id = client.build_package(Path("./my-package")).build_id

# Monitor with status output and automatic downloading
success = monitor_build(
    build_id,
    client,
    output_dir=Path("./output/x86_64"),
    verbose=True,
    arch="x86_64",
)

if success:
    print("Build completed successfully!")
else:
    print("Build failed or was cancelled")
```

### Multi-Architecture Build

```python
from pathlib import Path
from apb.client.cli import build_for_multiple_arches
from apb.config import load_config

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
from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient

# Setup authentication for farm
auth_client = APBAuthClient("http://farm.example.com:8080")
auth_client.login("username", "password")

# Connect to farm with authentication
client = APBotClient("http://farm.example.com:8080", auth_client)

# Farm automatically routes builds to appropriate servers
response = client.build_package(Path("./my-package"))

# Monitor as usual - farm handles server unavailability
status = client.get_build_status(response.build_id)
print(f"Build routed to: {status.server_url or 'unknown'}")
```

### Command Line Authentication Examples

```bash
# Complete workflow from scratch
python apb.py --farm --login --username myuser
python apb.py --farm ./my-package/

# Check what user is logged in
python apb.py --farm --auth-status

# Build only for selected PKGBUILD architectures (not every arch=() entry)
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
import getpass
from pathlib import Path

import httpx

from apb.client.api import APBotClient
from apb.client.auth import APBAuthClient

auth_client = APBAuthClient("https://farm.example.com")
client = APBotClient("https://farm.example.com", auth_client)

try:
    # This will fail if not authenticated
    build_id = client.build_package(Path("./my-package")).build_id
except httpx.HTTPStatusError as e:
    if e.response.status_code == 401:
        print("Authentication required - please login")
        # Attempt login
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        if auth_client.login(username, password):
            print("Login successful, retrying build...")
            # A new client picks up the new token
            client = APBotClient("https://farm.example.com", auth_client)
            build_id = client.build_package(Path("./my-package")).build_id
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
- Use `monitor_builds()` to follow several builds in parallel
- Use `stream_build_updates()` for custom status handling
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

Login with username and password, completing two-factor authentication when the account has it.

```python
def login(self, username: str, password: str, mfa_method: Optional[str] = None, prompt: Callable[[str], str] = getpass.getpass) -> bool
```

**Parameters:**
- `username` (str): Username for authentication
- `password` (str): Password for authentication
- `mfa_method` (str, optional): `totp`, `key` or `recovery`; by default a connected security key is preferred, then the authenticator code
- `prompt` (callable, optional): Reads the authenticator or recovery code

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


