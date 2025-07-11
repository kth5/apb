# APB Package Structure

This PKGBUILD creates a complete Arch Linux package for the APB (Arch Package Builder) system.

## Package Contents

The package installs the following files:

### Executables
- `/usr/bin/apb` - Main APB client for interacting with servers
- `/usr/bin/apb-farm` - APB farm component for managing multiple build servers
- `/usr/bin/apb-server` - APB server component for building packages

### Configuration
- `/etc/apb/apb.json.example` - Example configuration file

### Systemd Integration
- `/usr/lib/sysusers.d/apb.conf` - Creates `apb` user and group
- `/usr/lib/tmpfiles.d/apb.conf` - Creates necessary directories in `/var/lib/apb/`

### Directory Structure

After installation, the following directories are created under `/var/lib/apb/`:

```
/var/lib/apb/
├── builds/      # Build artifacts and packages
├── buildroot/   # Build environments  
├── cache/       # Cached files
├── logs/        # Log files
├── farm/        # Farm-specific data
├── server/      # Server-specific data
└── config/      # Runtime configuration files
```

All directories are owned by `apb:apb` with mode `0755`.

## Dependencies

The package depends on the following Python packages:
- `python-fastapi` - Web framework for API endpoints
- `python-uvicorn` - ASGI server
- `python-psutil` - System information
- `python-aiohttp` - Async HTTP client
- `python-requests` - HTTP client library  
- `python-multipart` - Multipart form handling

## Installation

1. Place all source files in the same directory as the PKGBUILD:
   - `apb.py`
   - `apb-farm.py`
   - `apb-server.py`
   - `apb.json`
   - `apb.sysusers`
   - `apb.tmpfiles`
   - `apb.install`

2. Build the package:
   ```bash
   makepkg -si
   ```

## Post-Installation Setup

1. Copy the example configuration:
   ```bash
   sudo cp /etc/apb/apb.json.example /etc/apb/apb.json
   ```

2. Edit the configuration to match your environment:
   ```bash
   sudo editor /etc/apb/apb.json
   ```

3. The `apb` user and required directories are automatically created during installation.

## Usage Examples

### Running APB Server
```bash
# Run on default port (8000)
sudo -u apb apb-server

# Run on custom port  
sudo -u apb apb-server --port 8080
```

### Running APB Farm
```bash
# Run on default port (8080)
sudo -u apb apb-farm

# Run with custom config
sudo -u apb apb-farm --config /var/lib/apb/config/apb.json
```

### Using APB Client
```bash
# Submit a build
apb build PKGBUILD

# Check build status
apb status <build-id>

# Download build results
apb download <build-id> --output ./output/
```

## Service Management

For production use, consider creating systemd service files to manage APB components. Example service files can be found in the `examples/` directory (if provided).

## Security Notes

- The `apb` user is created with `/usr/bin/nologin` shell for security
- All APB data is contained within `/var/lib/apb/` 
- Configuration files in `/etc/apb/` should have appropriate permissions
- Consider using systemd services with proper sandboxing for production deployments 