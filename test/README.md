# APB Test Scenario

This directory contains a comprehensive test scenario for the APB (Arch Package Builder) system. The test demonstrates a complete workflow from starting services to building and downloading packages.

## Test Overview

The test scenario includes:
1. **APB Server**: Handles the actual package building
2. **APB Farm**: Manages and distributes builds to servers
3. **Test Package**: A simple package (`apb-test-package`) that builds successfully
4. **Automated Testing**: Complete end-to-end test with verification

## Directory Structure

```
test/
├── README.md              # This file
├── run-test.sh            # Main test script
├── cleanup.sh             # Cleanup script
├── apb-test.json          # Configuration file
├── test-package/          # Test package directory
│   ├── PKGBUILD          # Package build script
│   └── test-script.sh    # Simple test script
├── output/               # Generated build outputs (created during test)
└── logs/                 # Log files (created during test)
```

## Prerequisites

Before running the test, ensure you have:

1. **Python packages**:
   ```bash
   pip install fastapi uvicorn psutil aiohttp
   ```

2. **System packages** (Arch Linux):
   ```bash
   sudo pacman -S base-devel
   ```

3. **Sudo access** (required for creating buildroot)

## Running the Test

### Quick Start

1. Make the test script executable:
   ```bash
   chmod +x test/run-test.sh
   ```

2. Run the test:
   ```bash
   ./test/run-test.sh
   ```

### What the Test Does

The test script performs the following steps:

1. **Initialize Environment**: Creates output directories and cleans up old data
2. **Check Dependencies**: Verifies all required packages are installed
3. **Start APB Server**: Launches the build server on `localhost:8000`
4. **Start APB Farm**: Launches the farm manager on `localhost:8080`
5. **Submit Build**: Submits the test package for building
6. **Monitor Progress**: Waits for the build to complete
7. **Download Results**: Downloads the built package and build log
8. **Verify Results**: Checks that expected files were created
9. **Keep Services Running**: Leaves services running for manual testing

### Expected Output

On successful completion, you should see:
- A package file: `apb-test-package-1.0.0-1-x86_64.pkg.tar.zst`
- A build log: `build.log`
- Various log files in the `logs/` directory

### Test Results

The test verifies:
- ✅ Package file (`.pkg.tar.zst`) is created
- ✅ Build log is available
- ✅ Package contains expected files (`usr/bin/apb-test`, `usr/share/man/man1/apb-test.1`)
- ✅ Services remain running and accessible

## Manual Testing

After the automated test completes, the services continue running. You can:

1. **Visit the Farm Dashboard**: http://localhost:8080/dashboard
2. **Check Build Status**: http://localhost:8080/build/{build_id}/status
3. **View Server Info**: http://localhost:8000/
4. **Submit Additional Builds**: Use the `apb.py` client with `--farm` flag

## Cleanup

To stop all services and clean up:

```bash
# Stop services but keep output files
./test/cleanup.sh

# Stop services and remove all output files
./test/cleanup.sh --full
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**:
   - Check if services are already running: `netstat -tlnp | grep :800`
   - Clean up: `./test/cleanup.sh`

2. **Permission Errors**:
   - Ensure you can run `sudo` commands
   - Check that your user is in the `wheel` group

3. **Build Failures**:
   - Check server logs: `test/logs/server.log`
   - Check farm logs: `test/logs/farm.log`
   - Verify buildroot setup: `ls -la ~/.apb/buildroot/`

4. **Missing Dependencies**:
   - Install FastAPI: `pip install fastapi uvicorn psutil aiohttp`
   - Install build tools: `sudo pacman -S base-devel`

### Log Files

- `test/logs/server.log`: APB Server output
- `test/logs/farm.log`: APB Farm output  
- `test/logs/client.log`: APB Client output
- `test/output/build.log`: Build process log

## Test Package Details

The test package (`apb-test-package`) is a minimal package that:
- Installs a simple shell script to `/usr/bin/apb-test`
- Creates a basic man page
- Has no external dependencies
- Builds quickly and reliably

You can examine the package contents with:
```bash
tar -tf test/output/apb-test-package-1.0.0-1-x86_64.pkg.tar.zst
```

## Configuration

The test uses `apb-test.json` for configuration:
- Server: `http://localhost:8000`
- Farm: `http://localhost:8080`
- Architecture: `x86_64`
- Output directory: `./test/output`

## Advanced Usage

### Running Individual Components

You can start components individually for debugging:

```bash
# Start server only
python3 apb-server.py --host localhost --port 8000

# Start farm only
python3 apb-farm.py --config test/apb-test.json --host localhost --port 8080

# Submit build manually
python3 apb.py --config test/apb-test.json --farm --verbose test/test-package/
```

### Custom Test Packages

You can create your own test packages by:
1. Creating a new directory in `test/`
2. Adding a `PKGBUILD` file
3. Running: `python3 apb.py --config test/apb-test.json --farm --verbose test/your-package/`

## Expected Test Duration

- **Setup**: ~10 seconds
- **Service Startup**: ~30 seconds
- **Build Process**: ~60-120 seconds
- **Total**: ~2-3 minutes

The test is designed to be fast and reliable for continuous integration and development testing. 