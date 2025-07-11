#!/bin/bash
# APB Test Script - Comprehensive test scenario
# This script starts a server, farm, and runs a complete build test

set -e  # Exit on error

# Configuration
TEST_DIR="$(pwd)/test"
ROOT_DIR="$(dirname "$TEST_DIR")"
CONFIG_FILE="$TEST_DIR/apb-test.json"
PACKAGE_DIR="$TEST_DIR/test-package"
OUTPUT_DIR="$TEST_DIR/output"
LOGS_DIR="$TEST_DIR/logs"

# Process IDs for cleanup
SERVER_PID=""
FARM_PID=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Cleanup function
cleanup() {
    log "Cleaning up test environment..."
    
    # Kill farm process
    if [ -n "$FARM_PID" ]; then
        log "Stopping APB Farm (PID: $FARM_PID)"
        kill $FARM_PID 2>/dev/null || true
        wait $FARM_PID 2>/dev/null || true
    fi
    
    # Kill server process
    if [ -n "$SERVER_PID" ]; then
        log "Stopping APB Server (PID: $SERVER_PID)"
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    
    # Clean up any remaining processes
    pkill -f "apb-server.py" 2>/dev/null || true
    pkill -f "apb-farm.py" 2>/dev/null || true
    
    log "Cleanup completed"
}

# Set up signal handlers
trap cleanup EXIT
trap cleanup SIGINT
trap cleanup SIGTERM

# Initialize test environment
init_test_env() {
    log "Initializing test environment..."
    
    # Create directories
    mkdir -p "$OUTPUT_DIR"
    mkdir -p "$LOGS_DIR"
    
    # Clean up any existing APB data
    rm -rf ~/.apb/buildroot 2>/dev/null || true
    rm -rf ~/.apb/builds 2>/dev/null || true
    rm -rf ~/.apb/farm.db 2>/dev/null || true
    
    # Make test script executable
    chmod +x "$PACKAGE_DIR/test-script.sh"
    
    success "Test environment initialized"
}

# Check dependencies
check_dependencies() {
    log "Checking dependencies..."
    
    local missing_deps=()
    
    # Check for required Python packages
    if ! python3 -c "import fastapi, uvicorn, psutil, aiohttp" 2>/dev/null; then
        missing_deps+=("python-fastapi python-uvicorn python-psutil python-aiohttp")
    fi
    
    # Check for makepkg and sudo
    if ! command -v makepkg &> /dev/null; then
        missing_deps+=("makepkg")
    fi
    
    if ! command -v sudo &> /dev/null; then
        missing_deps+=("sudo")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        error "Please install missing dependencies and try again"
        exit 1
    fi
    
    success "All dependencies found"
}

# Start APB Server
start_server() {
    log "Starting APB Server..."
    
    cd "$ROOT_DIR"
    python3 apb-server.py --host localhost --port 8000 > "$LOGS_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    
    log "APB Server started with PID: $SERVER_PID"
    
    # Wait for server to be ready
    local retries=0
    while [ $retries -lt 30 ]; do
        if curl -s http://localhost:8000/health > /dev/null 2>&1; then
            success "APB Server is ready"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done
    
    error "APB Server failed to start or is not responding"
    return 1
}

# Start APB Farm
start_farm() {
    log "Starting APB Farm..."
    
    cd "$ROOT_DIR"
    python3 apb-farm.py --config "$CONFIG_FILE" --host localhost --port 8080 > "$LOGS_DIR/farm.log" 2>&1 &
    FARM_PID=$!
    
    log "APB Farm started with PID: $FARM_PID"
    
    # Wait for farm to be ready
    local retries=0
    while [ $retries -lt 30 ]; do
        if curl -s http://localhost:8080/health > /dev/null 2>&1; then
            success "APB Farm is ready"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done
    
    error "APB Farm failed to start or is not responding"
    return 1
}

# Submit build to farm
submit_build() {
    log "Submitting build to APB Farm..."
    set -x
    cd "$ROOT_DIR"
    local build_output
    build_output=$(python3 apb.py --config "$CONFIG_FILE" --farm --verbose "$PACKAGE_DIR" 2>&1)
    local exit_code=$?
    
    echo "$build_output" | tee "$LOGS_DIR/client.log"
    
    if [ $exit_code -eq 0 ]; then
        success "Build completed successfully"
        return 0
    else
        error "Build failed with exit code: $exit_code"
        return 1
    fi
}

# Verify build results
verify_results() {
    log "Verifying build results..."
    
    # Check if package file exists
    local pkg_file=$(find "$OUTPUT_DIR" -name "*.pkg.tar.zst" | head -1)
    if [ -z "$pkg_file" ]; then
        error "No package file (*.pkg.tar.zst) found in output directory"
        return 1
    fi
    
    success "Found package file: $(basename "$pkg_file")"
    
    # Check if build.log exists
    local log_file=$(find "$OUTPUT_DIR" -name "build.log" | head -1)
    if [ -z "$log_file" ]; then
        error "No build.log found in output directory"
        return 1
    fi
    
    success "Found build log: $(basename "$log_file")"
    
    # Verify package contents
    log "Verifying package contents..."
    if tar -tf "$pkg_file" | grep -q "usr/bin/apb-test"; then
        success "Package contains expected binary"
    else
        error "Package does not contain expected binary"
        return 1
    fi
    
    if tar -tf "$pkg_file" | grep -q "usr/share/man/man1/apb-test.1"; then
        success "Package contains expected man page"
    else
        error "Package does not contain expected man page"
        return 1
    fi
    
    success "Package verification completed"
    return 0
}

# Print test summary
print_summary() {
    log "Test Summary:"
    echo "============================================="
    echo "Test Directory: $TEST_DIR"
    echo "Package Directory: $PACKAGE_DIR"
    echo "Output Directory: $OUTPUT_DIR"
    echo "Logs Directory: $LOGS_DIR"
    echo ""
    echo "Generated Files:"
    find "$OUTPUT_DIR" -type f -exec ls -lh {} \; 2>/dev/null || echo "  No files found"
    echo ""
    echo "Log Files:"
    find "$LOGS_DIR" -type f -exec ls -lh {} \; 2>/dev/null || echo "  No log files found"
    echo "============================================="
}

# Main test execution
main() {
    log "Starting APB Test Scenario"
    log "Test directory: $TEST_DIR"
    
    # Initialize
    init_test_env
    check_dependencies
    
    # Start services
    start_server
    start_farm
    
    # Give services time to fully initialize
    sleep 2
    
    # Run build test
    submit_build
    
    # Verify results
    verify_results
    
    # Print summary
    print_summary
    
    success "APB Test Scenario completed successfully!"
    
    log "Services will continue running. Press Ctrl+C to stop them."
    
    # Keep script running to maintain services
    while true; do
        sleep 10
        # Check if services are still running
        if ! kill -0 $SERVER_PID 2>/dev/null; then
            error "APB Server has stopped unexpectedly"
            break
        fi
        if ! kill -0 $FARM_PID 2>/dev/null; then
            error "APB Farm has stopped unexpectedly"
            break
        fi
    done
}

# Execute main function
main "$@" 
