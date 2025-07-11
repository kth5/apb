#!/bin/bash
# APB Test Cleanup Script
# This script stops all APB processes and cleans up test data

set -e

# Configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$TEST_DIR/output"
LOGS_DIR="$TEST_DIR/logs"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

main() {
    log "Starting APB Test Cleanup"
    
    # Stop all APB processes
    log "Stopping all APB processes..."
    pkill -f "apb-server.py" 2>/dev/null || true
    pkill -f "apb-farm.py" 2>/dev/null || true
    sleep 2
    
    # Force kill if still running
    pkill -9 -f "apb-server.py" 2>/dev/null || true
    pkill -9 -f "apb-farm.py" 2>/dev/null || true
    
    # Clean up APB data directories
    log "Cleaning up APB data directories..."
    rm -rf ~/.apb/buildroot 2>/dev/null || true
    rm -rf ~/.apb/builds 2>/dev/null || true
    rm -rf ~/.apb/farm.db 2>/dev/null || true
    
    # Clean up test outputs (optional)
    if [ "$1" = "--full" ]; then
        log "Removing test output directories..."
        rm -rf "$OUTPUT_DIR"
        rm -rf "$LOGS_DIR"
        success "Full cleanup completed"
    else
        log "Keeping test output directories (use --full to remove them)"
        success "Cleanup completed"
    fi
    
    log "All APB processes stopped and data cleaned up"
}

main "$@" 