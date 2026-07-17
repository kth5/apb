"""APB server CLI entry point."""

import argparse
import logging
import resource
import signal
import sys

import uvicorn

from apb import VERSION
from apb.multipart_compat import install_multipart_compat
from apb.server import engine

install_multipart_compat()

from apb.server.app import create_app

logger = logging.getLogger(__name__)


def signal_handler(signum, frame):
    logger.info("Received signal %s, shutting down...", signum)
    engine.shutdown_event.set()
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="APB Server - Arch Package Builder")
    parser.add_argument("--host", default=engine.DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=engine.DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--buildroot", type=engine.Path, default=engine.DEFAULT_BUILDROOT, help="Buildroot directory")
    parser.add_argument("--builds-dir", type=engine.Path, default=engine.DEFAULT_BUILDS_DIR, help="Builds directory")
    parser.add_argument("--max-concurrent", type=int, default=engine.DEFAULT_MAX_CONCURRENT, help="Max concurrent builds")
    parser.add_argument("--buildroot-autorecreate", type=int, help="Recreate buildroot after N builds")
    parser.add_argument("--architecture", type=str, help="Override detected architecture")
    parser.add_argument("--max-file-size", type=int, default=100 * 1024 * 1024, help="Maximum file size in bytes")
    parser.add_argument("--max-request-size", type=int, default=500 * 1024 * 1024, help="Maximum total request size")
    parser.add_argument("--build-timeout", type=int, default=engine.BUILD_TIMEOUT_DEFAULT, help="Maximum build time")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    engine.MAX_FILE_SIZE = args.max_file_size
    engine.MAX_REQUEST_SIZE = args.max_request_size
    engine.BUILD_TIMEOUT = args.build_timeout

    engine.server_config = {
        "host": args.host,
        "port": args.port,
        "buildroot": args.buildroot,
        "builds_dir": args.builds_dir,
        "max_concurrent": args.max_concurrent,
        "buildroot_autorecreate": args.buildroot_autorecreate,
        "architecture_override": args.architecture,
        "max_file_size": args.max_file_size,
        "max_request_size": args.max_request_size,
        "build_timeout": args.build_timeout,
    }

    args.buildroot.mkdir(parents=True, exist_ok=True)
    args.builds_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Starting APB Server v%s", VERSION)
    logger.info("Detected server architecture: %s", engine.get_server_architecture())

    if not engine.setup_buildroot(args.buildroot):
        logger.error("Failed to setup buildroot during startup")
        sys.exit(1)

    engine.cleanup_orphaned_srcdest_locks()

    try:
        for limit_name in (
            "RLIMIT_AS", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_CORE",
            "RLIMIT_FSIZE", "RLIMIT_NOFILE", "RLIMIT_NPROC",
        ):
            if hasattr(resource, limit_name):
                try:
                    resource.setrlimit(getattr(resource, limit_name), (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                except (OSError, ValueError):
                    pass
    except Exception as exc:
        logger.warning("Error configuring resource limits: %s", exc)

    try:
        uvicorn.run(
            create_app(),
            host=args.host,
            port=args.port,
            log_level="debug" if args.debug else "info",
            workers=1,
            timeout_keep_alive=60,
            access_log=args.debug,
            limit_concurrency=100,
        )
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
    except Exception as exc:
        logger.error("Server error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
