"""APB farm CLI entry point."""

import argparse
import logging
import signal
from pathlib import Path

from apb import VERSION
from apb.config import load_config
from apb.constants import FARM_DEFAULT_HOST, FARM_DEFAULT_PORT
from apb.farm import core
from apb.multipart_compat import install_multipart_compat
from apb.service import configure_logging, run_uvicorn

install_multipart_compat()

from apb.farm.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="APB Farm - Arch Package Builder Farm")
    parser.add_argument("--host", default=FARM_DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=FARM_DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("--config", type=Path, help="Configuration file path")
    args = parser.parse_args()

    configure_logging(args.log_level)

    signal.signal(signal.SIGINT, core.signal_handler)
    signal.signal(signal.SIGTERM, core.signal_handler)

    core.config = load_config(args.config, strict=True)
    if not core.config.get("servers"):
        logging.error("No servers configured in apb.json")
        raise SystemExit(1)

    logging.info("Starting APB Farm v%s on %s:%s", VERSION, args.host, args.port)
    run_uvicorn(create_app(), host=args.host, port=args.port, log_level=args.log_level)


if __name__ == "__main__":
    main()
