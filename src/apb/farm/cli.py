"""APB farm CLI entry point."""

import argparse
import logging
import signal

import uvicorn

from apb import VERSION
from apb.config import load_config
from apb.farm import core
from apb.farm.app import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="APB Farm - Arch Package Builder Farm")
    parser.add_argument("--host", default=core.DEFAULT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=core.DEFAULT_PORT, help="Port to bind to")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
    parser.add_argument("--config", type=core.Path, help="Configuration file path")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    signal.signal(signal.SIGINT, core.signal_handler)
    signal.signal(signal.SIGTERM, core.signal_handler)

    core.config = load_config(args.config, strict=True)
    if not core.config.get("servers"):
        logging.error("No servers configured in apb.json")
        raise SystemExit(1)

    logging.info("Starting APB Farm v%s on %s:%s", VERSION, args.host, args.port)
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level=args.log_level.lower())


if __name__ == "__main__":
    main()
