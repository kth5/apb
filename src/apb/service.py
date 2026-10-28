"""Shared FastAPI app and CLI bootstrap for the APB server and farm."""

import logging
from typing import Any, Union

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def configure_logging(level: Union[int, str] = logging.INFO) -> None:
    """Configure root logging with the shared APB format."""
    resolved_level = getattr(logging, level.upper()) if isinstance(level, str) else level
    logging.basicConfig(level=resolved_level, format=LOG_FORMAT)


def add_default_cors(app: FastAPI) -> None:
    """Allow cross-origin requests from any origin (dashboard and API clients)."""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def run_uvicorn(app: FastAPI, *, host: str, port: int, log_level: str = "info", **uvicorn_kwargs: Any) -> None:
    """Run ``app`` with uvicorn in a single worker."""
    uvicorn.run(app, host=host, port=port, log_level=log_level.lower(), workers=1, **uvicorn_kwargs)
