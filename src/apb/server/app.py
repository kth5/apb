"""APB server FastAPI application factory."""

import asyncio
import gc
import logging
import subprocess
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from apb import VERSION
from apb.server import engine
from apb.server.routes import router
from apb.service import add_default_cors

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global resource_monitor_thread
    resource_monitor_thread = None

    if "max_concurrent" in engine.server_config:
        engine.build_executor.shutdown(wait=False)
        from concurrent.futures import ThreadPoolExecutor

        engine.build_executor = ThreadPoolExecutor(max_workers=engine.server_config["max_concurrent"])
        logger.info("Build executor updated with %s max workers", engine.server_config["max_concurrent"])

    resource_monitor_thread = threading.Thread(target=engine.monitor_resources, daemon=True)
    resource_monitor_thread.start()

    queue_thread = threading.Thread(target=engine.process_build_queue, daemon=True)
    queue_thread.start()
    logger.info("Queue processor thread started: %s", queue_thread.is_alive())

    if engine.server_config.get("srcdest_cleanup_interval", 0) > 0:
        srcdest_cleanup_thread = threading.Thread(
            target=engine.monitor_srcdest_cleanup,
            daemon=True,
        )
        srcdest_cleanup_thread.start()
        logger.info("SRCDEST cleanup thread started")

    logger.info("APB Server background tasks started")

    yield

    logger.info("APB Server shutting down...")
    engine.shutdown_event.set()

    for build_id, process in engine.running_processes.items():
        try:
            is_buildroot_recreation = engine.buildroot_recreation_builds.get(build_id, False)
            termination_timeout = 300 if is_buildroot_recreation else 10
            process.terminate()
            process.wait(timeout=termination_timeout)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except Exception:
                pass
        except Exception as exc:
            logger.error("Error terminating build %s during shutdown: %s", build_id, exc)
            try:
                process.kill()
            except Exception:
                pass

    engine.build_executor.shutdown(wait=False)
    logger.info("APB Server shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(title="APB Server", version=VERSION, lifespan=lifespan)
    add_default_cors(app)

    @app.middleware("http")
    async def request_timeout_middleware(request: Request, call_next):
        try:
            if request.url.path.startswith("/build"):
                timeout = 300
            elif request.url.path.startswith("/stream"):
                timeout = None
            else:
                timeout = 30

            if timeout:
                return await asyncio.wait_for(call_next(request), timeout=timeout)
            return await call_next(request)
        except asyncio.TimeoutError:
            logger.warning("Request timeout for %s %s", request.method, request.url.path)
            return JSONResponse(
                status_code=408,
                content={"error": "Request timeout", "detail": "Request took too long to process"},
            )
        except Exception as exc:
            logger.error("Error in request timeout middleware: %s", exc)
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "detail": str(exc)},
            )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception in %s %s: %s", request.method, request.url, exc)
        gc.collect()
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc), "type": type(exc).__name__},
        )

    app.include_router(router)
    return app


app = create_app()
