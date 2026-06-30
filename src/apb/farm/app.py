"""APB farm FastAPI application."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apb import VERSION
from apb.config import load_config
from apb.farm import core
from apb.farm.routes import router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    core.config = load_config()
    if not core.config.get("servers"):
        logger.error("No servers configured")
        yield
        return

    core.build_database = core.init_database()
    core.auth_manager = core.AuthManager(core.build_database)
    await core.setup_http_session()

    core.background_tasks.extend([
        asyncio.create_task(core.process_build_queue()),
        asyncio.create_task(core.update_build_status()),
        asyncio.create_task(core.discover_builds()),
        asyncio.create_task(core.handle_unavailable_servers()),
        asyncio.create_task(core.cleanup_expired_tokens_task()),
        asyncio.create_task(core.cleanup_cache_task()),
    ])

    logger.info("APB Farm started with %s architecture groups", len(core.config.get("servers", {})))
    yield

    logger.info("Starting APB Farm shutdown...")
    core.shutdown_event.set()

    if core.background_tasks:
        for task in core.background_tasks:
            if not task.done():
                task.cancel()
        try:
            await asyncio.wait_for(asyncio.gather(*core.background_tasks, return_exceptions=True), timeout=10)
        except asyncio.TimeoutError:
            logger.warning("Some background tasks did not complete within timeout")

    try:
        await core.cleanup_http_session()
    except Exception as exc:
        logger.warning("Error cleaning up HTTP session: %s", exc)

    if core.build_database:
        try:
            core.build_database.close()
        except Exception as exc:
            logger.warning("Error closing database: %s", exc)

    logger.info("APB Farm shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(title="APB Farm", version=VERSION, lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    return app


app = create_app()
