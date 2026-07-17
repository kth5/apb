"""Upstream server proxy helpers for farm routes."""

from typing import Any, Dict, Optional

import httpx
from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse

from apb.farm import core


async def get_build_server_url(build_id: str) -> str:
    cursor = core.build_database.cursor()
    cursor.execute("SELECT server_url FROM builds WHERE id = ?", (build_id,))
    row = cursor.fetchone()
    if not row or not row[0]:
        raise HTTPException(status_code=404, detail="Build not found")
    return row[0]


async def proxy_get(build_id: str, path: str, *, timeout: float = 30.0) -> httpx.Response:
    server_url = await get_build_server_url(build_id)
    return await core.http_session.get(f"{server_url}{path}", timeout=timeout)


async def proxy_stream(build_id: str, path: str) -> StreamingResponse:
    server_url = await get_build_server_url(build_id)

    async def event_generator():
        async with core.http_session.stream("GET", f"{server_url}{path}") as response:
            async for chunk in response.aiter_bytes():
                yield chunk

    return StreamingResponse(event_generator(), media_type="text/event-stream")
