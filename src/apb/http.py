"""HTTP client helpers."""

import httpx

from apb.constants import user_agent


def create_sync_client(*, component: str = "Client", timeout: float = 300.0) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        headers={"User-Agent": user_agent(component)},
        follow_redirects=True,
    )


def create_async_client(*, component: str = "Farm", timeout: float = 120.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        headers={"User-Agent": user_agent(component)},
        follow_redirects=True,
    )
