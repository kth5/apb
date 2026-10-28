"""Unit tests for build server admin cleanup endpoint."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from apb.multipart_compat import install_multipart_compat

install_multipart_compat()

from apb.server import routes as server_routes


@pytest.fixture
def admin_client():
    app = FastAPI()
    app.include_router(server_routes.router)
    return TestClient(app)


def test_admin_cleanup_triggers_memory_cleanup(admin_client: TestClient):
    with patch("apb.server.routes.engine.cleanup_build_data") as cleanup_mock:
        response = admin_client.post("/admin/cleanup")

    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["message"] == "In-memory build data cleanup completed"
    assert payload["cleanup_id"].startswith("cleanup_")
    cleanup_mock.assert_called_once()
