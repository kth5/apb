from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from apb.models import (
    BuildListResponse,
    BuildStatusResponse,
    BuildSummary,
    FarmBuildSubmitResponse,
    LoginResponse,
    utc_datetime,
)

EPOCH = 1_700_000_000
EPOCH_UTC = datetime.fromtimestamp(EPOCH, timezone.utc)


@pytest.mark.parametrize(
    "value",
    [EPOCH, float(EPOCH), EPOCH_UTC.isoformat(), EPOCH_UTC.strftime("%Y-%m-%d %H:%M:%S UTC"), EPOCH_UTC.replace(tzinfo=None)],
)
def test_utc_datetime_normalises_inputs(value):
    assert utc_datetime(value) == EPOCH_UTC


@pytest.mark.parametrize("value", [None, "", 0, "unknown"])
def test_utc_datetime_treats_missing_as_none(value):
    assert utc_datetime(value) is None


def test_build_summary_serializes_iso_utc():
    summary = BuildSummary(build_id="b1", pkgname="foo", status="completed", start_time=EPOCH, created_at=EPOCH)
    data = summary.model_dump(mode="json")
    assert data["start_time"] == "2023-11-14T22:13:20Z"
    assert data["end_time"] is None
    assert BuildSummary.model_validate(data) == summary


def test_build_list_response_round_trip():
    response = BuildListResponse(
        pkgname="foo",
        builds=[BuildSummary(build_id="b1", pkgname="foo", status="queued", server_arch="x86_64")],
        total=3,
    )
    assert BuildListResponse.model_validate_json(response.model_dump_json()) == response


def test_build_status_response_ignores_internal_fields():
    status = BuildStatusResponse.model_validate({
        "build_id": "b1",
        "pkgname": "foo",
        "status": "completed",
        "start_time": EPOCH,
        "packages": [{"filename": "foo-1-1-x86_64.pkg.tar.zst", "size": 10, "download_url": "/build/b1/download/foo"}],
        "extra_repos": [{"name": "internal"}],
        "artifacts_ready": True,
    })
    assert status.start_time == EPOCH
    assert status.packages[0].size == 10
    assert status.logs == []
    assert "extra_repos" not in status.model_dump()


def test_farm_build_submit_response_requires_build_id():
    with pytest.raises(ValidationError):
        FarmBuildSubmitResponse.model_validate({"error": "No builds queued", "pkgname": "foo"})


def test_login_response_parses_user():
    login = LoginResponse.model_validate({
        "token": "t",
        "user": {"id": 1, "username": "alice", "role": "user", "created_at": EPOCH},
    })
    assert login.user.username == "alice"
    assert login.user.email_notifications_enabled is True
    assert login.expires_in_days == 10
