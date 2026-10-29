"""Jinja2 rendering and static assets for the farm and server HTML UI."""

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from apb import VERSION

_WEB_DIR = Path(__file__).resolve().parent
_TEMPLATE_DIR = _WEB_DIR / "templates"
_STATIC_DIR = _WEB_DIR / "static"
STATIC_CACHE_CONTROL = "public, max-age=31536000, immutable"


def static_url(path: str) -> str:
    """Versioned URL for a static asset so upgrades bust long-lived caches."""
    return f"/static/{path}?v={VERSION}"


def format_timestamp(value: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Render an epoch number or preformatted string; empty values become ``-``."""
    if value is None or value == "":
        return "-"
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value).strftime(fmt)
        except (OverflowError, OSError, ValueError):
            return "-"
    return str(value)


def format_filesize(value: Any) -> str:
    try:
        size = float(value)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"


def format_duration(value: Any) -> str:
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return "-"
    if seconds <= 0:
        return "-"
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.globals.update(version=VERSION, static_url=static_url)
_env.filters.update(timestamp=format_timestamp, filesize=format_filesize, duration=format_duration)


def render_template(template_name: str, **context: Any) -> str:
    return _env.get_template(template_name).render(**context)


def render_page(
    template_name: str,
    *,
    status_code: int = 200,
    headers: Optional[dict] = None,
    **context: Any,
) -> HTMLResponse:
    return HTMLResponse(render_template(template_name, **context), status_code=status_code, headers=headers)


class _CachedStaticFiles(StaticFiles):
    def file_response(self, *args: Any, **kwargs: Any):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = STATIC_CACHE_CONTROL
        return response


def mount_static(app: FastAPI) -> None:
    app.mount("/static", _CachedStaticFiles(directory=str(_STATIC_DIR)), name="static")
