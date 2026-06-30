# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Integration test that builds the `apb` Arch package via spawned farm and server processes using the APB client (`APB_INTEGRATION=1` on Linux with Arch build tools)

### Fixed

- Farm artifact downloads no longer crash with 500 when a file is not cached locally; missing files return a 404 error page instead
- Integration tests now fail fast when server/farm subprocesses crash (for example missing or wrong `multipart` package) instead of timing out
- Client build tarballs now include source directories (for example `src/`) required by the root `PKGBUILD`
- PKGBUILD `pkgname` and `pkgver` (and related scalar fields) now resolve bash-style variable substitutions such as `"tde-${_mod}"` and `"14.1.$_minor"` without invoking bash
- Pytest could not import `apb` when run outside the project venv; `pythonpath` and explicit src-layout packaging are now configured in `pyproject.toml`

### Changed

- Farm dashboard pagination on Recent Builds now preserves the active tab across page changes
- Farm dashboard Recent Builds pagination is shown at the top and bottom of the list
- Farm dashboard tabs and build pagination now use path-based URLs (for example `/dashboard/builds/2`) instead of query strings
- `dev` optional dependencies now include full runtime packages needed to spawn server and farm during integration tests

## [2026-06-30]

### Added

- Python package layout under `src/apb/` with shared library modules
- `pyproject.toml` with console script entry points (`apb`, `apb-farm`, `apb-server`)
- Unified PKGBUILD parser, config loader, architecture helpers, and tarball utilities
- Jinja2-based minimal HTML templates for server and farm web UI
- `httpx` as unified HTTP client (replaces `aiohttp` and `requests`)

### Changed

- Restructured monolithic `apb.py`, `apb-farm.py`, and `apb-server.py` into installable package modules
- Farm build proxy routes consolidated via shared proxy helpers

### Fixed

- Client `get_builds_by_pkgname()` now uses `/builds/pkgname/` endpoint path

### Removed

- Standalone root-level `apb.py`, `apb-farm.py`, and `apb-server.py` scripts (replaced by package entry points)
