# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- `apb --farm --download` can resolve a PKGBUILD's `pkgname`/`pkgbase` and download the latest successful farm build for each architecture in `arch=()`
- Farm API endpoints `GET /builds/pkgname/{pkgname}`, `GET /builds/pkgname/{pkgname}/latest`, `GET /builds/pkgname/{pkgname}/arch/{arch}/latest`, and `GET /builds/pkgname/{pkgname}/latest-by-arch`
- Build servers write the full `build.log` to disk as output is produced (no longer limited by in-memory truncation)
- Farm serves the last 100 lines of `build.log` to unauthenticated users; authenticated dashboard and APB client users get the full log
- Unit tests for full on-disk `build.log` writes and guest vs authenticated farm log downloads
- Integration test fixture package at `tests/fixtures/test-package`
- `tests/run-integration.sh` prepares a project virtualenv with `multipart>=1.3` and runs integration tests
- Unit tests for runtime dependency detection for `multipart>=1.3`
- Farm holds builds in queue until a build server with a free `--max-concurrent` slot and matching architecture is available
- Farm build status and submission responses expose farm queue position and jobs ahead while waiting for server assignment
- Client displays farm queue status while waiting and removes queued builds from the farm on interrupt or `--cancel`
- Unit tests for farm queue scheduling, architecture-aware assignment, and cancellation
- Integration test that builds the `tests/fixtures/test-package` fixture via spawned farm and server processes using the APB client (`APB_INTEGRATION=1` on Linux with Arch build tools)

### Changed

- In-memory build output truncation (10,000 lines) no longer affects the on-disk `build.log`; live `/output` and SSE remain memory-limited
- `nginx-apb-farm.conf` now allowlists all current farm endpoints (email notifications, cache, repositories, pkgname build lookups) with matching method restrictions
- Project dependencies now require PyPI `multipart>=1.3` instead of Kludex `python-multipart`

### Removed

- Optional `ruff` development dependency (Rust-based linter/formatter)

### Fixed

- `apb --farm --login` no longer raises `NameError` because `getpass` was not imported in the client CLI
- Client no longer raises `UnboundLocalError` in `check_package_exists` when the output directory is missing (local variable shadowed the `package_arch_suffix` import)
- Build servers drain makechrootpkg stdout in large binary chunks without a per-line sleep, and flush `build.log` periodically, so high-volume builds no longer stall on a full pipe buffer
- Unit tests for process stdout draining under high output volume
- Integration test fixture PKGBUILD uses `$srcdir` for the script source and generates the man page inline so only `test-script.sh` must be present in the build tarball
- Integration test failures now include `build.log`, `server.log`, and `farm.log` excerpts in the assertion message
- defnull multipart compatibility now adapts `parse_options_header()` to Starlette's bytes-based Content-Type checks so uploaded files are parsed
- defnull multipart streaming parser now skips empty ASGI body chunks instead of treating them as end-of-stream
- Integration test package fixture restored under `tests/fixtures/test-package` after the legacy `test/` tree was removed
- Compatibility layer so FastAPI/Starlette form uploads work with defnull `multipart>=1.3` shipped by Arch
- Hatchling wheel build no longer fails on duplicate `apb/web/static` and `apb/web/templates` paths from redundant `force-include` entries
- Farm now downloads completed build artifacts from the build server with retries and exposes `artifacts_ready` in build status
- Client downloads wait for `artifacts_ready` instead of hitting the farm before artifact caching finishes
- Farm download endpoints serve cached artifacts only; a cache miss returns 404 and does not re-fetch from the build server
- Farm lifespan no longer reloads default config over a `--config` file passed on the CLI, which left integration tests with no reachable build servers
- Farm routes no longer use aiohttp-style `async with http_session.get()` against httpx, which left status proxy coroutines unawaited
- Farm no longer warns about architecture mismatch for servers listed under the `any` config group
- Queued farm builds no longer return 404 from `/build/{build_id}/status` before a build server is assigned
- Client artifact downloads and output streaming no longer pass requests-style `stream=True` to httpx
- Farm `/farm` endpoint no longer crashes with `NameError` for bare `get_server_info`, `find_build_server`, and `build_queue` references in routes
- Integration test now builds the minimal `tests/fixtures/test-package` fixture instead of the root `apb` PKGBUILD
- Test package PKGBUILD uses `arch=('any')` so integration builds work on any build server architecture
- Integration tests now start the build server before the farm, wait for buildroot creation, and wait until the farm discovers an online server before submitting builds
- `arch=(any)` packages fall back to any configured build server when load-based server selection cannot reach server status endpoints
- Farm build submission no longer returns 500 when uploading a tarball (`Path` was used without import in `/build`)
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
