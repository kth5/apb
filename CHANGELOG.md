# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [ UNRELEASED ]

### Added

- PKGBUILD `apb_arch_hint=<arch>` for `arch=(any)` packages: farm and config-based client builds use only servers of that architecture (no cross-arch fallback); ignored for any other `arch=()` combination
- `apb-server --makepkg-conf PATH` uses an alternate host `makepkg.conf` for `SRCDEST`, `CCACHE_DIR`, and chroot configuration so multiple servers on one host can stay isolated (default: `/etc/makepkg.conf`)
- `apb-server --srcdest PATH` overrides `SRCDEST` from the configured `makepkg.conf`; the directory is created if missing, written into the buildroot's `makepkg.conf`, and used for source locking, bind mounting, and periodic cleanup
- Unit tests for SRCDEST command-line precedence, `makepkg.conf` fallback, and buildroot configuration updates
- Shared helpers: `apb.tarball.extract_build_tarball` (safe `data`-filtered extraction with PKGBUILD check), `apb.validation.validate_build_timeout`, `apb.upstream` (endpoint path builders, `upstream_url`, and `download`/`download_async` streaming to a file or to bytes) and `apb.service` (`configure_logging`, `add_default_cors`, `run_uvicorn`)
- Unit tests for build timeout validation, tarball extraction, and upstream path and download helpers
- Shared response models in `apb.models`: `BuildSummary`, `BuildListResponse`, `BuildStatusResponse`, `BuildArtifact`, `QueuedBuildInfo`, `FarmQueueStatus` and `FarmBuildSubmitResponse`, plus `utc_datetime` to normalise epoch, ISO and legacy `"... UTC"` timestamps
- Unit tests for model round-trips and timestamp normalisation
- Unit tests for client CLI dispatch, config-based multi-architecture builds, auth client URL handling, and farm database creation and migration
- Shared `farm_db` and `farm_queue_state` pytest fixtures in `tests/conftest.py`, built from the real farm schema via `core.init_database(":memory:")` instead of per-file hand-written tables
- Farm web form endpoints that work without JavaScript (lynx, w3m, very old browsers): `GET`/`POST /login`, `POST /logout`, `GET /account` and `POST /account/password`; the build status page has a plain HTML cancel form, and `POST /build/{build_id}/cancel` answers form submissions with `303 See Other` back to the status page
- CSRF protection for cookie-authenticated non-GET requests (`csrf_token` form field or `X-CSRF-Token` header); Bearer-token requests from the APB client are unaffected
- Shared web UI stylesheet and scripts served from `GET /static/{path}` on farm and server, with versioned URLs and long-lived `Cache-Control`
- Dark color scheme via `prefers-color-scheme`, a print stylesheet, and tables that stack on narrow screens
- Progressive live updates (`/static/apb.js`, ES5): unfinished build status pages and the dashboard servers tab reload only their status section in place, one request at a time, paused while the browser tab is hidden and backing off after errors; without JavaScript, build status pages fall back to a `<noscript>` meta refresh
- Admin panel can edit and enable/disable custom repositories (the edit button used to call an undefined function)
- `tests/test_web_ui.py` covering page rendering, HTML escaping, the no-JS login, logout and password change flows, and CSRF rejection
- Two-factor authentication for farm logins with TOTP authenticator apps and WebAuthn security keys (YubiKey and other FIDO2/U2F keys), implemented in the new `apb.farm.mfa` module (`pyotp`, `fido2` and `segno` are new dependencies)
- Farm 2FA JSON endpoints: `POST /auth/login/2fa`, `POST /auth/login/2fa/webauthn-options`, `GET /auth/my/2fa`, `POST /auth/my/2fa/totp`, `POST /auth/my/2fa/totp/confirm`, `DELETE /auth/my/2fa/totp`, `POST /auth/my/2fa/webauthn/register-options`, `POST /auth/my/2fa/webauthn`, `DELETE /auth/my/2fa/webauthn/{credential_id}` and `POST /auth/my/2fa/recovery-codes`
- Ten single-use recovery codes, shown once when the first second factor is enrolled and regenerable with the account password
- Admin endpoint `DELETE /auth/users/{user_id}/2fa` and a "Reset 2FA" button in the admin panel to remove a user's second factors, plus a 2FA column in the admin user list and `mfa_enabled` in user responses
- Farm web pages `GET`/`POST /login/2fa` (authenticator code, recovery code or security key) and `/account/2fa` (QR code enrollment, security key registration and removal, recovery code regeneration); `/static/webauthn.js` drives the browser security key prompts
- `apb --farm --login` asks for the authenticator or recovery code, or uses a connected FIDO2 security key through `python-fido2`; `--2fa-method totp|key|recovery` overrides the automatic choice
- `apb --2fa-setup totp|key` enrolls a second factor from the command line: `totp` prints the QR code in the terminal and asks for a code to confirm it, `key` registers a connected FIDO2 security key; combined with `--login` it also finishes the forced enrollment of admins without 2FA. `--login` reminds users without a second factor that they can add one, and the account page links to the setup directly
- `nginx-apb-farm.conf` passes the new 2FA endpoints and pages through to the farm with their allowed methods
- `tests/test_farm_mfa.py` covering TOTP, recovery codes, security keys, pending login limits, forced admin enrollment and admin reset

### Changed

- All farm and server HTML pages (dashboard, build status, download error, admin, login and account on the farm; build details, cancel confirmation, file view and cleanup on the server) are rendered from autoescaped Jinja templates in `apb.web` with one shared layout and stylesheet instead of inline f-strings with per-page CSS; emoji icons replaced by text labels and status badges
- Dashboard tabs are plain links to `/dashboard`, `/dashboard/builds/{page}` and `/dashboard/statistics`; only the requested tab's data is queried, builds are shown in a table, "Next" only appears when another page exists, and server info lookups run concurrently
- The 6 build status page variants (not found, queued, submission failed, server unavailable with and without cached status, connection failed, live) are one template
- Admin panel sections are reachable through in-page links instead of JS tabs; `/static/admin.js` is ES5 (`XMLHttpRequest`, event delegation, `textContent`) and authenticates with the session cookie plus CSRF header
- Web login sets the `authToken` cookie server-side with `HttpOnly`, `SameSite=Lax` and `Secure` on HTTPS
- `PUT /auth/change-password` and `POST /account/password` share one `core.change_user_password` helper
- **Breaking:** `POST /auth/login` returns `{"mfa_required": true, "mfa_token": ...}` instead of a session token for users with 2FA, and `{"mfa_setup_required": true, "setup_token": ...}` for admins without 2FA. Users without 2FA get the same response as before
- **Breaking:** admins must use two-factor authentication. An admin without a second factor (including the default `admin` account) only gets a 15-minute enrollment session after the password step, and promoting a user without 2FA to admin ends all of their sessions
- Farm tokens have a `scope` (`full`, `mfa_pending` or `mfa_setup`); only `full` tokens authenticate normal requests and get the sliding 10-day renewal

- Farm default host, port and config search paths now come from `apb.constants` (`FARM_DEFAULT_HOST`, `FARM_DEFAULT_PORT`, `DEFAULT_CONFIG_PATHS`) instead of duplicated definitions in `farm/core.py`
- Build timeout bounds and default (300, 14400 and 7200 seconds) come from `BUILD_TIMEOUT_MIN`, `BUILD_TIMEOUT_MAX` and `BUILD_TIMEOUT_DEFAULT` in `apb.constants` on server, farm and client
- Client compares build states through `apb.constants.BuildStatus` (new `BuildStatus.TERMINAL` tuple) instead of raw strings
- Farm `UserRole` values come from the `ADMIN_ROLE`, `USER_ROLE` and `GUEST_ROLE` constants
- Farm upstream HTTP session is created with `apb.http.create_async_client`, so farm requests send the shared `APB-Farm/<version>` User-Agent; the client no longer overrides the User-Agent already set by `create_sync_client`
- Package version has a single source: `pyproject.toml` reads it dynamically from `apb.VERSION` via `[tool.hatch.version]`; version bumped to `2026.10.28` (PKGBUILD `pkgver` and the version examples in `doc/*.md` updated to match)
- `dev` extra only lists development tools (`pytest`); runtime dependencies are no longer repeated there
- Server and farm `POST /build` extract uploaded tarballs and validate `build_timeout` through the shared helpers; the farm forwards legacy individual-file submissions as an in-memory tarball built with `create_build_tarball` instead of hand-rolled `tarfile` code and temporary files
- Client, farm upstream calls (status, output, stream, cancel, download, submit, discovery) and farm notification links build URLs with `apb.upstream`; farm artifact caching and client downloads stream through the shared download helper
- Server and farm apps and CLIs share logging setup, CORS configuration and uvicorn startup via `apb.service`
- `LoginRequest`, `LoginResponse` and `UserResponse` moved from `apb.farm.core` to `apb.models`; farm auth routes serialize users through one `core.user_response` helper, and `POST /auth/login` now returns the same `user` object as `GET /auth/me` (adds `email_notifications_enabled`)
- Client parses login, user info and build submit responses with the shared models instead of raw dicts
- **Breaking:** server and farm build listings (`GET /builds/latest`, `/builds/pkgname/{pkgname}` and `/builds/pkgname/{pkgname}/latest`, plus the farm-only `/builds/pkgname/{pkgname}/arch/{arch}/latest`, `/builds/pkgname/{pkgname}/latest-by-arch`, `/my/builds` and `/auth/users/{user_id}/builds`) return the shared `BuildSummary` / `BuildListResponse` shape. Each build has `build_id`, `pkgname`, `status`, `start_time`, `end_time`, `created_at` and `duration`. Timestamps are ISO 8601 UTC (no `"... UTC"` strings or epoch numbers). Farm entries add `server_arch`, `server_url` (obfuscated, except on the admin-only `/auth/users/{user_id}/builds`), `display_name` and `username`. The farm `id`, `epoch`, `pkgver` and `pkgrel` fields are removed; use `build_id` and `display_name` instead. Fields without a value are omitted
- **Breaking:** build list `total` is the full count of matching builds on both server and farm (the farm previously omitted it or returned the page size). All list endpoints take `limit` (default 20, 1-100) and an optional `status` filter. This replaces the server's defaults of 10 and 5, and `/my/builds` and `/auth/users/{user_id}/builds` defaults of 50
- **Breaking:** `GET /build/{build_id}/status-api` (and the farm's `/build/{build_id}/status?format=json`) returns the shared `BuildStatusResponse`. The server no longer exposes its raw internal build record (for example `extra_repos`). Farm extras (`artifacts_ready`, `queue_state`, `queue_position`, `jobs_ahead`, `farm_queue_size`, `server_unavailable`, `last_status_update`, `error_message`) are only present when set
- Client parses build listings and status with `BuildListResponse`, `BuildSummary` and `BuildStatusResponse`. `get_builds_by_pkgname` returns a `BuildListResponse`, `get_latest_build_by_pkgname` returns a `BuildSummary` or `None`, and `get_latest_builds_by_pkgname_per_arch` maps architectures to `BuildSummary`. The `id` to `build_id` fallbacks are gone
- `doc/apb-client-api.md` lists the config search paths actually used (`DEFAULT_CONFIG_PATHS`); `doc/apb-farm-api.md` drops the unimplemented `database`, `security` and `notifications` config keys
- Client farm and direct-server submissions share one tarball-plus-form submit: `APBotClient.build_package(build_path, exclude_paths=None, architectures=None, build_timeout=None)` returns a `BuildSubmitResponse` (a `FarmBuildSubmitResponse` when the farm queued per-architecture builds) and raises `BuildRejectedError` when the farm refuses the submission. `submit_build` in `apb.client.cli` returns that response (or `None`) and takes the same `architectures` and `build_timeout` options
- Client monitoring uses one status poll loop for farm and direct builds, driven by `BuildStatusResponse`. `monitor_builds(targets)` monitors `MonitorTarget` entries in parallel and cancels unfinished builds on Ctrl-C; `monitor_build(build_id, client, output_dir=None, verbose=False, arch=None)` wraps it for a single build. Config-based multi-architecture builds are now monitored in parallel instead of one after the other
- `APBotClient.get_build_status`, `get_build_by_id` and `stream_build_updates` return `BuildStatusResponse` models instead of dicts; `wait_for_farm_artifacts` returns the ready status (or `None`) so the client does not fetch it a second time before downloading
- `apb --build-timeout` is also sent to direct server submissions, which already accept it
- `apb.client.cli.main` is split into `parse_args`, `resolve_context` and one `run_*` function per command (`run_login`, `run_monitor`, `run_download`, `run_farm_build`, `run_direct_build`, `run_config_build`, ...) that return exit codes; farm and direct builds share `_submit_and_monitor`, and the skip-existing-package and `--arch` filter checks are shared helpers
- `build_for_multiple_arches` accepts a comma-separated `specific_arch` (as documented) and new `build_timeout` and `download` options. Config-based `apb --arch a,b` builds are submitted and monitored together with one summary instead of running one full build cycle per architecture
- Client `APBAuthClient` sends its requests through `create_sync_client` (shared User-Agent) and keeps any path prefix in the farm URL
- Local default server and farm URLs come from `DEFAULT_SERVER_URL` and `DEFAULT_FARM_URL` in `apb.constants`; farm email links are built with one `farm_page_url` helper
- Client fallback list of package architecture suffixes is derived from `apb.arch` (`KNOWN_PACKAGE_ARCH_SUFFIXES`)
- Farm `init_database` takes an optional database path (default `~/.apb/farm.db`) and adds missing `builds` columns from one `BUILD_COLUMN_MIGRATIONS` table instead of eleven `ALTER TABLE` / `try` blocks; the resulting schema is unchanged

### Removed

- Unused `apb.farm.proxy` module
- Dead `aiohttp`-based `setup_http_session`, `cleanup_http_session` and `signal_handler` at the end of `farm/routes.py` (the active versions live in `farm/core.py`)
- Duplicate `load_config` in `apb.client.api` (use `apb.config.load_config`) and the unimplemented `APBotClient.get_latest_successful_build_id` stub
- `requirements.txt`; dependencies are declared only in `pyproject.toml` (install with `pip install -e .` or `pip install -e '.[dev]'`)
- `submit_build_to_farm` and `monitor_farm_builds` in `apb.client.cli` (use `submit_build` and `monitor_builds`), and the unused `allow_toggle`, `status_callback` and `pkgname` parameters of `monitor_build`
- Dashboard JavaScript login and password dialogs, `localStorage` token storage, client-side `authToken` cookie writes and the global `window.fetch` monkeypatch that added the token to every request

### Fixed

- `/account` showed `none` as email and always showed notifications as enabled, and `GET /auth/me` returned `email: null`: users loaded from a session or API token were missing `email` and `email_notifications_enabled`
- Build completion emails were only sent when the 2-minute status poller noticed the final status itself. Whenever the APB client or the build status page fetched it first, the build was already stored as finished and no email went out. Cancellations, submission failures, rejected builds and builds lost on unavailable servers never sent one. Every path now goes through `core.finish_build`, which emails exactly once, on the actual transition to `completed`, `failed` or `cancelled`
- Sending email no longer blocks the farm's event loop: SMTP delivery for build notifications runs in a worker thread with a 30 second timeout, and notification tasks are kept referenced until they finish
- `nginx-apb-farm.conf` lets `/static/`, `/login`, `/logout`, `/account` and `/account/password` through to the farm. They used to hit the catch-all redirect to `/dashboard`, so pages loaded without stylesheet and scripts and the login form could not be reached
- `GET /farm` used to fail with a `NameError` (`running_builds_by_server`) when listing running builds per server
- Client `get_build_status` queries `/build/{build_id}/status-api`, which both server and farm serve. It used to query `/build/{build_id}/status?format=json`, which only the farm implements, so status calls against a server directly returned 404
- Farm build list timestamps are real UTC; they used to be local time with a `UTC` suffix
- Farm build discovery parses server build lists with `BuildListResponse` and stores epoch timestamps. It used to write the server's ISO strings into numeric columns, and gave unstarted builds a fake `start_time`
- Server build lists no longer count a cancelled build twice when it is in both active builds and history
- Client requests keep a path prefix in the server or farm URL (e.g. `https://host/apb`) instead of dropping it via `urljoin`
- Client downloads write to a `.part` file and rename on success, so failed downloads no longer leave truncated artifacts in the output directory
- Farm forwarding of legacy individual-file submissions no longer drops source files whose names end in `.sig` or `.log`
- Farm `SIGINT`/`SIGTERM` handler sets `shutdown_event` (as the server does) instead of calling `sys.exit(0)`, so background tasks and the lifespan shutdown run cleanly
- Client downloads from a direct build server no longer wait for the 300 second farm artifact timeout first; `artifacts_ready` is only awaited when the status comes from a farm
- Config-based builds honour `--no-download` and `--build-timeout`, report architectures without configured servers as failed instead of silently dropping them, and with `--detach` exit non-zero when a submission failed
- Direct server builds without `--arch` or `default_arch` exit with a clear error instead of a `TypeError` traceback; `--monitor` and `--download` without a known architecture write into the output directory itself
- `apb --farm --arch` now limits farm submission to the requested PKGBUILD `arch=()` entries instead of queuing every architecture in the PKGBUILD
- PKGBUILD parser uses only the first top-level `arch=()` assignment; later or indented `arch=` lines (e.g. inside `package_*()` functions) are ignored
- Client build tarballs no longer include the output directory, build artifacts (`.pkg.tar.*`, `.sig`, `.log`), or common non-source paths (`pkg/`, `.git/`, etc.)
- PKGBUILD parser now collects multi-line bash arrays (`apb_extra_repos=(...)`, `arch=(...)`, `pkgname=(...)`) instead of treating a lone `(` as a repository name and rejecting farm submissions
- `apb_extra_repos` URLs preserve pacman `$arch` / `$repo` placeholders so they match admin-configured repository URLs and expand at pacman runtime; other `${var}` references in those URLs still expand normally
- Admin user list shows each user's real email notification setting (it always showed "Enabled")
- `src/apb/web` templates and `style.css` are actually used; `/static` was never mounted, so the stylesheet was never served

### Security

- Farm strips directory components from legacy individual-file source filenames before writing them, and the client strips them from download filenames, so crafted names such as `../x` cannot write outside the target directory
- HTML pages escape all dynamic values. Usernames, package names, versions, repository data, file contents and the build ID from the URL were inserted unescaped (including into inline `onclick` handlers), which allowed stored and reflected XSS
- Cookie-authenticated state-changing requests require a CSRF token, and the session cookie is `HttpOnly`, so page scripts can no longer read the token
- Second-factor logins are limited to 5 attempts per 5-minute pending login, TOTP codes cannot be replayed, and security key sign counters are checked to detect cloned keys

## 2026.08.06

### Added

- Build server periodic SRCDEST cleanup: orphaned lock removal and age-based pruning of cached source files when `SRCDEST` is set in `/etc/makepkg.conf`, configurable via `--srcdest-cleanup-interval` and `--srcdest-retention-days`
- Build servers purge failed build sources and artifacts from `BUILDS_DIR` immediately after finalizing the build, retaining `build.log` so the farm and clients can still download it
- Unit tests for immediate failed build directory cleanup on the build server
- Unit tests for build server admin in-memory cleanup endpoint
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

- Build server `POST /admin/cleanup` and `apb --cleanup` now trigger in-memory build data cleanup only
- In-memory build output truncation (10,000 lines) no longer affects the on-disk `build.log`; live `/output` and SSE remain memory-limited
- `nginx-apb-farm.conf` now allowlists all current farm endpoints (email notifications, cache, repositories, pkgname build lookups) with matching method restrictions
- Project dependencies now require PyPI `multipart>=1.3` instead of Kludex `python-multipart`

### Removed

- Build server age-based disk cleanup that removed build directories older than 7 days
- Optional `ruff` development dependency (Rust-based linter/formatter)

### Fixed

- Build servers no longer remove failed build directories while the build subprocess is still running; cleanup runs only after the process exits and logs are finalized
- Failed-build cleanup explicitly preserves directories for builds still in the `BUILDING` state
- Failed build cleanup no longer deletes `build.log` before the farm has fetched it, which made farm artifact caching return 404
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
