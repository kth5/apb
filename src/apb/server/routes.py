"""APB server HTTP routes."""

import json
import logging
import platform
import queue
import shutil
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import psutil

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from apb import VERSION
from apb.constants import BUILD_TIMEOUT_MAX, BUILD_TIMEOUT_MIN, BuildStatus
from apb.pkgbuild import parse_pkgbuild_file, pkgbuild_info_to_dict
from apb.server import engine

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/")
async def get_server_info():
    """Get server information and status"""
    try:
        return {
            "status": "running",
            "version": VERSION,
            "supported_architecture": engine.get_server_architecture(),
            "system_info": engine.get_system_info(),
            "queue_status": engine.get_queue_status()
        }
    except Exception as e:
        logger.error(f"Error getting server info: {e}")
        # Return minimal info to prevent HTTP 502
        return {
            "status": "running",
            "version": VERSION,
            "supported_architecture": engine.get_server_architecture(),
            "system_info": {"architecture": platform.machine()},
            "queue_status": {"current_builds_count": 0, "queued_builds": 0}
        }


@router.get("/health")
async def health_check():
    """Enhanced health check endpoint that actually tests server responsiveness"""
    start_time = time.time()

    try:
        health_status = {
            "status": "healthy",
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {}
        }

        # Test memory usage
        try:
            memory = psutil.virtual_memory()
            health_status["checks"]["memory"] = {
                "status": "ok" if memory.percent < 95 else "warning",
                "usage_percent": memory.percent,
                "available_mb": memory.available // (1024 * 1024)
            }
        except Exception as e:
            health_status["checks"]["memory"] = {"status": "error", "error": str(e)}

        # Test disk space
        try:
            disk = psutil.disk_usage(engine.server_config.get("builds_dir", "/tmp"))
            disk_percent = (disk.used / disk.total) * 100
            health_status["checks"]["disk"] = {
                "status": "ok" if disk_percent < 95 else "warning",
                "usage_percent": disk_percent,
                "free_gb": disk.free // (1024 * 1024 * 1024)
            }
        except Exception as e:
            health_status["checks"]["disk"] = {"status": "error", "error": str(e)}

        # Test thread pool
        try:
            # Check if executor is responsive
            future = engine.build_executor.submit(lambda: "test")
            try:
                result = future.result(timeout=1.0)
                health_status["checks"]["executor"] = {"status": "ok", "test_result": result}
            except Exception as e:
                health_status["checks"]["executor"] = {"status": "error", "error": str(e)}
        except Exception as e:
            health_status["checks"]["executor"] = {"status": "error", "error": str(e)}

        # Test build queue
        try:
            health_status["checks"]["build_queue"] = {
                "status": "ok",
                "queue_size": engine.build_queue.qsize(),
                "active_builds": len(engine.active_builds),
                "running_processes": len(engine.running_processes)
            }
        except Exception as e:
            health_status["checks"]["build_queue"] = {"status": "error", "error": str(e)}

        # Test file system access
        try:
            test_file = Path(engine.server_config.get("builds_dir", "/tmp")) / ".health_check"
            test_file.write_text("health_check")
            test_file.unlink()
            health_status["checks"]["filesystem"] = {"status": "ok"}
        except Exception as e:
            health_status["checks"]["filesystem"] = {"status": "error", "error": str(e)}

        # Calculate response time
        response_time = time.time() - start_time
        health_status["response_time_ms"] = round(response_time * 1000, 2)

        # Determine overall status
        check_statuses = [check.get("status", "error") for check in health_status["checks"].values()]
        if "error" in check_statuses:
            health_status["status"] = "degraded"
        elif "warning" in check_statuses:
            health_status["status"] = "warning"

        # If response time is too high, mark as degraded
        if response_time > 5.0:
            health_status["status"] = "degraded"
            health_status["warning"] = "High response time"

        return health_status

    except Exception as e:
        logger.error(f"Error in health check: {e}")
        # Return degraded status instead of always healthy
        return {
            "status": "degraded",
            "version": VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "response_time_ms": round((time.time() - start_time) * 1000, 2)
        }


@router.post("/build")
async def submit_build(
    build_tarball: UploadFile = File(None),
    pkgbuild: UploadFile = File(None),
    build_id: str = Form(...),
    sources: List[UploadFile] = File(default=[]),
    build_timeout: Optional[int] = Form(None),
    extra_repos: Optional[str] = Form(None)
):
    """Submit a new build request (supports both tarball and individual file uploads)"""
    try:
        # Check if build_id already exists
        if build_id in engine.active_builds or build_id in engine.build_history:
            raise HTTPException(
                status_code=400,
                detail={"error": "Build ID already exists", "detail": f"Build with ID '{build_id}' already exists"}
            )

        # Validate and set build timeout
        timeout_seconds = engine.BUILD_TIMEOUT  # Default timeout
        if build_timeout is not None:
            if build_timeout < 300 or build_timeout > 14400:  # 5 minutes to 4 hours
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Invalid timeout", "detail": "Build timeout must be between 300 and 14400 seconds"}
                )
            timeout_seconds = build_timeout
            logger.info(f"Build {build_id} using custom timeout: {timeout_seconds} seconds")

        # Create build directory
        builds_dir = Path(engine.server_config["builds_dir"])
        builds_dir.mkdir(parents=True, exist_ok=True)

        build_dir = builds_dir / build_id
        build_dir.mkdir(exist_ok=True)

        # Handle tarball upload (new method)
        if build_tarball and build_tarball.filename:
            # Check file size first
            if build_tarball.size and build_tarball.size > engine.MAX_REQUEST_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail={"error": "File too large", "detail": f"Tarball exceeds {engine.MAX_REQUEST_SIZE} bytes"}
                )

            # Save tarball temporarily
            tarball_path = build_dir / "build.tar.gz"
            try:
                with open(tarball_path, 'wb') as f:
                    bytes_written = 0
                    while True:
                        chunk = await build_tarball.read(8192)  # 8KB chunks
                        if not chunk:
                            break

                        bytes_written += len(chunk)
                        if bytes_written > engine.MAX_REQUEST_SIZE:
                            f.close()
                            tarball_path.unlink(missing_ok=True)  # Delete partial file
                            raise HTTPException(
                                status_code=413,
                                detail={"error": "File too large", "detail": f"Tarball exceeds {engine.MAX_REQUEST_SIZE} bytes"}
                            )

                        f.write(chunk)

                # Extract tarball
                try:
                    with tarfile.open(tarball_path, 'r:gz') as tar:
                        # Extract all files to build directory
                        tar.extractall(path=build_dir, filter='data')

                    # Remove the tarball after extraction
                    tarball_path.unlink(missing_ok=True)

                    # Verify PKGBUILD exists
                    pkgbuild_path = build_dir / "PKGBUILD"
                    if not pkgbuild_path.exists():
                        raise HTTPException(
                            status_code=400,
                            detail={"error": "Invalid tarball", "detail": "Tarball must contain a PKGBUILD file"}
                        )

                except (tarfile.TarError, OSError) as e:
                    # Clean up on extraction error
                    tarball_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=400,
                        detail={"error": "Invalid tarball", "detail": f"Could not extract tarball: {str(e)}"}
                    )

            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Failed to save tarball", "detail": str(e)}
                )

        # Handle individual file uploads (legacy method for backward compatibility)
        elif pkgbuild and pkgbuild.filename:
            # Validate PKGBUILD file
            if pkgbuild.filename.lower() != "pkgbuild":
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Invalid PKGBUILD file", "detail": "File must be named 'PKGBUILD'"}
                )

            # Save PKGBUILD with size limit and streaming
            pkgbuild_path = build_dir / "PKGBUILD"
            try:
                # Check file size first
                if pkgbuild.size and pkgbuild.size > engine.MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail={"error": "File too large", "detail": f"PKGBUILD exceeds {engine.MAX_FILE_SIZE} bytes"}
                    )

                # Stream file to disk to avoid memory issues
                with open(pkgbuild_path, 'wb') as f:
                    bytes_written = 0
                    while True:
                        # Read in chunks to avoid memory exhaustion
                        chunk = await pkgbuild.read(8192)  # 8KB chunks
                        if not chunk:
                            break

                        bytes_written += len(chunk)
                        if bytes_written > engine.MAX_FILE_SIZE:
                            f.close()
                            pkgbuild_path.unlink(missing_ok=True)  # Delete partial file
                            raise HTTPException(
                                status_code=413,
                                detail={"error": "File too large", "detail": f"PKGBUILD exceeds {engine.MAX_FILE_SIZE} bytes"}
                            )

                        f.write(chunk)

            except HTTPException:
                raise
            except Exception as e:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Failed to save PKGBUILD", "detail": str(e)}
                )

            # Save source files with size limits and streaming
            total_size = 0
            for source in sources:
                if source.filename:
                    source_path = build_dir / source.filename
                    try:
                        # Check individual file size
                        if source.size and source.size > engine.MAX_FILE_SIZE:
                            logger.error(f"Source file {source.filename} too large: {source.size} bytes")
                            continue

                        # Stream file to disk
                        with open(source_path, 'wb') as f:
                            bytes_written = 0
                            while True:
                                chunk = await source.read(8192)  # 8KB chunks
                                if not chunk:
                                    break

                                bytes_written += len(chunk)
                                total_size += len(chunk)

                                # Check individual file size limit
                                if bytes_written > engine.MAX_FILE_SIZE:
                                    f.close()
                                    source_path.unlink(missing_ok=True)
                                    logger.error(f"Source file {source.filename} exceeded size limit")
                                    break

                                # Check total request size limit
                                if total_size > engine.MAX_REQUEST_SIZE:
                                    f.close()
                                    source_path.unlink(missing_ok=True)
                                    raise HTTPException(
                                        status_code=413,
                                        detail={"error": "Request too large", "detail": f"Total request size exceeds {engine.MAX_REQUEST_SIZE} bytes"}
                                    )

                                f.write(chunk)

                    except HTTPException:
                        raise
                    except Exception as e:
                        logger.error(f"Error saving source file {source.filename}: {e}")
                        # Continue with other files
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": "No build files provided", "detail": "Either build_tarball or pkgbuild must be provided"}
            )

        # Parse PKGBUILD (same path regardless of upload method)
        pkgbuild_path = build_dir / "PKGBUILD"
        pkgbuild_info = engine.parse_pkgbuild(pkgbuild_path)

        if pkgbuild_info["pkgname"] == "unknown":
            raise HTTPException(
                status_code=400,
                detail={"error": "Invalid PKGBUILD file", "detail": "Missing required pkgname field"}
            )

        # Parse extra repositories
        extra_repos_list = []
        if extra_repos:
            try:
                import json
                extra_repos_list = json.loads(extra_repos)
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"Invalid extra_repos JSON: {e}")
                extra_repos_list = []

        # Create build record
        engine.active_builds[build_id] = {
            "build_id": build_id,
            "pkgname": pkgbuild_info["pkgname"],
            "status": BuildStatus.QUEUED,
            "created_at": time.time(),
            "arch": pkgbuild_info["arch"],
            "packages": [],
            "logs": [],
            "build_timeout": timeout_seconds,
            "extra_repos": extra_repos_list
        }

        # Add to queue
        engine.build_queue.put({
            "build_id": build_id,
            "build_dir": build_dir,
            "pkgbuild_info": pkgbuild_info,
            "build_timeout": timeout_seconds,
            "extra_repos": extra_repos_list
        })

        logger.info(f"Build {build_id} added to queue (queue size now: {engine.build_queue.qsize()})")

        return {
            "build_id": build_id,
            "status": "queued",
            "message": "Build queued successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting build: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Internal server error", "detail": str(e)}
        )


@router.get("/build/{build_id}/status-api")
async def get_build_status(build_id: str):
    """Get build status as JSON"""
    build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    return build_info


@router.get("/build/{build_id}/output")
async def get_build_output(build_id: str, start_index: int = 0, limit: int = 50):
    """Get build output/logs"""
    if build_id not in engine.build_outputs:
        raise HTTPException(status_code=404, detail="Build not found")

    output_lines = engine.build_outputs[build_id]
    total_lines = len(output_lines)

    end_index = min(start_index + limit, total_lines)
    returned_lines = output_lines[start_index:end_index]

    return {
        "output": returned_lines,
        "total_lines": total_lines,
        "start_index": start_index,
        "returned_lines": len(returned_lines)
    }


@router.get("/build/{build_id}/stream")
async def stream_build_output(build_id: str):
    """Stream build output using Server-Sent Events"""

    async def event_generator():
        # Create queue for this stream
        stream_queue = queue.Queue()

        if build_id not in engine.build_streams:
            engine.build_streams[build_id] = []
        engine.build_streams[build_id].append(stream_queue)

        try:
            # Send existing output
            if build_id in engine.build_outputs:
                for line in engine.build_outputs[build_id]:
                    yield f"event: output\ndata: {line}\n\n"

            # Send current status
            build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)
            if build_info:
                yield f"event: status\ndata: {json.dumps({'status': build_info['status']})}\n\n"

            # Stream new events
            while True:
                try:
                    event_type, data = stream_queue.get(timeout=30)

                    if event_type == "output":
                        yield f"event: output\ndata: {data}\n\n"
                    elif event_type == "status":
                        yield f"event: status\ndata: {json.dumps(data)}\n\n"
                    elif event_type == "complete":
                        yield f"event: complete\ndata: {json.dumps(data)}\n\n"
                        break

                except queue.Empty:
                    # Send heartbeat
                    yield f"event: heartbeat\ndata: {time.time()}\n\n"

                    # Check if build is done
                    build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)
                    if build_info and build_info["status"] in [BuildStatus.COMPLETED, BuildStatus.FAILED, BuildStatus.CANCELLED]:
                        break

        finally:
            # Remove from streams
            if build_id in engine.build_streams:
                engine.build_streams[build_id].remove(stream_queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/build/{build_id}/cancel")
async def cancel_build(build_id: str):
    """Cancel a build"""
    if build_id not in engine.active_builds:
        raise HTTPException(status_code=404, detail="Build not found")

    build_info = engine.active_builds[build_id]

    if build_info["status"] in [BuildStatus.COMPLETED, BuildStatus.FAILED, BuildStatus.CANCELLED]:
        return {"success": False, "message": "Build already finished"}

    # Mark as cancelled
    build_info["status"] = BuildStatus.CANCELLED
    build_info["end_time"] = time.time()

    if "start_time" in build_info:
        build_info["duration"] = build_info["end_time"] - build_info["start_time"]

    # Move to history
    engine.build_history[build_id] = build_info.copy()

    return {"success": True, "message": "Build cancelled successfully"}


@router.get("/build/{build_id}/confirm-cancel")
async def confirm_cancel_build(build_id: str):
    """Get build cancellation confirmation page"""
    build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    return HTMLResponse(f"""
    <html>
    <head><title>Cancel Build - {build_info['pkgname']}</title></head>
    <body>
        <h1>Cancel Build Confirmation</h1>
        <p>Are you sure you want to cancel the build for <strong>{build_info['pkgname']}</strong>?</p>
        <p>Build ID: {build_id}</p>
        <p>Status: {build_info['status']}</p>
        <form method="post" action="/build/{build_id}/cancel">
            <button type="submit" style="background-color: #ff4444; color: white; padding: 10px 20px; border: none; cursor: pointer;">Cancel Build</button>
            <a href="/build/{build_id}" style="margin-left: 10px; text-decoration: none; background-color: #ccc; color: black; padding: 10px 20px; display: inline-block;">Go Back</a>
        </form>
    </body>
    </html>
    """)


@router.get("/build/{build_id}/view/{filename}")
async def view_file(build_id: str, filename: str):
    """View a text file in the browser"""
    builds_dir = Path(engine.server_config["builds_dir"])
    build_dir = builds_dir / build_id
    file_path = build_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        return HTMLResponse(f"""
        <html>
        <head><title>View File - {filename}</title></head>
        <body>
            <h1>File: {filename}</h1>
            <p>Build ID: {build_id}</p>
            <pre style="background-color: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow-x: auto;">{content}</pre>
            <a href="/build/{build_id}">Back to Build</a>
        </body>
        </html>
        """)
    except UnicodeDecodeError:
        # If file is not text, redirect to download
        return FileResponse(
            path=str(file_path),
            filename=filename,
            media_type='application/octet-stream'
        )


@router.get("/build/{build_id}/download/{filename}")
async def download_file(build_id: str, filename: str):
    """Download a build artifact"""
    builds_dir = Path(engine.server_config["builds_dir"])
    build_dir = builds_dir / build_id
    file_path = build_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type='application/octet-stream'
    )


@router.get("/builds/latest")
async def get_latest_builds(limit: int = 10, status: Optional[str] = None):
    """Get latest builds"""
    all_builds = list(engine.build_history.values()) + list(engine.active_builds.values())

    if status:
        all_builds = [b for b in all_builds if b["status"] == status]

    # Sort by creation time (newest first)
    all_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    builds = []
    for build in all_builds[:limit]:
        builds.append({
            "build_id": build["build_id"],
            "pkgname": build["pkgname"],
            "status": build["status"],
            "start_time": datetime.fromtimestamp(build.get("start_time", build.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build["end_time"], timezone.utc).isoformat() if build.get("end_time") else None,
            "duration": build.get("duration", 0)
        })

    return {"builds": builds, "total": len(all_builds)}


@router.get("/builds/pkgname/{pkgname}")
async def get_builds_for_package(pkgname: str, limit: int = 5):
    """Get builds for a specific package"""
    all_builds = list(engine.build_history.values()) + list(engine.active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    builds = []
    for build in pkg_builds[:limit]:
        builds.append({
            "build_id": build["build_id"],
            "status": build["status"],
            "start_time": datetime.fromtimestamp(build.get("start_time", build.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build["end_time"], timezone.utc).isoformat() if build.get("end_time") else None,
            "duration": build.get("duration", 0)
        })

    return {"pkgname": pkgname, "builds": builds, "total": len(pkg_builds)}


@router.get("/builds/pkgname/{pkgname}/latest")
async def get_latest_build_for_package(pkgname: str, successful_only: bool = True):
    """Get the latest build for a specific package"""
    all_builds = list(engine.build_history.values()) + list(engine.active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    if successful_only:
        pkg_builds = [b for b in pkg_builds if b["status"] == BuildStatus.COMPLETED]

    if not pkg_builds:
        raise HTTPException(status_code=404, detail="No builds found for package")

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    latest_build = pkg_builds[0]

    return {
        "build_id": latest_build["build_id"],
        "pkgname": latest_build["pkgname"],
        "status": latest_build["status"],
        "start_time": datetime.fromtimestamp(latest_build.get("start_time", latest_build.get("created_at", 0)), timezone.utc).isoformat(),
        "end_time": datetime.fromtimestamp(latest_build["end_time"], timezone.utc).isoformat() if latest_build.get("end_time") else None,
        "duration": latest_build.get("duration", 0),
        "packages": latest_build.get("packages", [])
    }


@router.get("/builds/pkgname/{pkgname}/latest/download/{file_type}")
async def download_latest_build_file(pkgname: str, file_type: str, successful_only: bool = True):
    """Download the latest build file for a package"""
    all_builds = list(engine.build_history.values()) + list(engine.active_builds.values())
    pkg_builds = [b for b in all_builds if b["pkgname"] == pkgname]

    if successful_only:
        pkg_builds = [b for b in pkg_builds if b["status"] == BuildStatus.COMPLETED]

    if not pkg_builds:
        raise HTTPException(status_code=404, detail="No builds found for package")

    # Sort by creation time (newest first)
    pkg_builds.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    latest_build = pkg_builds[0]

    builds_dir = Path(engine.server_config["builds_dir"])
    build_dir = builds_dir / latest_build["build_id"]

    # Handle different file types
    if file_type == "package":
        # Find main package file
        for pkg_file in build_dir.glob("*.pkg.tar.*"):
            if not pkg_file.name.endswith("-debug.pkg.tar.xz"):
                return FileResponse(
                    path=str(pkg_file),
                    filename=pkg_file.name,
                    media_type='application/octet-stream'
                )
    elif file_type == "debug":
        # Find debug package file
        for pkg_file in build_dir.glob("*-debug.pkg.tar.*"):
            return FileResponse(
                path=str(pkg_file),
                filename=pkg_file.name,
                media_type='application/octet-stream'
            )
    elif file_type == "log":
        log_file = build_dir / "build.log"
        if log_file.exists():
            return FileResponse(
                path=str(log_file),
                filename="build.log",
                media_type='text/plain'
            )
    elif file_type == "pkgbuild":
        pkgbuild_file = build_dir / "PKGBUILD"
        if pkgbuild_file.exists():
            return FileResponse(
                path=str(pkgbuild_file),
                filename="PKGBUILD",
                media_type='text/plain'
            )

    raise HTTPException(status_code=404, detail=f"File type '{file_type}' not found")


@router.get("/build/{build_id}")
async def get_build_details(build_id: str, request: Request):
    """Get detailed build information (HTML or JSON based on Accept header)"""
    build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    # Check Accept header for JSON vs HTML
    accept_header = request.headers.get("Accept", "")
    if "application/json" in accept_header:
        # Return JSON response
        sources = []
        builds_dir = Path(engine.server_config["builds_dir"])
        build_dir = builds_dir / build_id

        # List source files
        for src_file in build_dir.iterdir():
            if src_file.is_file() and src_file.name not in ["build.log"] and not src_file.name.endswith(".pkg.tar.xz"):
                sources.append({
                    "filename": src_file.name,
                    "size": src_file.stat().st_size,
                    "download_url": f"/build/{build_id}/download/{src_file.name}"
                })

        return {
            "build_id": build_info["build_id"],
            "pkgname": build_info["pkgname"],
            "status": build_info["status"],
            "start_time": datetime.fromtimestamp(build_info.get("start_time", build_info.get("created_at", 0)), timezone.utc).isoformat(),
            "end_time": datetime.fromtimestamp(build_info["end_time"], timezone.utc).isoformat() if build_info.get("end_time") else None,
            "duration": build_info.get("duration", 0),
            "exit_code": build_info.get("exit_code", 0),
            "packages": build_info.get("packages", []),
            "logs": build_info.get("logs", []),
            "sources": sources
        }
    else:
        # Return HTML response
        packages_html = ""
        for pkg in build_info.get("packages", []):
            packages_html += f'<li><a href="{pkg["download_url"]}">{pkg["filename"]}</a> ({pkg["size"]} bytes)</li>'

        logs_html = ""
        for log in build_info.get("logs", []):
            logs_html += f'<li><a href="{log["download_url"]}">{log["filename"]}</a> ({log["size"]} bytes)</li>'

        return HTMLResponse(f"""
        <html>
        <head><title>Build Details - {build_info['pkgname']}</title></head>
        <body>
            <h1>Build Details: {build_info['pkgname']}</h1>
            <p><strong>Build ID:</strong> {build_id}</p>
            <p><strong>Status:</strong> {build_info['status']}</p>
            <p><strong>Start Time:</strong> {datetime.fromtimestamp(build_info.get("start_time", build_info.get("created_at", 0)), timezone.utc).isoformat()}</p>
            <p><strong>End Time:</strong> {datetime.fromtimestamp(build_info["end_time"], timezone.utc).isoformat() if build_info.get("end_time") else "N/A"}</p>
            <p><strong>Duration:</strong> {build_info.get("duration", 0):.2f} seconds</p>
            <p><strong>Exit Code:</strong> {build_info.get("exit_code", 0)}</p>

            <h2>Packages</h2>
            <ul>{packages_html}</ul>

            <h2>Logs</h2>
            <ul>{logs_html}</ul>

            <h2>Actions</h2>
            <a href="/build/{build_id}/stream">Stream Output</a> |
            <a href="/build/{build_id}/output">View Output</a> |
            <a href="/build/{build_id}/confirm-cancel">Cancel Build</a>
        </body>
        </html>
        """)


@router.get("/build/{build_id}/packages")
async def get_build_packages(build_id: str):
    """List packages produced by a build"""
    build_info = engine.active_builds.get(build_id) or engine.build_history.get(build_id)

    if not build_info:
        raise HTTPException(status_code=404, detail="Build not found")

    packages = []
    for pkg in build_info.get("packages", []):
        packages.append({
            "filename": pkg["filename"],
            "size": pkg["size"],
            "created_at": datetime.fromtimestamp(build_info.get("end_time", build_info.get("created_at", 0)), timezone.utc).isoformat(),
            "download_url": pkg["download_url"]
        })

    return {
        "build_id": build_id,
        "packages": packages
    }


@router.get("/admin/cleanup")
async def admin_cleanup_page():
    """Get cleanup administration page"""
    return HTMLResponse("""
    <html>
    <head><title>APB Server Admin - Cleanup</title></head>
    <body>
        <h1>APB Server Administration - Cleanup</h1>
        <p>Use this page to clean up old builds and temporary files.</p>
        <form method="post" action="/admin/cleanup">
            <button type="submit">Start Cleanup</button>
        </form>
    </body>
    </html>
    """)


@router.post("/admin/cleanup")
async def admin_cleanup():
    """Trigger server cleanup"""
    try:
        cleanup_id = f"cleanup_{int(time.time())}"

        # Clean up old builds (example: remove builds older than 7 days)
        builds_dir = Path(engine.server_config["builds_dir"])
        current_time = time.time()
        week_ago = current_time - (7 * 24 * 60 * 60)

        cleaned_count = 0
        for build_dir in builds_dir.iterdir():
            if build_dir.is_dir():
                try:
                    # Check if build is old
                    if build_dir.stat().st_mtime < week_ago:
                        shutil.rmtree(build_dir)
                        cleaned_count += 1
                except Exception as e:
                    logger.error(f"Error cleaning up {build_dir}: {e}")

        logger.info(f"Cleanup completed: removed {cleaned_count} old builds")

        return {
            "success": True,
            "message": f"Cleanup completed: removed {cleaned_count} old builds",
            "cleanup_id": cleanup_id
        }

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


