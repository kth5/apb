"""APB farm HTTP routes."""

import asyncio
import json
import logging
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apb import VERSION
from apb.constants import (
    GUEST_BUILD_LOG_TAIL_LINES,
    GUEST_ROLE,
    TOKEN_EXPIRY_DAYS,
    BuildStatus,
)
from apb.farm import core
from apb.models import (
    BuildListResponse,
    BuildStatusResponse,
    BuildSummary,
    LoginRequest,
    LoginResponse,
    UserResponse,
)
from apb.tarball import InvalidBuildTarball, extract_build_tarball
from apb.upstream import (
    build_cancel_path,
    build_output_path,
    build_status_path,
    build_stream_path,
    upstream_url,
)
from apb.validation import validate_build_timeout
from apb.web import render_page

logger = logging.getLogger(__name__)
router = APIRouter()


def _build_status_json(build_status: Dict) -> Dict:
    return BuildStatusResponse.model_validate(build_status).model_dump(exclude_none=True)


def _is_admin(user: Optional[core.User]) -> bool:
    return bool(user and user.role == core.UserRole.ADMIN)


def _display_server_url(server_url: str, current_user: Optional[core.User]) -> str:
    return server_url if _is_admin(current_user) else core.obfuscate_server_url(server_url)


def _render_farm_page(
    template_name: str,
    request: Optional[Request],
    current_user: Optional[core.User],
    *,
    status_code: int = 200,
    **context: Any,
) -> HTMLResponse:
    csrf_token = core.csrf_token_for(core.session_token(request)) if current_user else ""
    return render_page(
        template_name,
        status_code=status_code,
        current_user=current_user,
        csrf_token=csrf_token,
        **context,
    )


def _render_farm_error(
    request: Optional[Request],
    current_user: Optional[core.User],
    status_code: int,
    title: str,
    message: str,
    **context: Any,
) -> HTMLResponse:
    return _render_farm_page(
        "farm/error.html",
        request,
        current_user,
        status_code=status_code,
        title=title,
        message=message,
        **context,
    )


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
    response.set_cookie(
        core.AUTH_COOKIE_NAME,
        token,
        max_age=TOKEN_EXPIRY_DAYS * 24 * 3600,
        path="/",
        httponly=True,
        samesite="lax",
        secure=is_https,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(core.AUTH_COOKIE_NAME, path="/")


def _see_other(path: str) -> RedirectResponse:
    return RedirectResponse(url=path, status_code=303)


@router.post("/auth/login", response_model=LoginResponse)
async def login(login_data: LoginRequest) -> LoginResponse:
    """Login with username and password"""
    user = core.auth_manager.authenticate_user(login_data.username, login_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = core.auth_manager.create_token(user)

    return LoginResponse(token=token, user=core.user_response(user))


@router.post("/auth/logout")
async def logout(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Logout current user (revoke current token)"""
    global auth_manager

    # Get token from header or cookie
    token = None
    if credentials:
        token = credentials.credentials
    else:
        token = request.cookies.get("authToken")

    if token and core.auth_manager:
        core.auth_manager.revoke_token(token)

    return {"message": "Logged out successfully"}


@router.get("/auth/logout")
async def logout_get(request: Request):
    """Browser-friendly logout endpoint"""
    # For GET requests, just return a message directing to POST
    # The JavaScript will handle the actual logout
    return {"message": "Use POST /auth/logout or JavaScript logout() function"}


@router.get("/auth/me", response_model=UserResponse)
async def get_current_user_info(current_user: core.User = Depends(core.require_auth)) -> UserResponse:
    """Get current user information"""
    return core.user_response(current_user)


@router.get("/auth/users", response_model=List[UserResponse])
async def list_users(current_user: core.User = Depends(core.require_admin)) -> List[UserResponse]:
    """List all users (admin only)"""
    return [core.user_response(user) for user in core.auth_manager.list_users()]


@router.post("/auth/users", response_model=UserResponse)
async def create_user(
    user_data: core.CreateUserRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Create a new user (admin only)"""
    global auth_manager
    try:
        role = core.UserRole(user_data.role)
        new_user = core.auth_manager.create_user(user_data.username, user_data.password, role, user_data.email)

        # Send email notification if user has email and SMTP is configured
        if new_user.email:
            try:
                core.auth_manager.send_user_notification(
                    new_user.email,
                    'created',
                    new_user.username,
                    current_user.username
                )
            except Exception as e:
                logger.warning(f"Failed to send user creation email to {new_user.email}: {e}")

        return core.user_response(new_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/auth/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: core.User = Depends(core.require_admin)
):
    """Delete a user (admin only)"""
    global auth_manager
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    # Get user info before deletion for email notification
    user_to_delete = core.auth_manager.get_user_by_id(user_id)
    if not user_to_delete:
        raise HTTPException(status_code=404, detail="User not found")

    if core.auth_manager.delete_user(user_id):
        # Send email notification if user has email and SMTP is configured
        if user_to_delete.email:
            try:
                core.auth_manager.send_user_notification(
                    user_to_delete.email,
                    'deleted',
                    user_to_delete.username,
                    current_user.username
                )
            except Exception as e:
                logger.warning(f"Failed to send user deletion email to {user_to_delete.email}: {e}")

        return {"message": f"User {user_id} deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="User not found")


@router.put("/auth/users/{user_id}/role")
async def change_user_role(
    user_id: int,
    role_data: core.ChangeRoleRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Change user role (admin only)"""
    global auth_manager
    try:
        new_role = core.UserRole(role_data.role)

        # Get user info before update for email notification
        user_to_update = core.auth_manager.get_user_by_id(user_id)
        if not user_to_update:
            raise HTTPException(status_code=404, detail="User not found")

        if core.auth_manager.change_user_role(user_id, new_role):
            # Send email notification if user has email and SMTP is configured
            if user_to_update.email:
                try:
                    core.auth_manager.send_user_notification(
                        user_to_update.email,
                        'updated',
                        user_to_update.username,
                        current_user.username
                    )
                except Exception as e:
                    logger.warning(f"Failed to send user update email to {user_to_update.email}: {e}")

            return {"message": f"User role changed to {new_role.value}"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/auth/users/{user_id}/revoke-tokens")
async def revoke_user_tokens(
    user_id: int,
    current_user: core.User = Depends(core.require_admin)
):
    """Revoke all tokens for a user (admin only)"""
    global auth_manager
    count = core.auth_manager.revoke_user_tokens(user_id)
    return {"message": f"Revoked {count} tokens for user {user_id}"}


@router.get("/auth/users/{user_id}/builds", response_model=BuildListResponse, response_model_exclude_none=True)
async def get_user_builds(
    user_id: int,
    current_user: core.User = Depends(core.require_admin),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
) -> BuildListResponse:
    """Get builds for a specific user (admin only)"""
    return core.list_builds(user_id=user_id, status=status, limit=limit, obfuscate=False)


@router.put("/auth/change-password")
async def change_password(
    password_data: core.ChangePasswordRequest,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Change current user's password"""
    global auth_manager

    current_user = await core.get_current_user(credentials, request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        core.change_user_password(
            current_user,
            password_data.current_password,
            password_data.new_password,
            password_data.confirm_password,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {"message": "Password changed successfully. Please log in again."}


# Web form endpoints (work without JavaScript)

@router.get("/login")
async def login_page(
    request: Request,
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """HTML login form."""
    if current_user:
        return _see_other("/dashboard")
    return _render_farm_page("farm/login.html", request, None, title="Log in", nav="login")


@router.post("/login")
async def login_form(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    """Log in from the HTML form and start a cookie session."""
    user = core.auth_manager.authenticate_user(username, password) if username and password else None
    if not user:
        return _render_farm_page(
            "farm/login.html",
            request,
            None,
            status_code=401,
            title="Log in",
            nav="login",
            username=username,
            error="Invalid username or password",
        )

    response = _see_other("/dashboard")
    _set_session_cookie(response, request, core.auth_manager.create_token(user))
    return response


@router.post("/logout")
async def logout_form(request: Request):
    """End the cookie session from the HTML form."""
    token = core.session_token(request)
    if token:
        await core.require_csrf(request, token)
        core.auth_manager.revoke_token(token)
    response = _see_other("/dashboard")
    _clear_session_cookie(response)
    return response


@router.get("/account")
async def account_page(
    request: Request,
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """HTML account page with password change form."""
    if not current_user:
        return _see_other("/login")
    return _render_farm_page("farm/account.html", request, current_user, title="Account", nav="account")


@router.post("/account/password")
async def account_password_form(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Change the password from the HTML form; ends all sessions of the user."""
    if not current_user:
        return _see_other("/login")
    try:
        core.change_user_password(current_user, current_password, new_password, confirm_password)
    except ValueError as e:
        return _render_farm_page(
            "farm/account.html",
            request,
            current_user,
            status_code=400,
            title="Account",
            nav="account",
            error=str(e),
        )

    response = _render_farm_page(
        "farm/login.html",
        request,
        None,
        title="Log in",
        nav="login",
        username=current_user.username,
        success="Password changed. Please log in again.",
    )
    _clear_session_cookie(response)
    return response


@router.put("/auth/users/{user_id}/email-notifications")
async def update_user_email_notifications_admin(
    user_id: int,
    notification_data: core.UpdateEmailNotificationsRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Update user's email notification preference (admin only)"""
    global auth_manager
    try:
        if core.auth_manager.update_user_email_notifications(user_id, notification_data.enabled):
            return {"message": f"Email notifications {'enabled' if notification_data.enabled else 'disabled'} for user {user_id}"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Error updating email notifications for user {user_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update email notification preference")


@router.put("/auth/users/{user_id}/email")
async def update_user_email(
    user_id: int,
    email_data: core.UpdateEmailRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Update user email (admin only)"""
    global auth_manager
    try:
        # Get user info before update for email notification
        user_to_update = core.auth_manager.get_user_by_id(user_id)
        if not user_to_update:
            raise HTTPException(status_code=404, detail="User not found")

        if core.auth_manager.update_user_email(user_id, email_data.email):
            # Send email notification to old email if it exists and SMTP is configured
            if user_to_update.email and user_to_update.email != email_data.email:
                try:
                    core.auth_manager.send_user_notification(
                        user_to_update.email,
                        'updated',
                        user_to_update.username,
                        current_user.username
                    )
                except Exception as e:
                    logger.warning(f"Failed to send user update email to old address {user_to_update.email}: {e}")

            # Send email notification to new email if it exists and SMTP is configured
            if email_data.email and email_data.email != user_to_update.email:
                try:
                    core.auth_manager.send_user_notification(
                        email_data.email,
                        'updated',
                        user_to_update.username,
                        current_user.username
                    )
                except Exception as e:
                    logger.warning(f"Failed to send user update email to new address {email_data.email}: {e}")

            return {"message": f"Email updated for user {user_id}"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/auth/my/email")
async def update_my_email(
    email_data: core.UpdateEmailRequest,
    current_user: core.User = Depends(core.require_auth)
):
    """Update current user's email"""
    global auth_manager
    try:
        if core.auth_manager.update_user_email(current_user.id, email_data.email):
            return {"message": "Email updated successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/auth/my/email-notifications")
async def update_my_email_notifications(
    notification_data: core.UpdateEmailNotificationsRequest,
    current_user: core.User = Depends(core.require_auth)
):
    """Update current user's email notification preference"""
    global auth_manager
    try:
        if core.auth_manager.update_user_email_notifications(current_user.id, notification_data.enabled):
            return {"message": f"Email notifications {'enabled' if notification_data.enabled else 'disabled'} successfully"}
        else:
            raise HTTPException(status_code=404, detail="User not found")
    except Exception as e:
        logger.error(f"Error updating email notifications for user {current_user.id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to update email notification preference")


# SMTP Configuration Endpoints

@router.get("/admin/smtp", response_model=Optional[core.SMTPConfigResponse])
async def get_smtp_config(current_user: core.User = Depends(core.require_admin)):
    """Get current SMTP configuration (admin only)"""
    global auth_manager
    smtp_config = core.auth_manager.get_smtp_config()

    if smtp_config:
        return core.SMTPConfigResponse(
            id=smtp_config.id,
            server=smtp_config.server,
            port=smtp_config.port,
            username=smtp_config.username,
            use_tls=smtp_config.use_tls,
            from_email=smtp_config.from_email,
            from_name=smtp_config.from_name,
            created_at=smtp_config.created_at,
            updated_at=smtp_config.updated_at
        )
    return None


@router.post("/admin/smtp", response_model=core.SMTPConfigResponse)
async def save_smtp_config(
    smtp_data: core.SMTPConfigRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Save SMTP configuration (admin only)"""
    global auth_manager
    try:
        smtp_config = core.auth_manager.save_smtp_config(
            server=smtp_data.server,
            port=smtp_data.port,
            username=smtp_data.username,
            password=smtp_data.password,
            use_tls=smtp_data.use_tls,
            from_email=smtp_data.from_email,
            from_name=smtp_data.from_name
        )

        return core.SMTPConfigResponse(
            id=smtp_config.id,
            server=smtp_config.server,
            port=smtp_config.port,
            username=smtp_config.username,
            use_tls=smtp_config.use_tls,
            from_email=smtp_config.from_email,
            from_name=smtp_config.from_name,
            created_at=smtp_config.created_at,
            updated_at=smtp_config.updated_at
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/admin/smtp")
async def delete_smtp_config(current_user: core.User = Depends(core.require_admin)):
    """Delete SMTP configuration (admin only)"""
    global auth_manager
    if core.auth_manager.delete_smtp_config():
        return {"message": "SMTP configuration deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="No SMTP configuration found")


@router.post("/admin/smtp/test")
async def test_smtp_config(
    test_data: core.SMTPTestRequest,
    current_user: core.User = Depends(core.require_admin)
):
    """Test SMTP configuration by sending a test email (admin only)"""
    global auth_manager, config

    dashboard_url = core.farm_page_url("/dashboard")

    subject = "APB Farm SMTP Test"
    body = f"""This is a test email from APB Farm.

If you received this email, your SMTP configuration is working correctly.

Test sent by: {current_user.username}
Test time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

APB Farm Dashboard: {dashboard_url}

Best regards,
APB Farm System"""

    if core.auth_manager.send_email(test_data.test_email, subject, body):
        return {"message": f"Test email sent successfully to {test_data.test_email}"}
    else:
        raise HTTPException(status_code=400, detail="Failed to send test email. Check SMTP configuration and logs.")


# API Endpoints

@router.get("/farm")
async def get_farm_info(current_user: Optional[core.User] = Depends(core.get_current_user_optional)):
    """Get farm information and status of all managed servers"""
    servers = []
    available_archs = await core.get_available_architectures()

    # Group servers by their actual supported architecture
    for arch, server_urls in available_archs.items():
        for server_url in server_urls:
            server_info = await core.get_server_info(server_url)

            # Obfuscate URLs for non-admin users
            display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)

            servers.append({
                "url": display_url,
                "arch": arch,  # Use actual supported architecture
                "status": "online" if server_info else "offline",
                "info": server_info
            })

    # Check for truly misconfigured servers (conservative approach)
    for config_arch, server_urls in core.config.get("servers", {}).items():
        for server_url in server_urls:
            # Check if this server is already properly listed
            # For admin users, check against real URL; for non-admin, check against obfuscated URL
            compare_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)
            already_listed = any(
                server["url"] == compare_url
                for server in servers
            )

            if not already_listed:
                # Get server status for detailed health information
                status = core.server_status_tracker.get(server_url)

                # Only mark as misconfigured if we have strong evidence
                if status and status.health == core.ServerHealth.MISCONFIGURED:
                    # Obfuscate URLs for non-admin users
                    display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)
                    servers.append({
                        "url": display_url,
                        "arch": f"{config_arch} (misconfigured)",
                        "status": "misconfigured",
                        "consecutive_failures": status.consecutive_failures,
                        "info": None
                    })
                elif status and status.health in [core.ServerHealth.DEGRADED, core.ServerHealth.UNAVAILABLE]:
                    # Don't mark degraded/unavailable servers as misconfigured
                    # They're already listed in their proper architecture group
                    pass
                else:
                    # Server not in tracking yet - get info to initialize
                    server_info = await core.get_server_info(server_url)
                    if not server_info:
                        # Initial failure - don't immediately mark as misconfigured
                        current_builds = _running_builds_by_server().get(server_url, [])
                        # Obfuscate URLs for non-admin users
                        display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)
                        servers.append({
                            "url": display_url,
                            "arch": f"{config_arch} (checking...)",
                            "status": "initializing",
                            "info": None,
                            "current_builds": current_builds,
                            "real_server_url": server_url
                        })

    return {
        "status": "running",
        "version": VERSION,
        "servers": servers,
        "available_architectures": list(available_archs.keys()),
        "total_servers": len(servers),
        "authenticated": current_user is not None,
        "user_role": current_user.role.value if current_user else GUEST_ROLE
    }


@router.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "version": VERSION
    }


@router.post("/build/{build_id}/cancel")
async def cancel_build(
    build_id: str,
    request: Request,
    current_user: core.User = Depends(core.require_auth)
):
    """Cancel a build (users can cancel own builds, admins can cancel any).

    HTML form submissions get a 303 back to the status page instead of JSON.
    """
    if not core.is_form_submission(request):
        return await _cancel_build(build_id, current_user)
    try:
        await _cancel_build(build_id, current_user)
    except HTTPException as e:
        return _render_farm_error(
            request,
            current_user,
            e.status_code,
            "Cancel failed",
            str(e.detail),
            build_id=build_id,
        )
    return _see_other(f"/build/{build_id}/status")


async def _cancel_build(build_id: str, current_user: core.User) -> Dict:
    if not core.auth_manager.can_cancel_build(current_user, build_id):
        raise HTTPException(status_code=403, detail="Not authorized to cancel this build")

    farm_cancel_result = await core.cancel_farm_queued_build(build_id)
    if farm_cancel_result is not None:
        return farm_cancel_result

    server_url = await core.find_build_server(build_id)

    if not server_url:
        cursor = core.build_database.cursor()
        cursor.execute("SELECT status FROM builds WHERE id = ?", (build_id,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Build not found")
        raise HTTPException(status_code=404, detail="Build not found on any server")

    try:
        response = await core.http_session.post(upstream_url(server_url, build_cancel_path(build_id)), timeout=10)
        if response.status_code == 200:
            result = response.json()
            core.finish_build(build_id, core.BuildStatus.CANCELLED)

            return {
                "success": True,
                "message": f"Build {build_id} cancelled successfully",
                "server_response": result
            }

        raise HTTPException(
            status_code=response.status_code,
            detail=f"Server error: {response.text}",
        )
    except Exception as e:
        logger.error(f"Error cancelling build {build_id} on server {server_url}: {e}")
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


VALID_DASHBOARD_TABS = frozenset({"servers", "builds", "statistics"})


def dashboard_path(tab: str, page: int = 1) -> str:
    if tab not in VALID_DASHBOARD_TABS or tab == "servers":
        return "/dashboard"
    if tab == "builds":
        return "/dashboard/builds" if page <= 1 else f"/dashboard/builds/{page}"
    return f"/dashboard/{tab}"


def legacy_dashboard_redirect_path(
    tab: Optional[str],
    page: Optional[int],
    *,
    current_tab: str,
    current_page: int,
) -> Optional[str]:
    if tab is None and page is None:
        return None
    resolved_tab = tab if tab in VALID_DASHBOARD_TABS else current_tab
    resolved_page = page if page is not None and page >= 1 else current_page
    canonical_path = dashboard_path(resolved_tab, resolved_page)
    current_path = dashboard_path(current_tab, current_page)
    if canonical_path == current_path:
        return None
    return canonical_path


@router.get("/dashboard/builds/{page}")
async def get_dashboard_builds_page(
    page: int,
    request: Request,
    tab: Optional[str] = Query(None),
    page_legacy: Optional[int] = Query(None, alias="page"),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Get farm dashboard on Recent Builds tab with pagination."""
    if page < 1:
        raise HTTPException(status_code=404, detail="Page not found")
    redirect_path = legacy_dashboard_redirect_path(
        tab, page_legacy, current_tab="builds", current_page=page
    )
    if redirect_path:
        return RedirectResponse(url=redirect_path, status_code=301)
    return await _render_dashboard("builds", page, request, current_user)


@router.get("/dashboard/{tab}")
async def get_dashboard_tab(
    tab: str,
    request: Request,
    tab_legacy: Optional[str] = Query(None, alias="tab"),
    page_legacy: Optional[int] = Query(None, alias="page"),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Get farm dashboard on a specific tab."""
    if tab not in VALID_DASHBOARD_TABS:
        raise HTTPException(status_code=404, detail="Unknown dashboard tab")
    redirect_path = legacy_dashboard_redirect_path(
        tab_legacy, page_legacy, current_tab=tab, current_page=1
    )
    if redirect_path:
        return RedirectResponse(url=redirect_path, status_code=301)
    return await _render_dashboard(tab, 1, request, current_user)


@router.get("/dashboard")
async def get_dashboard(
    request: Request,
    tab: Optional[str] = Query(None),
    page: Optional[int] = Query(None),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Get farm dashboard HTML."""
    redirect_path = legacy_dashboard_redirect_path(tab, page, current_tab="servers", current_page=1)
    if redirect_path:
        return RedirectResponse(url=redirect_path, status_code=301)
    return await _render_dashboard("servers", 1, request, current_user)


DASHBOARD_PAGE_SIZE = 20
DASHBOARD_RUNNING_BUILDS_SHOWN = 3
DASHBOARD_POLL_SECONDS = 30


def _running_builds_by_server() -> Dict[str, List[Dict]]:
    cursor = core.build_database.cursor()
    cursor.execute('''
        SELECT b.id, b.server_url, b.pkgname, b.start_time, u.username, b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.status = ? AND b.server_url IS NOT NULL
        ORDER BY b.start_time DESC
    ''', (BuildStatus.BUILDING,))

    running_builds: Dict[str, List[Dict]] = {}
    for build_id, server_url, pkgname, start_time, username, epoch, pkgver, pkgrel in cursor.fetchall():
        running_builds.setdefault(server_url, []).append({
            "id": build_id,
            "display_name": core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel),
            "start_time": core.safe_timestamp_to_datetime(start_time),
            "username": username or "#anon#",
        })
    return running_builds


def _dashboard_server(
    server_url: str,
    server_info: Optional[Dict],
    status: str,
    state: str,
    running_builds: List[Dict],
    current_user: Optional[core.User],
) -> Dict:
    queue_status = (server_info or {}).get("queue_status", {})
    is_busy_with_buildroot = bool(queue_status.get("server_busy_with_buildroot"))
    return {
        "url": _display_server_url(server_url, current_user),
        "status": status,
        "state": state,
        "has_info": server_info is not None,
        "current_builds_count": queue_status.get("current_builds_count", 0),
        "queued_builds": queue_status.get("queued_builds", 0),
        "buildroot_recreation_count": queue_status.get("buildroot_recreation_count", 0) if is_busy_with_buildroot else None,
        "running_builds": running_builds[:DASHBOARD_RUNNING_BUILDS_SHOWN],
        "more_running_builds": max(0, len(running_builds) - DASHBOARD_RUNNING_BUILDS_SHOWN),
    }


async def _dashboard_servers(current_user: Optional[core.User]) -> Dict[str, List[Dict]]:
    """Servers grouped by supported architecture, plus confirmed-misconfigured servers."""
    available_archs = await core.get_available_architectures()
    running_builds = _running_builds_by_server()

    servers_by_arch: Dict[str, List[Dict]] = {}
    for arch, server_urls in available_archs.items():
        server_infos = await asyncio.gather(*(core.get_server_info(server_url) for server_url in server_urls))
        servers_by_arch[arch] = [
            _dashboard_server(
                server_url,
                server_info,
                "online" if server_info else "offline",
                "online" if server_info else "offline",
                running_builds.get(server_url, []),
                current_user,
            )
            for server_url, server_info in zip(server_urls, server_infos)
        ]

    listed_urls = {server_url for server_urls in available_archs.values() for server_url in server_urls}
    for server_urls in core.config.get("servers", {}).values():
        for server_url in server_urls:
            status = core.server_status_tracker.get(server_url)
            if server_url in listed_urls or not status or status.health != core.ServerHealth.MISCONFIGURED:
                continue
            listed_urls.add(server_url)
            servers_by_arch.setdefault("misconfigured", []).append(_dashboard_server(
                server_url,
                None,
                f"misconfigured ({status.consecutive_failures} failures)",
                "misconfigured",
                running_builds.get(server_url, []),
                current_user,
            ))
    return servers_by_arch


def _dashboard_builds(page: int, current_user: Optional[core.User]) -> Dict[str, Any]:
    """One page of recent builds; fetches one extra row to know whether a next page exists."""
    cursor = core.build_database.cursor()
    cursor.execute('''
        SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.created_at, u.username, b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.created_at DESC LIMIT ? OFFSET ?
    ''', (DASHBOARD_PAGE_SIZE + 1, (page - 1) * DASHBOARD_PAGE_SIZE))
    rows = cursor.fetchall()

    builds = [
        {
            "id": build_id,
            "server_url": _display_server_url(server_url, current_user) if server_url else "unknown",
            "server_arch": server_arch,
            "display_name": core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel),
            "status": status,
            "created_at": core.safe_timestamp_to_datetime(created_at),
            "username": username or "#anon#",
        }
        for build_id, server_url, server_arch, pkgname, status, created_at, username, epoch, pkgver, pkgrel
        in rows[:DASHBOARD_PAGE_SIZE]
    ]
    has_next_page = len(rows) > DASHBOARD_PAGE_SIZE
    return {
        "builds": builds,
        "prev_url": dashboard_path("builds", page - 1) if page > 1 else None,
        "next_url": dashboard_path("builds", page + 1) if has_next_page else None,
    }


def _top_users(status: Optional[str] = None) -> List[Dict]:
    """Top 10 active users by build count, optionally only counting builds with status."""
    status_filter = "AND b.status = ?" if status else ""
    cursor = core.build_database.cursor()
    cursor.execute(f'''
        SELECT u.username, COUNT(b.id) AS build_count
        FROM users u
        LEFT JOIN builds b ON u.id = b.user_id
        WHERE u.is_active = 1 {status_filter}
        GROUP BY u.id, u.username
        ORDER BY build_count DESC
        LIMIT 10
    ''', (status,) if status else ())
    return [{"username": username, "count": count} for username, count in cursor.fetchall()]


def _dashboard_statistics() -> List[Dict]:
    return [
        {"title": "Top 10 users by total builds", "column": "Total builds", "rows": _top_users()},
        {"title": "Top 10 users by successful builds", "column": "Successful builds", "rows": _top_users(BuildStatus.COMPLETED)},
        {"title": "Top 10 users by failed builds", "column": "Failed builds", "rows": _top_users(BuildStatus.FAILED)},
    ]


async def _render_dashboard(
    tab: str,
    page: int,
    request: Request,
    current_user: Optional[core.User],
) -> HTMLResponse:
    """Render farm dashboard HTML; only the active tab's data is loaded."""
    active_tab = tab if tab in VALID_DASHBOARD_TABS else "servers"
    if active_tab == "statistics" and not current_user:
        active_tab = "servers"

    context: Dict[str, Any] = {"active_tab": active_tab, "page": page}
    if active_tab == "servers":
        context["servers_by_arch"] = await _dashboard_servers(current_user)
        context["poll_seconds"] = DASHBOARD_POLL_SECONDS
    elif active_tab == "builds":
        context.update(_dashboard_builds(page, current_user))
    else:
        context["statistics"] = _dashboard_statistics()

    return _render_farm_page(
        "farm/dashboard.html",
        request,
        current_user,
        title="Dashboard",
        nav=active_tab,
        **context,
    )


@router.post("/build")
async def submit_build(
    build_tarball: UploadFile = File(None),
    pkgbuild: UploadFile = File(None),
    sources: List[UploadFile] = File(default=[]),
    architectures: str = Form(None),
    build_timeout: Optional[int] = Form(None),
    current_user: core.User = Depends(core.require_auth)  # Require authentication
):
    """Submit a build request (authenticated users only, supports both tarball and individual file uploads)"""
    try:
        if build_timeout is not None and current_user.role != core.UserRole.ADMIN:
            raise HTTPException(
                status_code=403,
                detail="Only admin users can specify custom build timeouts"
            )
        try:
            timeout_seconds = validate_build_timeout(build_timeout)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        original_tarball = None
        if build_tarball and build_tarball.filename:
            # Extract only to read metadata; the original tarball is forwarded unchanged
            original_tarball = await build_tarball.read()
            with tempfile.TemporaryDirectory() as temp_dir:
                try:
                    pkgbuild_path = extract_build_tarball(original_tarball, Path(temp_dir))
                    pkgbuild_content = pkgbuild_path.read_text(encoding="utf-8")
                except (InvalidBuildTarball, UnicodeDecodeError) as e:
                    raise HTTPException(status_code=400, detail=str(e))
            source_files = []

        # Handle individual file uploads (legacy method for backward compatibility)
        elif pkgbuild and pkgbuild.filename:
            # Read PKGBUILD content
            pkgbuild_content = (await pkgbuild.read()).decode('utf-8')

            # Read source files
            source_files = []
            for source in sources:
                if source.filename:
                    content = await source.read()
                    source_files.append({
                        "filename": source.filename,
                        "content": content,
                        "content_type": source.content_type or "application/octet-stream"
                    })
        else:
            raise HTTPException(
                status_code=400,
                detail="Either build_tarball or pkgbuild must be provided"
            )

        # Parse PKGBUILD (same logic regardless of upload method)
        pkgname = core.parse_pkgbuild_name(pkgbuild_content)
        pkgbuild_archs = core.parse_pkgbuild_arch(pkgbuild_content)

        # Parse and validate extra repositories
        requested_repos = core.parse_pkgbuild_extra_repos(pkgbuild_content)
        valid_repos, invalid_repos = core.validate_extra_repos(requested_repos)

        if invalid_repos:
            return {
                "error": "Invalid custom repositories",
                "message": f"The following custom repositories are not configured by an admin: {', '.join(invalid_repos)}",
                "pkgname": pkgname,
                "invalid_repositories": invalid_repos
            }

        # Determine target architectures
        if architectures:
            # Use architectures provided by client (filtered list)
            target_archs = [arch.strip() for arch in architectures.split(',') if arch.strip()]
            logger.info(f"Using client-specified architectures: {target_archs}")
        else:
            # Fall back to all architectures from PKGBUILD
            target_archs = pkgbuild_archs
            logger.info(f"Using all PKGBUILD architectures: {target_archs}")

        # Validate that requested architectures are actually in the PKGBUILD
        invalid_archs = [arch for arch in target_archs if arch not in pkgbuild_archs and arch != "any"]
        if invalid_archs:
            logger.warning(f"Requested architectures {invalid_archs} not found in PKGBUILD arch={pkgbuild_archs}")
            # Filter out invalid architectures
            target_archs = [arch for arch in target_archs if arch in pkgbuild_archs or arch == "any"]

        if not target_archs:
            return {
                "error": "No valid architectures",
                "message": "No valid architectures specified or found in PKGBUILD",
                "pkgname": pkgname,
                "pkgbuild_architectures": pkgbuild_archs,
                "requested_architectures": architectures.split(',') if architectures else []
            }

        queued_builds = await core.queue_builds_for_architectures(
            pkgbuild_content, pkgname, target_archs, source_files, current_user.id, timeout_seconds, original_tarball, valid_repos
        )

        if not queued_builds:
            # Get available architectures for error message
            available_archs = await core.get_available_architectures()
            return {
                "error": "No builds queued",
                "message": "No servers available for any of the target architectures",
                "pkgname": pkgname,
                "target_architectures": target_archs,
                "available_architectures": list(available_archs.keys()),
                "pkgbuild_architectures": pkgbuild_archs
            }

        # Return the first build ID for backward compatibility, plus info about all builds
        primary_build = queued_builds[0]

        response = {
            "build_id": primary_build["build_id"],  # Primary build ID for backward compatibility
            "status": core.BuildStatus.QUEUED,
            "message": f"Queued {len(queued_builds)} build(s) for processing",
            "pkgname": pkgname,
            "target_architectures": target_archs,
            "pkgbuild_architectures": pkgbuild_archs,  # Show all architectures from PKGBUILD
            "builds": queued_builds,  # Information about all queued builds
            "submission_group": primary_build["submission_group"],
            "queue_status": {
                "queue_size": len(core.build_queue),
                "builds_queued": len(queued_builds),
                "message": (
                    f"Build(s) queued on farm; waiting for server capacity "
                    f"({len(core.build_queue)} job(s) in farm queue)"
                ),
            },
            "created_at": time.time()
        }

        # Include timeout info in response
        if build_timeout is not None:
            response["build_timeout"] = timeout_seconds
            response["timeout_set_by"] = current_user.username

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error submitting build: {e}")
        raise HTTPException(status_code=500, detail=str(e))


BUILD_STATUS_REFRESH_SECONDS = {
    "queued": 10,
    "live": 30,
    "cached": 30,
    "connection_failed": 30,
    "unavailable": 60,
    "unreachable": 60,
}
BUILD_STATUS_HTTP_CODES = {"not_found": 404, "submission_failed": 404, "unavailable": 503, "unreachable": 503}
CANCELLABLE_STATES = frozenset({"queued", "live", "cached", "connection_failed"})


def _cached_build_status(cached_response: Optional[str]) -> Optional[Dict]:
    if not cached_response:
        return None
    try:
        return json.loads(cached_response)
    except json.JSONDecodeError:
        return None


async def _load_build_status(build_id: str) -> Dict[str, Any]:
    """Resolve a build's status from the farm database, farm queue, build server or cache.

    ``state`` is one of not_found, queued, submission_failed, cached (server marked
    unavailable), unavailable, live, connection_failed (cached after a failed
    request) or unreachable.
    """
    cursor = core.build_database.cursor()
    cursor.execute('''
        SELECT b.server_url, b.server_arch, b.pkgname, b.status, b.last_known_status,
               b.server_available, b.cached_response, b.last_status_update, b.created_at, u.username,
               b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.id = ?
    ''', (build_id,))
    row = cursor.fetchone()

    if not row:
        return {
            "state": "not_found",
            "error_detail": {
                "error": "Build not found",
                "detail": f"Build {build_id} was not found in the farm database. "
                         "This build may not have been submitted through this farm, "
                         "or the submission may have failed before being recorded.",
                "build_id": build_id,
            },
        }

    (server_url, server_arch, pkgname, status, last_known_status, server_available, cached_response,
     last_status_update, created_at, username, epoch, pkgver, pkgrel) = row
    record = {
        "server_arch": server_arch,
        "pkgname": pkgname,
        "status": status,
        "last_known_status": last_known_status,
        "last_status_update": last_status_update,
        "created_at": created_at,
        "username": username or "#anon#",
        "display_name": core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel),
        "server": core.obfuscate_server_url(server_url) if server_url else None,
    }

    # Builds waiting in the farm queue have no server assignment yet
    if not server_url and status == BuildStatus.QUEUED:
        return {
            "state": "queued",
            "record": record,
            "build_status": {
                "build_id": build_id,
                "pkgname": pkgname,
                "status": status,
                "server_arch": server_arch,
                "created_at": created_at,
                "packages": [],
                "logs": [],
                "artifacts_ready": False,
                **core.get_farm_queue_status_for_build(build_id),
            },
        }

    if not server_url:
        return {
            "state": "submission_failed",
            "record": record,
            "error_detail": {
                "error": "Build submission failed",
                "detail": f"Build {build_id} failed during submission and was never assigned to a server. "
                         f"Current status: {status}",
                "build_id": build_id,
                "status": status,
                "created_at": created_at,
            },
        }

    if server_available is False:
        build_status = _cached_build_status(cached_response)
        if build_status is not None:
            build_status.update({
                "server_unavailable": True,
                "last_status_update": last_status_update,
                "server_url": record["server"],
                "server_arch": server_arch,
            })
            return {"state": "cached", "record": record, "build_status": build_status}
        return {
            "state": "unavailable",
            "record": record,
            "error_detail": {
                "error": "Server unavailable",
                "detail": f"Build {build_id} is assigned to server {record['server']} "
                         "but the server is currently unavailable and no cached status is available.",
                "build_id": build_id,
                "server_url": record["server"],
                "last_known_status": last_known_status or status,
            },
        }

    try:
        response = await core.http_session.get(upstream_url(server_url, build_status_path(build_id)), timeout=10)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Build not found")
        build_status = response.json()
        build_status["server_url"] = record["server"]
        if server_arch:
            build_status["server_arch"] = server_arch
        else:
            logger.warning(f"server_arch is None/empty for build {build_id}")

        core.persist_live_build_status(build_id, build_status)
        build_status = await core.enrich_build_status_with_artifact_cache(build_id, server_url, build_status)
        return {"state": "live", "record": record, "build_status": build_status}
    except Exception as e:
        cursor.execute('SELECT cached_response, last_status_update, server_arch FROM builds WHERE id = ?', (build_id,))
        cached_row = cursor.fetchone()
        build_status = _cached_build_status(cached_row[0]) if cached_row else None
        error = str(e.detail) if isinstance(e, HTTPException) else str(e)
        if build_status is None:
            return {"state": "unreachable", "record": record, "error": error}
        record["last_status_update"] = cached_row[1]
        build_status.update({
            "server_unavailable": True,
            "last_status_update": cached_row[1],
            "server_url": record["server"],
            "server_arch": cached_row[2],
            "error_message": f"Server unavailable: {error}",
        })
        return {"state": "connection_failed", "record": record, "build_status": build_status, "error": error}


async def _build_status_json_response(build_id: str) -> Dict:
    result = await _load_build_status(build_id)
    state = result["state"]
    if state in BUILD_STATUS_HTTP_CODES and "error_detail" in result:
        raise HTTPException(status_code=BUILD_STATUS_HTTP_CODES[state], detail=result["error_detail"])
    if state == "unreachable":
        raise HTTPException(status_code=503, detail=f"Server unavailable: {result['error']}")
    return _build_status_json(result["build_status"])


def _build_status_page(
    build_id: str,
    result: Dict[str, Any],
    request: Request,
    current_user: Optional[core.User],
) -> HTMLResponse:
    state = result["state"]
    record = result.get("record") or {}
    build_status = result.get("build_status") or {}
    status = build_status.get("status") or record.get("status")
    if state == "unavailable":
        status = record.get("last_known_status") or record.get("status")

    is_active = status not in BuildStatus.TERMINAL
    refresh_seconds = BUILD_STATUS_REFRESH_SECONDS.get(state) if (is_active or state in ("unavailable", "unreachable")) else None
    can_cancel = bool(
        current_user
        and state in CANCELLABLE_STATES
        and status in (BuildStatus.QUEUED, BuildStatus.BUILDING)
        and core.auth_manager.can_cancel_build(current_user, build_id)
    )
    return _render_farm_page(
        "farm/build_status.html",
        request,
        current_user,
        status_code=BUILD_STATUS_HTTP_CODES.get(state, 200),
        title="Build not found" if state == "not_found" else f"Build: {record.get('display_name')}",
        nav="builds",
        state=state,
        build_id=build_id,
        record=record,
        build_status=build_status,
        status=status,
        error=result.get("error"),
        detail=(result.get("error_detail") or {}).get("detail"),
        refresh_seconds=refresh_seconds,
        can_cancel=can_cancel,
    )


@router.get("/build/{build_id}/status")
async def get_build_status(
    build_id: str,
    request: Request,
    format: str = Query("html"),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Get build status as HTML (default) or JSON (format=json)."""
    if format == "json":
        return await _build_status_json_response(build_id)
    return _build_status_page(build_id, await _load_build_status(build_id), request, current_user)


@router.get("/build/{build_id}/status-api", response_model=BuildStatusResponse, response_model_exclude_none=True)
async def get_build_status_api(build_id: str) -> Dict:
    """Get build status as JSON"""
    return await _build_status_json_response(build_id)


@router.get("/build/{build_id}/output")
async def get_build_output(build_id: str, start_index: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=1000)):
    """Get build output/logs"""
    server_url = await core.find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        params = {"start_index": start_index, "limit": limit}
        response = await core.http_session.get(
            upstream_url(server_url, build_output_path(build_id)),
            params=params,
            timeout=10,
        )
        if response.status_code == 200:
            return response.json()

        raise HTTPException(status_code=response.status_code, detail="Build output not found")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@router.get("/build/{build_id}/stream")
async def stream_build_output(build_id: str):
    """Stream build output in real-time"""
    server_url = await core.find_build_server(build_id)

    if not server_url:
        # Check if we have build information in database
        cursor = core.build_database.cursor()
        cursor.execute('''
            SELECT server_url, server_available, pkgname
            FROM builds WHERE id = ?
        ''', (build_id,))
        result = cursor.fetchone()

        if result:
            server_url, server_available, pkgname = result
            if not server_available:
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error": "Server unavailable",
                        "message": f"The server handling build {build_id} is currently unavailable",
                        "pkgname": pkgname,
                        "suggestion": "Please try again later when the server recovers"
                    }
                )

        raise HTTPException(status_code=404, detail="Build not found")

    try:
        async def event_generator():
            async with core.http_session.stream(
                "GET",
                upstream_url(server_url, build_stream_path(build_id)),
                timeout=None,
            ) as response:
                if response.status_code == 200:
                    async for line in response.aiter_lines():
                        yield f"{line}\n"
                else:
                    yield f"data: Error: {response.status_code}\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")
    except Exception as e:
        if "503" in str(e) or "502" in str(e) or "Connection" in str(e):
            # Server unavailable
            cursor = core.build_database.cursor()
            cursor.execute('''
                SELECT pkgname FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()
            pkgname = result[0] if result else "unknown"

            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Server unavailable",
                    "message": f"The server handling build {build_id} is currently unavailable",
                    "pkgname": pkgname,
                    "suggestion": "Please try again later when the server recovers"
                }
            )
        else:
            raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@router.get("/build/{build_id}/download/{filename}")
async def download_file(
    build_id: str,
    filename: str,
    request: Request,
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Download build artifact from local cache.

    build.log is truncated to the last GUEST_BUILD_LOG_TAIL_LINES for unauthenticated
    callers; authenticated dashboard and APB client users receive the full log.
    """

    cached_artifact = await core.get_cached_artifact(build_id, filename)
    if cached_artifact:
        file_path = cached_artifact["file_path"]
        file_size = cached_artifact["file_size"]
    else:
        file_path = core.get_local_artifact_path(build_id, filename)
        if not file_path:
            return _render_farm_error(
                request,
                current_user,
                404,
                "File not found",
                "The requested file is not available on this farm.",
                build_id=build_id,
                rows=[("Build ID", build_id), ("Filename", filename)],
                hints=[
                    "Artifacts are cached when builds complete; check whether the build has finished",
                    "Verify that the build ID and filename are correct",
                    "The cached copy may have expired; try again later if the build is still in progress",
                ],
            )
        file_size = file_path.stat().st_size

    logger.debug(f"Serving {filename} for build {build_id} from local cache")

    content_type, disposition = core.determine_content_type_and_disposition(filename)

    # Guests only get a truncated build.log; authenticated users get the full file
    if filename == "build.log" and current_user is None:
        body = core.format_guest_build_log_tail(file_path, GUEST_BUILD_LOG_TAIL_LINES).encode("utf-8")
        headers = {
            "Cache-Control": "private, no-store",
            "ETag": f'"{build_id}-{filename}-guest-tail"',
            "Content-Length": str(len(body)),
            "X-APB-Log-Truncated": "true",
            "X-APB-Log-Tail-Lines": str(GUEST_BUILD_LOG_TAIL_LINES),
        }
        if disposition == "attachment":
            headers["Content-Disposition"] = f"attachment; filename={filename}"
        else:
            headers["Content-Disposition"] = f"inline; filename={filename}"
        return Response(content=body, media_type="text/plain; charset=utf-8", headers=headers)

    headers = {
        "Content-Length": str(file_size),
    }
    if filename == "build.log":
        # Avoid caching full vs truncated variants interchangeably
        headers["Cache-Control"] = "private, no-store"
        headers["ETag"] = f'"{build_id}-{filename}-full"'
    else:
        headers["Cache-Control"] = "public, max-age=2592000, immutable"
        headers["ETag"] = f'"{build_id}-{filename}"'

    if disposition == "attachment":
        headers["Content-Disposition"] = f"attachment; filename={filename}"
    else:
        headers["Content-Disposition"] = f"inline; filename={filename}"

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type=content_type,
        headers=headers
    )


@router.get("/builds/pkgname/{pkgname}", response_model=BuildListResponse, response_model_exclude_none=True)
async def get_builds_for_package(
    pkgname: str,
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
) -> BuildListResponse:
    """Get recent builds for a specific package name known to the farm."""
    return core.list_builds(pkgname=pkgname, status=status, limit=limit)


@router.get("/builds/pkgname/{pkgname}/latest", response_model=BuildSummary, response_model_exclude_none=True)
async def get_latest_build_for_package(
    pkgname: str,
    successful_only: bool = Query(True),
) -> BuildSummary:
    """Get the latest build for a package across all architectures."""
    build = core.get_latest_build_for_pkgname(pkgname, successful_only=successful_only)
    if not build:
        raise HTTPException(status_code=404, detail=f"No builds found for package '{pkgname}'")
    return build


@router.get("/builds/pkgname/{pkgname}/arch/{arch}/latest", response_model=BuildSummary, response_model_exclude_none=True)
async def get_latest_build_for_package_arch(
    pkgname: str,
    arch: str,
    successful_only: bool = Query(True),
) -> BuildSummary:
    """Get the latest build for a package on a specific architecture.

    Use arch `any` to match the latest successful build regardless of server_arch
    (for PKGBUILD `arch=('any')` packages).
    """
    build = core.get_latest_build_for_pkgname(pkgname, arch=arch, successful_only=successful_only)
    if not build:
        raise HTTPException(
            status_code=404,
            detail=f"No builds found for package '{pkgname}' (arch={arch})",
        )
    return build


@router.get("/builds/pkgname/{pkgname}/latest-by-arch", response_model=BuildListResponse, response_model_exclude_none=True)
async def get_latest_builds_by_arch_for_package(
    pkgname: str,
    successful_only: bool = Query(True),
) -> BuildListResponse:
    """Get the latest build for each architecture of a package."""
    return core.get_latest_builds_by_arch_for_pkgname(pkgname, successful_only=successful_only)


@router.get("/builds/latest", response_model=BuildListResponse, response_model_exclude_none=True)
async def get_latest_builds(
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
) -> BuildListResponse:
    """Get latest builds across all servers"""
    return core.list_builds(status=status, limit=limit)


@router.get("/my/builds", response_model=BuildListResponse, response_model_exclude_none=True)
async def get_my_builds(
    current_user: core.User = Depends(core.require_auth),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
) -> BuildListResponse:
    """Get builds submitted by current user"""
    return core.list_builds(user_id=current_user.id, status=status, limit=limit)


@router.get("/admin/cache")
async def get_cache_status(current_user: core.User = Depends(core.require_admin)):
    """Get cache status information for administrators"""
    cache_config = core.get_cache_config()

    if not cache_config["enabled"]:
        return {
            "enabled": False,
            "message": "Caching is disabled"
        }

    cursor = core.build_database.cursor()

    # Get cache statistics
    cursor.execute('SELECT COUNT(*) FROM cached_artifacts')
    total_artifacts = cursor.fetchone()[0]

    cursor.execute('SELECT SUM(file_size) FROM cached_artifacts')
    total_size_result = cursor.fetchone()
    total_size = total_size_result[0] if total_size_result[0] else 0

    cursor.execute('SELECT MIN(cached_at) FROM cached_artifacts')
    oldest_cache_result = cursor.fetchone()
    oldest_cache = oldest_cache_result[0] if oldest_cache_result[0] else None

    # Get expired artifacts count
    retention_seconds = cache_config["retention_days"] * 24 * 60 * 60
    current_time = time.time()
    cutoff_time = current_time - retention_seconds

    cursor.execute('SELECT COUNT(*) FROM cached_artifacts WHERE cached_at < ?', (cutoff_time,))
    expired_artifacts = cursor.fetchone()[0]

    return {
        "enabled": True,
        "retention_days": cache_config["retention_days"],
        "directory": str(cache_config["directory"]),
        "max_size_mb": cache_config["max_size_mb"],
        "total_artifacts": total_artifacts,
        "total_size_bytes": total_size,
        "total_size_mb": round(total_size / 1024 / 1024, 2) if total_size else 0,
        "expired_artifacts": expired_artifacts,
        "oldest_cache_timestamp": oldest_cache,
        "oldest_cache_age_days": round((current_time - oldest_cache) / 86400, 1) if oldest_cache else None
    }


@router.post("/admin/cache/cleanup")
async def manual_cache_cleanup(current_user: core.User = Depends(core.require_admin)):
    """Manually trigger cache cleanup for administrators"""
    cache_config = core.get_cache_config()

    if not cache_config["enabled"]:
        return {
            "success": False,
            "message": "Caching is disabled"
        }

    try:
        # Get count before cleanup
        cursor = core.build_database.cursor()
        cursor.execute('SELECT COUNT(*) FROM cached_artifacts')
        artifacts_before = cursor.fetchone()[0]

        # Run cleanup
        await core.cleanup_expired_cache()

        # Get count after cleanup
        cursor.execute('SELECT COUNT(*) FROM cached_artifacts')
        artifacts_after = cursor.fetchone()[0]

        cleaned_count = artifacts_before - artifacts_after

        return {
            "success": True,
            "artifacts_before": artifacts_before,
            "artifacts_after": artifacts_after,
            "artifacts_cleaned": cleaned_count,
            "message": f"Cache cleanup completed. Removed {cleaned_count} expired artifacts."
        }

    except Exception as e:
        logger.error(f"Manual cache cleanup failed: {e}")
        return {
            "success": False,
            "message": f"Cache cleanup failed: {str(e)}"
        }


# Repository management endpoints
@router.get("/admin/repositories")
async def get_repositories(current_user: core.User = Depends(core.require_admin)):
    """Get all custom repositories (admin only)"""
    try:
        cursor = core.build_database.cursor()
        cursor.execute('''
            SELECT id, name, url, gpg_key_id, description, is_active, created_at, created_by
            FROM custom_repositories
            ORDER BY created_at DESC
        ''')

        repos = []
        for row in cursor.fetchall():
            repos.append({
                "id": row[0],
                "name": row[1],
                "url": row[2],
                "gpg_key_id": row[3],
                "description": row[4],
                "is_active": bool(row[5]),
                "created_at": row[6],
                "created_by": row[7]
            })

        return {"repositories": repos}
    except Exception as e:
        logger.error(f"Error fetching repositories: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch repositories")


@router.post("/admin/repositories")
async def create_repository(
    name: str = Form(...),
    url: str = Form(...),
    gpg_key_id: str = Form(...),
    description: str = Form(""),
    current_user: core.User = Depends(core.require_admin)
):
    """Create a new custom repository (admin only)"""
    try:
        # Validate URL format
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL format")

        # Check if repository name already exists
        cursor = core.build_database.cursor()
        cursor.execute('SELECT id FROM custom_repositories WHERE name = ?', (name,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Repository name already exists")

        # Insert new repository
        cursor.execute('''
            INSERT INTO custom_repositories (name, url, gpg_key_id, description, is_active, created_at, created_by)
            VALUES (?, ?, ?, ?, 1, ?, ?)
        ''', (name, url, gpg_key_id, description, time.time(), current_user.id))
        core.build_database.commit()

        return {"success": True, "message": f"Repository '{name}' created successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating repository: {e}")
        raise HTTPException(status_code=500, detail="Failed to create repository")


@router.put("/admin/repositories/{repo_id}")
async def update_repository(
    repo_id: int,
    name: str = Form(None),
    url: str = Form(None),
    gpg_key_id: str = Form(None),
    description: str = Form(None),
    is_active: bool = Form(None),
    current_user: core.User = Depends(core.require_admin)
):
    """Update a custom repository (admin only)"""
    try:
        cursor = core.build_database.cursor()

        # Check if repository exists
        cursor.execute('SELECT id FROM custom_repositories WHERE id = ?', (repo_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Repository not found")

        # Build update query dynamically
        updates = []
        params = []

        if name is not None:
            # Check if new name conflicts with existing repository
            cursor.execute('SELECT id FROM custom_repositories WHERE name = ? AND id != ?', (name, repo_id))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="Repository name already exists")
            updates.append("name = ?")
            params.append(name)

        if url is not None:
            # Validate URL format
            from urllib.parse import urlparse
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise HTTPException(status_code=400, detail="Invalid URL format")
            updates.append("url = ?")
            params.append(url)

        if gpg_key_id is not None:
            updates.append("gpg_key_id = ?")
            params.append(gpg_key_id)

        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)

        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")

        params.append(repo_id)
        query = f"UPDATE custom_repositories SET {', '.join(updates)} WHERE id = ?"

        cursor.execute(query, params)
        core.build_database.commit()

        return {"success": True, "message": f"Repository updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating repository: {e}")
        raise HTTPException(status_code=500, detail="Failed to update repository")


@router.delete("/admin/repositories/{repo_id}")
async def delete_repository(repo_id: int, current_user: core.User = Depends(core.require_admin)):
    """Delete a custom repository (admin only)"""
    try:
        cursor = core.build_database.cursor()

        # Check if repository exists
        cursor.execute('SELECT name FROM custom_repositories WHERE id = ?', (repo_id,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Repository not found")

        repo_name = result[0]

        # Delete repository
        cursor.execute('DELETE FROM custom_repositories WHERE id = ?', (repo_id,))
        core.build_database.commit()

        return {"success": True, "message": f"Repository '{repo_name}' deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting repository: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete repository")


@router.get("/admin")
async def get_admin_panel(
    request: Request,
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Admin panel (admin only); user actions, SMTP, repositories and cache go through the JSON API."""
    if not current_user:
        return _see_other("/login")
    if not _is_admin(current_user):
        return _render_farm_error(request, current_user, 403, "Admin access required", "Only administrators can open the admin panel.")
    return _render_farm_page(
        "farm/admin.html",
        request,
        current_user,
        title="Admin",
        nav="admin",
        users=core.auth_manager.list_users(),
    )
