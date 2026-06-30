"""APB farm HTTP routes."""

import json
import logging
import time
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from apb import VERSION
from apb.farm import core

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/auth/login", response_model=core.LoginResponse)
async def login(login_data: core.LoginRequest):
    """Login with username and password"""
    global auth_manager
    user = core.auth_manager.authenticate_user(login_data.username, login_data.password)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = core.auth_manager.create_token(user)

    return core.LoginResponse(
        token=token,
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "email": user.email
        }
    )


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


@router.get("/auth/me", response_model=core.UserResponse)
async def get_current_user_info(current_user: core.User = Depends(core.require_auth)):
    """Get current user information"""
    return core.UserResponse(
        id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        email=current_user.email,
        email_notifications_enabled=current_user.email_notifications_enabled
    )


@router.get("/auth/users", response_model=List[core.UserResponse])
async def list_users(current_user: core.User = Depends(core.require_admin)):
    """List all users (admin only)"""
    global auth_manager
    users = core.auth_manager.list_users()
    return [
        core.UserResponse(
            id=user.id,
            username=user.username,
            role=user.role.value,
            created_at=user.created_at,
            last_login=user.last_login,
            email=user.email,
            email_notifications_enabled=user.email_notifications_enabled
        )
        for user in users
    ]


@router.post("/auth/users", response_model=core.UserResponse)
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

        return core.UserResponse(
            id=new_user.id,
            username=new_user.username,
            role=new_user.role.value,
            created_at=new_user.created_at,
            last_login=new_user.last_login,
            email=new_user.email,
            email_notifications_enabled=new_user.email_notifications_enabled
        )
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


@router.get("/auth/users/{user_id}/builds")
async def get_user_builds(
    user_id: int,
    current_user: core.User = Depends(core.require_admin),
    limit: int = 50
):
    """Get builds for a specific user (admin only)"""
    global auth_manager
    builds = core.auth_manager.get_user_builds(user_id, limit)
    return {"builds": builds}


@router.put("/auth/change-password")
async def change_password(
    password_data: core.ChangePasswordRequest,
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Change current user's password"""
    global auth_manager

    # Get current user
    current_user = await get_current_user(credentials, request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Validate password confirmation
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirmation do not match")

    # Change password
    success = core.auth_manager.change_password(
        current_user.id,
        password_data.current_password,
        password_data.new_password
    )

    if not success:
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    # Revoke all existing tokens for this user (force re-login)
    core.auth_manager.revoke_user_tokens(current_user.id)

    return {"message": "Password changed successfully. Please log in again."}


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

    # Get dashboard URL from configuration
    farm_url = core.config.get('farm_url', 'http://localhost:8080')
    dashboard_url = f"{farm_url.rstrip('/')}/dashboard"

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
            server_info = await get_server_info(server_url)

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
                    server_info = await get_server_info(server_url)
                    if not server_info:
                        # Initial failure - don't immediately mark as misconfigured
                        current_builds = running_builds_by_server.get(server_url, [])
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
        "user_role": current_user.role.value if current_user else "guest"
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
    current_user: core.User = Depends(core.require_auth)
):
    """Cancel a build (users can cancel own builds, admins can cancel any)"""
    global auth_manager

    # Check permissions
    if not core.auth_manager.can_cancel_build(current_user, build_id):
        raise HTTPException(status_code=403, detail="Not authorized to cancel this build")

    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        async with core.http_session.post(f"{server_url}/build/{build_id}/cancel", timeout=10) as response:
            if response.status == 200:
                result = await response.json()

                # Update local database
                cursor = core.build_database.cursor()
                cursor.execute('''
                    UPDATE builds SET status = ?, end_time = ?
                    WHERE id = ?
                ''', (core.BuildStatus.CANCELLED, time.time(), build_id))
                core.build_database.commit()

                return {
                    "success": True,
                    "message": f"Build {build_id} cancelled successfully",
                    "server_response": result
                }
            else:
                error_detail = await response.text()
                raise HTTPException(status_code=response.status, detail=f"Server error: {error_detail}")
    except Exception as e:
        logger.error(f"Error cancelling build {build_id} on server {server_url}: {e}")
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@router.get("/dashboard")
async def get_dashboard(
    page: int = Query(1, ge=1),
    tab: str = Query("servers"),
    current_user: Optional[core.User] = Depends(core.get_current_user_optional),
):
    """Get farm dashboard HTML"""
    valid_tabs = {"servers", "builds", "statistics"}
    active_tab = tab if tab in valid_tabs else "servers"
    if active_tab == "statistics" and not current_user:
        active_tab = "servers"
    # Get server status grouped by actual supported architecture
    available_archs = await core.get_available_architectures()
    servers_by_arch = {}

    # Get currently running builds for all servers
    cursor = core.build_database.cursor()
    cursor.execute('''
        SELECT b.id, b.server_url, b.pkgname, b.start_time, b.created_at, u.username, b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.status = ? AND b.server_url IS NOT NULL
        ORDER BY b.start_time DESC
    ''', (core.BuildStatus.BUILDING,))

    running_builds_by_server = {}
    for build_id, server_url, pkgname, start_time, created_at, username, epoch, pkgver, pkgrel in cursor.fetchall():
        if server_url not in running_builds_by_server:
            running_builds_by_server[server_url] = []

        # Format package name with version
        display_name = core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel)

        running_builds_by_server[server_url].append({
            "id": build_id,
            "pkgname": pkgname,
            "display_name": display_name,
            "start_time": core.safe_timestamp_to_datetime(start_time),
            "created_at": core.safe_timestamp_to_datetime(created_at),
            "username": username if username else "#anon#"
        })

    for arch, server_urls in available_archs.items():
        servers_by_arch[arch] = []
        for server_url in server_urls:
            server_info = await get_server_info(server_url)
            # Get running builds for this server
            current_builds = running_builds_by_server.get(server_url, [])
            # Show real URLs to admin users, obfuscated URLs to non-admin users
            display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)
            servers_by_arch[arch].append({
                "url": display_url,
                "status": "online" if server_info else "offline",
                "info": server_info,
                "current_builds": current_builds,
                "real_server_url": server_url  # Keep for matching builds
            })

    # Check for truly misconfigured servers (conservative dashboard logic)
    for config_arch, server_urls in core.config.get("servers", {}).items():
        for server_url in server_urls:
            # Check if this server is already listed in available architectures
            already_listed = any(
                server_url in arch_servers
                for arch_servers in available_archs.values()
            )
            if not already_listed:
                # Get server status for health information
                status = core.server_status_tracker.get(server_url)

                # Only show as misconfigured if we have strong evidence
                if status and status.health == core.ServerHealth.MISCONFIGURED:
                    if "misconfigured" not in servers_by_arch:
                        servers_by_arch["misconfigured"] = []
                    # Get running builds for misconfigured server too
                    current_builds = running_builds_by_server.get(server_url, [])
                    # Show real URLs to admin users, obfuscated URLs to non-admin users
                    display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)
                    servers_by_arch["misconfigured"].append({
                        "url": display_url,
                        "status": f"misconfigured ({status.consecutive_failures} failures)",
                        "info": None,
                        "current_builds": current_builds,
                        "real_server_url": server_url
                    })
                elif not status or status.consecutive_failures < 3:
                    # Don't show servers that are just initializing or have few failures
                    pass

    # Get recent builds with user information
    cursor = core.build_database.cursor()
    offset = (page - 1) * 20
    cursor.execute('''
        SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username, b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        ORDER BY b.created_at DESC LIMIT 20 OFFSET ?
    ''', (offset,))

    builds = []
    for row in cursor.fetchall():
        # Show real URLs to admin users, obfuscated URLs to non-admin users
        server_url = row[1]
        display_url = "unknown"
        if server_url:
            display_url = server_url if (current_user and current_user.role == core.UserRole.ADMIN) else core.obfuscate_server_url(server_url)

        # Format package name with version
        pkgname = row[3]
        epoch = row[9]
        pkgver = row[10]
        pkgrel = row[11]
        display_name = core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel)

        builds.append({
            "id": row[0],
            "server_url": display_url,
            "server_arch": row[2],
            "pkgname": pkgname,
            "display_name": display_name,
            "status": row[4],
            "start_time": core.safe_timestamp_to_datetime(row[5]),
            "end_time": core.safe_timestamp_to_datetime(row[6]),
            "created_at": core.safe_timestamp_to_datetime(row[7]) or "unknown",
            "username": row[8] if row[8] else "#anon#"
        })

    # Get user statistics (only for logged-in users)
    user_stats = {}
    if current_user:
        # Top 10 users by total builds
        cursor.execute('''
            SELECT u.username, COUNT(b.id) as total_builds
            FROM users u
            LEFT JOIN builds b ON u.id = b.user_id
            WHERE u.is_active = 1
            GROUP BY u.id, u.username
            ORDER BY total_builds DESC
            LIMIT 10
        ''')
        user_stats['top_builders'] = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Top 10 users by successful builds
        cursor.execute('''
            SELECT u.username, COUNT(b.id) as successful_builds
            FROM users u
            LEFT JOIN builds b ON u.id = b.user_id
            WHERE u.is_active = 1 AND b.status = ?
            GROUP BY u.id, u.username
            ORDER BY successful_builds DESC
            LIMIT 10
        ''', (core.BuildStatus.COMPLETED,))
        user_stats['top_successful'] = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]

        # Top 10 users by failed builds
        cursor.execute('''
            SELECT u.username, COUNT(b.id) as failed_builds
            FROM users u
            LEFT JOIN builds b ON u.id = b.user_id
            WHERE u.is_active = 1 AND b.status = ?
            GROUP BY u.id, u.username
            ORDER BY failed_builds DESC
            LIMIT 10
        ''', (core.BuildStatus.FAILED,))
        user_stats['top_failed'] = [{'username': row[0], 'count': row[1]} for row in cursor.fetchall()]

    # Generate HTML with authentication UI
    auth_section = ""
    if current_user:
        admin_link = ""
        if current_user.role == core.UserRole.ADMIN:
            admin_link = '<a href="/admin" class="admin-link" title="User Administration">⚙️ Admin</a>'

        auth_section = f"""
        <div class="auth-section">
            {admin_link}
            <span class="auth-user clickable" onclick="showPasswordChangeForm()" title="Click to change password">👤 {current_user.username} ({current_user.role.value})</span>
            <button onclick="logout()" class="auth-button logout-button">Logout</button>
        </div>
        """
    else:
        auth_section = """
        <div class="auth-section">
            <button onclick="showLoginForm()" class="auth-button login-button">Login</button>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APB Farm Dashboard</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; position: relative; }}
            .header {{ text-align: center; margin-bottom: 30px; position: relative; }}
            .auth-section {{ position: absolute; top: 10px; right: 10px; display: flex; align-items: center; gap: 10px; }}
            .admin-link {{ color: #ffc107; font-weight: bold; text-decoration: none; padding: 5px 8px; border-radius: 3px; background-color: rgba(255, 193, 7, 0.1); }}
            .admin-link:hover {{ background-color: rgba(255, 193, 7, 0.2); text-decoration: underline; }}
            .auth-user {{ margin-right: 10px; font-weight: bold; color: #28a745; }}
            .auth-user.clickable {{ cursor: pointer; text-decoration: underline; }}
            .auth-user.clickable:hover {{ color: #1e7e34; }}
            .auth-button {{ padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }}
            .login-button {{ background-color: #007bff; color: white; }}
            .login-button:hover {{ background-color: #0056b3; }}
            .logout-button {{ background-color: #dc3545; color: white; }}
            .logout-button:hover {{ background-color: #c82333; }}
            .login-form {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border: 2px solid #ddd; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); z-index: 1000; display: none; }}
            .login-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; display: none; }}
            .login-form input {{ display: block; width: 200px; margin: 10px 0; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
            .login-form button {{ margin: 5px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
            .login-submit {{ background-color: #28a745; color: white; }}
            .login-cancel {{ background-color: #6c757d; color: white; }}
            .error-message {{ color: #dc3545; margin: 10px 0; }}
            .success-message {{ color: #28a745; margin: 10px 0; font-weight: bold; }}
            .password-hint {{ color: #6c757d; font-size: 0.9em; margin: 5px 0; }}
            .servers {{ margin-bottom: 30px; }}
            .arch-group {{ margin-bottom: 20px; }}
            .arch-title {{ font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
            .server {{ margin: 5px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
            .online {{ background-color: #d4edda; }}
            .offline {{ background-color: #f8d7da; }}
            .misconfigured {{ background-color: #fff3cd; }}
            .builds {{ margin-top: 30px; }}
            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
            .completed {{ background-color: #d4edda; }}
            .failed {{ background-color: #f8d7da; }}
            .building {{ background-color: #fff3cd; }}
            .queued {{ background-color: #d1ecf1; }}
            .cancelled {{ background-color: #e2e3e5; }}
            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
            .build a:hover {{ text-decoration: underline; }}
            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
            .pagination {{ text-align: center; margin: 20px 0; }}
            .pagination a {{ margin: 0 5px; padding: 5px 10px; text-decoration: none; border: 1px solid #ddd; }}
            .running-builds {{ margin-top: 8px; padding: 8px; background-color: #f8f9fa; border-radius: 3px; border-left: 3px solid #007bff; }}
            .running-builds ul {{ margin: 5px 0 0 0; padding-left: 20px; }}
            .running-builds li {{ margin: 2px 0; font-size: 0.9em; }}
            .running-builds a {{ color: #007bff; text-decoration: none; }}
            .running-builds a:hover {{ text-decoration: underline; }}
            .running-builds small {{ color: #666; margin-left: 5px; }}
            .tabs {{ margin: 20px 0; }}
            .tab-buttons {{ display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; }}
            .tab-button {{ padding: 12px 24px; background: #f8f9fa; border: 1px solid #ddd; border-bottom: none; cursor: pointer; margin-right: 2px; border-radius: 8px 8px 0 0; transition: all 0.3s; }}
            .tab-button:hover {{ background: #e9ecef; }}
            .tab-button.active {{ background: white; border-bottom: 2px solid white; margin-bottom: -2px; font-weight: bold; color: #007bff; }}
            .tab-content {{ display: none; }}
            .tab-content.active {{ display: block; }}
            .statistics {{ margin: 20px 0; }}
            .stat-section {{ margin: 30px 0; }}
            .stat-section h3 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; margin-bottom: 15px; }}
            .stats-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; max-width: 600px; }}
            .stats-table th, .stats-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
            .stats-table th {{ background-color: #f8f9fa; font-weight: bold; }}
            .stats-table tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .stats-table tr:hover {{ background-color: #e9ecef; }}
            .stats-table td:first-child {{ text-align: center; font-weight: bold; }}
            .stats-table td:last-child {{ text-align: center; }}
        </style>
    </head>
    <body>
        <div class="login-overlay" id="loginOverlay" onclick="hideLoginForm()"></div>
        <div class="login-form" id="loginForm">
            <h3>Login to APB Farm</h3>
            <form id="loginFormElement" onsubmit="submitLogin(event)">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <div class="error-message" id="loginError"></div>
                <button type="submit" class="login-submit">Login</button>
                <button type="button" class="login-cancel" onclick="hideLoginForm()">Cancel</button>
            </form>
        </div>

        <div class="login-overlay" id="passwordChangeOverlay" onclick="hidePasswordChangeForm()"></div>
        <div class="login-form" id="passwordChangeForm">
            <h3>Change Password</h3>
            <form id="passwordChangeFormElement" onsubmit="submitPasswordChange(event)">
                <input type="password" id="currentPassword" placeholder="Current Password" required>
                <input type="password" id="newPassword" placeholder="New Password (min 8 characters)" required>
                <input type="password" id="confirmPassword" placeholder="Confirm New Password" required>
                <div class="password-hint">Password must be at least 8 characters long</div>
                <div class="error-message" id="passwordChangeError"></div>
                <div class="success-message" id="passwordChangeSuccess"></div>
                <button type="submit" class="login-submit">Change Password</button>
                <button type="button" class="login-cancel" onclick="hidePasswordChangeForm()">Cancel</button>
            </form>
        </div>

        <div class="header">
            {auth_section}
            <h1>APB Farm Dashboard</h1>
            <p>Version: {VERSION}</p>
            <p>Available Architectures: {', '.join(available_archs.keys())}</p>
        </div>

        <div class="tabs">
            <div class="tab-buttons">
                <div class="tab-button{' active' if active_tab == 'servers' else ''}" onclick="switchTab('servers-tab', this)">🌾 Servers by Architecture</div>
                <div class="tab-button{' active' if active_tab == 'builds' else ''}" onclick="switchTab('builds-tab', this)">📋 Recent Builds</div>
                {'<div class="tab-button' + (' active' if active_tab == 'statistics' else '') + '" onclick="switchTab(\'statistics-tab\', this)">📊 Statistics</div>' if current_user else ''}
            </div>

            <div id="servers-tab" class="tab-content{' active' if active_tab == 'servers' else ''}">
                <div class="servers">
    """

    for arch, servers in servers_by_arch.items():
        html += f"""
            <div class="arch-group">
                <div class="arch-title">{arch}</div>
        """
        for server in servers:
            status_class = "online" if server["status"] == "online" else ("misconfigured" if arch == "misconfigured" else "offline")
            queue_info = ""
            buildroot_info = ""
            if server["info"]:
                queue_status = server["info"].get("queue_status", {})
                queue_info = f" - Builds: {queue_status.get('current_builds_count', 0)}, Queued: {queue_status.get('queued_builds', 0)}"

                # Add buildroot recreation information
                if queue_status.get("server_busy_with_buildroot", False):
                    buildroot_count = queue_status.get("buildroot_recreation_count", 0)
                    buildroot_info = f" - <span style='color: #ff8c00; font-weight: bold;'>🔨 Buildroot Recreation ({buildroot_count})</span>"

            # Show currently running builds
            current_builds_html = ""
            if server.get("current_builds"):
                current_builds_html = "<div class='running-builds'><strong>Currently Building:</strong><ul>"
                for build in server["current_builds"][:3]:  # Show max 3 builds to avoid clutter
                    start_time = build["start_time"] or "unknown"
                    username = build.get("username", "#anon#")
                    display_name = build.get("display_name", build["pkgname"])
                    current_builds_html += f"""
                        <li>
                            <a href="/build/{build['id']}/status">{display_name}</a> by <strong>{username}</strong>
                            <small>(started: {start_time})</small>
                        </li>
                    """
                if len(server["current_builds"]) > 3:
                    current_builds_html += f"<li><em>... and {len(server['current_builds']) - 3} more</em></li>"
                current_builds_html += "</ul></div>"

            html += f"""
                <div class="server {status_class}">
                    <strong>{server['url']}</strong> ({server['status']}){queue_info}{buildroot_info}
                    {current_builds_html}
                </div>
            """
        html += "</div>"

    builds_pagination = f"""
                <div class="pagination">
                    <a href="/dashboard?page={max(1, page-1)}&tab=builds">&laquo; Previous</a>
                    <span>Page {page}</span>
                    <a href="/dashboard?page={page+1}&tab=builds">Next &raquo;</a>
                </div>
    """

    html += f"""
                </div>
            </div>

            <div id="builds-tab" class="tab-content{' active' if active_tab == 'builds' else ''}">
                {builds_pagination}
                <div class="builds">
    """

    for build in builds:
        display_name = build.get('display_name', build['pkgname'])
        html += f"""
            <div class="build {build['status']}">
                <strong>{display_name}</strong> - {build['status']} on {build['server_url']} ({build['server_arch']})
                <br>
                <span class="build-id">Build ID: {build['id']}</span>
                <br>
                <small>Created: {build['created_at']} by <strong>{build['username']}</strong></small>
                <br>
                <small>
                    <a href="/build/{build['id']}/status">📋 View Details & Logs</a>
                </small>
            </div>
        """

    html += f"""
                </div>
                {builds_pagination}
            </div>

            {'<div id="statistics-tab" class="tab-content' + (' active' if active_tab == 'statistics' else '') + '">' if current_user else ''}
            {'<div class="statistics">' if current_user else ''}

            {'<div class="stat-section">' if current_user else ''}
            {'<h3>📈 Top 10 Users by Total Builds</h3>' if current_user else ''}
            {'<table class="stats-table">' if current_user else ''}
            {'<thead><tr><th>Rank</th><th>Username</th><th>Total Builds</th></tr></thead>' if current_user else ''}
            {'<tbody>' if current_user else ''}
            {''.join([f'<tr><td>{i+1}</td><td>{user["username"]}</td><td>{user["count"]}</td></tr>' for i, user in enumerate(user_stats.get('top_builders', []))]) if current_user else ''}
            {'</tbody></table></div>' if current_user else ''}

            {'<div class="stat-section">' if current_user else ''}
            {'<h3>✅ Top 10 Users by Successful Builds</h3>' if current_user else ''}
            {'<table class="stats-table">' if current_user else ''}
            {'<thead><tr><th>Rank</th><th>Username</th><th>Successful Builds</th></tr></thead>' if current_user else ''}
            {'<tbody>' if current_user else ''}
            {''.join([f'<tr><td>{i+1}</td><td>{user["username"]}</td><td>{user["count"]}</td></tr>' for i, user in enumerate(user_stats.get('top_successful', []))]) if current_user else ''}
            {'</tbody></table></div>' if current_user else ''}

            {'<div class="stat-section">' if current_user else ''}
            {'<h3>❌ Top 10 Users by Failed Builds</h3>' if current_user else ''}
            {'<table class="stats-table">' if current_user else ''}
            {'<thead><tr><th>Rank</th><th>Username</th><th>Failed Builds</th></tr></thead>' if current_user else ''}
            {'<tbody>' if current_user else ''}
            {''.join([f'<tr><td>{i+1}</td><td>{user["username"]}</td><td>{user["count"]}</td></tr>' for i, user in enumerate(user_stats.get('top_failed', []))]) if current_user else ''}
            {'</tbody></table></div>' if current_user else ''}

            {'</div></div>' if current_user else ''}
        </div>

        <script>
            // Tab switching function
            function switchTab(tabId, button) {{
                // Hide all tab contents
                const tabContents = document.querySelectorAll('.tab-content');
                tabContents.forEach(content => {{
                    content.classList.remove('active');
                }});

                // Remove active class from all tab buttons
                const tabButtons = document.querySelectorAll('.tab-button');
                tabButtons.forEach(btn => {{
                    btn.classList.remove('active');
                }});

                // Show selected tab content
                document.getElementById(tabId).classList.add('active');

                // Add active class to clicked tab button
                button.classList.add('active');

                // Persist active tab in URL so pagination and reloads keep the selection
                const tabName = tabId.replace('-tab', '');
                const url = new URL(window.location);
                url.searchParams.set('tab', tabName);
                if (tabName !== 'builds') {{
                    url.searchParams.delete('page');
                }}
                history.replaceState(null, '', url);
            }}

            function showLoginForm() {{
                document.getElementById('loginOverlay').style.display = 'block';
                document.getElementById('loginForm').style.display = 'block';
                document.getElementById('username').focus();
            }}

            function hideLoginForm() {{
                document.getElementById('loginOverlay').style.display = 'none';
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('loginError').textContent = '';
                document.getElementById('loginFormElement').reset();
            }}

            function showPasswordChangeForm() {{
                document.getElementById('passwordChangeOverlay').style.display = 'block';
                document.getElementById('passwordChangeForm').style.display = 'block';
                document.getElementById('currentPassword').focus();
            }}

            function hidePasswordChangeForm() {{
                document.getElementById('passwordChangeOverlay').style.display = 'none';
                document.getElementById('passwordChangeForm').style.display = 'none';
                document.getElementById('passwordChangeError').textContent = '';
                document.getElementById('passwordChangeSuccess').textContent = '';
                document.getElementById('passwordChangeFormElement').reset();
            }}

            async function submitLogin(event) {{
                event.preventDefault();

                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                const errorDiv = document.getElementById('loginError');

                try {{
                    const response = await fetch('/auth/login', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{ username, password }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        // Store token in localStorage and cookie
                        localStorage.setItem('authToken', data.token);
                        document.cookie = `authToken=${{data.token}}; path=/; max-age=${{data.expires_in_days * 24 * 3600}}; SameSite=Lax`;
                        // Reload page to show authenticated state
                        window.location.reload();
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Login failed';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Login error:', error);
                }}
            }}

            async function submitPasswordChange(event) {{
                event.preventDefault();

                const currentPassword = document.getElementById('currentPassword').value;
                const newPassword = document.getElementById('newPassword').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const errorDiv = document.getElementById('passwordChangeError');
                const successDiv = document.getElementById('passwordChangeSuccess');

                // Clear previous messages
                errorDiv.textContent = '';
                successDiv.textContent = '';

                // Client-side validation
                if (newPassword !== confirmPassword) {{
                    errorDiv.textContent = 'New password and confirmation do not match';
                    return;
                }}

                if (newPassword.length < 8) {{
                    errorDiv.textContent = 'New password must be at least 8 characters long';
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/auth/change-password', {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{
                            current_password: currentPassword,
                            new_password: newPassword,
                            confirm_password: confirmPassword
                        }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        successDiv.textContent = data.message;

                        // Auto-logout and redirect to login after 3 seconds
                        setTimeout(() => {{
                            localStorage.removeItem('authToken');
                            document.cookie = 'authToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                            window.location.reload();
                        }}, 3000);
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Password change failed';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Password change error:', error);
                }}
            }}

            async function logout() {{
                try {{
                    const token = getAuthToken();
                    if (token) {{
                        await fetch('/auth/logout', {{
                            method: 'POST',
                            headers: {{
                                'Authorization': `Bearer ${{token}}`
                            }}
                        }});
                    }}
                }} catch (error) {{
                    console.error('Logout error:', error);
                }} finally {{
                    // Always remove token from localStorage and cookie
                    localStorage.removeItem('authToken');
                    document.cookie = 'authToken=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
                    window.location.reload();
                }}
            }}

            // Helper function to get auth token from localStorage or cookie
            function getAuthToken() {{
                // Try localStorage first
                let token = localStorage.getItem('authToken');
                if (token) return token;

                // Fall back to cookie
                const cookies = document.cookie.split(';');
                for (let cookie of cookies) {{
                    const [name, value] = cookie.trim().split('=');
                    if (name === 'authToken') {{
                        return value;
                    }}
                }}
                return null;
            }}

            // Sync token between localStorage and cookie on page load
            const token = getAuthToken();
            if (token) {{
                // Ensure token is in both localStorage and cookie
                localStorage.setItem('authToken', token);
                if (!document.cookie.includes('authToken=')) {{
                    document.cookie = `authToken=${{token}}; path=/; max-age=${{10 * 24 * 3600}}; SameSite=Lax`;
                }}

                // Add auth header to future requests
                const originalFetch = window.fetch;
                window.fetch = function(...args) {{
                    if (args[1]) {{
                        args[1].headers = args[1].headers || {{}};
                        args[1].headers['Authorization'] = `Bearer ${{token}}`;
                    }} else {{
                        args[1] = {{
                            headers: {{ 'Authorization': `Bearer ${{token}}` }}
                        }};
                    }}
                    return originalFetch.apply(this, args);
                }};
            }}
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


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
        # Validate timeout parameter
        if build_timeout is not None:
            if current_user.role != core.UserRole.ADMIN:
                raise HTTPException(
                    status_code=403,
                    detail="Only admin users can specify custom build timeouts"
                )
            if build_timeout < 300 or build_timeout > 14400:  # 5 minutes to 4 hours
                raise HTTPException(
                    status_code=400,
                    detail="Build timeout must be between 300 and 14400 seconds (5 minutes to 4 hours)"
                )

        # Use default timeout if not specified
        timeout_seconds = build_timeout if build_timeout is not None else 7200

        # Handle tarball upload (new method)
        if build_tarball and build_tarball.filename:
            # Create temporary directory for extraction
            import tempfile
            import tarfile

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_dir_path = Path(temp_dir)

                # Save tarball temporarily and keep original content
                tarball_path = temp_dir_path / "build.tar.gz"
                original_tarball_content = await build_tarball.read()
                with open(tarball_path, 'wb') as f:
                    f.write(original_tarball_content)

                # Extract tarball ONLY to read metadata - don't recreate from extracted files
                try:
                    with tarfile.open(tarball_path, 'r:gz') as tar:
                        # Extract all files to temp directory
                        tar.extractall(path=temp_dir_path, filter='data')

                    # Read PKGBUILD content for metadata
                    pkgbuild_path = temp_dir_path / "PKGBUILD"
                    if not pkgbuild_path.exists():
                        raise HTTPException(
                            status_code=400,
                            detail="Tarball must contain a PKGBUILD file"
                        )

                    with open(pkgbuild_path, 'r', encoding='utf-8') as f:
                        pkgbuild_content = f.read()

                    # For tarball submissions, source_files are not needed since we forward the original tarball
                    source_files = []

                except (tarfile.TarError, OSError) as e:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Could not extract tarball: {str(e)}"
                    )

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

        # Queue builds for each architecture - pass original tarball if available
        original_tarball = original_tarball_content if 'original_tarball_content' in locals() else None
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
                "queue_size": len(build_queue),
                "builds_queued": len(queued_builds)
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


@router.get("/build/{build_id}/status")
async def get_build_status(build_id: str, format: str = Query("html")):
    """Get build status"""
    # First check our database for build information
    cursor = core.build_database.cursor()
    cursor.execute('''
        SELECT b.server_url, b.server_arch, b.pkgname, b.status, b.last_known_status,
               b.server_available, b.cached_response, b.last_status_update, b.created_at, u.username,
               b.epoch, b.pkgver, b.pkgrel
        FROM builds b
        LEFT JOIN users u ON b.user_id = u.id
        WHERE b.id = ?
    ''', (build_id,))
    result = cursor.fetchone()

    if not result:
        # Build not found in our database
        error_detail = {
            "error": "Build not found",
            "detail": f"Build {build_id} was not found in the farm database. "
                     "This build may not have been submitted through this farm, "
                     "or the submission may have failed before being recorded.",
            "build_id": build_id
        }
        if format == "json":
            raise HTTPException(status_code=404, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Build Not Found</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                </div>

                <div class="build failed">
                    <h2>❌ Build Not Found</h2>
                    <div class="error-detail">
                        <strong>Error:</strong> The requested build could not be found in the farm database.
                    </div>

                    <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>

                    <h3>Details</h3>
                    <p>{error_detail['detail']}</p>

                    <h3>Next Steps</h3>
                    <ul>
                        <li>Verify that you're using the correct build ID</li>
                        <li>Ensure the build was submitted through this farm</li>
                        <li>Check if the build was submitted to a different farm instance</li>
                    </ul>

                    <p>
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a>
                    </p>
                </div>
            </body>
            </html>
            """, status_code=404)

    server_url, server_arch, pkgname, status, last_known_status, server_available, cached_response, last_status_update, created_at, username, epoch, pkgver, pkgrel = result
    username = username if username else "#anon#"

    # Format package name with version for display
    display_name = core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel)

    # If we don't have a server_url, the build failed during submission
    if not server_url:
        error_detail = {
            "error": "Build submission failed",
            "detail": f"Build {build_id} failed during submission and was never assigned to a server. "
                     f"Current status: {status}",
            "build_id": build_id,
            "status": status,
            "created_at": created_at
        }
        if format == "json":
            raise HTTPException(status_code=404, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Build Submission Failed - {display_name}</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                    .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                    .metadata p {{ margin: 5px 0; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                </div>

                <div class="build failed">
                    <h2>❌ Build Submission Failed: {display_name}</h2>
                    <div class="error-detail">
                        <strong>Submission Error:</strong> This build failed during submission and was never assigned to a server.
                    </div>

                    <div class="metadata">
                        <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                        <p><strong>Package:</strong> {display_name}</p>
                        <p><strong>Status:</strong> {status}</p>
                        <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                        <p><strong>Created:</strong> {datetime.fromtimestamp(created_at).strftime('%Y-%m-%d %H:%M:%S') if created_at else 'unknown'}</p>
                        <p><strong>Triggered by:</strong> {username}</p>
                    </div>

                    <h3>Possible Causes</h3>
                    <ul>
                        <li>No servers available for the target architecture</li>
                        <li>All servers at capacity during submission</li>
                        <li>Network connectivity issues</li>
                        <li>Invalid PKGBUILD or source files</li>
                    </ul>

                    <h3>Next Steps</h3>
                    <ul>
                        <li>Check server availability for your architecture</li>
                        <li>Verify your PKGBUILD is valid</li>
                        <li>Try submitting the build again</li>
                    </ul>

                    <p>
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a> |
                        <a href="/farm">🌾 View Farm Status</a>
                    </p>
                </div>
            </body>
            </html>
            """, status_code=404)

    # We have a server assignment - check if server is available
    if server_available is False:
        # Server is marked as unavailable, use cached data if available
        if cached_response:
            try:
                build_status = json.loads(cached_response)
                build_status["server_unavailable"] = True
                build_status["last_status_update"] = last_status_update
                build_status["server_url"] = core.obfuscate_server_url(server_url)
                build_status["server_arch"] = server_arch  # Add architecture from farm database

                if format == "json":
                    return build_status
                else:
                    status_class = build_status.get('status', 'unknown')
                    # Get detailed status information if available
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status (Server Unavailable) - {display_name}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .warning-detail {{ background-color: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; margin: 15px 0; }}
                            .warning-detail strong {{ color: #856404; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{display_name}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>⚠️ Build Status (Server Unavailable)</h2>
                            <div class="warning-detail">
                                <strong>Server Status:</strong> The build server is currently unavailable. Showing last known status.<br>
                                <em>This page will auto-refresh every 30 seconds to check for server recovery.</em>
                            </div>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {display_name}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {core.obfuscate_server_url(server_url)} (unavailable)</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_status_update).strftime('%Y-%m-%d %H:%M:%S UTC') if last_status_update else 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>

                            <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                                <strong>Note:</strong> This information may be outdated due to server unavailability.
                                The server will automatically reconnect when available, and status will update.
                            </div>
                        </div>
                    </body>
                    </html>
                    """)
            except json.JSONDecodeError:
                pass

        # No cached data and server unavailable
        error_detail = {
            "error": "Server unavailable",
            "detail": f"Build {build_id} is assigned to server {core.obfuscate_server_url(server_url)} "
                     "but the server is currently unavailable and no cached status is available.",
            "build_id": build_id,
            "server_url": core.obfuscate_server_url(server_url),
            "last_known_status": last_known_status or status
        }
        if format == "json":
            raise HTTPException(status_code=503, detail=error_detail)
        else:
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Server Unavailable - {display_name}</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <meta http-equiv="refresh" content="60">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                    .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                    .metadata p {{ margin: 5px 0; }}
                    .retry-info {{ background-color: #d1ecf1; padding: 15px; border: 1px solid #bee5eb; border-radius: 5px; margin: 15px 0; }}
                    .retry-info strong {{ color: #0c5460; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Build Status</h1>
                    <p>Package: <strong>{display_name}</strong></p>
                </div>

                <div class="build failed">
                    <h2>❌ Server Unavailable</h2>
                    <div class="error-detail">
                        <strong>Connection Error:</strong> The server handling this build is currently unavailable and no cached status is available.
                    </div>

                    <div class="metadata">
                        <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                        <p><strong>Package:</strong> {display_name}</p>
                        <p><strong>Server:</strong> {core.obfuscate_server_url(server_url)} (unavailable)</p>
                        <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                        <p><strong>Last Known Status:</strong> {last_known_status or status}</p>
                        <p><strong>Triggered by:</strong> {username}</p>
                    </div>

                    <div class="retry-info">
                        <strong>Auto-Retry:</strong> This page will automatically refresh every 60 seconds to check for server recovery.<br>
                        <em>The farm will continue attempting to connect to the server in the background.</em>
                    </div>

                    <h3>Possible Causes</h3>
                    <ul>
                        <li>Server is temporarily down for maintenance</li>
                        <li>Network connectivity issues</li>
                        <li>Server overload or high resource usage</li>
                        <li>Server configuration problems</li>
                    </ul>

                    <h3>What to Do</h3>
                    <ul>
                        <li>Wait for the server to recover (auto-refresh will detect this)</li>
                        <li>Check the farm dashboard for other available servers</li>
                        <li>Contact the farm administrator if the issue persists</li>
                        <li>Consider submitting to a different architecture if available</li>
                    </ul>

                    <h3>Actions</h3>
                    <p>
                        <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                        <a href="/dashboard">🏠 Back to Dashboard</a> |
                        <a href="/farm">🌾 View Farm Status</a> |
                        <a href="/builds/latest">📋 View Recent Builds</a>
                    </p>

                    <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                        <strong>Status Monitoring:</strong> The farm is actively monitoring this server and will update the build status
                        as soon as connectivity is restored. Your build may still be running on the server.
                    </div>
                </div>
            </body>
            </html>
            """, status_code=503)

    # Server should be available - try to contact it
    if format == "json":
        try:
            async with core.http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                if response.status == 200:
                    build_status = await response.json()
                    build_status["server_url"] = core.obfuscate_server_url(server_url)
                    if server_arch:
                        build_status["server_arch"] = server_arch  # Add architecture from farm database
                    else:
                        logger.warning(f"server_arch is None/empty for build {build_id}")

                    # Update our cache with the latest status
                    cursor = core.build_database.cursor()
                    cursor.execute('''
                        UPDATE builds SET
                            last_known_status = ?,
                            last_status_update = ?,
                            server_available = 1,
                            cached_response = ?
                        WHERE id = ?
                    ''', (build_status.get('status', 'unknown'), time.time(),
                         json.dumps(build_status), build_id))
                    core.build_database.commit()

                    return build_status
                else:
                    raise HTTPException(status_code=response.status, detail="Build not found")
        except Exception as e:
            # Server is unavailable, try to return cached response
            cursor = core.build_database.cursor()
            cursor.execute('''
                SELECT cached_response, last_status_update, server_arch, pkgname
                FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()

            if result and result[0]:  # cached_response exists
                try:
                    build_status = json.loads(result[0])
                    build_status["server_unavailable"] = True
                    build_status["last_status_update"] = result[1]
                    build_status["server_url"] = core.obfuscate_server_url(server_url)
                    build_status["server_arch"] = result[2]  # Add architecture from database result
                    build_status["error_message"] = f"Server unavailable: {str(e)}"
                    return build_status
                except json.JSONDecodeError:
                    pass

            raise HTTPException(status_code=503, detail=f"Server unavailable: {str(e)}")
    else:
        # Generate farm's own HTML page instead of forwarding to server
        try:
            async with core.http_session.get(f"{server_url}/build/{build_id}/status-api", timeout=10) as response:
                if response.status == 200:
                    build_status = await response.json()
                    build_status["server_url"] = core.obfuscate_server_url(server_url)
                    if server_arch:
                        build_status["server_arch"] = server_arch

                    # Update our cache with the latest status
                    cursor = core.build_database.cursor()
                    cursor.execute('''
                        UPDATE builds SET
                            last_known_status = ?,
                            last_status_update = ?,
                            server_available = 1,
                            cached_response = ?
                        WHERE id = ?
                    ''', (build_status.get('status', 'unknown'), time.time(),
                         json.dumps(build_status), build_id))
                    core.build_database.commit()

                    # Generate HTML response
                    status_class = build_status.get('status', 'unknown')
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status - {display_name}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{display_name}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>📋 Build Status</h2>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {display_name}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {core.obfuscate_server_url(server_url)}</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>
                        </div>
                    </body>
                    </html>
                    """)
                else:
                    raise HTTPException(status_code=response.status, detail="Build not found")
        except Exception as e:
            # Server is unavailable, try to return cached response as HTML
            cursor = core.build_database.cursor()
            cursor.execute('''
                SELECT cached_response, last_status_update, server_arch, pkgname, epoch, pkgver, pkgrel
                FROM builds WHERE id = ?
            ''', (build_id,))
            result = cursor.fetchone()

            if result and result[0]:  # cached_response exists
                try:
                    build_status = json.loads(result[0])
                    cached_pkgname = result[3] or 'unknown'
                    last_update = result[1]
                    cached_epoch = result[4]
                    cached_pkgver = result[5]
                    cached_pkgrel = result[6]
                    status_class = build_status.get('status', 'unknown')

                    # Format package name with version for cached response
                    cached_display_name = core.format_package_name_with_version(cached_pkgname, cached_epoch, cached_pkgver, cached_pkgrel)

                    # Get detailed status information if available
                    packages = build_status.get('packages', [])
                    logs = build_status.get('logs', [])
                    start_time = build_status.get('start_time')
                    end_time = build_status.get('end_time')
                    duration = build_status.get('duration', 0)

                    # Build packages HTML
                    packages_html = ""
                    if packages:
                        packages_html = "<h3>📦 Available Packages</h3><ul>"
                        for pkg in packages:
                            packages_html += f'<li><a href="{pkg.get("download_url", "#")}">{pkg.get("filename", "unknown")}</a> ({pkg.get("size", 0)} bytes)</li>'
                        packages_html += "</ul>"

                    # Build logs HTML
                    logs_html = ""
                    if logs:
                        logs_html = "<h3>📄 Build Logs</h3><ul>"
                        for log in logs:
                            logs_html += f'<li><a href="{log.get("download_url", "#")}">{log.get("filename", "unknown")}</a> ({log.get("size", 0)} bytes)</li>'
                        logs_html += "</ul>"

                    return HTMLResponse(f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Build Status (Server Unavailable) - {cached_display_name}</title>
                        <meta charset="utf-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1">
                        <meta http-equiv="refresh" content="30">
                        <style>
                            body {{ font-family: Arial, sans-serif; margin: 20px; }}
                            .header {{ text-align: center; margin-bottom: 30px; }}
                            .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                            .completed {{ background-color: #d4edda; }}
                            .failed {{ background-color: #f8d7da; }}
                            .building {{ background-color: #fff3cd; }}
                            .queued {{ background-color: #d1ecf1; }}
                            .cancelled {{ background-color: #e2e3e5; }}
                            .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                            .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                            .build a:hover {{ text-decoration: underline; }}
                            .warning-detail {{ background-color: #fff3cd; padding: 15px; border: 1px solid #ffeaa7; border-radius: 5px; margin: 15px 0; }}
                            .warning-detail strong {{ color: #856404; }}
                            .metadata {{ background-color: #f8f9fa; padding: 10px; border: 1px solid #dee2e6; border-radius: 5px; margin: 15px 0; }}
                            .metadata p {{ margin: 5px 0; }}
                            .status-indicator {{ padding: 5px 10px; border-radius: 3px; font-weight: bold; display: inline-block; }}
                            .status-completed {{ background-color: #d4edda; color: #155724; }}
                            .status-failed {{ background-color: #f8d7da; color: #721c24; }}
                            .status-building {{ background-color: #fff3cd; color: #856404; }}
                            .status-queued {{ background-color: #d1ecf1; color: #0c5460; }}
                            .status-cancelled {{ background-color: #e2e3e5; color: #383d41; }}
                            .error-info {{ background-color: #f8d7da; padding: 10px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; font-size: 0.9em; }}
                        </style>
                    </head>
                    <body>
                        <div class="header">
                            <h1>APB Farm - Build Status</h1>
                            <p>Package: <strong>{cached_display_name}</strong></p>
                        </div>

                        <div class="build {status_class}">
                            <h2>⚠️ Build Status (Server Connection Failed)</h2>
                            <div class="warning-detail">
                                <strong>Connection Issue:</strong> Unable to contact the build server. Showing last cached status.<br>
                                <em>This page will auto-refresh every 30 seconds to check for server recovery.</em>
                            </div>

                            <div class="metadata">
                                <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                                <p><strong>Package:</strong> {cached_display_name}</p>
                                <p><strong>Status:</strong> <span class="status-indicator status-{status_class}">{build_status.get('status', 'unknown')}</span></p>
                                <p><strong>Server:</strong> {core.obfuscate_server_url(server_url)} (connection failed)</p>
                                <p><strong>Architecture:</strong> {server_arch or 'unknown'}</p>
                                <p><strong>Last Update:</strong> {datetime.fromtimestamp(last_update).strftime('%Y-%m-%d %H:%M:%S UTC') if last_update else 'unknown'}</p>
                                <p><strong>Triggered by:</strong> {username}</p>
                                {f'<p><strong>Start Time:</strong> {datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if start_time else ''}
                                {f'<p><strong>End Time:</strong> {datetime.fromtimestamp(end_time).strftime("%Y-%m-%d %H:%M:%S UTC")}</p>' if end_time else ''}
                                {f'<p><strong>Duration:</strong> {duration:.1f} seconds</p>' if duration > 0 else ''}
                            </div>

                            <div class="error-info">
                                <strong>Connection Error:</strong> {str(e)}
                            </div>

                            {packages_html}
                            {logs_html}

                            <h3>Actions</h3>
                            <p>
                                <a href="/build/{build_id}/status" onclick="location.reload()">🔄 Refresh Status</a> |
                                <a href="/dashboard">🏠 Back to Dashboard</a> |
                                <a href="/farm">🌾 View Farm Status</a>
                            </p>

                            <div style="margin-top: 20px; padding: 10px; background-color: #e9ecef; border-radius: 5px; font-size: 0.9em;">
                                <strong>Note:</strong> This information may be outdated due to server connectivity issues.
                                The farm will automatically retry connection and update status when possible.
                            </div>
                        </div>
                    </body>
                    </html>
                    """)
                except json.JSONDecodeError:
                    pass

            raise HTTPException(status_code=503, detail=f"Server unavailable: {str(e)}")


@router.get("/build/{build_id}/status-api")
async def get_build_status_api(build_id: str):
    """Get build status as JSON"""
    return await get_build_status(build_id, format="json")


@router.get("/build/{build_id}/output")
async def get_build_output(build_id: str, start_index: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=1000)):
    """Get build output/logs"""
    server_url = await find_build_server(build_id)

    if not server_url:
        raise HTTPException(status_code=404, detail="Build not found")

    try:
        params = {"start_index": start_index, "limit": limit}
        async with core.http_session.get(f"{server_url}/build/{build_id}/output", params=params, timeout=10) as response:
            if response.status == 200:
                return await response.json()
            else:
                raise HTTPException(status_code=response.status, detail="Build output not found")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Error contacting server: {e}")


@router.get("/build/{build_id}/stream")
async def stream_build_output(build_id: str):
    """Stream build output in real-time"""
    server_url = await find_build_server(build_id)

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
            async with core.http_session.get(f"{server_url}/build/{build_id}/stream", timeout=None) as response:
                if response.status == 200:
                    async for line in response.content:
                        yield line.decode('utf-8')
                else:
                    yield f"data: Error: {response.status}\n\n"

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
async def download_file(build_id: str, filename: str):
    """Download build artifact from local cache"""

    cached_artifact = await core.get_cached_artifact(build_id, filename)
    if cached_artifact:
        file_path = cached_artifact["file_path"]
        file_size = cached_artifact["file_size"]
    else:
        file_path = core.get_local_artifact_path(build_id, filename)
        if not file_path:
            return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>File Not Found</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ text-align: center; margin-bottom: 30px; }}
                    .build {{ margin: 5px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; word-break: break-all; }}
                    .failed {{ background-color: #f8d7da; }}
                    .build-id {{ font-family: 'Courier New', monospace; font-size: 0.9em; color: #666; }}
                    .build a {{ color: #007bff; text-decoration: none; margin-right: 10px; }}
                    .build a:hover {{ text-decoration: underline; }}
                    .error-detail {{ background-color: #f8d7da; padding: 15px; border: 1px solid #f5c6cb; border-radius: 5px; margin: 15px 0; }}
                    .error-detail strong {{ color: #721c24; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>APB Farm - Download</h1>
                </div>

                <div class="build failed">
                    <h2>❌ File Not Found</h2>
                    <div class="error-detail">
                        <strong>Error:</strong> The requested file is not available on this farm.
                    </div>

                    <p><strong>Build ID:</strong> <span class="build-id">{build_id}</span></p>
                    <p><strong>Filename:</strong> <span class="build-id">{filename}</span></p>

                    <h3>Details</h3>
                    <p>The file has not been cached locally on this farm. Artifacts are cached when builds
                    complete; if the build is still running or the cache has expired, the file may not
                    be available for download.</p>

                    <h3>Next Steps</h3>
                    <ul>
                        <li>Check the build status to see if the build has completed</li>
                        <li>Verify that you're using the correct build ID and filename</li>
                        <li>Try again later if the build is still in progress</li>
                    </ul>

                    <p>
                        <a href="/build/{build_id}/status">📋 View Build Status</a> |
                        <a href="/dashboard">🏠 Back to Dashboard</a>
                    </p>
                </div>
            </body>
            </html>
            """, status_code=404)
        file_size = file_path.stat().st_size

    logger.debug(f"Serving {filename} for build {build_id} from local cache")

    content_type, disposition = core.determine_content_type_and_disposition(filename)

    headers = {
        "Cache-Control": "public, max-age=2592000, immutable",
        "ETag": f'"{build_id}-{filename}"',
        "Content-Length": str(file_size)
    }

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


@router.get("/builds/latest")
async def get_latest_builds(limit: int = Query(20, ge=1, le=100), status: Optional[str] = Query(None)):
    """Get latest builds across all servers"""
    cursor = core.build_database.cursor()

    if status:
        cursor.execute('''
            SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username, b.epoch, b.pkgver, b.pkgrel
            FROM builds b
            LEFT JOIN users u ON b.user_id = u.id
            WHERE b.status = ? ORDER BY b.created_at DESC LIMIT ?
        ''', (status, limit))
    else:
        cursor.execute('''
            SELECT b.id, b.server_url, b.server_arch, b.pkgname, b.status, b.start_time, b.end_time, b.created_at, u.username, b.epoch, b.pkgver, b.pkgrel
            FROM builds b
            LEFT JOIN users u ON b.user_id = u.id
            ORDER BY b.created_at DESC LIMIT ?
        ''', (limit,))

    builds = []
    for row in cursor.fetchall():
        start_time_str = core.safe_timestamp_to_datetime(row[5])
        end_time_str = core.safe_timestamp_to_datetime(row[6])
        created_at_str = core.safe_timestamp_to_datetime(row[7])

        # Format package name with version
        pkgname = row[3]
        epoch = row[9]
        pkgver = row[10]
        pkgrel = row[11]
        display_name = core.format_package_name_with_version(pkgname, epoch, pkgver, pkgrel)

        builds.append({
            "id": row[0],
            "server_url": core.obfuscate_server_url(row[1]) if row[1] else "unknown",
            "server_arch": row[2],
            "pkgname": pkgname,
            "display_name": display_name,
            "status": row[4],
            "start_time": f"{start_time_str} UTC" if start_time_str else None,
            "end_time": f"{end_time_str} UTC" if end_time_str else None,
            "created_at": f"{created_at_str} UTC" if created_at_str else "unknown",
            "username": row[8] if row[8] else "#anon#"
        })

    return {"builds": builds}


@router.get("/my/builds")
async def get_my_builds(
    current_user: core.User = Depends(core.require_auth),
    limit: int = Query(50, ge=1, le=200)
):
    """Get builds submitted by current user"""
    global auth_manager
    builds = core.auth_manager.get_user_builds(current_user.id, limit)

    # Add obfuscated server URLs for user display
    for build in builds:
        if build["server_url"]:
            build["server_url"] = core.obfuscate_server_url(build["server_url"])

    return {"builds": builds}


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
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False))
):
    """Admin panel for user management (admin only)"""
    current_user = await core.require_admin(request, credentials)

    # Get all users
    global auth_manager
    users = core.auth_manager.list_users()

    # Convert users to dict format for display
    users_data = []
    for user in users:
        users_data.append({
            "id": user.id,
            "username": user.username,
            "role": user.role.value,
            "created_at": datetime.fromtimestamp(user.created_at).strftime('%Y-%m-%d %H:%M:%S') if user.created_at else 'unknown',
            "last_login": datetime.fromtimestamp(user.last_login).strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'never',
            "email": user.email or 'none'
        })

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>APB Farm - Admin Panel</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ text-align: center; margin-bottom: 30px; }}
            .admin-section {{ margin: 20px 0; }}
            .admin-section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }}
            .user-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .user-table th, .user-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; word-wrap: break-word; }}
            .user-table th {{ background-color: #f8f9fa; font-weight: bold; }}
            .user-table tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .user-table tr:hover {{ background-color: #e9ecef; }}
            .email-cell {{ max-width: 150px; overflow: hidden; text-overflow: ellipsis; }}
            .action-button {{ padding: 5px 10px; margin: 2px; border: none; border-radius: 3px; cursor: pointer; font-size: 12px; }}
            .edit-button {{ background-color: #ffc107; color: #000; }}
            .delete-button {{ background-color: #dc3545; color: white; }}
            .admin-badge {{ background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
            .user-badge {{ background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }}
            .add-user-form, .smtp-config-form {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
            .add-user-form input, .add-user-form select, .smtp-config-form input, .smtp-config-form select {{ display: block; width: 200px; margin: 10px 0; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
            .add-user-form button, .smtp-config-form button {{ margin: 5px; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; }}
            .smtp-config-form label {{ margin-top: 10px; display: block; font-weight: bold; }}
            .smtp-config-form input[type="checkbox"] {{ width: auto; display: inline; margin-right: 5px; }}
            .submit-button {{ background-color: #28a745; color: white; }}
            .cancel-button {{ background-color: #6c757d; color: white; }}
            .nav-links {{ margin: 20px 0; text-align: center; }}
            .nav-links a {{ margin: 0 10px; color: #007bff; text-decoration: none; }}
            .nav-links a:hover {{ text-decoration: underline; }}
            .error-message {{ color: #dc3545; margin: 10px 0; }}
            .success-message {{ color: #28a745; margin: 10px 0; font-weight: bold; }}
            .modal {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border: 2px solid #ddd; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); z-index: 1000; display: none; max-width: 90%; max-height: 90%; overflow-y: auto; }}
            .modal-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 999; display: none; }}
            .tabs {{ margin: 20px 0; }}
            .tab-buttons {{ display: flex; border-bottom: 2px solid #ddd; margin-bottom: 20px; }}
            .tab-button {{ padding: 12px 24px; background: #f8f9fa; border: 1px solid #ddd; border-bottom: none; cursor: pointer; margin-right: 2px; border-radius: 8px 8px 0 0; transition: all 0.3s; }}
            .tab-button:hover {{ background: #e9ecef; }}
            .tab-button.active {{ background: white; border-bottom: 2px solid white; margin-bottom: -2px; font-weight: bold; color: #007bff; }}
            .tab-content {{ display: none; }}
            .tab-content.active {{ display: block; }}
        </style>
    </head>
    <body>
        <div class="modal-overlay" id="modalOverlay" onclick="hideModal()"></div>
        <div class="modal" id="editUserModal">
            <h3>Edit User</h3>
            <form id="editUserForm" onsubmit="submitEditUser(event)">
                <input type="hidden" id="editUserId">
                <label>Username:</label>
                <input type="text" id="editUsername" readonly>
                <label>Role:</label>
                <select id="editRole" required>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
                <label>Email:</label>
                <input type="email" id="editEmail" placeholder="user@example.com">
                <label>
                    <input type="checkbox" id="editEmailNotifications"> Email notifications enabled
                </label>
                <div class="error-message" id="editError"></div>
                <div class="success-message" id="editSuccess"></div>
                <button type="submit" class="submit-button">Update User</button>
                <button type="button" class="cancel-button" onclick="hideModal()">Cancel</button>
            </form>
        </div>

        <div class="header">
            <h1>APB Farm - Admin Panel</h1>
            <p>Logged in as: <strong>{current_user.username}</strong> (Admin)</p>
        </div>

        <div class="nav-links">
            <a href="/dashboard">🏠 Back to Dashboard</a>
            <a href="/farm">🌾 Farm Status</a>
            <a href="/builds/latest">📋 Recent Builds</a>
        </div>

        <div class="tabs">
            <div class="tab-buttons">
                <div class="tab-button active" onclick="switchTab('smtp-tab')">📧 SMTP Configuration</div>
                <div class="tab-button" onclick="switchTab('repositories-tab')">📦 Repository Management</div>
                <div class="tab-button" onclick="switchTab('users-tab')">👥 User Management</div>
                <div class="tab-button" onclick="switchTab('admin-functions-tab')">⚙️ Admin Functions</div>
            </div>

            <div id="smtp-tab" class="tab-content active">
                <div class="admin-section">
                    <div class="smtp-config-form">
                        <h3>Email Server Settings</h3>
                        <form id="smtpConfigForm" onsubmit="saveSmtpConfig(event)">
                            <label>SMTP Server:</label>
                            <input type="text" id="smtpServer" placeholder="mail.example.com" required>
                            <label>Port:</label>
                            <input type="number" id="smtpPort" placeholder="587" min="1" max="65535" required>
                            <label>Username (optional):</label>
                            <input type="text" id="smtpUsername" placeholder="username@example.com">
                            <label>Password (optional):</label>
                            <input type="password" id="smtpPassword" placeholder="password">
                            <label>From Email:</label>
                            <input type="email" id="smtpFromEmail" placeholder="noreply@example.com">
                            <label>From Name:</label>
                            <input type="text" id="smtpFromName" placeholder="APB Farm">
                            <label>
                                <input type="checkbox" id="smtpUseTls" checked> Use TLS/STARTTLS
                            </label>
                            <div class="error-message" id="smtpError"></div>
                            <div class="success-message" id="smtpSuccess"></div>
                            <button type="submit" class="submit-button">Save SMTP Config</button>
                            <button type="button" class="cancel-button" onclick="loadSmtpConfig()">Reload</button>
                            <button type="button" class="cancel-button" onclick="deleteSmtpConfig()">Delete Config</button>
                        </form>

                        <div style="margin-top: 20px;">
                            <h4>Test Email</h4>
                            <form id="smtpTestForm" onsubmit="testSmtpConfig(event)">
                                <label>Test Email Address:</label>
                                <input type="email" id="testEmail" placeholder="test@example.com" required>
                                <div class="error-message" id="testError"></div>
                                <div class="success-message" id="testSuccess"></div>
                                <button type="submit" class="submit-button">Send Test Email</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

            <div id="repositories-tab" class="tab-content">
                <div class="admin-section">
                    <h2>📦 Custom Repository Management</h2>
                    <p>Manage custom pacman repositories that users can request in their PKGBUILD files using the <code>apb_extra_repos</code> variable.</p>

                    <div class="smtp-config-form">
                        <h3>Add New Repository</h3>
                        <form id="addRepoForm" onsubmit="submitAddRepository(event)">
                            <label>Repository Name:</label>
                            <input type="text" id="repoName" placeholder="myrepo" required>
                            <label>Repository URL:</label>
                            <input type="url" id="repoUrl" placeholder="https://myrepo.example.com" required>
                            <label>GPG Key ID:</label>
                            <input type="text" id="repoGpgKey" placeholder="ABCD1234..." required>
                            <label>Description (optional):</label>
                            <input type="text" id="repoDescription" placeholder="My custom repository">
                            <div class="error-message" id="repoAddError"></div>
                            <div class="success-message" id="repoAddSuccess"></div>
                            <button type="submit" class="submit-button">Add Repository</button>
                            <button type="button" class="cancel-button" onclick="clearRepoForm()">Clear</button>
                        </form>
                    </div>

                    <div style="margin-top: 30px;">
                        <h3>Existing Repositories</h3>
                        <div id="repositoriesList">Loading repositories...</div>
                    </div>
                </div>
            </div>

            <div id="admin-functions-tab" class="tab-content">
                <div class="admin-section">
                    <h2>🗂️ Cache Management</h2>
                    <div class="smtp-config-form">
                        <h3>Build Artifact Cache</h3>
                        <p>The farm caches build artifacts (packages and logs) for faster downloads and improved reliability.</p>

                        <div id="cacheStatusSection">
                            <h4>Cache Status</h4>
                            <div id="cacheStatusDisplay">Loading cache status...</div>
                            <button type="button" class="submit-button" onclick="loadCacheStatus()">🔄 Refresh Status</button>
                        </div>

                        <div style="margin-top: 20px;">
                            <h4>Cache Cleanup</h4>
                            <p>Manually remove expired cache artifacts. This operation runs automatically every 4 hours.</p>
                            <div class="error-message" id="cleanupError"></div>
                            <div class="success-message" id="cleanupSuccess"></div>
                            <button type="button" class="submit-button" onclick="performCacheCleanup()">🧹 Clean Up Cache</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="users-tab" class="tab-content">
                <div class="admin-section">

            <div class="add-user-form">
                <h3>Add New User</h3>
                <form id="addUserForm" onsubmit="submitAddUser(event)">
                    <label>Username:</label>
                    <input type="text" id="newUsername" placeholder="Username (min 3 characters)" required>
                    <label>Password:</label>
                    <input type="password" id="newPassword" placeholder="Password (min 8 characters)" required>
                    <label>Email:</label>
                    <input type="email" id="newEmail" placeholder="user@example.com (optional)">
                    <label>Role:</label>
                    <select id="newRole" required>
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                    </select>
                    <div class="error-message" id="addError"></div>
                    <div class="success-message" id="addSuccess"></div>
                    <button type="submit" class="submit-button">Add User</button>
                    <button type="button" class="cancel-button" onclick="clearAddForm()">Clear</button>
                </form>
            </div>

            <table class="user-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Email Notifications</th>
                        <th>Role</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    """

    for user in users_data:
        role_badge = f'<span class="admin-badge">ADMIN</span>' if user["role"] == "admin" else f'<span class="user-badge">USER</span>'
        delete_disabled = 'disabled title="Cannot delete yourself"' if user["id"] == current_user.id else ''
        email_display = user["email"] if user["email"] != "none" else '<em>none</em>'
        notifications_display = '✓ Enabled' if user.get("email_notifications_enabled", True) else '✗ Disabled'

        html += f"""
                    <tr>
                        <td>{user["id"]}</td>
                        <td>{user["username"]}</td>
                        <td class="email-cell" title="{user['email']}">{email_display}</td>
                        <td>{notifications_display}</td>
                        <td>{role_badge}</td>
                        <td>{user["created_at"]}</td>
                        <td>{user["last_login"]}</td>
                        <td>
                            <button class="action-button edit-button" onclick="editUser({user['id']}, '{user['username']}', '{user['role']}', '{user['email'] if user['email'] != 'none' else ''}', {str(user.get('email_notifications_enabled', True)).lower()})">Edit</button>
                            <button class="action-button delete-button" onclick="deleteUser({user['id']}, '{user['username']}')" {delete_disabled}>Delete</button>
                        </td>
                    </tr>
        """

    html += f"""
                </tbody>
            </table>
                </div>
            </div>
        </div>

        <script>
            // Tab switching function
            function switchTab(tabId) {{
                // Hide all tab contents
                const tabContents = document.querySelectorAll('.tab-content');
                tabContents.forEach(content => {{
                    content.classList.remove('active');
                }});

                // Remove active class from all tab buttons
                const tabButtons = document.querySelectorAll('.tab-button');
                tabButtons.forEach(button => {{
                    button.classList.remove('active');
                }});

                // Show selected tab content
                document.getElementById(tabId).classList.add('active');

                // Add active class to clicked tab button
                event.target.classList.add('active');
            }}

            // Helper function to get auth token
            function getAuthToken() {{
                let token = localStorage.getItem('authToken');
                if (token) return token;

                const cookies = document.cookie.split(';');
                for (let cookie of cookies) {{
                    const [name, value] = cookie.trim().split('=');
                    if (name === 'authToken') {{
                        return value;
                    }}
                }}
                return null;
            }}

            function clearAddForm() {{
                document.getElementById('addUserForm').reset();
                document.getElementById('addError').textContent = '';
                document.getElementById('addSuccess').textContent = '';
            }}

            async function submitAddUser(event) {{
                event.preventDefault();

                const username = document.getElementById('newUsername').value;
                const password = document.getElementById('newPassword').value;
                const email = document.getElementById('newEmail').value || null;
                const role = document.getElementById('newRole').value;
                const errorDiv = document.getElementById('addError');
                const successDiv = document.getElementById('addSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/auth/users', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ username, password, email, role }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        successDiv.textContent = `User '${{username}}' created successfully!`;
                        clearAddForm();
                        setTimeout(() => window.location.reload(), 2000);
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Failed to create user';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Add user error:', error);
                }}
            }}

            function editUser(id, username, role, email, emailNotifications) {{
                document.getElementById('editUserId').value = id;
                document.getElementById('editUsername').value = username;
                document.getElementById('editRole').value = role;
                document.getElementById('editEmail').value = email || '';
                document.getElementById('editEmailNotifications').checked = emailNotifications !== false;
                document.getElementById('editError').textContent = '';
                document.getElementById('editSuccess').textContent = '';

                document.getElementById('modalOverlay').style.display = 'block';
                document.getElementById('editUserModal').style.display = 'block';
            }}

            function hideModal() {{
                document.getElementById('modalOverlay').style.display = 'none';
                document.getElementById('editUserModal').style.display = 'none';
            }}

            async function submitEditUser(event) {{
                event.preventDefault();

                const userId = document.getElementById('editUserId').value;
                const role = document.getElementById('editRole').value;
                const email = document.getElementById('editEmail').value || null;
                const emailNotifications = document.getElementById('editEmailNotifications').checked;
                const errorDiv = document.getElementById('editError');
                const successDiv = document.getElementById('editSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();

                    // Update role
                    const roleResponse = await fetch(`/auth/users/${{userId}}/role`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ role }})
                    }});

                    if (!roleResponse.ok) {{
                        const errorData = await roleResponse.json();
                        errorDiv.textContent = errorData.detail || 'Failed to update role';
                        return;
                    }}

                    // Update email notifications
                    const notificationsResponse = await fetch(`/auth/users/${{userId}}/email-notifications`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ enabled: emailNotifications }})
                    }});

                    if (!notificationsResponse.ok) {{
                        const errorData = await notificationsResponse.json();
                        errorDiv.textContent = errorData.detail || 'Failed to update email notifications';
                        return;
                    }}

                    // Update email
                    const emailResponse = await fetch(`/auth/users/${{userId}}/email`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ email }})
                    }});

                    if (emailResponse.ok) {{
                        successDiv.textContent = 'User updated successfully!';
                        setTimeout(() => {{
                            hideModal();
                            window.location.reload();
                        }}, 1500);
                    }} else {{
                        const errorData = await emailResponse.json();
                        errorDiv.textContent = errorData.detail || 'Failed to update email';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Edit user error:', error);
                }}
            }}

            async function deleteUser(id, username) {{
                if (!confirm(`Are you sure you want to delete user '${{username}}'? This action cannot be undone.`)) {{
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch(`/auth/users/${{id}}`, {{
                        method: 'DELETE',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        alert(`User '${{username}}' deleted successfully!`);
                        window.location.reload();
                    }} else {{
                        const errorData = await response.json();
                        alert(`Failed to delete user: ${{errorData.detail || 'Unknown error'}}`);
                    }}
                }} catch (error) {{
                    alert('Network error. Please try again.');
                    console.error('Delete user error:', error);
                }}
            }}

            // SMTP Configuration Functions
            async function loadSmtpConfig() {{
                try {{
                    const token = getAuthToken();
                    const response = await fetch('/admin/smtp', {{
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        const config = await response.json();
                        if (config) {{
                            document.getElementById('smtpServer').value = config.server || '';
                            document.getElementById('smtpPort').value = config.port || 587;
                            document.getElementById('smtpUsername').value = config.username || '';
                            document.getElementById('smtpPassword').value = ''; // Don't populate password for security
                            document.getElementById('smtpFromEmail').value = config.from_email || '';
                            document.getElementById('smtpFromName').value = config.from_name || '';
                            document.getElementById('smtpUseTls').checked = config.use_tls !== false;
                        }}
                    }}
                }} catch (error) {{
                    console.error('Error loading SMTP config:', error);
                }}
            }}

            async function saveSmtpConfig(event) {{
                event.preventDefault();

                const server = document.getElementById('smtpServer').value;
                const port = parseInt(document.getElementById('smtpPort').value);
                const username = document.getElementById('smtpUsername').value || null;
                const password = document.getElementById('smtpPassword').value || null;
                const fromEmail = document.getElementById('smtpFromEmail').value || null;
                const fromName = document.getElementById('smtpFromName').value || null;
                const useTls = document.getElementById('smtpUseTls').checked;
                const errorDiv = document.getElementById('smtpError');
                const successDiv = document.getElementById('smtpSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/admin/smtp', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{
                            server, port, username, password, from_email: fromEmail, from_name: fromName, use_tls: useTls
                        }})
                    }});

                    if (response.ok) {{
                        successDiv.textContent = 'SMTP configuration saved successfully!';
                        // Clear password field for security
                        document.getElementById('smtpPassword').value = '';
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Failed to save SMTP configuration';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Save SMTP config error:', error);
                }}
            }}

            async function deleteSmtpConfig() {{
                if (!confirm('Are you sure you want to delete the SMTP configuration? This will disable email notifications.')) {{
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/admin/smtp', {{
                        method: 'DELETE',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        document.getElementById('smtpConfigForm').reset();
                        document.getElementById('smtpSuccess').textContent = 'SMTP configuration deleted successfully!';
                        document.getElementById('smtpError').textContent = '';
                    }} else {{
                        const errorData = await response.json();
                        document.getElementById('smtpError').textContent = errorData.detail || 'Failed to delete SMTP configuration';
                    }}
                }} catch (error) {{
                    document.getElementById('smtpError').textContent = 'Network error. Please try again.';
                    console.error('Delete SMTP config error:', error);
                }}
            }}

            async function testSmtpConfig(event) {{
                event.preventDefault();

                const testEmail = document.getElementById('testEmail').value;
                const errorDiv = document.getElementById('testError');
                const successDiv = document.getElementById('testSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();
                    const response = await fetch('/admin/smtp/test', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: JSON.stringify({{ test_email: testEmail }})
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        successDiv.textContent = data.message;
                    }} else {{
                        const errorData = await response.json();
                        errorDiv.textContent = errorData.detail || 'Failed to send test email';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Network error. Please try again.';
                    console.error('Test SMTP config error:', error);
                }}
            }}

            // Cache management functions
            async function loadCacheStatus() {{
                const displayElement = document.getElementById('cacheStatusDisplay');
                displayElement.innerHTML = 'Loading...';

                try {{
                    const token = getAuthToken();
                    if (!token) {{
                        displayElement.innerHTML = '<span class="error-message">Authentication required</span>';
                        return;
                    }}

                    const response = await fetch('/admin/cache', {{
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        if (data.enabled) {{
                            displayElement.innerHTML = `
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #28a745;">
                                    <h5 style="margin-top: 0; color: #28a745;">✅ Cache Enabled</h5>
                                    <p><strong>Retention:</strong> ${{data.retention_days}} days</p>
                                    <p><strong>Total Artifacts:</strong> ${{data.total_artifacts}} files</p>
                                    <p><strong>Total Size:</strong> ${{data.total_size_mb}} MB (${{data.total_size_bytes}} bytes)</p>
                                    <p><strong>Expired Artifacts:</strong> ${{data.expired_artifacts}} files</p>
                                    ${{data.oldest_cache_age_days ? `<p><strong>Oldest Cache:</strong> ${{data.oldest_cache_age_days}} days old</p>` : ''}}
                                </div>
                            `;
                        }} else {{
                            displayElement.innerHTML = `
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107;">
                                    <h5 style="margin-top: 0; color: #856404;">⚠️ Cache Disabled</h5>
                                    <p>${{data.message}}</p>
                                </div>
                            `;
                        }}
                    }} else {{
                        displayElement.innerHTML = '<span class="error-message">Failed to load cache status</span>';
                    }}
                }} catch (error) {{
                    displayElement.innerHTML = '<span class="error-message">Error loading cache status</span>';
                }}
            }}

            async function performCacheCleanup() {{
                const errorElement = document.getElementById('cleanupError');
                const successElement = document.getElementById('cleanupSuccess');

                // Clear previous messages
                errorElement.textContent = '';
                successElement.textContent = '';

                try {{
                    const token = getAuthToken();
                    if (!token) {{
                        errorElement.textContent = 'Authentication required';
                        return;
                    }}

                    const response = await fetch('/admin/cache/cleanup', {{
                        method: 'POST',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    const data = await response.json();

                    if (response.ok && data.success) {{
                        successElement.textContent = data.message;
                        // Reload cache status to show updated information
                        loadCacheStatus();
                    }} else {{
                        errorElement.textContent = data.message || 'Cache cleanup failed';
                    }}
                }} catch (error) {{
                    errorElement.textContent = 'Error performing cache cleanup';
                }}
            }}

            // Repository management functions
            async function loadRepositories() {{
                try {{
                    const token = getAuthToken();
                    const response = await fetch('/admin/repositories', {{
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        displayRepositories(data.repositories);
                    }} else {{
                        document.getElementById('repositoriesList').innerHTML = 'Error loading repositories';
                    }}
                }} catch (error) {{
                    console.error('Error loading repositories:', error);
                    document.getElementById('repositoriesList').innerHTML = 'Error loading repositories';
                }}
            }}

            function displayRepositories(repositories) {{
                const container = document.getElementById('repositoriesList');

                if (repositories.length === 0) {{
                    container.innerHTML = '<p>No repositories configured.</p>';
                    return;
                }}

                let html = '<table class="user-table"><thead><tr><th>Name</th><th>URL</th><th>GPG Key</th><th>Description</th><th>Status</th><th>Actions</th></tr></thead><tbody>';

                repositories.forEach(repo => {{
                    const statusBadge = repo.is_active ?
                        '<span class="admin-badge">Active</span>' :
                        '<span style="background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px;">Inactive</span>';

                    html += `<tr>
                        <td>${{repo.name}}</td>
                        <td class="email-cell">${{repo.url}}</td>
                        <td>${{repo.gpg_key_id}}</td>
                        <td>${{repo.description || '-'}}</td>
                        <td>${{statusBadge}}</td>
                        <td>
                            <button class="action-button edit-button" onclick="editRepository(${{repo.id}}, '${{repo.name}}', '${{repo.url}}', '${{repo.gpg_key_id}}', '${{repo.description || ''}}', ${{repo.is_active}})">Edit</button>
                            <button class="action-button delete-button" onclick="deleteRepository(${{repo.id}}, '${{repo.name}}')">Delete</button>
                        </td>
                    </tr>`;
                }});

                html += '</tbody></table>';
                container.innerHTML = html;
            }}

            async function submitAddRepository(event) {{
                event.preventDefault();

                const name = document.getElementById('repoName').value;
                const url = document.getElementById('repoUrl').value;
                const gpgKey = document.getElementById('repoGpgKey').value;
                const description = document.getElementById('repoDescription').value;
                const errorDiv = document.getElementById('repoAddError');
                const successDiv = document.getElementById('repoAddSuccess');

                errorDiv.textContent = '';
                successDiv.textContent = '';

                try {{
                    const token = getAuthToken();
                    const formData = new FormData();
                    formData.append('name', name);
                    formData.append('url', url);
                    formData.append('gpg_key_id', gpgKey);
                    formData.append('description', description);

                    const response = await fetch('/admin/repositories', {{
                        method: 'POST',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }},
                        body: formData
                    }});

                    const data = await response.json();

                    if (response.ok && data.success) {{
                        successDiv.textContent = data.message;
                        clearRepoForm();
                        loadRepositories();
                    }} else {{
                        errorDiv.textContent = data.message || 'Failed to add repository';
                    }}
                }} catch (error) {{
                    errorDiv.textContent = 'Error adding repository';
                }}
            }}

            function clearRepoForm() {{
                document.getElementById('addRepoForm').reset();
                document.getElementById('repoAddError').textContent = '';
                document.getElementById('repoAddSuccess').textContent = '';
            }}

            async function deleteRepository(repoId, repoName) {{
                if (!confirm(`Are you sure you want to delete repository "${{repoName}}"?`)) {{
                    return;
                }}

                try {{
                    const token = getAuthToken();
                    const response = await fetch(`/admin/repositories/${{repoId}}`, {{
                        method: 'DELETE',
                        headers: {{
                            'Authorization': `Bearer ${{token}}`
                        }}
                    }});

                    const data = await response.json();

                    if (response.ok && data.success) {{
                        loadRepositories();
                    }} else {{
                        alert(data.message || 'Failed to delete repository');
                    }}
                }} catch (error) {{
                    alert('Error deleting repository');
                }}
            }}

            // Load SMTP config and cache status on page load
            window.addEventListener('load', function() {{
                loadSmtpConfig();
                loadCacheStatus();
                loadRepositories();
            }});
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html)


async def setup_http_session():
    """Setup HTTP session with optimized timeouts and connection pooling for farm responsiveness"""
    global http_session

    # Optimize connector for farm use case - many short requests to potentially slow servers
    connector = aiohttp.TCPConnector(
        limit=50,  # Reduced total connection pool size to prevent resource exhaustion
        limit_per_host=5,  # Reduced per-host limit to prevent single slow server from hogging connections
        ttl_dns_cache=300,  # DNS cache TTL
        use_dns_cache=True,
        keepalive_timeout=15,  # Reduced keepalive to free up connections faster
        enable_cleanup_closed=True
    )

    # Use conservative default timeout - individual operations will override as needed
    timeout = aiohttp.ClientTimeout(
        total=30,  # Reduced default timeout to prevent blocking
        connect=5,  # Faster connection timeout
        sock_read=15   # Faster socket read timeout
    )

    core.http_session = aiohttp.ClientSession(
        timeout=timeout,
        connector=connector,
        trust_env=True
    )


async def cleanup_http_session():
    """Cleanup HTTP session"""
    global http_session
    if core.http_session:
        await core.http_session.close()


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info(f"Received signal {signum}, shutting down...")
    sys.exit(0)

