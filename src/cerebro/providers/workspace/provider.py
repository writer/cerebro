"""
Google Workspace provider implementation using GAM authentication patterns.

Provides comprehensive Google Workspace administration capabilities using
the same patterns as GAM (Google Apps Manager).
"""

import asyncio
from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
from pathlib import Path
from uuid import UUID
import logging

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..base import (
    BaseProvider,
    ResourceInfo,
    PrincipalInfo,
    ConfigurationSnapshot,
    IamPermission,
    ProviderError,
)

logger = logging.getLogger(__name__)


class GoogleWorkspaceProvider(BaseProvider):
    """
    Google Workspace provider using GAM authentication and API patterns.

    Provides comprehensive Google Workspace administration capabilities:
    - User and group management
    - Organizational unit administration
    - Device management (Chrome OS, Mobile)
    - Domain and security settings
    - Admin audit logs and reports
    - Application and OAuth token management

    Uses service account with domain-wide delegation, following GAM patterns.
    """

    # Google Workspace Admin SDK scopes (comprehensive set from GAM)
    ADMIN_SCOPES = [
        # Directory API - Users, Groups, OrgUnits
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.group.readonly",
        "https://www.googleapis.com/auth/admin.directory.orgunit",
        "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
        "https://www.googleapis.com/auth/admin.directory.domain",
        "https://www.googleapis.com/auth/admin.directory.domain.readonly",
        # Device management
        "https://www.googleapis.com/auth/admin.directory.device.chromeos",
        "https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly",
        "https://www.googleapis.com/auth/admin.directory.device.mobile",
        "https://www.googleapis.com/auth/admin.directory.device.mobile.readonly",
        # Role and privilege management
        "https://www.googleapis.com/auth/admin.directory.rolemanagement",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        # Application and token management
        "https://www.googleapis.com/auth/admin.directory.user.security",
        "https://www.googleapis.com/auth/admin.directory.notifications",
        # Reports and audit logs
        "https://www.googleapis.com/auth/admin.reports.audit.readonly",
        "https://www.googleapis.com/auth/admin.reports.usage.readonly",
        # Groups Settings API
        "https://www.googleapis.com/auth/apps.groups.settings",
        # Additional APIs
        "https://www.googleapis.com/auth/admin.datatransfer",
        "https://www.googleapis.com/auth/admin.datatransfer.readonly",
        "https://www.googleapis.com/auth/admin.directory.customer",
        "https://www.googleapis.com/auth/admin.directory.customer.readonly",
    ]

    def __init__(
        self,
        account_id: UUID,
        domain: str,
        service_account_file: str,
        delegate_user: str,
        **kwargs,
    ):
        """
        Initialize Google Workspace provider.

        Args:
            account_id: Account identifier
            domain: Google Workspace domain
            service_account_file: Path to service account JSON key file
            delegate_user: Admin user to impersonate for domain operations
        """
        super().__init__(account_id, **kwargs)
        self.domain = domain
        self.service_account_file = service_account_file
        self.delegate_user = delegate_user

        # API service clients
        self._credentials = None
        self._admin_service = None
        self._reports_service = None
        self._groups_settings_service = None
        self._datatransfer_service = None

    @property
    def name(self) -> str:
        """Get provider name."""
        return "workspace"

    async def authenticate(self) -> bool:
        """
        Authenticate using service account with domain-wide delegation.

        This follows the GAM authentication pattern:
        1. Load service account credentials
        2. Create delegated credentials for admin user
        3. Build API service clients
        4. Test authentication with a simple API call
        """
        try:
            if not Path(self.service_account_file).exists():
                raise ProviderError(
                    f"Service account file not found: {self.service_account_file}"
                )

            # Load service account credentials
            credentials = service_account.Credentials.from_service_account_file(
                self.service_account_file, scopes=self.ADMIN_SCOPES
            )

            # Create delegated credentials (impersonate admin user)
            self._credentials = credentials.with_subject(self.delegate_user)

            # Build API service clients
            loop = asyncio.get_event_loop()

            # Admin SDK Directory API
            self._admin_service = await loop.run_in_executor(
                None,
                lambda: build(
                    "admin",
                    "directory_v1",
                    credentials=self._credentials,
                    cache_discovery=False,
                ),
            )

            # Admin SDK Reports API
            self._reports_service = await loop.run_in_executor(
                None,
                lambda: build(
                    "admin",
                    "reports_v1",
                    credentials=self._credentials,
                    cache_discovery=False,
                ),
            )

            # Groups Settings API
            self._groups_settings_service = await loop.run_in_executor(
                None,
                lambda: build(
                    "groupssettings",
                    "v1",
                    credentials=self._credentials,
                    cache_discovery=False,
                ),
            )

            # Test authentication with a simple API call
            await loop.run_in_executor(
                None,
                lambda: self._admin_service.users()
                .list(domain=self.domain, maxResults=1)
                .execute(),
            )

            logger.info(
                f"Successfully authenticated with Google Workspace domain: {self.domain}"
            )
            return True

        except FileNotFoundError:
            logger.error(f"Service account file not found: {self.service_account_file}")
            return False
        except HttpError as e:
            logger.error(f"Google API authentication failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Workspace authentication failed: {e}")
            return False

    async def discover_resources(
        self, resource_types: Optional[List[str]] = None
    ) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Google Workspace resources."""
        if not self._admin_service:
            await self.authenticate()

        # Organizational units
        if not resource_types or "workspace.orgunit" in resource_types:
            async for ou in self._discover_org_units():
                yield ou

        # Chrome OS devices
        if not resource_types or "workspace.device.chromeos" in resource_types:
            async for device in self._discover_chromeos_devices():
                yield device

        # Mobile devices
        if not resource_types or "workspace.device.mobile" in resource_types:
            async for device in self._discover_mobile_devices():
                yield device

        # Domains
        if not resource_types or "workspace.domain" in resource_types:
            async for domain in self._discover_domains():
                yield domain

        # Admin roles
        if not resource_types or "workspace.admin.role" in resource_types:
            async for role in self._discover_admin_roles():
                yield role

    async def _discover_org_units(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover organizational units."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.orgunits()
                .list(customerId="my_customer", type="all")
                .execute(),
            )

            for orgunit in result.get("organizationUnits", []):
                yield ResourceInfo(
                    external_id=orgunit["orgUnitId"],
                    name=orgunit["name"],
                    resource_type="workspace.orgunit",
                    region="global",
                    tags={
                        "path": orgunit["orgUnitPath"],
                        "parent": orgunit.get("parentOrgUnitPath", "/"),
                    },
                    created_at=datetime.utcnow(),
                    account_id=self.account_id,
                    metadata={
                        "org_unit_path": orgunit["orgUnitPath"],
                        "parent_org_unit_id": orgunit.get("parentOrgUnitId"),
                        "parent_org_unit_path": orgunit.get("parentOrgUnitPath"),
                        "description": orgunit.get("description"),
                        "block_inheritance": orgunit.get("blockInheritance", False),
                    },
                )
        except HttpError as e:
            logger.error(f"Failed to discover organizational units: {e}")

    async def _discover_chromeos_devices(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover Chrome OS devices with comprehensive metadata."""
        try:
            loop = asyncio.get_event_loop()

            # Use pagination for large device inventories
            page_token = None
            while True:
                request_params = {
                    "customerId": "my_customer",
                    "maxResults": 100,
                    "projection": "FULL",
                    "orderBy": "lastSync",
                }
                if page_token:
                    request_params["pageToken"] = page_token

                result = await loop.run_in_executor(
                    None,
                    lambda: self._admin_service.chromeosdevices()
                    .list(**request_params)
                    .execute(),
                )

                for device in result.get("chromeosdevices", []):
                    # Process recent users
                    recent_users = []
                    for user in device.get("recentUsers", []):
                        user_info = {
                            "email": user.get("email"),
                            "type": user.get("type"),
                            "last_login": user.get("lastLoginTime"),
                        }
                        recent_users.append(user_info)

                    # Process active time ranges
                    active_time_ranges = []
                    for time_range in device.get("activeTimeRanges", []):
                        range_info = {
                            "date": time_range.get("date"),
                            "active_time": time_range.get("activeTime"),
                        }
                        active_time_ranges.append(range_info)

                    # Determine device status and risk factors
                    status = device.get("status", "UNKNOWN")
                    is_managed = status in ["ACTIVE", "DISABLED"]
                    needs_attention = status in ["DEPROVISIONED", "UNPROVISIONED"]

                    # Check for security concerns
                    boot_mode = device.get("bootMode", "Verified")
                    is_dev_mode = boot_mode == "Dev"

                    last_sync = device.get("lastSync")
                    is_stale = False
                    if last_sync:
                        try:
                            last_sync_dt = datetime.fromisoformat(
                                last_sync.replace("Z", "+00:00")
                            )
                            is_stale = (
                                datetime.now(last_sync_dt.tzinfo) - last_sync_dt
                            ).days > 30
                        except (ValueError, TypeError, AttributeError) as e:
                            logger.debug(
                                f"Failed to parse lastSync date for device {device.get('deviceId')}: {last_sync}, error: {e}"
                            )

                    yield ResourceInfo(
                        external_id=device["deviceId"],
                        name=device.get("annotatedUser")
                        or device.get("serialNumber")
                        or device["deviceId"],
                        resource_type="workspace.device.chromeos",
                        region="global",
                        tags={
                            "status": status.lower(),
                            "model": device.get("model", "").replace(" ", "_").lower(),
                            "managed": str(is_managed).lower(),
                            "dev_mode": str(is_dev_mode).lower(),
                            "stale": str(is_stale).lower(),
                        },
                        created_at=self._parse_timestamp(
                            device.get("firstEnrollmentTime")
                        ),
                        account_id=self.account_id,
                        metadata={
                            # Basic device info
                            "device_id": device["deviceId"],
                            "serial_number": device.get("serialNumber"),
                            "model": device.get("model"),
                            "platform_version": device.get("platformVersion"),
                            "os_version": device.get("osVersion"),
                            "firmware_version": device.get("firmwareVersion"),
                            # Network info
                            "ethernet_mac_address": device.get("ethernetMacAddress"),
                            "mac_address": device.get("macAddress"),
                            "meid": device.get("meid"),
                            # Management info
                            "status": status,
                            "annotated_location": device.get("annotatedLocation"),
                            "annotated_user": device.get("annotatedUser"),
                            "notes": device.get("notes"),
                            "org_unit_path": device.get("orgUnitPath"),
                            # Time tracking
                            "first_enrollment_time": device.get("firstEnrollmentTime"),
                            "last_enrollment_time": device.get("lastEnrollmentTime"),
                            "last_sync": last_sync,
                            # Security info
                            "boot_mode": boot_mode,
                            "is_dev_mode": is_dev_mode,
                            "tpm_version_info": device.get("tpmVersionInfo"),
                            # Support info
                            "auto_update_expiration": device.get(
                                "autoUpdateExpiration"
                            ),
                            "support_end_date": device.get("supportEndDate"),
                            "will_auto_renew": device.get("willAutoRenew"),
                            # Usage info
                            "recent_users": recent_users,
                            "active_time_ranges": active_time_ranges,
                            # Risk factors
                            "needs_attention": needs_attention,
                            "is_stale": is_stale,
                        },
                    )

                # Check for next page
                page_token = result.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            logger.error(f"Failed to discover Chrome OS devices: {e}")

    async def _discover_mobile_devices(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover mobile devices (iOS, Android)."""
        try:
            loop = asyncio.get_event_loop()

            page_token = None
            while True:
                request_params = {
                    "customerId": "my_customer",
                    "maxResults": 100,
                    "projection": "FULL",
                }
                if page_token:
                    request_params["pageToken"] = page_token

                result = await loop.run_in_executor(
                    None,
                    lambda: self._admin_service.mobiledevices()
                    .list(**request_params)
                    .execute(),
                )

                for device in result.get("mobiledevices", []):
                    # Extract applications
                    applications = []
                    for app in device.get("applications", []):
                        app_info = {
                            "display_name": app.get("displayName"),
                            "package_name": app.get("packageName"),
                            "version_name": app.get("versionName"),
                            "version_code": app.get("versionCode"),
                        }
                        applications.append(app_info)

                    # Determine device type and OS
                    device_type = device.get("type", "UNKNOWN")
                    os_info = device.get("os", "Unknown")

                    # Security status
                    is_managed = device.get("managedAccountIsOnOwnerProfile", False)
                    is_compromised = device.get("compromisedStatus") == "COMPROMISED"

                    yield ResourceInfo(
                        external_id=device["resourceId"],
                        name=device.get("name")
                        or device.get("deviceId")
                        or device["resourceId"],
                        resource_type="workspace.device.mobile",
                        region="global",
                        tags={
                            "type": device_type.lower(),
                            "os": os_info.lower().replace(" ", "_"),
                            "managed": str(is_managed).lower(),
                            "compromised": str(is_compromised).lower(),
                        },
                        created_at=self._parse_timestamp(device.get("firstSync")),
                        account_id=self.account_id,
                        metadata={
                            # Device identifiers
                            "resource_id": device["resourceId"],
                            "device_id": device.get("deviceId"),
                            "imei": device.get("imei"),
                            "meid": device.get("meid"),
                            "serial_number": device.get("serialNumber"),
                            # Device info
                            "name": device.get("name"),
                            "type": device_type,
                            "model": device.get("model"),
                            "os": os_info,
                            "kernel_version": device.get("kernelVersion"),
                            "baseband_version": device.get("basebandVersion"),
                            # User info
                            "email": device.get("email", []),
                            "user_agent": device.get("userAgent"),
                            # Network info
                            "wifi_mac_address": device.get("wifiMacAddress"),
                            "hardware_id": device.get("hardwareId"),
                            "network_operator": device.get("networkOperator"),
                            # Management info
                            "status": device.get("status"),
                            "managed_account_is_on_owner_profile": is_managed,
                            "device_compromised_status": device.get(
                                "compromisedStatus"
                            ),
                            "default_language": device.get("defaultLanguage"),
                            # Security info
                            "is_compromised": is_compromised,
                            "adb_status": device.get("adbStatus"),
                            "developer_options_status": device.get(
                                "developerOptionsStatus"
                            ),
                            "unknown_sources_status": device.get(
                                "unknownSourcesStatus"
                            ),
                            "encryption_status": device.get("encryptionStatus"),
                            # Sync info
                            "first_sync": device.get("firstSync"),
                            "last_sync": device.get("lastSync"),
                            # Applications
                            "applications": applications,
                            "app_count": len(applications),
                        },
                    )

                # Check for next page
                page_token = result.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            logger.error(f"Failed to discover mobile devices: {e}")

    async def _discover_domains(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover domain information."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.domains()
                .list(customer="my_customer")
                .execute(),
            )

            for domain in result.get("domains", []):
                domain_name = domain["domainName"]
                is_primary = domain.get("isPrimary", False)
                is_verified = domain.get("verified", False)

                yield ResourceInfo(
                    external_id=domain_name,
                    name=domain_name,
                    resource_type="workspace.domain",
                    region="global",
                    tags={
                        "primary": str(is_primary).lower(),
                        "verified": str(is_verified).lower(),
                    },
                    created_at=self._parse_timestamp(domain.get("creationTime")),
                    account_id=self.account_id,
                    metadata={
                        "domain_name": domain_name,
                        "is_primary": is_primary,
                        "verified": is_verified,
                        "creation_time": domain.get("creationTime"),
                        "domain_aliases": domain.get("domainAliases", []),
                        "etag": domain.get("etag"),
                    },
                )
        except HttpError as e:
            logger.error(f"Failed to discover domains: {e}")

    async def _discover_admin_roles(self) -> AsyncGenerator[ResourceInfo, None]:
        """Discover admin roles and privileges."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.roles()
                .list(customer="my_customer")
                .execute(),
            )

            for role in result.get("items", []):
                # Get role privileges
                privileges = []
                for privilege in role.get("rolePrivileges", []):
                    priv_info = {
                        "privilege_name": privilege.get("privilegeName"),
                        "service_id": privilege.get("serviceId"),
                    }
                    privileges.append(priv_info)

                is_system_role = role.get("isSystemRole", False)
                is_super_admin = role.get("isSuperAdminRole", False)

                yield ResourceInfo(
                    external_id=str(role["roleId"]),
                    name=role["roleName"],
                    resource_type="workspace.admin.role",
                    region="global",
                    tags={
                        "system_role": str(is_system_role).lower(),
                        "super_admin": str(is_super_admin).lower(),
                    },
                    created_at=datetime.utcnow(),
                    account_id=self.account_id,
                    metadata={
                        "role_id": role["roleId"],
                        "role_name": role["roleName"],
                        "role_description": role.get("roleDescription"),
                        "is_system_role": is_system_role,
                        "is_super_admin": is_super_admin,
                        "privileges": privileges,
                        "privilege_count": len(privileges),
                        "etag": role.get("etag"),
                    },
                )
        except HttpError as e:
            logger.error(f"Failed to discover admin roles: {e}")

    async def discover_principals(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace users and groups."""
        if not self._admin_service:
            await self.authenticate()

        # Discover users
        async for user in self._discover_users():
            yield user

        # Discover groups
        async for group in self._discover_groups():
            yield group

    async def _discover_users(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace users with comprehensive information."""
        try:
            loop = asyncio.get_event_loop()

            page_token = None
            while True:
                request_params = {
                    "domain": self.domain,
                    "maxResults": 100,
                    "projection": "full",
                    "viewType": "admin_view",
                }
                if page_token:
                    request_params["pageToken"] = page_token

                result = await loop.run_in_executor(
                    None,
                    lambda: self._admin_service.users()
                    .list(**request_params)
                    .execute(),
                )

                for user in result.get("users", []):
                    # Extract user status and security info
                    is_suspended = user.get("suspended", False)
                    is_archived = user.get("archived", False)
                    is_admin = user.get("isAdmin", False)
                    is_delegated_admin = user.get("isDelegatedAdmin", False)

                    # Extract name information
                    name_info = user.get("name", {})
                    full_name = name_info.get("fullName", "")
                    given_name = name_info.get("givenName", "")
                    family_name = name_info.get("familyName", "")

                    # Extract organizational info
                    org_info = user.get("organizations", [{}])[0]

                    # Extract phone and address info
                    phones = user.get("phones", [])
                    addresses = user.get("addresses", [])

                    # 2FA status
                    is_enforced_in = user.get("isEnforcedIn2Sv", False)
                    is_enrolled_in_2sv = user.get("isEnrolledIn2Sv", False)

                    yield PrincipalInfo(
                        external_id=user["id"],
                        principal_type="user",
                        email=user["primaryEmail"],
                        display_name=full_name or user["primaryEmail"],
                        is_human=True,
                        account_id=self.account_id,
                        metadata={
                            # Basic info
                            "primary_email": user["primaryEmail"],
                            "given_name": given_name,
                            "family_name": family_name,
                            "full_name": full_name,
                            # Status
                            "suspended": is_suspended,
                            "archived": is_archived,
                            "agreed_to_terms": user.get("agreedToTerms", False),
                            "include_in_global_address_list": user.get(
                                "includeInGlobalAddressList", True
                            ),
                            # Admin status
                            "is_admin": is_admin,
                            "is_delegated_admin": is_delegated_admin,
                            # Organization
                            "org_unit_path": user.get("orgUnitPath", "/"),
                            "organization": {
                                "title": org_info.get("title"),
                                "department": org_info.get("department"),
                                "description": org_info.get("description"),
                                "location": org_info.get("location"),
                                "type": org_info.get("type"),
                            },
                            # Security
                            "is_enforced_in_2sv": is_enforced_in,
                            "is_enrolled_in_2sv": is_enrolled_in_2sv,
                            "change_password_at_next_login": user.get(
                                "changePasswordAtNextLogin", False
                            ),
                            # Contact info
                            "phones": [
                                {"value": p.get("value"), "type": p.get("type")}
                                for p in phones
                            ],
                            "addresses": [
                                {"formatted": a.get("formatted"), "type": a.get("type")}
                                for a in addresses
                            ],
                            # Account info
                            "creation_time": user.get("creationTime"),
                            "last_login_time": user.get("lastLoginTime"),
                            "customer_id": user.get("customerId"),
                            # Additional fields
                            "aliases": user.get("aliases", []),
                            "non_editable_aliases": user.get("nonEditableAliases", []),
                            "recovery_email": user.get("recoveryEmail"),
                            "recovery_phone": user.get("recoveryPhone"),
                            # Quota and usage (if available)
                            "usage_quota_in_bytes": user.get("usageQuotaInBytes"),
                            # Custom schemas (if any)
                            "custom_schemas": user.get("customSchemas", {}),
                            # Relations (manager, assistant, etc.)
                            "relations": user.get("relations", []),
                            # External IDs
                            "external_ids": user.get("externalIds", []),
                        },
                    )

                # Check for next page
                page_token = result.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            logger.error(f"Failed to discover users: {e}")

    async def _discover_groups(self) -> AsyncGenerator[PrincipalInfo, None]:
        """Discover Google Workspace groups with member information."""
        try:
            loop = asyncio.get_event_loop()

            page_token = None
            while True:
                request_params = {"domain": self.domain, "maxResults": 100}
                if page_token:
                    request_params["pageToken"] = page_token

                result = await loop.run_in_executor(
                    None,
                    lambda: self._admin_service.groups()
                    .list(**request_params)
                    .execute(),
                )

                for group in result.get("groups", []):
                    group_email = group["email"]

                    # Get group members
                    members = []
                    try:
                        members_result = await loop.run_in_executor(
                            None,
                            lambda: self._admin_service.members()
                            .list(groupKey=group_email)
                            .execute(),
                        )

                        for member in members_result.get("members", []):
                            member_info = {
                                "email": member.get("email"),
                                "role": member.get("role", "MEMBER"),
                                "type": member.get("type", "USER"),
                                "status": member.get("status", "ACTIVE"),
                            }
                            members.append(member_info)
                    except HttpError as e:
                        logger.warning(
                            f"Could not get members for group {group_email}: {e}"
                        )

                    # Get group settings if possible
                    group_settings = {}
                    try:
                        if self._groups_settings_service:
                            settings_result = await loop.run_in_executor(
                                None,
                                lambda: self._groups_settings_service.groups()
                                .get(groupUniqueId=group_email)
                                .execute(),
                            )
                            group_settings = {
                                "who_can_join": settings_result.get("whoCanJoin"),
                                "who_can_view_membership": settings_result.get(
                                    "whoCanViewMembership"
                                ),
                                "who_can_view_group": settings_result.get(
                                    "whoCanViewGroup"
                                ),
                                "who_can_post_message": settings_result.get(
                                    "whoCanPostMessage"
                                ),
                                "message_moderation_level": settings_result.get(
                                    "messageModerationLevel"
                                ),
                                "is_archived": settings_result.get("isArchived", False),
                                "allow_external_members": settings_result.get(
                                    "allowExternalMembers", False
                                ),
                            }
                    except HttpError as e:
                        logger.debug(
                            f"Could not get settings for group {group_email}: {e}"
                        )

                    yield PrincipalInfo(
                        external_id=group["id"],
                        principal_type="group",
                        email=group_email,
                        display_name=group.get("name", group_email),
                        is_human=False,
                        account_id=self.account_id,
                        metadata={
                            # Basic info
                            "email": group_email,
                            "name": group.get("name"),
                            "description": group.get("description"),
                            # Member info
                            "members": members,
                            "member_count": len(members),
                            "direct_members_count": group.get("directMembersCount", 0),
                            # Aliases
                            "aliases": group.get("aliases", []),
                            "non_editable_aliases": group.get("nonEditableAliases", []),
                            # Administrative
                            "admin_created": group.get("adminCreated", False),
                            # Settings
                            "group_settings": group_settings,
                            # Additional metadata
                            "etag": group.get("etag"),
                        },
                    )

                # Check for next page
                page_token = result.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            logger.error(f"Failed to discover groups: {e}")

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse Google API timestamp to datetime."""
        if not timestamp_str:
            return None
        try:
            if timestamp_str.endswith("Z"):
                return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            else:
                return datetime.fromisoformat(timestamp_str)
        except Exception:
            logger.warning(f"Failed to parse timestamp: {timestamp_str}")
            return None

    async def get_resource_configuration(
        self, resource: ResourceInfo
    ) -> ConfigurationSnapshot:
        """Get comprehensive resource configuration."""
        # Implementation for detailed configuration collection
        config = {}

        if resource.resource_type == "workspace.orgunit":
            config = await self._get_orgunit_config(resource.external_id)
        elif resource.resource_type == "workspace.device.chromeos":
            config = await self._get_chromeos_config(resource.external_id)
        elif resource.resource_type == "workspace.admin.role":
            config = await self._get_admin_role_config(resource.external_id)

        return ConfigurationSnapshot(
            resource_external_id=resource.external_id,
            captured_at=datetime.utcnow(),
            normalized_config=config,
        )

    async def _get_orgunit_config(self, orgunit_id: str) -> Dict[str, Any]:
        """Get organizational unit configuration and policies."""
        # TODO: Implement orgunit configuration collection
        return {}

    async def _get_chromeos_config(self, device_id: str) -> Dict[str, Any]:
        """Get Chrome OS device configuration and policies."""
        # TODO: Implement Chrome OS device configuration collection
        return {}

    async def _get_admin_role_config(self, role_id: str) -> Dict[str, Any]:
        """Get admin role configuration and privileges."""
        # TODO: Implement admin role configuration collection
        return {}

    async def discover_iam_edges(
        self, resource: Optional[ResourceInfo] = None
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover Google Workspace IAM permissions and role assignments."""
        if not self._admin_service:
            await self.authenticate()

        # Discover admin role assignments
        async for permission in self._discover_admin_role_assignments():
            yield permission

        # Discover group memberships (as permissions)
        async for permission in self._discover_group_memberships():
            yield permission

    async def _discover_admin_role_assignments(
        self,
    ) -> AsyncGenerator[IamPermission, None]:
        """Discover admin role assignments."""
        try:
            loop = asyncio.get_event_loop()

            # Get all admin roles
            roles_result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.roles()
                .list(customer="my_customer")
                .execute(),
            )

            for role in roles_result.get("items", []):
                role_id = str(role["roleId"])
                role_name = role["roleName"]
                is_super_admin = role.get("isSuperAdminRole", False)

                # Get role assignments
                try:
                    assignments_result = await loop.run_in_executor(
                        None,
                        lambda: self._admin_service.roleAssignments()
                        .list(customer="my_customer", roleId=role_id)
                        .execute(),
                    )

                    for assignment in assignments_result.get("items", []):
                        assigned_to = assignment.get("assignedTo")
                        scope_type = assignment.get("scopeType", "CUSTOMER")

                        yield IamPermission(
                            principal_external_id=assigned_to,
                            resource_external_id=None,  # Domain-level permission
                            permission=f"workspace.admin.role.{role_id}",
                            via=f"admin_role:{role_name}",
                            effective_at=datetime.utcnow(),
                            is_admin=True,
                            metadata={
                                "role_id": role_id,
                                "role_name": role_name,
                                "is_super_admin": is_super_admin,
                                "scope_type": scope_type,
                                "org_unit_id": assignment.get("orgUnitId"),
                            },
                        )
                except HttpError as e:
                    logger.warning(
                        f"Could not get assignments for role {role_name}: {e}"
                    )

        except HttpError as e:
            logger.error(f"Failed to discover admin role assignments: {e}")

    async def _discover_group_memberships(self) -> AsyncGenerator[IamPermission, None]:
        """Discover group memberships as permissions."""
        try:
            loop = asyncio.get_event_loop()

            # Get all groups
            groups_result = await loop.run_in_executor(
                None,
                lambda: self._admin_service.groups().list(domain=self.domain).execute(),
            )

            for group in groups_result.get("groups", []):
                group_id = group["id"]
                group_email = group["email"]

                # Get group members
                try:
                    members_result = await loop.run_in_executor(
                        None,
                        lambda: self._admin_service.members()
                        .list(groupKey=group_email)
                        .execute(),
                    )

                    for member in members_result.get("members", []):
                        member_email = member.get("email")
                        member_role = member.get("role", "MEMBER")
                        member_type = member.get("type", "USER")

                        # Determine if this is an admin-level permission
                        is_admin = "admin" in group_email.lower() or member_role in [
                            "OWNER",
                            "MANAGER",
                        ]

                        yield IamPermission(
                            principal_external_id=member_email,
                            resource_external_id=group_id,
                            permission=f"workspace.group.{member_role.lower()}",
                            via=f"group_membership:{group_email}",
                            effective_at=datetime.utcnow(),
                            is_admin=is_admin,
                            metadata={
                                "group_id": group_id,
                                "group_email": group_email,
                                "member_role": member_role,
                                "member_type": member_type,
                            },
                        )
                except HttpError as e:
                    logger.warning(
                        f"Could not get members for group {group_email}: {e}"
                    )

        except HttpError as e:
            logger.error(f"Failed to discover group memberships: {e}")
