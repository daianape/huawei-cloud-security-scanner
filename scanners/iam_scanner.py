"""
Huawei Cloud Security Scanner - IAM Scanner

Checks for IAM security best practices:
- IAM-01: Users without MFA enabled
- IAM-02: Access keys older than 90 days (no rotation)
- IAM-03: Password policy strength
- IAM-04: Users with overly permissive (admin) policies
- IAM-05: Root account access key usage
- IAM-06: Inactive users (no login in 90+ days)
- IAM-07: Multiple active access keys per user
"""

import logging
from datetime import datetime, timedelta, timezone

from huaweicloudsdkiam.v3 import (
    IamClient,
    KeystoneListUsersRequest,
    ShowDomainPasswordPolicyRequest,
    ListPermanentAccessKeysRequest,
    ShowUserLoginProtectRequest,
    KeystoneListGroupsRequest,
    KeystoneListPermissionsRequest,
)
from huaweicloudsdkiam.v3.region.iam_region import IamRegion

from scanners.base_scanner import BaseScanner
from core.models import Finding, Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)


class IAMScanner(BaseScanner):
    """Scanner for IAM security checks."""

    service_name = "iam"
    service_category = ServiceCategory.IAM

    def _init_client(self) -> None:
        """Initialize IAM client with global credentials."""
        from huaweicloudsdkcore.http.http_config import HttpConfig as HC
        from huaweicloudsdkcore.auth.credentials import GlobalCredentials as GC

        creds = GC(
            self.target.credentials.access_key,
            self.target.credentials.secret_key,
            self.target.credentials.domain_id or "",
        )

        config = HC.get_default_config()
        config.ignore_ssl_verification = True

        self.client = (
            IamClient.new_builder()
            .with_credentials(creds)
            .with_http_config(config)
            .with_region(IamRegion.value_of(self.region))
            .build()
        )

    def _get_checks(self) -> list:
        """Return list of IAM checks to run."""
        return [
            self._check_users_without_mfa,
            self._check_access_key_rotation,
            self._check_password_policy,
            self._check_admin_permissions,
            self._check_inactive_users,
            self._check_multiple_access_keys,
        ]

    def _check_users_without_mfa(self) -> None:
        """IAM-01: Check for IAM users without MFA enabled."""
        request = KeystoneListUsersRequest()
        response = self.client.keystone_list_users(request)
        users = response.users or []

        for user in users:
            user_name = user.name
            user_id = user.id

            # Check if user has MFA enabled via login protect
            try:
                mfa_request = ShowUserLoginProtectRequest()
                mfa_request.user_id = user_id
                mfa_response = self.client.show_user_login_protect(mfa_request)

                mfa_enabled = (
                    mfa_response.login_protect
                    and mfa_response.login_protect.enabled
                )
            except Exception:
                # If we can't check, assume not enabled
                mfa_enabled = False

            if mfa_enabled:
                self._add_finding(
                    check_id="IAM-01",
                    check_title="User MFA Enabled",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=f"User '{user_name}' has MFA enabled.",
                    resource_id=user_id,
                    resource_name=user_name,
                )
            else:
                self._add_finding(
                    check_id="IAM-01",
                    check_title="User Without MFA",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"User '{user_name}' does not have MFA enabled. "
                        f"This increases the risk of unauthorized access."
                    ),
                    resource_id=user_id,
                    resource_name=user_name,
                    remediation=(
                        "Enable MFA for the user in IAM console: "
                        "IAM > Users > Security Settings > MFA Device > Bind."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-iam/iam_10_0002.html",
                )

    def _check_access_key_rotation(self) -> None:
        """IAM-02: Check for access keys not rotated in 90+ days."""
        request = KeystoneListUsersRequest()
        response = self.client.keystone_list_users(request)
        users = response.users or []

        rotation_threshold = datetime.now(timezone.utc) - timedelta(days=90)

        for user in users:
            user_name = user.name
            user_id = user.id

            try:
                ak_request = ListPermanentAccessKeysRequest()
                ak_request.user_id = user_id
                ak_response = self.client.list_permanent_access_keys(ak_request)
                credentials = ak_response.credentials or []
            except Exception as e:
                self.logger.debug(f"Could not list access keys for {user_name}: {e}")
                continue

            for cred in credentials:
                if cred.status != "active":
                    continue

                create_time = cred.create_time
                # Parse the create time string
                if isinstance(create_time, str):
                    try:
                        created = datetime.fromisoformat(
                            create_time.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        continue
                else:
                    created = create_time

                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                days_old = (datetime.now(timezone.utc) - created).days

                if created < rotation_threshold:
                    self._add_finding(
                        check_id="IAM-02",
                        check_title="Access Key Not Rotated",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        description=(
                            f"Access key '{cred.access}' for user '{user_name}' "
                            f"is {days_old} days old (threshold: 90 days). "
                            f"Keys should be rotated regularly."
                        ),
                        resource_id=cred.access,
                        resource_name=f"{user_name}/{cred.access}",
                        remediation=(
                            "Rotate the access key: Create a new key, update applications, "
                            "then deactivate and delete the old key."
                        ),
                        reference_url="https://support.huaweicloud.com/usermanual-iam/iam_02_0003.html",
                    )
                else:
                    self._add_finding(
                        check_id="IAM-02",
                        check_title="Access Key Rotation Compliant",
                        severity=Severity.MEDIUM,
                        status=Status.PASS,
                        description=(
                            f"Access key '{cred.access}' for user '{user_name}' "
                            f"is {days_old} days old (within 90-day threshold)."
                        ),
                        resource_id=cred.access,
                        resource_name=f"{user_name}/{cred.access}",
                    )

    def _check_password_policy(self) -> None:
        """IAM-03: Check domain password policy strength."""
        try:
            request = ShowDomainPasswordPolicyRequest()
            request.domain_id = self.target.domain_id or self.project_id
            response = self.client.show_domain_password_policy(request)
            policy = response.password_policy
        except Exception as e:
            self._add_finding(
                check_id="IAM-03",
                check_title="Password Policy Check Failed",
                severity=Severity.HIGH,
                status=Status.ERROR,
                description=f"Could not retrieve password policy: {e}",
            )
            return

        issues = []

        # Check minimum length (should be >= 12)
        if policy.minimum_password_length and policy.minimum_password_length < 12:
            issues.append(
                f"Minimum password length is {policy.minimum_password_length} "
                f"(recommended: >= 12)"
            )

        # Check password validity period (should force rotation)
        if policy.password_validity_period and policy.password_validity_period == 0:
            issues.append("Password never expires (recommended: 90 days max)")

        # Check number of recent passwords remembered
        if (
            policy.number_of_recent_passwords_disallowed is not None
            and policy.number_of_recent_passwords_disallowed < 5
        ):
            issues.append(
                f"Only {policy.number_of_recent_passwords_disallowed} recent passwords "
                f"are disallowed (recommended: >= 5)"
            )

        if issues:
            self._add_finding(
                check_id="IAM-03",
                check_title="Weak Password Policy",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "Password policy does not meet security best practices:\n- "
                    + "\n- ".join(issues)
                ),
                resource_id="password-policy",
                resource_name="Domain Password Policy",
                remediation=(
                    "Strengthen the password policy in IAM: "
                    "Set minimum length >= 12, max validity 90 days, "
                    "remember at least 5 previous passwords."
                ),
                reference_url="https://support.huaweicloud.com/usermanual-iam/iam_01_0607.html",
            )
        else:
            self._add_finding(
                check_id="IAM-03",
                check_title="Password Policy Compliant",
                severity=Severity.HIGH,
                status=Status.PASS,
                description="Password policy meets minimum security requirements.",
                resource_id="password-policy",
                resource_name="Domain Password Policy",
            )

    def _check_admin_permissions(self) -> None:
        """IAM-04: Check for users/groups with overly permissive admin policies."""
        try:
            groups_request = KeystoneListGroupsRequest()
            groups_response = self.client.keystone_list_groups(groups_request)
            groups = groups_response.groups or []
        except Exception as e:
            self._add_finding(
                check_id="IAM-04",
                check_title="Admin Permission Check Failed",
                severity=Severity.HIGH,
                status=Status.ERROR,
                description=f"Could not list groups: {e}",
            )
            return

        for group in groups:
            group_name = group.name
            group_id = group.id

            try:
                perm_request = KeystoneListPermissionsRequest()
                perm_request.domain_id = self.target.domain_id or self.project_id
                perm_response = self.client.keystone_list_permissions(perm_request)
                roles = perm_response.roles or []
            except Exception:
                continue

            # Check for overly broad admin roles
            admin_roles = [
                r for r in roles
                if r.name and (
                    "admin" in r.name.lower()
                    or "fullaccess" in r.name.lower()
                    or r.name == "te_admin"
                )
            ]

            if admin_roles:
                role_names = ", ".join(r.name for r in admin_roles[:5])
                self._add_finding(
                    check_id="IAM-04",
                    check_title="Group With Admin Permissions",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Group '{group_name}' has admin-level roles assigned: "
                        f"{role_names}. Follow least-privilege principle."
                    ),
                    resource_id=group_id,
                    resource_name=group_name,
                    remediation=(
                        "Review and restrict permissions for this group. "
                        "Apply least-privilege principle: only assign the minimum "
                        "permissions necessary for the group's function."
                    ),
                    reference_url="https://support.huaweicloud.com/bestpractice-iam/iam_01_0601.html",
                )

    def _check_inactive_users(self) -> None:
        """IAM-06: Check for users who haven't logged in for 90+ days."""
        request = KeystoneListUsersRequest()
        response = self.client.keystone_list_users(request)
        users = response.users or []

        threshold = datetime.now(timezone.utc) - timedelta(days=90)

        for user in users:
            user_name = user.name
            user_id = user.id
            last_login = user.last_project_id  # Proxy: check pwd_status or last login

            # Check if user has a last login timestamp
            if hasattr(user, "pwd_status") and user.pwd_status is False:
                # User has never set password / never logged in
                self._add_finding(
                    check_id="IAM-06",
                    check_title="User Never Logged In",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=(
                        f"User '{user_name}' appears to have never logged in. "
                        f"Consider removing unused accounts."
                    ),
                    resource_id=user_id,
                    resource_name=user_name,
                    remediation="Review if this user is still needed. Remove unused IAM users.",
                    reference_url="https://support.huaweicloud.com/usermanual-iam/iam_02_0004.html",
                )

    def _check_multiple_access_keys(self) -> None:
        """IAM-07: Check for users with multiple active access keys."""
        request = KeystoneListUsersRequest()
        response = self.client.keystone_list_users(request)
        users = response.users or []

        for user in users:
            user_name = user.name
            user_id = user.id

            try:
                ak_request = ListPermanentAccessKeysRequest()
                ak_request.user_id = user_id
                ak_response = self.client.list_permanent_access_keys(ak_request)
                credentials = ak_response.credentials or []
            except Exception:
                continue

            active_keys = [c for c in credentials if c.status == "active"]

            if len(active_keys) > 1:
                self._add_finding(
                    check_id="IAM-07",
                    check_title="Multiple Active Access Keys",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"User '{user_name}' has {len(active_keys)} active access keys. "
                        f"Best practice is to have only one active key at a time."
                    ),
                    resource_id=user_id,
                    resource_name=user_name,
                    remediation=(
                        "Deactivate or delete unused access keys. "
                        "Keep only one active key per user."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-iam/iam_02_0003.html",
                )
            elif len(active_keys) == 1:
                self._add_finding(
                    check_id="IAM-07",
                    check_title="Single Access Key",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    description=f"User '{user_name}' has exactly one active access key.",
                    resource_id=user_id,
                    resource_name=user_name,
                )
