"""
Huawei Cloud Security Scanner - OBS Scanner

Checks for OBS (Object Storage Service) security best practices:
- OBS-01: Buckets with public read access
- OBS-02: Buckets with public write access
- OBS-03: Buckets without server-side encryption
- OBS-04: Buckets without logging enabled
"""

import logging

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

# OBS uses its own SDK (esdk-obs-python), but we can use REST API approach
# For simplicity, we use the obs SDK if available, otherwise document the check

try:
    from obs import ObsClient
    OBS_SDK_AVAILABLE = True
except ImportError:
    OBS_SDK_AVAILABLE = False


class OBSScanner(BaseScanner):
    """Scanner for OBS security checks."""

    service_name = "obs"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        """Initialize OBS client."""
        creds = self.target.credentials
        if OBS_SDK_AVAILABLE:
            self.obs_client = ObsClient(
                access_key_id=creds.access_key,
                secret_access_key=creds.secret_key,
                server=f"https://obs.{self.region}.myhuaweicloud.com",
            )
            if creds.security_token:
                self.obs_client = ObsClient(
                    access_key_id=creds.access_key,
                    secret_access_key=creds.secret_key,
                    security_token=creds.security_token,
                    server=f"https://obs.{self.region}.myhuaweicloud.com",
                )
        else:
            self.obs_client = None
            self.logger.warning(
                "OBS SDK (esdk-obs-python) not installed. "
                "Install it with: pip install esdk-obs-python"
            )

    def _get_checks(self) -> list:
        """Return list of OBS checks to run."""
        if not OBS_SDK_AVAILABLE or not self.obs_client:
            self._add_finding(
                check_id="OBS-00",
                check_title="OBS SDK Not Available",
                severity=Severity.INFORMATIONAL,
                status=Status.ERROR,
                description=(
                    "OBS SDK (esdk-obs-python) is not installed. "
                    "OBS checks will be skipped. "
                    "Install with: pip install esdk-obs-python"
                ),
            )
            return []
        return [
            self._check_public_buckets,
            self._check_bucket_encryption,
            self._check_bucket_logging,
        ]

    def _get_all_buckets(self) -> list:
        """List all OBS buckets."""
        resp = self.obs_client.listBuckets()
        if resp.status < 300:
            return resp.body.buckets or []
        return []

    def _check_public_buckets(self) -> None:
        """OBS-01/02: Check for buckets with public access."""
        buckets = self._get_all_buckets()

        for bucket in buckets:
            bucket_name = bucket.name

            try:
                acl_resp = self.obs_client.getBucketAcl(bucket_name)
                if acl_resp.status >= 300:
                    continue

                grants = acl_resp.body.grants or []
                public_read = False
                public_write = False

                for grant in grants:
                    grantee = grant.grantee
                    if hasattr(grantee, 'group') and grantee.group:
                        group_uri = grantee.group
                        if "AllUsers" in str(group_uri):
                            permission = grant.permission
                            if permission in ("READ", "FULL_CONTROL"):
                                public_read = True
                            if permission in ("WRITE", "FULL_CONTROL"):
                                public_write = True

                if public_read:
                    self._add_finding(
                        check_id="OBS-01",
                        check_title="Bucket Publicly Readable",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=(
                            f"Bucket '{bucket_name}' is publicly readable. "
                            f"Anyone on the internet can list and read objects."
                        ),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        remediation=(
                            "Remove public read access from the bucket ACL. "
                            "Use IAM policies to grant access to specific users."
                        ),
                        reference_url="https://support.huaweicloud.com/perms-cfg-obs/obs_40_0001.html",
                    )

                if public_write:
                    self._add_finding(
                        check_id="OBS-02",
                        check_title="Bucket Publicly Writable",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=(
                            f"Bucket '{bucket_name}' is publicly writable. "
                            f"Anyone can upload or delete objects."
                        ),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        remediation=(
                            "Remove public write access immediately. "
                            "This is a critical security risk."
                        ),
                        reference_url="https://support.huaweicloud.com/perms-cfg-obs/obs_40_0001.html",
                    )

                if not public_read and not public_write:
                    self._add_finding(
                        check_id="OBS-01",
                        check_title="Bucket Not Public",
                        severity=Severity.CRITICAL,
                        status=Status.PASS,
                        description=f"Bucket '{bucket_name}' is not publicly accessible.",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                    )

            except Exception as e:
                self.logger.debug(f"Error checking ACL for {bucket_name}: {e}")

    def _check_bucket_encryption(self) -> None:
        """OBS-03: Check for buckets without server-side encryption."""
        buckets = self._get_all_buckets()

        for bucket in buckets:
            bucket_name = bucket.name

            try:
                enc_resp = self.obs_client.getBucketEncryption(bucket_name)
                if enc_resp.status < 300:
                    self._add_finding(
                        check_id="OBS-03",
                        check_title="Bucket Encryption Enabled",
                        severity=Severity.MEDIUM,
                        status=Status.PASS,
                        description=f"Bucket '{bucket_name}' has server-side encryption enabled.",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                    )
                else:
                    self._add_finding(
                        check_id="OBS-03",
                        check_title="Bucket Without Encryption",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        description=(
                            f"Bucket '{bucket_name}' does not have server-side "
                            f"encryption enabled. Data at rest is not encrypted."
                        ),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        remediation=(
                            "Enable server-side encryption (SSE-KMS or SSE-OBS) "
                            "on the bucket to protect data at rest."
                        ),
                        reference_url="https://support.huaweicloud.com/usermanual-obs/obs_03_0088.html",
                    )
            except Exception:
                self._add_finding(
                    check_id="OBS-03",
                    check_title="Bucket Without Encryption",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=f"Bucket '{bucket_name}' does not have encryption configured.",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    remediation="Enable server-side encryption on this bucket.",
                    reference_url="https://support.huaweicloud.com/usermanual-obs/obs_03_0088.html",
                )

    def _check_bucket_logging(self) -> None:
        """OBS-04: Check for buckets without access logging."""
        buckets = self._get_all_buckets()

        for bucket in buckets:
            bucket_name = bucket.name

            try:
                log_resp = self.obs_client.getBucketLogging(bucket_name)
                if log_resp.status < 300 and log_resp.body.targetBucket:
                    self._add_finding(
                        check_id="OBS-04",
                        check_title="Bucket Logging Enabled",
                        severity=Severity.LOW,
                        status=Status.PASS,
                        description=f"Bucket '{bucket_name}' has access logging enabled.",
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                    )
                else:
                    self._add_finding(
                        check_id="OBS-04",
                        check_title="Bucket Without Logging",
                        severity=Severity.LOW,
                        status=Status.FAIL,
                        description=(
                            f"Bucket '{bucket_name}' does not have access logging "
                            f"enabled. Access events are not being recorded."
                        ),
                        resource_id=bucket_name,
                        resource_name=bucket_name,
                        remediation="Enable access logging to track who accesses the bucket.",
                        reference_url="https://support.huaweicloud.com/usermanual-obs/obs_03_0064.html",
                    )
            except Exception:
                self._add_finding(
                    check_id="OBS-04",
                    check_title="Bucket Logging Unknown",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=f"Could not determine logging status for '{bucket_name}'.",
                    resource_id=bucket_name,
                    resource_name=bucket_name,
                    remediation="Enable access logging on the bucket.",
                    reference_url="https://support.huaweicloud.com/usermanual-obs/obs_03_0064.html",
                )
