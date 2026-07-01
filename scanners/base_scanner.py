"""
Huawei Cloud Security Scanner - Base Scanner

Abstract base class for all service-specific scanners.
Each scanner implements checks for a particular Huawei Cloud service.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from huaweicloudsdkcore.auth.credentials import BasicCredentials, GlobalCredentials

from core.auth import HuaweiCloudAuth, ScanTarget
from core.models import Finding, Severity, Status, ServiceCategory, ScanSummary, ScanResult

logger = logging.getLogger(__name__)


class BaseScanner(ABC):
    """
    Base class for all Huawei Cloud service scanners.
    
    Each scanner:
    1. Receives a ScanTarget (authenticated credentials for one account)
    2. Runs a set of security checks against the service
    3. Returns a list of Findings
    """

    # Subclasses must override these
    service_name: str = "unknown"
    service_category: ServiceCategory = ServiceCategory.IAM

    def __init__(self, target: ScanTarget):
        self.target = target
        self.findings: list[Finding] = []
        self.region = target.region
        self.project_id = target.project_id
        self.account_name = target.account_name
        self.verify_ssl = getattr(target, 'verify_ssl', True)
        self.cloud_domain = getattr(target, 'cloud_domain', 'myhuaweicloud.com')
        self.logger = logging.getLogger(f"{__name__}.{self.service_name}")

        # HTTP config for SSL verification
        if not self.verify_ssl:
            from huaweicloudsdkcore.http.http_config import HttpConfig
            self.http_config = HttpConfig.get_default_config()
            self.http_config.ignore_ssl_verification = True
        else:
            self.http_config = None

    def _get_endpoint(self, service: str) -> str:
        """Build the endpoint URL for a service using the correct cloud domain."""
        # Note: This is kept for reference but we use .with_region() for proper signing
        return f"https://{service}.{self.region}.{self.cloud_domain}"

    def _build_client(self, client_class, region_class, credentials):
        """
        Build a service client with proper HTTP config.
        Uses explicit endpoint for reliable connectivity.
        """
        endpoint = f"https://{self.service_name}.{self.region}.myhuaweicloud.com"

        # Build credentials directly from target (same as test_connection.py)
        direct_creds = BasicCredentials(
            self.target.credentials.access_key,
            self.target.credentials.secret_key,
            self.target.project_id,
        )

        builder = (
            client_class.new_builder()
            .with_credentials(direct_creds)
            .with_endpoint(endpoint)
        )
        if self.http_config:
            builder.with_http_config(self.http_config)
        return builder.build()

    def run(self) -> list[Finding]:
        """
        Execute all checks for this scanner.
        Returns a list of findings.
        """
        import time

        self.logger.info(
            f"Starting {self.service_name} scan for account: {self.account_name} "
            f"in region: {self.region}"
        )
        self.findings = []

        try:
            self._init_client()
            checks = self._get_checks()

            for i, check_fn in enumerate(checks):
                # Add delay between checks to avoid rate limiting
                if i > 0:
                    time.sleep(2)

                try:
                    check_fn()
                except Exception as e:
                    error_msg = str(e)
                    # Retry once if rate limited
                    if "failed to reach the limit" in error_msg.lower() or "forbidden" in error_msg.lower():
                        self.logger.warning(
                            f"Rate limited on {check_fn.__name__}, "
                            f"waiting 10s and retrying..."
                        )
                        time.sleep(10)
                        try:
                            check_fn()
                            continue
                        except Exception as retry_e:
                            e = retry_e

                    self.logger.error(
                        f"Error running check {check_fn.__name__} "
                        f"in {self.service_name}: {e}"
                    )
                    # Record the error as a finding
                    self._add_finding(
                        check_id=f"{self.service_name.upper()}-ERR",
                        check_title=f"Error in {check_fn.__name__}",
                        severity=Severity.INFORMATIONAL,
                        status=Status.ERROR,
                        description=f"Check failed with error: {str(e)}",
                    )

        except Exception as e:
            self.logger.error(f"Failed to initialize {self.service_name} scanner: {e}")
            self._add_finding(
                check_id=f"{self.service_name.upper()}-INIT-ERR",
                check_title=f"Scanner initialization failed",
                severity=Severity.HIGH,
                status=Status.ERROR,
                description=f"Could not initialize {self.service_name} client: {str(e)}",
            )

        self.logger.info(
            f"Completed {self.service_name} scan: "
            f"{len(self.findings)} findings "
            f"({sum(1 for f in self.findings if f.status == Status.FAIL)} failed)"
        )

        return self.findings

    @abstractmethod
    def _init_client(self) -> None:
        """Initialize the service-specific SDK client."""
        pass

    @abstractmethod
    def _get_checks(self) -> list:
        """Return list of check methods to execute."""
        pass

    def _add_finding(
        self,
        check_id: str,
        check_title: str,
        severity: Severity,
        status: Status,
        description: str,
        resource_id: str = "",
        resource_name: str = "",
        remediation: str = "",
        reference_url: str = "",
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            check_id=check_id,
            check_title=check_title,
            service=self.service_name,
            category=self.service_category,
            severity=severity,
            status=status,
            description=description,
            resource_id=resource_id,
            resource_name=resource_name,
            region=self.region,
            account_id=self.target.domain_id or self.project_id,
            account_name=self.account_name,
            remediation=remediation,
            reference_url=reference_url,
        )
        self.findings.append(finding)

    def _get_basic_credentials(self) -> BasicCredentials:
        """Get BasicCredentials for regional services."""
        return HuaweiCloudAuth.get_basic_credentials(self.target)

    def _get_global_credentials(self) -> GlobalCredentials:
        """Get GlobalCredentials for global services (IAM)."""
        return HuaweiCloudAuth.get_global_credentials(self.target)
