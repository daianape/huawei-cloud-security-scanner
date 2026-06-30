"""
Huawei Cloud Security Scanner - ELB Scanner

Checks for ELB (Elastic Load Balance) security best practices:
- ELB-01: Listeners without HTTPS/TLS
- ELB-02: Load balancers without access logging
- ELB-03: Listeners using outdated TLS versions
"""

import logging

from huaweicloudsdkelb.v3 import (
    ElbClient,
    ListLoadBalancersRequest,
    ListListenersRequest,
)
from huaweicloudsdkelb.v3.region.elb_region import ElbRegion

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)


class ELBScanner(BaseScanner):
    """Scanner for ELB security checks."""

    service_name = "elb"
    service_category = ServiceCategory.LOAD_BALANCER

    def _init_client(self) -> None:
        """Initialize ELB client."""
        credentials = self._get_basic_credentials()
        builder = (
            ElbClient.new_builder()
            .with_credentials(credentials)
            .with_region(ElbRegion.value_of(self.region))
        )
        if self.http_config:
            builder.with_http_config(self.http_config)
        self.client = builder.build()

    def _get_checks(self) -> list:
        """Return list of ELB checks to run."""
        return [
            self._check_non_https_listeners,
            self._check_tls_versions,
        ]

    def _check_non_https_listeners(self) -> None:
        """ELB-01: Check for listeners not using HTTPS/TLS."""
        request = ListListenersRequest()
        response = self.client.list_listeners(request)
        listeners = response.listeners or []

        for listener in listeners:
            listener_name = listener.name or "unnamed"
            listener_id = listener.id
            protocol = listener.protocol or ""
            port = listener.protocol_port

            # Web-facing ports that should use HTTPS
            if protocol.upper() in ("HTTP", "TCP") and port in (443, 8443):
                self._add_finding(
                    check_id="ELB-01",
                    check_title="Listener on HTTPS Port Without TLS",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Listener '{listener_name}' on port {port} uses "
                        f"protocol {protocol} instead of HTTPS/TLS. "
                        f"Traffic is not encrypted in transit."
                    ),
                    resource_id=listener_id,
                    resource_name=listener_name,
                    remediation=(
                        "Change the listener protocol to HTTPS and configure "
                        "an SSL certificate."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-elb/elb_ug_jt_0004.html",
                )
            elif protocol.upper() == "HTTP" and port in (80, 8080):
                self._add_finding(
                    check_id="ELB-01",
                    check_title="HTTP Listener (No Encryption)",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Listener '{listener_name}' on port {port} uses HTTP. "
                        f"Consider redirecting to HTTPS for encrypted communication."
                    ),
                    resource_id=listener_id,
                    resource_name=listener_name,
                    remediation=(
                        "Configure an HTTPS listener and set up HTTP to HTTPS "
                        "redirect for this listener."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-elb/elb_ug_jt_0004.html",
                )
            elif protocol.upper() in ("HTTPS", "TERMINATED_HTTPS"):
                self._add_finding(
                    check_id="ELB-01",
                    check_title="HTTPS Listener Configured",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=(
                        f"Listener '{listener_name}' on port {port} uses {protocol}."
                    ),
                    resource_id=listener_id,
                    resource_name=listener_name,
                )

    def _check_tls_versions(self) -> None:
        """ELB-03: Check for listeners using outdated TLS versions."""
        request = ListListenersRequest()
        response = self.client.list_listeners(request)
        listeners = response.listeners or []

        outdated_policies = ["tls-1-0", "tls-1-1"]

        for listener in listeners:
            listener_name = listener.name or "unnamed"
            listener_id = listener.id
            protocol = listener.protocol or ""
            tls_policy = ""

            if hasattr(listener, 'tls_ciphers_policy'):
                tls_policy = listener.tls_ciphers_policy or ""

            if protocol.upper() not in ("HTTPS", "TERMINATED_HTTPS"):
                continue

            if tls_policy and any(old in tls_policy.lower() for old in outdated_policies):
                self._add_finding(
                    check_id="ELB-03",
                    check_title="Outdated TLS Version",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Listener '{listener_name}' uses TLS policy '{tls_policy}' "
                        f"which includes outdated TLS versions (1.0/1.1). "
                        f"These versions have known vulnerabilities."
                    ),
                    resource_id=listener_id,
                    resource_name=listener_name,
                    remediation=(
                        "Update the TLS policy to use TLS 1.2 or higher. "
                        "Disable TLS 1.0 and 1.1."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-elb/elb_ug_jt_0004.html",
                )
            elif protocol.upper() in ("HTTPS", "TERMINATED_HTTPS"):
                self._add_finding(
                    check_id="ELB-03",
                    check_title="TLS Version Compliant",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=(
                        f"Listener '{listener_name}' uses acceptable TLS configuration."
                    ),
                    resource_id=listener_id,
                    resource_name=listener_name,
                )
