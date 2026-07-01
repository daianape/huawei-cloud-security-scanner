"""
Huawei Cloud Security Scanner - WAF Scanner

Checks for Web Application Firewall security best practices:
- WAF-01: Domains without WAF protection enabled
- WAF-02: WAF policies in detection-only mode (not blocking)
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkwaf.v1 import (
        WafClient,
        ListHostRequest,
        ListPolicyRequest,
    )
    from huaweicloudsdkwaf.v1.region.waf_region import WafRegion
    WAF_AVAILABLE = True
except ImportError:
    WAF_AVAILABLE = False


class WAFScanner(BaseScanner):
    """Scanner for WAF security checks."""

    service_name = "waf"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not WAF_AVAILABLE:
            return
        self.client = self._build_client(WafClient, WafRegion, None)

    def _get_checks(self) -> list:
        if not WAF_AVAILABLE:
            self._add_finding(
                check_id="WAF-00", check_title="WAF SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkwaf",
            )
            return []
        return [self._check_unprotected_domains, self._check_detection_mode]

    def _check_unprotected_domains(self) -> None:
        """WAF-01: Check for domains not protected by WAF."""
        request = ListHostRequest()
        response = self.client.list_host(request)
        hosts = response.items or []

        for host in hosts:
            hostname = host.hostname or ""
            host_id = host.id
            protect_status = getattr(host, 'protect_status', None)

            if protect_status == 0 or protect_status == "inactive":
                self._add_finding(
                    check_id="WAF-01",
                    check_title="Dominio Sin Proteccion WAF",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=f"Dominio '{hostname}' tiene WAF deshabilitado.",
                    resource_id=host_id,
                    resource_name=hostname,
                    remediation="Activar la proteccion WAF para este dominio.",
                )
            else:
                self._add_finding(
                    check_id="WAF-01",
                    check_title="Dominio Protegido por WAF",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=f"Dominio '{hostname}' tiene WAF activo.",
                    resource_id=host_id,
                    resource_name=hostname,
                )

    def _check_detection_mode(self) -> None:
        """WAF-02: Check for policies in detection-only mode."""
        request = ListPolicyRequest()
        response = self.client.list_policy(request)
        policies = response.items or []

        for policy in policies:
            policy_name = policy.name or ""
            policy_id = policy.id
            action_mode = getattr(policy, 'action', None)
            level = getattr(policy, 'level', None)

            if action_mode and str(action_mode).lower() in ("detection", "log"):
                self._add_finding(
                    check_id="WAF-02",
                    check_title="WAF en Modo Solo Deteccion",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Politica WAF '{policy_name}' esta en modo deteccion "
                        f"(no bloquea ataques, solo los registra)."
                    ),
                    resource_id=policy_id,
                    resource_name=policy_name,
                    remediation="Cambiar a modo 'prevention' para bloquear ataques.",
                )
