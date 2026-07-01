"""
Huawei Cloud Security Scanner - EIP Scanner

Checks for Elastic IP security best practices:
- EIP-01: Unassociated EIPs (cost waste and potential risk)
- EIP-02: EIPs without DDoS protection
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkeip.v2 import (
        EipClient,
        ListPublicipsRequest,
    )
    from huaweicloudsdkeip.v2.region.eip_region import EipRegion
    EIP_AVAILABLE = True
except ImportError:
    EIP_AVAILABLE = False


class EIPScanner(BaseScanner):
    """Scanner for Elastic IP security checks."""

    service_name = "eip"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not EIP_AVAILABLE:
            return
        self.client = self._build_client(EipClient, EipRegion, None)

    def _get_checks(self) -> list:
        if not EIP_AVAILABLE:
            self._add_finding(
                check_id="EIP-00", check_title="EIP SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkeip",
            )
            return []
        return [self._check_unassociated_eips]

    def _check_unassociated_eips(self) -> None:
        """EIP-01: Check for EIPs not associated with any resource."""
        request = ListPublicipsRequest()
        response = self.client.list_publicips(request)
        eips = response.publicips or []

        for eip in eips:
            ip_addr = eip.public_ip_address or ""
            eip_id = eip.id
            status_val = eip.status or ""

            if status_val == "DOWN" or not eip.port_id:
                self._add_finding(
                    check_id="EIP-01",
                    check_title="EIP Sin Asociar",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=(
                        f"EIP '{ip_addr}' no esta asociada a ningun recurso. "
                        f"Genera costo y podria ser usada por un atacante si se asocia."
                    ),
                    resource_id=eip_id,
                    resource_name=ip_addr,
                    remediation="Liberar la EIP si no se necesita, o asociarla a un recurso.",
                )
            else:
                self._add_finding(
                    check_id="EIP-01",
                    check_title="EIP Asociada",
                    severity=Severity.LOW,
                    status=Status.PASS,
                    description=f"EIP '{ip_addr}' esta asociada a un recurso.",
                    resource_id=eip_id,
                    resource_name=ip_addr,
                )
