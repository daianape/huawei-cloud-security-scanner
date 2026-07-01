"""
Huawei Cloud Security Scanner - DNS Scanner

Checks for DNS security best practices:
- DNS-01: Public zones that may expose internal infrastructure
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkdns.v2 import (
        DnsClient,
        ListPublicZonesRequest,
    )
    from huaweicloudsdkdns.v2.region.dns_region import DnsRegion
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class DNSScanner(BaseScanner):
    """Scanner for DNS security checks."""

    service_name = "dns"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not DNS_AVAILABLE:
            return
        self.client = self._build_client(DnsClient, DnsRegion, None)

    def _get_checks(self) -> list:
        if not DNS_AVAILABLE:
            self._add_finding(
                check_id="DNS-00", check_title="DNS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkdns",
            )
            return []
        return [self._check_public_zones]

    def _check_public_zones(self) -> None:
        """DNS-01: List public DNS zones for review."""
        request = ListPublicZonesRequest()
        response = self.client.list_public_zones(request)
        zones = response.zones or []

        for zone in zones:
            zone_name = zone.name or ""
            zone_id = zone.id
            record_num = zone.record_num or 0

            self._add_finding(
                check_id="DNS-01",
                check_title="Zona DNS Publica Detectada",
                severity=Severity.LOW, status=Status.FAIL,
                description=(
                    f"Zona publica '{zone_name}' con {record_num} registros. "
                    f"Verificar que no exponga infraestructura interna."
                ),
                resource_id=zone_id, resource_name=zone_name,
                remediation="Revisar registros DNS publicos y eliminar los innecesarios.",
            )
