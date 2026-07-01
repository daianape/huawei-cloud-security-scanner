"""
Huawei Cloud Security Scanner - NAT Gateway Scanner

Checks for NAT Gateway security best practices:
- NAT-01: DNAT rules exposing internal services to internet
- NAT-02: DNAT rules exposing sensitive ports (DB, SSH, RDP)
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdknat.v2 import (
        NatClient,
        ListNatGatewaysRequest,
        ListNatGatewayDnatRulesRequest,
    )
    from huaweicloudsdknat.v2.region.nat_region import NatRegion
    NAT_AVAILABLE = True
except ImportError:
    NAT_AVAILABLE = False

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                   6379: "Redis", 27017: "MongoDB", 1433: "MSSQL"}


class NATScanner(BaseScanner):
    """Scanner for NAT Gateway security checks."""

    service_name = "nat"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not NAT_AVAILABLE:
            return
        self.client = self._build_client(NatClient, NatRegion, None)

    def _get_checks(self) -> list:
        if not NAT_AVAILABLE:
            self._add_finding(
                check_id="NAT-00", check_title="NAT SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdknat",
            )
            return []
        return [self._check_dnat_sensitive_ports]

    def _check_dnat_sensitive_ports(self) -> None:
        """NAT-01/02: Check DNAT rules exposing sensitive ports."""
        request = ListNatGatewayDnatRulesRequest()
        response = self.client.list_nat_gateway_dnat_rules(request)
        rules = response.dnat_rules or []

        for rule in rules:
            ext_port = rule.external_service_port
            protocol = rule.protocol or "tcp"
            floating_ip = rule.floating_ip_address or ""

            if ext_port in SENSITIVE_PORTS:
                svc = SENSITIVE_PORTS[ext_port]
                self._add_finding(
                    check_id="NAT-02",
                    check_title="DNAT Expone Puerto Sensible",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    description=(
                        f"Regla DNAT expone puerto {ext_port} ({svc}) "
                        f"en IP {floating_ip} al internet."
                    ),
                    resource_id=rule.id,
                    resource_name=f"DNAT:{floating_ip}:{ext_port}",
                    remediation=f"Eliminar la regla DNAT para {svc} o restringir acceso via security groups.",
                )
            else:
                self._add_finding(
                    check_id="NAT-01",
                    check_title="DNAT Rule Detectada",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=(
                        f"Regla DNAT expone puerto {ext_port}/{protocol} "
                        f"en IP {floating_ip}. Verificar que sea necesario."
                    ),
                    resource_id=rule.id,
                    resource_name=f"DNAT:{floating_ip}:{ext_port}",
                    remediation="Revisar si esta regla DNAT es necesaria.",
                )
