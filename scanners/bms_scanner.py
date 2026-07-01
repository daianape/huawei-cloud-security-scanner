"""
Huawei Cloud Security Scanner - BMS (Bare Metal Server) Scanner

Checks for Bare Metal Server security best practices:
- BMS-01: BMS instances with public IP directly assigned
- BMS-02: BMS instances using default security group
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkbms.v1 import (
        BmsClient,
        ListBareMetalServersRequest,
    )
    from huaweicloudsdkbms.v1.region.bms_region import BmsRegion
    BMS_AVAILABLE = True
except ImportError:
    BMS_AVAILABLE = False


class BMSScanner(BaseScanner):
    """Scanner for Bare Metal Server security checks."""

    service_name = "bms"
    service_category = ServiceCategory.COMPUTE

    def _init_client(self) -> None:
        if not BMS_AVAILABLE:
            return
        self.client = self._build_client(BmsClient, BmsRegion, None)

    def _get_checks(self) -> list:
        if not BMS_AVAILABLE:
            self._add_finding(
                check_id="BMS-00", check_title="BMS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkbms",
            )
            return []
        return [self._check_public_ip, self._check_security_group]

    def _check_public_ip(self) -> None:
        """BMS-01: Check for BMS with public IP."""
        request = ListBareMetalServersRequest()
        response = self.client.list_bare_metal_servers(request)
        servers = response.servers or []

        for server in servers:
            name = server.name or "unnamed"
            server_id = server.id
            addresses = server.addresses or {}
            has_public = False
            public_ips = []

            for net_name, net_addrs in addresses.items():
                if net_addrs:
                    for addr in net_addrs:
                        if hasattr(addr, 'os_ext_ips_type'):
                            if addr.os_ext_ips_type == "floating":
                                has_public = True
                                public_ips.append(addr.addr)

            if has_public:
                self._add_finding(
                    check_id="BMS-01",
                    check_title="BMS con IP Publica",
                    severity=Severity.MEDIUM, status=Status.FAIL,
                    description=(
                        f"Bare Metal Server '{name}' tiene IP publica: "
                        f"{', '.join(public_ips)}. Considerar NAT Gateway o ELB."
                    ),
                    resource_id=server_id, resource_name=name,
                    remediation="Remover IP publica directa. Usar NAT o ELB.",
                )
            else:
                self._add_finding(
                    check_id="BMS-01",
                    check_title="BMS Sin IP Publica",
                    severity=Severity.MEDIUM, status=Status.PASS,
                    description=f"BMS '{name}' no tiene IP publica directa.",
                    resource_id=server_id, resource_name=name,
                )

    def _check_security_group(self) -> None:
        """BMS-02: Check for BMS using default security group."""
        request = ListBareMetalServersRequest()
        response = self.client.list_bare_metal_servers(request)
        servers = response.servers or []

        for server in servers:
            name = server.name or "unnamed"
            server_id = server.id
            security_groups = server.security_groups or []

            uses_default = any(
                sg.name and sg.name.lower() in ("default", "sys_default")
                for sg in security_groups if hasattr(sg, 'name')
            )

            if uses_default:
                self._add_finding(
                    check_id="BMS-02",
                    check_title="BMS con Security Group Default",
                    severity=Severity.LOW, status=Status.FAIL,
                    description=f"BMS '{name}' usa security group default.",
                    resource_id=server_id, resource_name=name,
                    remediation="Crear security group custom con reglas especificas.",
                )
