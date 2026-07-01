"""
Huawei Cloud Security Scanner - Cloud Firewall Scanner

Checks for Cloud Firewall (CFW) security best practices:
- CFW-01: Cloud Firewall not enabled
- CFW-02: Overly permissive firewall rules (allow all)
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkcfw.v1 import (
        CfwClient,
        ListFirewallListRequest,
        ListAclRulesRequest,
    )
    from huaweicloudsdkcfw.v1.region.cfw_region import CfwRegion
    CFW_AVAILABLE = True
except ImportError:
    CFW_AVAILABLE = False


class CFWScanner(BaseScanner):
    """Scanner for Cloud Firewall security checks."""

    service_name = "cfw"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not CFW_AVAILABLE:
            return
        self.client = self._build_client(CfwClient, CfwRegion, None)

    def _get_checks(self) -> list:
        if not CFW_AVAILABLE:
            self._add_finding(
                check_id="CFW-00", check_title="CFW SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkcfw",
            )
            return []
        return [self._check_firewall_enabled]

    def _check_firewall_enabled(self) -> None:
        """CFW-01: Check if Cloud Firewall is enabled."""
        try:
            request = ListFirewallListRequest()
            response = self.client.list_firewall_list(request)
            firewalls = response.data or []

            if not firewalls:
                self._add_finding(
                    check_id="CFW-01",
                    check_title="Cloud Firewall No Desplegado",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        "No se encontro ningun Cloud Firewall desplegado. "
                        "El trafico de red no esta siendo inspeccionado."
                    ),
                    remediation="Desplegar Cloud Firewall para inspeccionar trafico norte-sur.",
                )
                return

            for fw in firewalls:
                fw_name = getattr(fw, 'name', 'unnamed')
                fw_id = getattr(fw, 'fw_instance_id', '')
                status_val = getattr(fw, 'status', None)

                if status_val and str(status_val) != "1":
                    self._add_finding(
                        check_id="CFW-01",
                        check_title="Cloud Firewall Inactivo",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        description=f"Cloud Firewall '{fw_name}' no esta activo.",
                        resource_id=fw_id,
                        resource_name=fw_name,
                        remediation="Activar el Cloud Firewall.",
                    )
                else:
                    self._add_finding(
                        check_id="CFW-01",
                        check_title="Cloud Firewall Activo",
                        severity=Severity.HIGH,
                        status=Status.PASS,
                        description=f"Cloud Firewall '{fw_name}' esta activo.",
                        resource_id=fw_id,
                        resource_name=fw_name,
                    )

        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                self._add_finding(
                    check_id="CFW-01",
                    check_title="Cloud Firewall No Disponible",
                    severity=Severity.INFORMATIONAL,
                    status=Status.NOT_AVAILABLE,
                    description="Cloud Firewall no esta disponible en esta region/cuenta.",
                )
            else:
                raise
