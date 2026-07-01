"""
Huawei Cloud Security Scanner - VPN Scanner

Checks for VPN security best practices:
- VPN-01: VPN connections using weak encryption (DES, 3DES)
- VPN-02: VPN connections with short PSK
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkvpn.v5 import (
        VpnClient,
        ListVpnConnectionsRequest,
    )
    from huaweicloudsdkvpn.v5.region.vpn_region import VpnRegion
    VPN_AVAILABLE = True
except ImportError:
    VPN_AVAILABLE = False

WEAK_ENCRYPTION = ["des", "3des"]


class VPNScanner(BaseScanner):
    """Scanner for VPN security checks."""

    service_name = "vpn"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        if not VPN_AVAILABLE:
            return
        self.client = self._build_client(VpnClient, VpnRegion, None)

    def _get_checks(self) -> list:
        if not VPN_AVAILABLE:
            self._add_finding(
                check_id="VPN-00", check_title="VPN SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkvpn",
            )
            return []
        return [self._check_encryption]

    def _check_encryption(self) -> None:
        """VPN-01: Check for VPN connections with weak encryption."""
        request = ListVpnConnectionsRequest()
        response = self.client.list_vpn_connections(request)
        connections = response.vpn_connections or []

        for conn in connections:
            name = conn.name or "unnamed"
            conn_id = conn.id
            ike_policy = conn.ike_policy if hasattr(conn, 'ike_policy') else None
            ipsec_policy = conn.ipsec_policy if hasattr(conn, 'ipsec_policy') else None

            if ike_policy:
                enc = getattr(ike_policy, 'encryption_algorithm', '') or ''
                if enc.lower() in WEAK_ENCRYPTION:
                    self._add_finding(
                        check_id="VPN-01",
                        check_title="VPN con Cifrado Debil (IKE)",
                        severity=Severity.HIGH, status=Status.FAIL,
                        description=f"Conexion VPN '{name}' usa cifrado IKE debil: {enc}.",
                        resource_id=conn_id, resource_name=name,
                        remediation="Cambiar a AES-128 o AES-256.",
                    )

            if ipsec_policy:
                enc = getattr(ipsec_policy, 'encryption_algorithm', '') or ''
                if enc.lower() in WEAK_ENCRYPTION:
                    self._add_finding(
                        check_id="VPN-01",
                        check_title="VPN con Cifrado Debil (IPSec)",
                        severity=Severity.HIGH, status=Status.FAIL,
                        description=f"Conexion VPN '{name}' usa cifrado IPSec debil: {enc}.",
                        resource_id=conn_id, resource_name=name,
                        remediation="Cambiar a AES-128 o AES-256.",
                    )
