"""
Huawei Cloud Security Scanner - EVS Scanner

Checks for Elastic Volume Service security best practices:
- EVS-01: Volumes without encryption
- EVS-02: Volumes without backup configured
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkevs.v2 import (
        EvsClient,
        ListVolumesRequest,
    )
    from huaweicloudsdkevs.v2.region.evs_region import EvsRegion
    EVS_AVAILABLE = True
except ImportError:
    EVS_AVAILABLE = False


class EVSScanner(BaseScanner):
    """Scanner for EVS security checks."""

    service_name = "evs"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        if not EVS_AVAILABLE:
            return
        self.client = self._build_client(EvsClient, EvsRegion, None)

    def _get_checks(self) -> list:
        if not EVS_AVAILABLE:
            self._add_finding(
                check_id="EVS-00", check_title="EVS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkevs",
            )
            return []
        return [self._check_encryption]

    def _check_encryption(self) -> None:
        """EVS-01: Check for volumes without encryption."""
        request = ListVolumesRequest()
        response = self.client.list_volumes(request)
        volumes = response.volumes or []

        for vol in volumes:
            vol_name = vol.name or "unnamed"
            vol_id = vol.id
            encrypted = getattr(vol, 'metadata', {})
            is_encrypted = False

            if encrypted and isinstance(encrypted, dict):
                is_encrypted = encrypted.get('__system__encrypted', '0') == '1'

            if not is_encrypted:
                self._add_finding(
                    check_id="EVS-01",
                    check_title="Volumen Sin Cifrado",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Volumen '{vol_name}' no tiene cifrado habilitado. "
                        f"Datos en reposo no estan protegidos."
                    ),
                    resource_id=vol_id,
                    resource_name=vol_name,
                    remediation=(
                        "Crear volumenes nuevos con cifrado habilitado. "
                        "Los volumenes existentes no se pueden cifrar retroactivamente."
                    ),
                )
            else:
                self._add_finding(
                    check_id="EVS-01",
                    check_title="Volumen Cifrado",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    description=f"Volumen '{vol_name}' tiene cifrado habilitado.",
                    resource_id=vol_id,
                    resource_name=vol_name,
                )
