"""
Huawei Cloud Security Scanner - Cloud Eye (CES) Scanner

Checks for monitoring best practices:
- CES-01: No alarm rules configured for critical services
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkces.v1 import (
        CesClient,
        ListAlarmsRequest,
    )
    from huaweicloudsdkces.v1.region.ces_region import CesRegion
    CES_AVAILABLE = True
except ImportError:
    CES_AVAILABLE = False


class CESScanner(BaseScanner):
    """Scanner for Cloud Eye monitoring checks."""

    service_name = "ces"
    service_category = ServiceCategory.LOGGING

    def _init_client(self) -> None:
        if not CES_AVAILABLE:
            return
        self.client = self._build_client(CesClient, CesRegion, None)

    def _get_checks(self) -> list:
        if not CES_AVAILABLE:
            self._add_finding(
                check_id="CES-00", check_title="CES SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkces",
            )
            return []
        return [self._check_alarms_configured]

    def _check_alarms_configured(self) -> None:
        """CES-01: Check if alarm rules exist."""
        request = ListAlarmsRequest()
        response = self.client.list_alarms(request)
        alarms = response.metric_alarms or []

        if not alarms:
            self._add_finding(
                check_id="CES-01",
                check_title="Sin Alarmas de Monitoreo",
                severity=Severity.MEDIUM, status=Status.FAIL,
                description=(
                    "No hay alarmas de Cloud Eye configuradas. "
                    "No se recibiran alertas ante incidentes de disponibilidad o seguridad."
                ),
                remediation="Configurar alarmas para CPU, disco, red y eventos de seguridad.",
            )
        else:
            enabled = sum(1 for a in alarms if getattr(a, 'alarm_enabled', True))
            disabled = len(alarms) - enabled

            if disabled > 0:
                self._add_finding(
                    check_id="CES-01",
                    check_title="Alarmas Deshabilitadas",
                    severity=Severity.LOW, status=Status.FAIL,
                    description=f"Hay {disabled} alarmas deshabilitadas de {len(alarms)} totales.",
                    remediation="Revisar y habilitar alarmas deshabilitadas.",
                )
            else:
                self._add_finding(
                    check_id="CES-01",
                    check_title="Alarmas Configuradas",
                    severity=Severity.MEDIUM, status=Status.PASS,
                    description=f"{len(alarms)} alarmas activas configuradas.",
                )
