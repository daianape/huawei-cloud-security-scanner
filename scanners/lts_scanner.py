"""
Huawei Cloud Security Scanner - LTS (Log Tank Service) Scanner

Checks for logging best practices:
- LTS-01: Log groups without transfer to OBS (no long-term retention)
- LTS-02: Log groups with short retention period
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdklts.v2 import (
        LtsClient,
        ListLogGroupsRequest,
    )
    from huaweicloudsdklts.v2.region.lts_region import LtsRegion
    LTS_AVAILABLE = True
except ImportError:
    LTS_AVAILABLE = False


class LTSScanner(BaseScanner):
    """Scanner for Log Tank Service checks."""

    service_name = "lts"
    service_category = ServiceCategory.LOGGING

    def _init_client(self) -> None:
        if not LTS_AVAILABLE:
            return
        self.client = self._build_client(LtsClient, LtsRegion, None)

    def _get_checks(self) -> list:
        if not LTS_AVAILABLE:
            self._add_finding(
                check_id="LTS-00", check_title="LTS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdklts",
            )
            return []
        return [self._check_log_retention]

    def _check_log_retention(self) -> None:
        """LTS-02: Check log group retention periods."""
        request = ListLogGroupsRequest()
        response = self.client.list_log_groups(request)
        groups = response.log_groups or []

        for group in groups:
            name = group.log_group_name or "unnamed"
            group_id = group.log_group_id or ""
            ttl = getattr(group, 'ttl_in_days', None)

            if ttl and ttl < 30:
                self._add_finding(
                    check_id="LTS-02",
                    check_title="Retencion de Logs Corta",
                    severity=Severity.MEDIUM, status=Status.FAIL,
                    description=(
                        f"Grupo de logs '{name}' tiene retencion de {ttl} dias. "
                        f"Recomendado minimo 30 dias para investigacion de incidentes."
                    ),
                    resource_id=group_id, resource_name=name,
                    remediation="Aumentar retencion a minimo 30 dias.",
                )
            elif ttl:
                self._add_finding(
                    check_id="LTS-02",
                    check_title="Retencion de Logs Adecuada",
                    severity=Severity.MEDIUM, status=Status.PASS,
                    description=f"Grupo '{name}' retiene logs {ttl} dias.",
                    resource_id=group_id, resource_name=name,
                )
