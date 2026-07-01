"""
Huawei Cloud Security Scanner - CBR (Cloud Backup) Scanner

Checks for Cloud Backup and Recovery best practices:
- CBR-01: Vaults without associated resources (empty)
- CBR-02: Backup policies without sufficient retention
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkcbr.v1 import (
        CbrClient,
        ListVaultRequest,
        ListPoliciesRequest,
    )
    from huaweicloudsdkcbr.v1.region.cbr_region import CbrRegion
    CBR_AVAILABLE = True
except ImportError:
    CBR_AVAILABLE = False


class CBRScanner(BaseScanner):
    """Scanner for Cloud Backup and Recovery checks."""

    service_name = "cbr"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        if not CBR_AVAILABLE:
            return
        self.client = self._build_client(CbrClient, CbrRegion, None)

    def _get_checks(self) -> list:
        if not CBR_AVAILABLE:
            self._add_finding(
                check_id="CBR-00", check_title="CBR SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkcbr",
            )
            return []
        return [self._check_vault_resources, self._check_retention]

    def _check_vault_resources(self) -> None:
        """CBR-01: Check for vaults without resources."""
        request = ListVaultRequest()
        response = self.client.list_vault(request)
        vaults = response.vaults or []

        for vault in vaults:
            name = vault.name or "unnamed"
            vault_id = vault.id
            resources = vault.resources or []

            if not resources:
                self._add_finding(
                    check_id="CBR-01",
                    check_title="Vault Sin Recursos Asociados",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=f"Vault '{name}' no tiene recursos asociados para backup.",
                    resource_id=vault_id, resource_name=name,
                    remediation="Asociar recursos al vault o eliminarlo si no se necesita.",
                )

    def _check_retention(self) -> None:
        """CBR-02: Check backup policies retention."""
        request = ListPoliciesRequest()
        response = self.client.list_policies(request)
        policies = response.policies or []

        for policy in policies:
            name = policy.name or "unnamed"
            policy_id = policy.id
            rules = policy.operation_definition if hasattr(policy, 'operation_definition') else None

            if rules and hasattr(rules, 'retention_duration_days'):
                days = rules.retention_duration_days
                if days and days < 7:
                    self._add_finding(
                        check_id="CBR-02",
                        check_title="Retencion de Backup Insuficiente",
                        severity=Severity.MEDIUM, status=Status.FAIL,
                        description=f"Politica '{name}' retiene backups solo {days} dias (minimo recomendado: 7).",
                        resource_id=policy_id, resource_name=name,
                        remediation="Aumentar retencion a minimo 7 dias.",
                    )
