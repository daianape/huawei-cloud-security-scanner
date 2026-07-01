"""
Huawei Cloud Security Scanner - RDS Scanner

Checks for Relational Database Service security best practices:
- RDS-01: Database instances with public access enabled
- RDS-02: Database instances without encryption (storage)
- RDS-03: Database instances without automatic backups
- RDS-04: Database instances without SSL enabled
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkrds.v3 import (
        RdsClient,
        ListInstancesRequest,
    )
    from huaweicloudsdkrds.v3.region.rds_region import RdsRegion
    RDS_AVAILABLE = True
except ImportError:
    RDS_AVAILABLE = False


class RDSScanner(BaseScanner):
    """Scanner for RDS security checks."""

    service_name = "rds"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        """Initialize RDS client."""
        if not RDS_AVAILABLE:
            return
        self.client = self._build_client(RdsClient, RdsRegion, None)

    def _get_checks(self) -> list:
        if not RDS_AVAILABLE:
            self._add_finding(
                check_id="RDS-00",
                check_title="RDS SDK No Disponible",
                severity=Severity.INFORMATIONAL,
                status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkrds",
            )
            return []
        return [
            self._check_public_access,
            self._check_backup_policy,
            self._check_ssl_enabled,
        ]

    def _get_all_instances(self) -> list:
        """Fetch all RDS instances."""
        request = ListInstancesRequest()
        response = self.client.list_instances(request)
        return response.instances or []

    def _check_public_access(self) -> None:
        """RDS-01: Check for database instances with public access."""
        instances = self._get_all_instances()

        for instance in instances:
            name = instance.name
            inst_id = instance.id
            # Check if instance has public IP (EIP bound)
            public_ips = instance.public_ips or []

            if public_ips:
                self._add_finding(
                    check_id="RDS-01",
                    check_title="Base de Datos con Acceso Publico",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    description=(
                        f"La instancia RDS '{name}' tiene IP publica asignada: "
                        f"{', '.join(public_ips)}. La base de datos es accesible "
                        f"desde internet."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation=(
                        "Desvincular la EIP de la instancia RDS. Acceder solo "
                        "via red privada (VPC) o VPN."
                    ),
                )
            else:
                self._add_finding(
                    check_id="RDS-01",
                    check_title="Base de Datos Sin Acceso Publico",
                    severity=Severity.CRITICAL,
                    status=Status.PASS,
                    description=f"Instancia RDS '{name}' no tiene IP publica.",
                    resource_id=inst_id,
                    resource_name=name,
                )

    def _check_backup_policy(self) -> None:
        """RDS-03: Check for instances without automatic backups."""
        instances = self._get_all_instances()

        for instance in instances:
            name = instance.name
            inst_id = instance.id
            backup_strategy = instance.backup_strategy

            if not backup_strategy or not backup_strategy.keep_days:
                self._add_finding(
                    check_id="RDS-03",
                    check_title="Sin Backup Automatico",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Instancia RDS '{name}' no tiene backup automatico "
                        f"configurado. Riesgo de perdida de datos."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Configurar backup automatico con retencion minima de 7 dias.",
                )
            elif backup_strategy.keep_days < 7:
                self._add_finding(
                    check_id="RDS-03",
                    check_title="Retencion de Backup Insuficiente",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Instancia RDS '{name}' tiene retencion de backup de "
                        f"{backup_strategy.keep_days} dias (recomendado: >= 7)."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Aumentar la retencion de backups a minimo 7 dias.",
                )
            else:
                self._add_finding(
                    check_id="RDS-03",
                    check_title="Backup Automatico Configurado",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=(
                        f"Instancia RDS '{name}' tiene backup automatico "
                        f"con {backup_strategy.keep_days} dias de retencion."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                )

    def _check_ssl_enabled(self) -> None:
        """RDS-04: Check for instances without SSL enabled."""
        instances = self._get_all_instances()

        for instance in instances:
            name = instance.name
            inst_id = instance.id
            # Check SSL enable status
            enable_ssl = getattr(instance, 'enable_ssl', None)

            if enable_ssl is False:
                self._add_finding(
                    check_id="RDS-04",
                    check_title="SSL No Habilitado en RDS",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Instancia RDS '{name}' no tiene SSL habilitado. "
                        f"Las conexiones no estan cifradas en transito."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Habilitar SSL en la instancia para cifrar conexiones.",
                )
            elif enable_ssl is True:
                self._add_finding(
                    check_id="RDS-04",
                    check_title="SSL Habilitado",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=f"Instancia RDS '{name}' tiene SSL habilitado.",
                    resource_id=inst_id,
                    resource_name=name,
                )
