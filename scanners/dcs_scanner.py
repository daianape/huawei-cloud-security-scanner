"""
Huawei Cloud Security Scanner - DCS (Redis) Scanner

Checks for Distributed Cache Service security best practices:
- DCS-01: Redis instances without password authentication
- DCS-02: Redis instances with public access
- DCS-03: Redis instances without SSL/TLS encryption
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkdcs.v2 import (
        DcsClient,
        ListInstancesRequest,
    )
    from huaweicloudsdkdcs.v2.region.dcs_region import DcsRegion
    DCS_AVAILABLE = True
except ImportError:
    DCS_AVAILABLE = False


class DCSScanner(BaseScanner):
    """Scanner for DCS (Redis) security checks."""

    service_name = "dcs"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        if not DCS_AVAILABLE:
            return
        self.client = self._build_client(DcsClient, DcsRegion, None)

    def _get_checks(self) -> list:
        if not DCS_AVAILABLE:
            self._add_finding(
                check_id="DCS-00",
                check_title="DCS SDK No Disponible",
                severity=Severity.INFORMATIONAL,
                status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkdcs",
            )
            return []
        return [
            self._check_no_password,
            self._check_public_access,
            self._check_ssl_enabled,
        ]

    def _get_all_instances(self) -> list:
        request = ListInstancesRequest()
        response = self.client.list_instances(request)
        return response.instances or []

    def _check_no_password(self) -> None:
        """DCS-01: Check for Redis instances without password."""
        instances = self._get_all_instances()
        for inst in instances:
            name = inst.name
            inst_id = inst.instance_id
            no_password = getattr(inst, 'no_password_access', None)

            if no_password == "true" or no_password is True:
                self._add_finding(
                    check_id="DCS-01",
                    check_title="Redis Sin Password",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    description=(
                        f"Instancia Redis '{name}' permite acceso sin password. "
                        f"Cualquier cliente en la VPC puede conectarse."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Habilitar autenticacion con password para la instancia.",
                )
            else:
                self._add_finding(
                    check_id="DCS-01",
                    check_title="Redis Con Password",
                    severity=Severity.CRITICAL,
                    status=Status.PASS,
                    description=f"Instancia Redis '{name}' requiere password.",
                    resource_id=inst_id,
                    resource_name=name,
                )

    def _check_public_access(self) -> None:
        """DCS-02: Check for Redis instances with public access."""
        instances = self._get_all_instances()
        for inst in instances:
            name = inst.name
            inst_id = inst.instance_id
            enable_publicip = getattr(inst, 'enable_publicip', False)

            if enable_publicip:
                self._add_finding(
                    check_id="DCS-02",
                    check_title="Redis con Acceso Publico",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    description=(
                        f"Instancia Redis '{name}' tiene acceso publico habilitado. "
                        f"Redis no debe exponerse a internet."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Deshabilitar el acceso publico. Acceder solo via VPC.",
                )
            else:
                self._add_finding(
                    check_id="DCS-02",
                    check_title="Redis Sin Acceso Publico",
                    severity=Severity.CRITICAL,
                    status=Status.PASS,
                    description=f"Instancia Redis '{name}' no tiene acceso publico.",
                    resource_id=inst_id,
                    resource_name=name,
                )

    def _check_ssl_enabled(self) -> None:
        """DCS-03: Check for Redis instances without SSL."""
        instances = self._get_all_instances()
        for inst in instances:
            name = inst.name
            inst_id = inst.instance_id
            enable_ssl = getattr(inst, 'enable_ssl', None)

            if enable_ssl is False:
                self._add_finding(
                    check_id="DCS-03",
                    check_title="Redis Sin SSL",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Instancia Redis '{name}' no tiene SSL habilitado. "
                        f"Datos en transito no estan cifrados."
                    ),
                    resource_id=inst_id,
                    resource_name=name,
                    remediation="Habilitar SSL/TLS para cifrar conexiones.",
                )
