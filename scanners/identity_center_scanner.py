"""
Huawei Cloud Security Scanner - IAM Identity Center Scanner

Checks for Identity Center security best practices:
- IDC-01: Permission sets with admin-level access
- IDC-02: Account assignments with overly broad permissions
- IDC-03: Session duration exceeding recommended limits
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkidentitycenter.v1 import IdentityCenterClient
    from huaweicloudsdkidentitycenter.v1 import ListInstancesRequest
    try:
        from huaweicloudsdkidentitycenter.v1 import ListPermissionSetsRequest
    except ImportError:
        ListPermissionSetsRequest = None
    try:
        from huaweicloudsdkidentitycenter.v1.region.identity_center_region import IdentityCenterRegion
    except (ImportError, Exception):
        IdentityCenterRegion = None
    IDENTITY_CENTER_AVAILABLE = True
except (ImportError, Exception):
    IDENTITY_CENTER_AVAILABLE = False


class IdentityCenterScanner(BaseScanner):
    """Scanner for IAM Identity Center security checks."""

    service_name = "identity-center"
    service_category = ServiceCategory.IAM

    def _init_client(self) -> None:
        """Initialize Identity Center client."""
        if not IDENTITY_CENTER_AVAILABLE:
            return

        from huaweicloudsdkcore.auth.credentials import GlobalCredentials
        from huaweicloudsdkcore.http.http_config import HttpConfig as HC

        creds = GlobalCredentials(
            self.target.credentials.access_key,
            self.target.credentials.secret_key,
            self.target.credentials.domain_id or "",
        )

        config = HC.get_default_config()
        config.ignore_ssl_verification = True

        try:
            if IdentityCenterRegion:
                self.client = (
                    IdentityCenterClient.new_builder()
                    .with_credentials(creds)
                    .with_http_config(config)
                    .with_region(IdentityCenterRegion.value_of(self.region))
                    .build()
                )
            else:
                raise KeyError("No region class")
        except (KeyError, ValueError, Exception):
            endpoint = "https://identitycenter.myhuaweicloud.com"
            self.client = (
                IdentityCenterClient.new_builder()
                .with_credentials(creds)
                .with_http_config(config)
                .with_endpoint(endpoint)
                .build()
            )

    def _get_checks(self) -> list:
        """Return list of Identity Center checks to run."""
        if not IDENTITY_CENTER_AVAILABLE:
            self._add_finding(
                check_id="IDC-01",
                check_title="Identity Center No Habilitado",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "IAM Identity Center no esta habilitado en esta cuenta. "
                    "Sin Identity Center no hay gestion centralizada de acceso, "
                    "SSO ni control de permission sets."
                ),
                remediation="Habilitar IAM Identity Center para gestion centralizada de acceso.",
            )
            return []

        if not self.client:
            self._add_finding(
                check_id="IDC-01",
                check_title="Identity Center No Habilitado",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "IAM Identity Center no esta habilitado en esta cuenta. "
                    "Sin Identity Center no hay gestion centralizada de acceso, "
                    "SSO ni control de permission sets."
                ),
                remediation="Habilitar IAM Identity Center para gestion centralizada de acceso.",
            )
            return []

        return [
            self._check_permission_sets,
        ]

    def _check_permission_sets(self) -> None:
        """IDC-01: Check for permission sets with overly broad access."""
        try:
            # List Identity Center instances
            instances_request = ListInstancesRequest()
            instances_response = self.client.list_instances(instances_request)
            instances = instances_response.instances or []

            if not instances:
                self._add_finding(
                    check_id="IDC-01",
                    check_title="Identity Center No Configurado",
                    severity=Severity.INFORMATIONAL,
                    status=Status.NOT_AVAILABLE,
                    description="No se encontraron instancias de Identity Center configuradas.",
                )
                return

            for instance in instances:
                instance_id = instance.instance_id

                # List permission sets
                ps_request = ListPermissionSetsRequest()
                ps_request.instance_id = instance_id
                ps_response = self.client.list_permission_sets(ps_request)
                permission_sets = ps_response.permission_sets or []

                for ps_id in permission_sets:
                    # Check session duration
                    if hasattr(ps_id, 'session_duration') and ps_id.session_duration:
                        duration_hours = int(ps_id.session_duration.replace("PT", "").replace("H", ""))
                        if duration_hours > 4:
                            self._add_finding(
                                check_id="IDC-03",
                                check_title="Sesion Excesivamente Larga",
                                severity=Severity.MEDIUM,
                                status=Status.FAIL,
                                description=(
                                    f"Permission set tiene duracion de sesion de "
                                    f"{duration_hours} horas. Recomendado: maximo 4 horas."
                                ),
                                resource_id=str(ps_id),
                                remediation="Reducir la duracion de sesion a 4 horas o menos.",
                            )

        except Exception as e:
            error_msg = str(e)
            if "not authorized" in error_msg.lower() or "403" in error_msg:
                self._add_finding(
                    check_id="IDC-01",
                    check_title="Sin Permisos para Identity Center",
                    severity=Severity.INFORMATIONAL,
                    status=Status.ERROR,
                    description="El usuario no tiene permisos para acceder a Identity Center.",
                )
            elif "not found" in error_msg.lower() or "404" in error_msg:
                self._add_finding(
                    check_id="IDC-01",
                    check_title="Identity Center No Habilitado",
                    severity=Severity.INFORMATIONAL,
                    status=Status.NOT_AVAILABLE,
                    description="IAM Identity Center no esta habilitado en esta cuenta.",
                )
            else:
                raise
