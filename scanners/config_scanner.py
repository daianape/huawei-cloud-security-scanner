"""
Huawei Cloud Security Scanner - Config/RMS Scanner

Checks for Resource Management Service (Config) best practices:
- CFG-01: Config service not enabled (no compliance monitoring)
- CFG-02: No compliance rules configured
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkrms.v1 import (
        RmsClient,
        ListPolicyAssignmentsRequest,
    )
    from huaweicloudsdkrms.v1.region.rms_region import RmsRegion
    RMS_AVAILABLE = True
except ImportError:
    RMS_AVAILABLE = False


class ConfigScanner(BaseScanner):
    """Scanner for Config/RMS compliance checks."""

    service_name = "config"
    service_category = ServiceCategory.LOGGING

    def _init_client(self) -> None:
        if not RMS_AVAILABLE:
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
            self.client = (
                RmsClient.new_builder()
                .with_credentials(creds)
                .with_http_config(config)
                .with_region(RmsRegion.value_of(self.region))
                .build()
            )
        except (KeyError, ValueError):
            endpoint = f"https://rms.{self.region}.myhuaweicloud.com"
            self.client = (
                RmsClient.new_builder()
                .with_credentials(creds)
                .with_http_config(config)
                .with_endpoint(endpoint)
                .build()
            )
        except Exception:
            self.client = None

    def _get_checks(self) -> list:
        if not RMS_AVAILABLE or not self.client:
            self._add_finding(
                check_id="CFG-01",
                check_title="Config Service No Habilitado",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "Config Service (RMS) no esta habilitado en esta cuenta. "
                    "No se esta monitoreando el cumplimiento de configuraciones "
                    "de los recursos cloud. No hay compliance automatizado."
                ),
                remediation="Habilitar Config Service y configurar reglas de compliance.",
            )
            return []
            )
            return []
        return [self._check_compliance_rules]

    def _check_compliance_rules(self) -> None:
        """CFG-02: Check if compliance rules are configured."""
        try:
            request = ListPolicyAssignmentsRequest()
            response = self.client.list_policy_assignments(request)
            rules = response.policy_assignments or []

            if not rules:
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Sin Reglas de Compliance",
                    severity=Severity.MEDIUM, status=Status.FAIL,
                    description=(
                        "No hay reglas de compliance configuradas en Config service. "
                        "No se esta monitoreando el cumplimiento de configuraciones."
                    ),
                    remediation="Configurar reglas de compliance en Config > Compliance.",
                )
            else:
                non_compliant = sum(
                    1 for r in rules
                    if hasattr(r, 'compliance_state') and r.compliance_state == "NonCompliant"
                )
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Reglas de Compliance Configuradas",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL if non_compliant > 0 else Status.PASS,
                    description=(
                        f"{len(rules)} reglas configuradas. "
                        f"{non_compliant} no cumplen compliance."
                    ),
                    remediation="Revisar reglas no compliant y remediar.",
                )
        except Exception as e:
            if "not authorized" in str(e).lower():
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Sin Permisos para Config",
                    severity=Severity.INFORMATIONAL, status=Status.ERROR,
                    description="Sin permisos para acceder a Config service.",
                )
            else:
                raise
