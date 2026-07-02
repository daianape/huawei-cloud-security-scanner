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
            endpoint = "https://rms.myhuaweicloud.com"
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
        return [self._check_compliance_rules]

    def _check_compliance_rules(self) -> None:
        """CFG-02: Check if compliance rules are configured and their status."""
        try:
            request = ListPolicyAssignmentsRequest()
            response = self.client.list_policy_assignments(request)

            # Get the list of policy assignments from response
            rules = None
            # Try different attribute names depending on SDK version
            for attr in ['policy_assignments', 'value', 'body']:
                val = getattr(response, attr, None)
                if val is not None:
                    rules = val
                    break

            # If response itself is iterable
            if rules is None:
                rules = []

            if isinstance(rules, list):
                total = len(rules)
            else:
                total = 0

            if total == 0:
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Sin Reglas de Compliance",
                    severity=Severity.HIGH, status=Status.FAIL,
                    description=(
                        "No hay reglas de compliance configuradas en Config service. "
                        "No se esta monitoreando el cumplimiento de configuraciones."
                    ),
                    remediation="Configurar reglas de compliance en Config > Compliance.",
                )
            else:
                # Count non-compliant rules
                non_compliant = 0
                for r in rules:
                    state = getattr(r, 'compliance_state', None) or getattr(r, 'state', None)
                    if state and str(state).lower() in ("noncompliant", "non_compliant"):
                        non_compliant += 1

                if non_compliant > 0:
                    self._add_finding(
                        check_id="CFG-02",
                        check_title="Reglas de Compliance No Conformes",
                        severity=Severity.HIGH, status=Status.FAIL,
                        description=(
                            f"{total} reglas configuradas, {non_compliant} no cumplen compliance. "
                            f"Tasa de conformidad: {round((total - non_compliant) / total * 100, 1)}%."
                        ),
                        remediation="Revisar reglas no conformes en Config > Conformidad de recursos.",
                    )
                else:
                    self._add_finding(
                        check_id="CFG-02",
                        check_title="Reglas de Compliance Conformes",
                        severity=Severity.MEDIUM, status=Status.PASS,
                        description=f"{total} reglas configuradas, todas conformes.",
                    )

        except Exception as e:
            error_msg = str(e).lower()
            if "not authorized" in error_msg or "403" in str(e):
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Sin Permisos para Config",
                    severity=Severity.INFORMATIONAL, status=Status.ERROR,
                    description="Sin permisos para acceder a Config service.",
                )
            else:
                raise
