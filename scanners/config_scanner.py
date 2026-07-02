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
        """CFG-02: Check compliance status of configured rules."""
        try:
            # First get the list of policy assignments
            request = ListPolicyAssignmentsRequest()
            response = self.client.list_policy_assignments(request)
            rules = getattr(response, 'value', None) or []
            total_rules = len(rules) if isinstance(rules, list) else 0

            if total_rules == 0:
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
                return

            # Get non-compliant count per rule
            import time
            non_compliant_rules = []
            total_nc_resources = 0

            try:
                from huaweicloudsdkrms.v1 import ListPolicyStatesByAssignmentIdRequest

                for rule in rules:
                    rule_id = rule.id
                    rule_name = rule.name or rule_id

                    try:
                        state_req = ListPolicyStatesByAssignmentIdRequest()
                        state_req.policy_assignment_id = rule_id
                        state_req.compliance_state = "NonCompliant"
                        state_resp = self.client.list_policy_states_by_assignment_id(state_req)
                        states = getattr(state_resp, 'value', None) or []
                        nc_count = len(states)

                        if nc_count > 0:
                            non_compliant_rules.append((rule_name, nc_count))
                            total_nc_resources += nc_count

                    except Exception:
                        continue

                    # Small delay to avoid rate limit
                    time.sleep(0.5)

            except ImportError:
                pass

            # Report findings
            if non_compliant_rules:
                # Sort by count descending
                non_compliant_rules.sort(key=lambda x: x[1], reverse=True)
                rule_details = "; ".join(
                    f"{name} ({count})" for name, count in non_compliant_rules[:5]
                )
                conformance_rate = round(
                    (total_rules - len(non_compliant_rules)) / total_rules * 100, 1
                )
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Reglas de Compliance No Conformes",
                    severity=Severity.HIGH, status=Status.FAIL,
                    description=(
                        f"{total_rules} reglas configuradas, "
                        f"{len(non_compliant_rules)} no conformes, "
                        f"{total_nc_resources} recursos en incumplimiento. "
                        f"Tasa de conformidad: {conformance_rate}%. "
                        f"Top reglas: {rule_details}"
                    ),
                    remediation="Revisar reglas no conformes en Config > Conformidad de recursos.",
                )
            else:
                self._add_finding(
                    check_id="CFG-02",
                    check_title="Reglas de Compliance Conformes",
                    severity=Severity.MEDIUM, status=Status.PASS,
                    description=f"{total_rules} reglas configuradas, todas conformes.",
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
