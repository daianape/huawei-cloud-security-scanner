"""
Huawei Cloud Security Scanner - TMS (Tag Management Service) Scanner

Checks for tag governance best practices:
- TMS-01: Resources without tags (governance gap)
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdktms.v1 import (
        TmsClient,
        ListPredefineTagsRequest,
    )
    from huaweicloudsdktms.v1.region.tms_region import TmsRegion
    TMS_AVAILABLE = True
except ImportError:
    TMS_AVAILABLE = False


class TMSScanner(BaseScanner):
    """Scanner for Tag Management checks."""

    service_name = "tms"
    service_category = ServiceCategory.IAM

    def _init_client(self) -> None:
        if not TMS_AVAILABLE:
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
                TmsClient.new_builder()
                .with_credentials(creds)
                .with_http_config(config)
                .with_region(TmsRegion.value_of(self.region))
                .build()
            )
        except (KeyError, ValueError):
            endpoint = f"https://tms.{self.region}.myhuaweicloud.com"
            self.client = (
                TmsClient.new_builder()
                .with_credentials(creds)
                .with_http_config(config)
                .with_endpoint(endpoint)
                .build()
            )
        except Exception:
            self.client = None

    def _get_checks(self) -> list:
        if not TMS_AVAILABLE or not self.client:
            self._add_finding(
                check_id="TMS-01",
                check_title="Tag Management Service No Habilitado",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "Tag Management Service (TMS) no esta habilitado en esta cuenta. "
                    "Sin politica de tagging, los recursos no se pueden clasificar "
                    "ni auditar por owner, proyecto o ambiente."
                ),
                remediation="Habilitar TMS y definir tags obligatorios (environment, owner, project).",
            )
            return []
        return [self._check_predefined_tags]

    def _check_predefined_tags(self) -> None:
        """TMS-01: Check if predefined tags exist for governance."""
        try:
            request = ListPredefineTagsRequest()
            response = self.client.list_predefine_tags(request)
            tags = response.tags or []

            if not tags:
                self._add_finding(
                    check_id="TMS-01",
                    check_title="Sin Tags Predefinidos",
                    severity=Severity.LOW, status=Status.FAIL,
                    description=(
                        "No hay tags predefinidos configurados. "
                        "Sin politica de tagging, los recursos no se pueden "
                        "clasificar ni auditar por owner/proyecto/ambiente."
                    ),
                    remediation=(
                        "Definir tags obligatorios (ej: environment, owner, project) "
                        "en Tag Management Service."
                    ),
                )
            else:
                self._add_finding(
                    check_id="TMS-01",
                    check_title="Tags Predefinidos Configurados",
                    severity=Severity.LOW, status=Status.PASS,
                    description=f"{len(tags)} tags predefinidos configurados.",
                )
        except Exception as e:
            if "not authorized" in str(e).lower():
                self._add_finding(
                    check_id="TMS-01",
                    check_title="Sin Permisos para TMS",
                    severity=Severity.INFORMATIONAL, status=Status.ERROR,
                    description="Sin permisos para acceder a Tag Management.",
                )
            else:
                raise
