"""
Huawei Cloud Security Scanner - KMS/DEW Scanner

Checks for Key Management Service security best practices:
- KMS-01: CMKs pending deletion
- KMS-02: CMKs without rotation enabled
- KMS-03: CMKs in disabled state
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkkms.v2 import (
        KmsClient,
        ListKeysRequest,
        ListKeyDetailRequest,
        ListKeysRequestBody,
    )
    from huaweicloudsdkkms.v2.region.kms_region import KmsRegion
    KMS_AVAILABLE = True
except ImportError:
    KMS_AVAILABLE = False


class KMSScanner(BaseScanner):
    """Scanner for KMS/DEW security checks."""

    service_name = "kms"
    service_category = ServiceCategory.IAM

    def _init_client(self) -> None:
        if not KMS_AVAILABLE:
            return
        self.client = self._build_client(KmsClient, KmsRegion, None)

    def _get_checks(self) -> list:
        if not KMS_AVAILABLE:
            self._add_finding(
                check_id="KMS-00", check_title="KMS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkkms",
            )
            return []
        return [self._check_key_status, self._check_key_rotation]

    def _get_all_keys(self) -> list:
        body = ListKeysRequestBody(limit="100")
        request = ListKeysRequest()
        request.body = body
        response = self.client.list_keys(request)
        return response.keys or []

    def _check_key_status(self) -> None:
        """KMS-01/03: Check for keys pending deletion or disabled."""
        keys = self._get_all_keys()
        for key_id in keys:
            detail_req = ListKeyDetailRequest()
            detail_req.body = {"key_id": key_id}
            try:
                detail_resp = self.client.list_key_detail(detail_req)
                key_info = detail_resp.key_info
                if not key_info:
                    continue

                key_alias = getattr(key_info, 'key_alias', key_id)
                key_state = getattr(key_info, 'key_state', '')

                if key_state == "4":  # Pending deletion
                    self._add_finding(
                        check_id="KMS-01",
                        check_title="CMK Pendiente de Eliminacion",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        description=f"CMK '{key_alias}' esta pendiente de eliminacion.",
                        resource_id=key_id,
                        resource_name=key_alias,
                        remediation="Cancelar la eliminacion si la key aun es necesaria.",
                    )
                elif key_state == "3":  # Disabled
                    self._add_finding(
                        check_id="KMS-03",
                        check_title="CMK Deshabilitada",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        description=f"CMK '{key_alias}' esta deshabilitada.",
                        resource_id=key_id,
                        resource_name=key_alias,
                        remediation="Habilitar o eliminar la CMK si no se necesita.",
                    )
            except Exception:
                continue

    def _check_key_rotation(self) -> None:
        """KMS-02: Check for keys without rotation enabled."""
        keys = self._get_all_keys()
        for key_id in keys:
            try:
                detail_req = ListKeyDetailRequest()
                detail_req.body = {"key_id": key_id}
                detail_resp = self.client.list_key_detail(detail_req)
                key_info = detail_resp.key_info
                if not key_info:
                    continue

                key_alias = getattr(key_info, 'key_alias', key_id)
                rotation = getattr(key_info, 'key_rotation_enabled', None)

                if rotation is False or rotation == "false":
                    self._add_finding(
                        check_id="KMS-02",
                        check_title="CMK Sin Rotacion",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        description=f"CMK '{key_alias}' no tiene rotacion automatica.",
                        resource_id=key_id,
                        resource_name=key_alias,
                        remediation="Habilitar rotacion automatica de la CMK.",
                    )
                elif rotation is True or rotation == "true":
                    self._add_finding(
                        check_id="KMS-02",
                        check_title="CMK Con Rotacion",
                        severity=Severity.MEDIUM,
                        status=Status.PASS,
                        description=f"CMK '{key_alias}' tiene rotacion automatica.",
                        resource_id=key_id,
                        resource_name=key_alias,
                    )
            except Exception:
                continue
