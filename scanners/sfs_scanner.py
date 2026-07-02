"""
Huawei Cloud Security Scanner - SFS (Scalable File Service) Scanner

Checks for SFS security best practices:
- SFS-01: File systems without encryption
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdksfsturbo.v1 import (
        SFSTurboClient,
        ListSharesRequest,
    )
    try:
        from huaweicloudsdksfsturbo.v1.region.sfs_turbo_region import SFSTurboRegion
    except (ImportError, Exception):
        SFSTurboRegion = None
    SFS_AVAILABLE = True
except (ImportError, Exception):
    SFS_AVAILABLE = False


class SFSScanner(BaseScanner):
    """Scanner for SFS security checks."""

    service_name = "sfs"
    service_category = ServiceCategory.STORAGE

    def _init_client(self) -> None:
        if not SFS_AVAILABLE:
            return
        self.client = self._build_client(SFSTurboClient, SFSTurboRegion, None)

    def _get_checks(self) -> list:
        if not SFS_AVAILABLE:
            self._add_finding(
                check_id="SFS-00", check_title="SFS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdksfsturbo",
            )
            return []
        return [self._check_encryption]

    def _check_encryption(self) -> None:
        """SFS-01: Check for file systems without encryption."""
        request = ListSharesRequest()
        response = self.client.list_shares(request)
        shares = response.shares or []

        for share in shares:
            name = share.name or "unnamed"
            share_id = share.id
            metadata = getattr(share, 'metadata', {}) or {}
            is_encrypted = metadata.get('crypt_key_id', '')

            if not is_encrypted:
                self._add_finding(
                    check_id="SFS-01",
                    check_title="SFS Sin Cifrado",
                    severity=Severity.MEDIUM, status=Status.FAIL,
                    description=f"File system '{name}' no tiene cifrado habilitado.",
                    resource_id=share_id, resource_name=name,
                    remediation="Crear file systems con cifrado KMS habilitado.",
                )
            else:
                self._add_finding(
                    check_id="SFS-01",
                    check_title="SFS Cifrado",
                    severity=Severity.MEDIUM, status=Status.PASS,
                    description=f"File system '{name}' tiene cifrado habilitado.",
                    resource_id=share_id, resource_name=name,
                )
