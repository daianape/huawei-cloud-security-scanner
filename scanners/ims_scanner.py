"""
Huawei Cloud Security Scanner - IMS (Image Management Service) Scanner

Checks for Image Management security best practices:
- IMS-01: Images shared publicly
- IMS-02: Old/unused private images (potential security debt)
"""

import logging
from datetime import datetime, timezone, timedelta

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkims.v2 import (
        ImsClient,
        ListImagesRequest,
    )
    from huaweicloudsdkims.v2.region.ims_region import ImsRegion
    IMS_AVAILABLE = True
except ImportError:
    IMS_AVAILABLE = False


class IMSScanner(BaseScanner):
    """Scanner for Image Management security checks."""

    service_name = "ims"
    service_category = ServiceCategory.COMPUTE

    def _init_client(self) -> None:
        if not IMS_AVAILABLE:
            return
        self.client = self._build_client(ImsClient, ImsRegion, None)

    def _get_checks(self) -> list:
        if not IMS_AVAILABLE:
            self._add_finding(
                check_id="IMS-00", check_title="IMS SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkims",
            )
            return []
        return [self._check_public_images, self._check_old_images]

    def _check_public_images(self) -> None:
        """IMS-01: Check for images shared publicly."""
        request = ListImagesRequest()
        request.visibility = "public"
        request.owner = "self"

        try:
            response = self.client.list_images(request)
            images = response.images or []

            for img in images:
                name = img.name or "unnamed"
                img_id = img.id
                self._add_finding(
                    check_id="IMS-01",
                    check_title="Imagen Compartida Publicamente",
                    severity=Severity.HIGH, status=Status.FAIL,
                    description=(
                        f"Imagen '{name}' esta compartida publicamente. "
                        f"Cualquier cuenta puede usarla."
                    ),
                    resource_id=img_id, resource_name=name,
                    remediation="Cambiar la visibilidad a 'private' si no es necesario compartirla.",
                )
        except Exception:
            pass

    def _check_old_images(self) -> None:
        """IMS-02: Check for old private images (>365 days)."""
        request = ListImagesRequest()
        request.visibility = "private"

        try:
            response = self.client.list_images(request)
            images = response.images or []
            threshold = datetime.now(timezone.utc) - timedelta(days=365)

            for img in images:
                name = img.name or "unnamed"
                img_id = img.id
                created = img.created_at or ""

                if created:
                    try:
                        created_dt = datetime.fromisoformat(
                            created.replace("Z", "+00:00")
                        )
                        if created_dt < threshold:
                            days_old = (datetime.now(timezone.utc) - created_dt).days
                            self._add_finding(
                                check_id="IMS-02",
                                check_title="Imagen Antigua",
                                severity=Severity.LOW, status=Status.FAIL,
                                description=(
                                    f"Imagen '{name}' tiene {days_old} dias. "
                                    f"Puede tener vulnerabilidades no parcheadas."
                                ),
                                resource_id=img_id, resource_name=name,
                                remediation="Actualizar o eliminar imagenes antiguas.",
                            )
                    except (ValueError, TypeError):
                        pass
        except Exception:
            pass
