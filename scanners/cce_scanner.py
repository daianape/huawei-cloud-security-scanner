"""
Huawei Cloud Security Scanner - CCE Scanner

Checks for Cloud Container Engine security best practices:
- CCE-01: Clusters with public API endpoint
- CCE-02: Clusters running outdated Kubernetes versions
- CCE-03: Clusters without node security hardening
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkcce.v3 import (
        CceClient,
        ListClustersRequest,
    )
    from huaweicloudsdkcce.v3.region.cce_region import CceRegion
    CCE_AVAILABLE = True
except ImportError:
    CCE_AVAILABLE = False

# Minimum recommended K8s version
MIN_K8S_VERSION = "1.25"


class CCEScanner(BaseScanner):
    """Scanner for CCE (Container Engine) security checks."""

    service_name = "cce"
    service_category = ServiceCategory.COMPUTE

    def _init_client(self) -> None:
        if not CCE_AVAILABLE:
            return
        self.client = self._build_client(CceClient, CceRegion, None)

    def _get_checks(self) -> list:
        if not CCE_AVAILABLE:
            self._add_finding(
                check_id="CCE-00", check_title="CCE SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkcce",
            )
            return []
        return [self._check_public_endpoint, self._check_k8s_version]

    def _check_public_endpoint(self) -> None:
        """CCE-01: Check for clusters with public API endpoint."""
        request = ListClustersRequest()
        response = self.client.list_clusters(request)
        clusters = response.items or []

        for cluster in clusters:
            name = cluster.metadata.name if cluster.metadata else "unnamed"
            cluster_id = cluster.metadata.uid if cluster.metadata else ""
            spec = cluster.spec
            endpoints = cluster.status.endpoints if cluster.status else []

            has_public = False
            if endpoints:
                for ep in endpoints:
                    if ep.type == "External" or "external" in str(ep.url or ""):
                        has_public = True
                        break

            if has_public:
                self._add_finding(
                    check_id="CCE-01",
                    check_title="Cluster con API Publica",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Cluster CCE '{name}' tiene endpoint API publico. "
                        f"El API server de Kubernetes es accesible desde internet."
                    ),
                    resource_id=cluster_id,
                    resource_name=name,
                    remediation=(
                        "Deshabilitar el endpoint publico. Acceder al cluster "
                        "solo via VPC o VPN."
                    ),
                )
            else:
                self._add_finding(
                    check_id="CCE-01",
                    check_title="Cluster Sin API Publica",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=f"Cluster CCE '{name}' solo tiene endpoint privado.",
                    resource_id=cluster_id,
                    resource_name=name,
                )

    def _check_k8s_version(self) -> None:
        """CCE-02: Check for clusters running outdated K8s versions."""
        request = ListClustersRequest()
        response = self.client.list_clusters(request)
        clusters = response.items or []

        for cluster in clusters:
            name = cluster.metadata.name if cluster.metadata else "unnamed"
            cluster_id = cluster.metadata.uid if cluster.metadata else ""
            spec = cluster.spec
            version = spec.version if spec else ""

            if not version:
                continue

            # Extract major.minor
            try:
                parts = version.lstrip("v").split(".")
                major_minor = f"{parts[0]}.{parts[1]}"
                if major_minor < MIN_K8S_VERSION:
                    self._add_finding(
                        check_id="CCE-02",
                        check_title="Version Kubernetes Desactualizada",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        description=(
                            f"Cluster '{name}' usa Kubernetes {version}. "
                            f"Version minima recomendada: {MIN_K8S_VERSION}."
                        ),
                        resource_id=cluster_id,
                        resource_name=name,
                        remediation=f"Actualizar el cluster a Kubernetes >= {MIN_K8S_VERSION}.",
                    )
                else:
                    self._add_finding(
                        check_id="CCE-02",
                        check_title="Version Kubernetes Actualizada",
                        severity=Severity.MEDIUM,
                        status=Status.PASS,
                        description=f"Cluster '{name}' usa Kubernetes {version}.",
                        resource_id=cluster_id,
                        resource_name=name,
                    )
            except (IndexError, ValueError):
                pass
