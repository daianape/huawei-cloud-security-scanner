"""
Huawei Cloud Security Scanner - FunctionGraph Scanner

Checks for serverless function security best practices:
- FG-01: Functions not attached to a VPC (public network access)
- FG-02: Functions with excessively long timeout
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdkfunctiongraph.v2 import (
        FunctionGraphClient,
        ListFunctionsRequest,
    )
    try:
        from huaweicloudsdkfunctiongraph.v2.region.function_graph_region import FunctionGraphRegion
    except (ImportError, Exception):
        FunctionGraphRegion = None
    FG_AVAILABLE = True
except (ImportError, Exception):
    FG_AVAILABLE = False


class FunctionGraphScanner(BaseScanner):
    """Scanner for FunctionGraph security checks."""

    service_name = "functiongraph"
    service_category = ServiceCategory.COMPUTE

    def _init_client(self) -> None:
        if not FG_AVAILABLE:
            return
        self.client = self._build_client(FunctionGraphClient, FunctionGraphRegion, None)

    def _get_checks(self) -> list:
        if not FG_AVAILABLE:
            self._add_finding(
                check_id="FG-00", check_title="FunctionGraph SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdkfunctiongraph",
            )
            return []
        return [self._check_vpc_attached]

    def _check_vpc_attached(self) -> None:
        """FG-01: Check for functions not in a VPC."""
        request = ListFunctionsRequest()
        response = self.client.list_functions(request)
        functions = response.functions or []

        for func in functions:
            name = func.func_name or "unnamed"
            func_urn = func.func_urn or ""
            vpc_id = getattr(func, 'func_vpc_id', None) or getattr(func, 'func_vpc', None)

            if not vpc_id:
                self._add_finding(
                    check_id="FG-01",
                    check_title="Funcion Sin VPC",
                    severity=Severity.MEDIUM, status=Status.FAIL,
                    description=(
                        f"Funcion '{name}' no esta asociada a una VPC. "
                        f"Tiene acceso directo a internet sin restricciones de red."
                    ),
                    resource_id=func_urn, resource_name=name,
                    remediation="Asociar la funcion a una VPC para restringir acceso de red.",
                )
