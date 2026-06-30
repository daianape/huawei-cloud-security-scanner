"""
Huawei Cloud Security Scanner - Scanners Package
"""
from scanners.iam_scanner import IAMScanner
from scanners.vpc_scanner import VPCScanner
from scanners.ecs_scanner import ECSScanner
from scanners.obs_scanner import OBSScanner
from scanners.cts_scanner import CTSScanner
from scanners.elb_scanner import ELBScanner

AVAILABLE_SCANNERS = {
    "iam": IAMScanner,
    "vpc": VPCScanner,
    "ecs": ECSScanner,
    "obs": OBSScanner,
    "cts": CTSScanner,
    "elb": ELBScanner,
}

__all__ = [
    "IAMScanner",
    "VPCScanner",
    "ECSScanner",
    "OBSScanner",
    "CTSScanner",
    "ELBScanner",
    "AVAILABLE_SCANNERS",
]
