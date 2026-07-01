"""
Huawei Cloud Security Scanner - Scanners Package
"""
from scanners.iam_scanner import IAMScanner
from scanners.vpc_scanner import VPCScanner
from scanners.ecs_scanner import ECSScanner
from scanners.obs_scanner import OBSScanner
from scanners.cts_scanner import CTSScanner
from scanners.elb_scanner import ELBScanner
from scanners.identity_center_scanner import IdentityCenterScanner
from scanners.rds_scanner import RDSScanner
from scanners.dcs_scanner import DCSScanner
from scanners.nat_scanner import NATScanner
from scanners.eip_scanner import EIPScanner
from scanners.waf_scanner import WAFScanner
from scanners.cfw_scanner import CFWScanner
from scanners.evs_scanner import EVSScanner
from scanners.kms_scanner import KMSScanner
from scanners.cce_scanner import CCEScanner

AVAILABLE_SCANNERS = {
    "vpc": VPCScanner,
    "ecs": ECSScanner,
    "cts": CTSScanner,
    "elb": ELBScanner,
    "obs": OBSScanner,
    "iam": IAMScanner,
    "identity-center": IdentityCenterScanner,
    "rds": RDSScanner,
    "dcs": DCSScanner,
    "nat": NATScanner,
    "eip": EIPScanner,
    "waf": WAFScanner,
    "cfw": CFWScanner,
    "evs": EVSScanner,
    "kms": KMSScanner,
    "cce": CCEScanner,
}

__all__ = [
    "IAMScanner",
    "VPCScanner",
    "ECSScanner",
    "OBSScanner",
    "CTSScanner",
    "ELBScanner",
    "IdentityCenterScanner",
    "RDSScanner",
    "DCSScanner",
    "NATScanner",
    "EIPScanner",
    "WAFScanner",
    "CFWScanner",
    "EVSScanner",
    "KMSScanner",
    "CCEScanner",
    "AVAILABLE_SCANNERS",
]
