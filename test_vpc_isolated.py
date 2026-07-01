"""
Minimal test to isolate what breaks VPC in the scanner.
Run: python test_vpc_isolated.py
"""

# Step 1: Import everything the scanner imports
print("Step 1: Importing core modules...")
from core.config_loader import load_config
from core.auth import HuaweiCloudAuth, ScanTarget
from core.models import ScanResult, ScanSummary, Severity, Status
from scanners import AVAILABLE_SCANNERS
print("  OK - all scanner modules imported")

# Step 2: Now try VPC directly (same as test_connection.py)
print("\nStep 2: Testing VPC directly after imports...")
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkvpc.v2 import VpcClient, ListVpcsRequest
from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion

# Load credentials from config
cfg = load_config()
ak = cfg["credentials"]["access_key"]
sk = cfg["credentials"]["secret_key"]
project_id = cfg["project_id"]
region = cfg["region"]

print(f"  AK: {ak[:8]}... SK: {sk[:4]}...{sk[-4:]}")
print(f"  Project: {project_id}")
print(f"  Region: {region}")

creds = BasicCredentials(ak, sk, project_id)
config = HttpConfig.get_default_config()
config.ignore_ssl_verification = True

client = (
    VpcClient.new_builder()
    .with_credentials(creds)
    .with_http_config(config)
    .with_region(VpcRegion.value_of(region))
    .build()
)

print("\n  Calling ListVpcs...")
try:
    resp = client.list_vpcs(ListVpcsRequest())
    print(f"  SUCCESS! Found {len(resp.vpcs)} VPCs")
except Exception as e:
    print(f"  ERROR: {e}")

# Step 3: Now try via the scanner class
print("\nStep 3: Testing via VPCScanner class...")
from scanners.vpc_scanner import VPCScanner
from core.auth import AccountCredentials

account_creds = AccountCredentials(
    access_key=ak,
    secret_key=sk,
    project_id=project_id,
    region=region,
    account_name="test",
)

target = ScanTarget(
    account_name="test",
    credentials=account_creds,
    region=region,
    project_id=project_id,
    verify_ssl=False,
)

scanner = VPCScanner(target)
print("  Running scanner...")
findings = scanner.run()
print(f"  Scanner returned {len(findings)} findings")
failed = sum(1 for f in findings if f.status == Status.FAIL)
print(f"  Failed: {failed}")
