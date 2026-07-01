"""
Test script to debug Huawei Cloud SDK connection.
Run: python test_connection.py
"""
import logging
logging.basicConfig(level=logging.DEBUG)

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkvpc.v2 import VpcClient, ListVpcsRequest
from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion

# === EDIT THESE WITH YOUR CREDENTIALS ===
AK = "TU_ACCESS_KEY_AQUI"
SK = "TU_SECRET_KEY_AQUI"
PROJECT_ID = "f521b5fa85c44e718d99e998d4ce7ea6"
REGION = "la-south-2"
# =========================================

print(f"AK: {AK[:8]}...")
print(f"SK: {SK[:4]}...{SK[-4:]}")
print(f"Project ID: {PROJECT_ID}")
print(f"Region: {REGION}")
print(f"AK length: {len(AK)}")
print(f"SK length: {len(SK)}")
print()

creds = BasicCredentials(AK, SK, PROJECT_ID)

config = HttpConfig.get_default_config()
config.ignore_ssl_verification = True

print("Building client with .with_region()...")
client = VpcClient.new_builder() \
    .with_credentials(creds) \
    .with_http_config(config) \
    .with_region(VpcRegion.value_of(REGION)) \
    .build()

print("Sending ListVpcs request...")
try:
    resp = client.list_vpcs(ListVpcsRequest())
    print(f"\nSUCCESS! Found {len(resp.vpcs)} VPCs")
except Exception as e:
    print(f"\nERROR: {e}")
    print()
    print("Trying with explicit endpoint instead...")
    
    client2 = VpcClient.new_builder() \
        .with_credentials(creds) \
        .with_http_config(config) \
        .with_endpoint(f"https://vpc.{REGION}.myhuaweicloud.com") \
        .build()
    
    try:
        resp2 = client2.list_vpcs(ListVpcsRequest())
        print(f"SUCCESS with explicit endpoint! Found {len(resp2.vpcs)} VPCs")
    except Exception as e2:
        print(f"ERROR with explicit endpoint too: {e2}")
