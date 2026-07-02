"""
Debug: test aggregate compliance API
"""
import os
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkrms.v1 import RmsClient, ListPolicyAssignmentsRequest

ak = os.environ.get("HWCLOUD_AK")
sk = os.environ.get("HWCLOUD_SK")
domain_id = "2e057fc2297549029c9e0dc90ec47251"

creds = GlobalCredentials(ak, sk, domain_id)
config = HttpConfig.get_default_config()
config.ignore_ssl_verification = True

client = (
    RmsClient.new_builder()
    .with_credentials(creds)
    .with_http_config(config)
    .with_endpoint("https://rms.myhuaweicloud.com")
    .build()
)

# Try show_aggregate_compliance_by_policy_assignment
print("=== Testing aggregate compliance ===")
try:
    from huaweicloudsdkrms.v1 import ShowAggregatePolicyStateComplianceSummaryRequest
    req = ShowAggregatePolicyStateComplianceSummaryRequest()
    resp = client.show_aggregate_policy_state_compliance_summary(req)
    print(f"Response: {resp}")
    for attr in dir(resp):
        if not attr.startswith("_") and not callable(getattr(resp, attr, None)):
            print(f"  {attr} = {getattr(resp, attr, None)}")
except Exception as e:
    print(f"Error: {e}")

# Try list_policy_states_by_assignment_id for first rule
print("\n=== Testing policy states by assignment ===")
try:
    from huaweicloudsdkrms.v1 import ListPolicyStatesByAssignmentIdRequest
    # First get an assignment ID
    req1 = ListPolicyAssignmentsRequest()
    resp1 = client.list_policy_assignments(req1)
    rules = resp1.value or []
    if rules:
        first_id = rules[0].id
        print(f"First rule ID: {first_id}, Name: {rules[0].name}")

        req2 = ListPolicyStatesByAssignmentIdRequest()
        req2.policy_assignment_id = first_id
        resp2 = client.list_policy_states_by_assignment_id(req2)
        print(f"States response attrs: {[a for a in dir(resp2) if not a.startswith('_') and not callable(getattr(resp2, a, None))]}")
        for attr in dir(resp2):
            if not attr.startswith("_") and not callable(getattr(resp2, attr, None)):
                val = getattr(resp2, attr, None)
                if isinstance(val, list) and val:
                    print(f"  {attr}: list[{len(val)}], first={val[0]}")
                else:
                    print(f"  {attr} = {val}")
except Exception as e:
    print(f"Error: {e}")

# Try show_policy_state_compliance_summary_by_assignment
print("\n=== Testing compliance summary ===")
try:
    # Look for the right request class
    import huaweicloudsdkrms.v1 as rms_module
    summary_classes = [c for c in dir(rms_module) if 'compliance' in c.lower() and 'request' in c.lower()]
    print(f"Available compliance request classes: {summary_classes}")
except Exception as e:
    print(f"Error: {e}")
