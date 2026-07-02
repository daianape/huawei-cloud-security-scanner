"""
Debug: find which API returns the non-compliant count for Config rules.
Run: python test_config2.py
"""
import os
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkrms.v1 import RmsClient, ListPolicyAssignmentsRequest
import huaweicloudsdkrms.v1 as rms

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

# List all methods that might give compliance data
print("=== Available compliance-related methods ===")
methods = [m for m in dir(client) if not m.startswith("_") and (
    "compliance" in m.lower() or "state" in m.lower() or "non_conform" in m.lower()
)]
for m in methods:
    print(f"  {m}")

# Get first rule to test with
req = ListPolicyAssignmentsRequest()
resp = client.list_policy_assignments(req)
rules = resp.value or []
print(f"\nTotal rules: {len(rules)}")

# Find "Multi-Factor Authentication Check" which has 32 non-conforming resources
mfa_rule = None
for r in rules:
    if "Multi-Factor" in (r.name or ""):
        mfa_rule = r
        break
    if "SSH" in (r.name or ""):
        mfa_rule = r  # backup - "Inbound Traffic Is Allowed on SSH Ports Only" has 27

if not mfa_rule:
    mfa_rule = rules[0]

print(f"\nTesting with rule: {mfa_rule.name} (id: {mfa_rule.id})")

# Test 1: list_policy_states_by_assignment_id with compliance_state filter
print("\n=== Test 1: list_policy_states_by_assignment_id ===")
try:
    from huaweicloudsdkrms.v1 import ListPolicyStatesByAssignmentIdRequest
    req2 = ListPolicyStatesByAssignmentIdRequest()
    req2.policy_assignment_id = mfa_rule.id
    # Try with compliance_state filter if available
    if hasattr(req2, 'compliance_state'):
        req2.compliance_state = "NonCompliant"
    resp2 = client.list_policy_states_by_assignment_id(req2)
    states = getattr(resp2, 'value', None) or []
    print(f"  Results with NonCompliant filter: {len(states)}")
    if states:
        first = states[0]
        print(f"  First state attrs: {[a for a in dir(first) if not a.startswith('_') and not callable(getattr(first, a, None))]}")
        for a in dir(first):
            if not a.startswith("_") and not callable(getattr(first, a, None)):
                print(f"    {a} = {getattr(first, a, None)}")
except Exception as e:
    print(f"  Error: {e}")

# Test 2: Try without filter
print("\n=== Test 2: list_policy_states_by_assignment_id (no filter) ===")
try:
    req3 = ListPolicyStatesByAssignmentIdRequest()
    req3.policy_assignment_id = mfa_rule.id
    resp3 = client.list_policy_states_by_assignment_id(req3)
    states = getattr(resp3, 'value', None) or []
    print(f"  Total states: {len(states)}")
    page = getattr(resp3, 'page_info', None)
    if page:
        print(f"  Page info: {page}")
except Exception as e:
    print(f"  Error: {e}")

# Test 3: show_policy_assignment (single rule detail)
print("\n=== Test 3: show_policy_assignment ===")
try:
    from huaweicloudsdkrms.v1 import ShowPolicyAssignmentRequest
    req4 = ShowPolicyAssignmentRequest()
    req4.policy_assignment_id = mfa_rule.id
    resp4 = client.show_policy_assignment(req4)
    for a in dir(resp4):
        if not a.startswith("_") and not callable(getattr(resp4, a, None)):
            val = getattr(resp4, a, None)
            if "complian" in a.lower() or "state" in a.lower() or "count" in a.lower():
                print(f"  {a} = {val}")
except Exception as e:
    print(f"  Error: {e}")
