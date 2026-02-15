"""Quick diagnostic script to test CVSS Scope:Changed detection."""
from scoring.vulnerability_context import VulnerabilityContext
from scoring.cvss_calculator import cvss_calculator

# Test 1: Command Injection (should be Scope:Changed)
print("=" * 60)
print("TEST 1: Command Injection (should have Scope:Changed)")
print("=" * 60)

ctx1 = VulnerabilityContext(
    vulnerability_type="os_command_injection",
    detection_method="error_based",
    endpoint="/api/ping",
    parameter="host",
    http_method="GET",
    escapes_security_boundary=True,
    can_execute_os_commands=True,
    data_exposed=["system_level_access"],
    service_disruption_possible=True,
    requires_user_interaction=False,
    payload_succeeded=True
)

result1 = cvss_calculator.calculate(ctx1)
print(f"Score: {result1.score}")
print(f"Vector: {result1.vector}")
print(f"Scope: {result1.metrics['S']}")
print(f"Expected: S:C, Actual: S:{result1.metrics['S']}")
print(f"PASSED: {result1.metrics['S'] == 'C'}")

print("\n" + "=" * 60)
print("TEST 2: SQL Injection with xp_cmdshell (should have Scope:Changed)")
print("=" * 60)

ctx2 = VulnerabilityContext(
    vulnerability_type="sql_injection",
    detection_method="error_based",
    endpoint="/api/products",
    parameter="id",
    http_method="GET",
    escapes_security_boundary=True,
    can_execute_os_commands=True,
    data_exposed=["database", "filesystem"],
    requires_user_interaction=False,
    payload_succeeded=True
)

result2 = cvss_calculator.calculate(ctx2)
print(f"Score: {result2.score}")
print(f"Vector: {result2.vector}")
print(f"Scope: {result2.metrics['S']}")
print(f"Expected: S:C, Actual: S:{result2.metrics['S']}")
print(f"PASSED: {result2.metrics['S'] == 'C'}")

print("\n" + "=" * 60)
print("TEST 3: Regular SQL Injection (should have Scope:Unchanged)")
print("=" * 60)

ctx3 = VulnerabilityContext(
    vulnerability_type="sql_injection",
    detection_method="error_based",
    endpoint="/api/products",
    parameter="id",
    http_method="GET",
    escapes_security_boundary=False,
    can_execute_os_commands=False,
    data_exposed=["database"],
    requires_user_interaction=False,
    payload_succeeded=True
)

result3 = cvss_calculator.calculate(ctx3)
print(f"Score: {result3.score}")
print(f"Vector: {result3.vector}")
print(f"Scope: {result3.metrics['S']}")
print(f"Expected: S:U, Actual: S:{result3.metrics['S']}")
print(f"PASSED: {result3.metrics['S'] == 'U'}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Test 1 (Command Injection): {'✅ PASS' if result1.metrics['S'] == 'C' else '❌ FAIL'}")
print(f"Test 2 (SQLi + xp_cmdshell): {'✅ PASS' if result2.metrics['S'] == 'C' else '❌ FAIL'}")
print(f"Test 3 (Regular SQLi): {'✅ PASS' if result3.metrics['S'] == 'U' else '❌ FAIL'}")
