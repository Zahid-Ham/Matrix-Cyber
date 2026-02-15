"""
Batch Test Runner for Matrix Security Scanner Validation.
Consolidates all validation phases (10-13) into a single execution suite.
"""
import subprocess
import sys
import os
import time

def run_test_module(name, path):
    print(f"\n{'='*60}")
    print(f" RUNNING: {name}")
    print(f" Path: {path}")
    print(f"{'='*60}")
    
    start_time = time.time()
    try:
        # Run pytest as a subprocess to keep the main script clean
        result = subprocess.run(
            [sys.executable, "-m", "pytest", path, "-v", "--tb=short"],
            capture_output=True,
            text=True
        )
        duration = time.time() - start_time
        
        print(result.stdout)
        if result.returncode == 0:
            print(f"✅ {name} PASSED in {duration:.2f}s")
            return True, duration
        else:
            print(f"❌ {name} FAILED in {duration:.2f}s")
            print("ERROR OUTPUT:")
            print(result.stderr)
            return False, duration
    except Exception as e:
        print(f"💥 ERROR executing {name}: {str(e)}")
        return False, 0

def main():
    test_suite = [
        ("Phase 10: Integration Tests", "tests/integration/test_orchestrator.py"),
        ("Phase 11: Performance Tests", "tests/performance/test_load.py"),
        ("Phase 12: False Positive Validation", "tests/performance/test_false_positives.py"),
        ("Phase 13: Real-World Validation", "tests/integration/test_real_world.py"),
        ("Phase 15: GitHub Agent", "tests/unit/test_github_agent.py"),
        ("Phase 16: Production Ops", "tests/integration/test_production_ops.py"),
        ("Phase 17: Self-Security", "tests/security/test_scanner_security.py"),
        ("Phase 18: Compliance Mapping", "tests/unit/test_compliance_mapping.py")
    ]
    
    overall_start = time.time()
    results = []
    
    print("Matrix Scanner Validation Suite")
    print("============================== \n")
    
    for name, path in test_suite:
        success, duration = run_test_module(name, path)
        results.append((name, success, duration))
        
    overall_duration = time.time() - overall_start
    
    print(f"\n{'='*60}")
    print(" VALIDATION SUMMARY")
    print(f"{'='*60}")
    
    all_passed = True
    for name, success, duration in results:
        status = "PASSED" if success else "FAILED"
        print(f"{name:<40} | {status:<8} | {duration:>6.2f}s")
        if not success:
            all_passed = False
            
    print(f"{'='*60}")
    print(f"Total Duration: {overall_duration:.2f}s")
    print(f"Final Status: {'✅ SUCCESS' if all_passed else '❌ FAILURE'}")
    print(f"{'='*60}")
    
    if not all_passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
