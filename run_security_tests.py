"""
Security Test Runner - Comprehensive Testing Suite
Implements Phase 1 testing requirements from the roadmap
"""
import asyncio
import sys
import json
import time
from pathlib import Path
from datetime import datetime

async def main():
    """Main test runner"""
    print("🔍" + "=" * 58 + "🔍")
    print("    INFINITE AI SECURITY - COMPREHENSIVE TEST SUITE")
    print("🔍" + "=" * 58 + "🔍")
    print()
    
    # Check if test suite exists
    test_suite_path = Path("testing/security_test_suite.py")
    if not test_suite_path.exists():
        print("❌ Security test suite not found!")
        print("   Expected: testing/security_test_suite.py")
        return
    
    try:
        # Import and run tests
        sys.path.append("testing")
        from security_test_suite import run_security_tests
        
        print("🚀 Starting comprehensive security tests...")
        print("⏳ This may take a few minutes...")
        print()
        
        # Run tests with different configurations
        test_configs = [
            {"url": "http://127.0.0.1:8000", "name": "Default Port"},
            {"url": "http://127.0.0.1:8001", "name": "Alternative Port"},
        ]
        
        all_results = []
        
        for config in test_configs:
            print(f"🎯 Testing {config['name']}: {config['url']}")
            try:
                result = await run_security_tests(config["url"])
                result["test_config"] = config
                all_results.append(result)
                
                # Brief summary
                summary = result["summary"]
                print(f"   ✅ {summary['passed_tests']}/{summary['total_tests']} tests passed")
                print(f"   📊 Success rate: {summary['success_rate']:.1f}%")
                
                if summary['failed_tests'] > 0:
                    print(f"   ⚠️  {summary['failed_tests']} tests failed")
                
            except Exception as e:
                print(f"   ❌ Testing failed: {e}")
                all_results.append({
                    "test_config": config,
                    "error": str(e),
                    "summary": {"total_tests": 0, "passed_tests": 0, "failed_tests": 0, "success_rate": 0}
                })
            
            print()
        
        # Generate comprehensive report
        generate_comprehensive_report(all_results)
        
    except ImportError as e:
        print(f"❌ Failed to import test suite: {e}")
        print("   Make sure all dependencies are installed:")
        print("   pip install aiohttp")
    except Exception as e:
        print(f"❌ Test execution failed: {e}")

def generate_comprehensive_report(results):
    """Generate comprehensive test report"""
    print("📊 COMPREHENSIVE TEST REPORT")
    print("=" * 60)
    
    total_tests = 0
    total_passed = 0
    total_failed = 0
    
    for result in results:
        if "error" not in result:
            summary = result["summary"]
            total_tests += summary["total_tests"]
            total_passed += summary["passed_tests"]
            total_failed += summary["failed_tests"]
    
    overall_success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Overall Results:")
    print(f"  Total Tests: {total_tests}")
    print(f"  Passed: {total_passed} ✅")
    print(f"  Failed: {total_failed} ❌")
    print(f"  Success Rate: {overall_success_rate:.1f}%")
    print()
    
    # Security assessment
    if overall_success_rate >= 95:
        security_level = "🟢 EXCELLENT"
    elif overall_success_rate >= 85:
        security_level = "🟡 GOOD"
    elif overall_success_rate >= 70:
        security_level = "🟠 ACCEPTABLE"
    else:
        security_level = "🔴 NEEDS IMPROVEMENT"
    
    print(f"Security Assessment: {security_level}")
    print()
    
    # Detailed breakdown
    print("Detailed Breakdown by Configuration:")
    for i, result in enumerate(results, 1):
        config = result["test_config"]
        print(f"\n{i}. {config['name']} ({config['url']})")
        
        if "error" in result:
            print(f"   ❌ Error: {result['error']}")
        else:
            summary = result["summary"]
            print(f"   Tests: {summary['passed_tests']}/{summary['total_tests']}")
            print(f"   Success Rate: {summary['success_rate']:.1f}%")
            
            # Show failed tests if any
            if "failed_tests" in result and result["failed_tests"]:
                print("   Failed Tests:")
                for test in result["failed_tests"][:5]:  # Show first 5
                    print(f"     - {test['name']} ({test['severity']})")
                if len(result["failed_tests"]) > 5:
                    print(f"     ... and {len(result['failed_tests']) - 5} more")
    
    # Save detailed report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"security_test_report_{timestamp}.json"
    
    try:
        with open(report_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "overall_summary": {
                    "total_tests": total_tests,
                    "passed_tests": total_passed,
                    "failed_tests": total_failed,
                    "success_rate": overall_success_rate,
                    "security_level": security_level
                },
                "detailed_results": results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved: {report_file}")
    except Exception as e:
        print(f"\n⚠️  Could not save report: {e}")
    
    # Recommendations
    print("\n💡 RECOMMENDATIONS:")
    
    if overall_success_rate < 85:
        print("  🔧 Review failed tests and implement fixes")
        print("  🛡️  Consider additional security hardening")
    
    if total_failed > 0:
        print("  📋 Prioritize fixing high and critical severity failures")
        print("  🔍 Run tests regularly to catch regressions")
    
    print("  📚 Review security best practices documentation")
    print("  🔄 Schedule regular security assessments")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Tests interrupted by user")
    except Exception as e:
        print(f"\n❌ Test runner failed: {e}")
        sys.exit(1)