#!/usr/bin/env python3
"""Test Scenario Generator

Quick test to verify all scenarios can be generated without errors.
"""

import sys
from pathlib import Path

# Add scenarios to path
scenarios_path = Path(__file__).parent.parent / "examples" / "scenarios"
sys.path.insert(0, str(scenarios_path))

def test_scenario_generation():
    """Test all scenario generators."""
    scenarios = {
        'Critical IAM': ('critical_iam_scenario', 'generate_critical_iam_scenario'),
        'Data Exfiltration': ('data_exfiltration_incident', 'generate_data_exfiltration_scenario'), 
        'Compliance Violation': ('compliance_violation', 'generate_compliance_violation_scenario'),
        'Multi-Cloud Review': ('multi_cloud_review', 'generate_multi_cloud_review_scenario'),
        'Attack Path Analysis': ('attack_path_scenario', 'generate_attack_path_scenario')
    }
    
    results = {}
    
    for name, (module_name, func_name) in scenarios.items():
        try:
            module = __import__(module_name)
            generator_func = getattr(module, func_name)
            
            print(f"Testing {name}...")
            scenario_data = generator_func()
            
            # Basic validation
            assert 'scenario_name' in scenario_data
            assert 'organization' in scenario_data
            assert 'findings' in scenario_data
            assert len(scenario_data['findings']) > 0
            
            results[name] = {
                'status': 'PASS',
                'findings': len(scenario_data['findings']),
                'accounts': len(scenario_data.get('accounts', [])),
                'principals': len(scenario_data.get('principals', []))
            }
            print(f"  ✅ {name}: {results[name]['findings']} findings generated")
            
        except Exception as e:
            results[name] = {
                'status': 'FAIL', 
                'error': str(e)
            }
            print(f"  ❌ {name}: {e}")
    
    # Summary
    print("\n" + "="*50)
    print("Test Results Summary:")
    passed = sum(1 for r in results.values() if r['status'] == 'PASS')
    total = len(results)
    
    for name, result in results.items():
        status_icon = "✅" if result['status'] == 'PASS' else "❌"
        print(f"  {status_icon} {name}: {result['status']}")
        if result['status'] == 'PASS':
            print(f"    - {result['findings']} findings, {result['accounts']} accounts, {result['principals']} principals")
    
    print(f"\nOverall: {passed}/{total} scenarios passed")
    
    if passed == total:
        print("🎉 All scenarios generated successfully!")
        return True
    else:
        print("⚠️  Some scenarios failed. Check errors above.")
        return False

if __name__ == "__main__":
    success = test_scenario_generation()
    sys.exit(0 if success else 1)
