"""
Integration layer between compliance frameworks, control tests, and rule engine.

Maps existing CEL rules to compliance controls and creates executable control tests.
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta

from .frameworks import ComplianceControl, get_framework
from .control_tests import ControlTest, ControlTestRunner, ControlFrequency, TestStatus
from ..rules.library import RuleLibrary, RuleTemplate


class FrameworkIntegration:
    """Integrates compliance frameworks with the rule engine."""

    def __init__(self, test_runner: ControlTestRunner):
        self.test_runner = test_runner
        self.rule_library = RuleLibrary()
        self._control_test_cache: Dict[str, List[ControlTest]] = {}

    def create_control_tests_for_framework(
        self, framework_name: str
    ) -> List[ControlTest]:
        """Create control tests for all controls in a compliance framework."""
        if framework_name in self._control_test_cache:
            return self._control_test_cache[framework_name]

        framework = get_framework(framework_name)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_name}")

        control_tests = []
        rules = self.rule_library.get_all_rules()

        for control in framework.controls:
            # Find rules that map to this control
            mapped_rules = self._find_rules_for_control(control, rules, framework_name)

            if mapped_rules or control.sql_queries:
                test = self._create_control_test(control, framework_name, mapped_rules)
                control_tests.append(test)

        self._control_test_cache[framework_name] = control_tests
        return control_tests

    def create_control_test(
        self, framework_name: str, control_id: str
    ) -> Optional[ControlTest]:
        """Create a control test for a specific control."""
        framework = get_framework(framework_name)
        if not framework:
            return None

        control = framework.get_control(control_id)
        if not control:
            return None

        rules = self.rule_library.get_all_rules()
        mapped_rules = self._find_rules_for_control(control, rules, framework_name)

        return self._create_control_test(control, framework_name, mapped_rules)

    def get_framework_coverage(self, framework_name: str) -> Dict[str, any]:
        """Get coverage statistics for a compliance framework."""
        framework = get_framework(framework_name)
        if not framework:
            return {}

        control_tests = self.create_control_tests_for_framework(framework_name)
        rules = self.rule_library.get_all_rules()

        # Calculate coverage metrics
        total_controls = len(framework.controls)
        automated_controls = len(
            [c for c in framework.controls if c.automation_level == "automated"]
        )
        semi_automated = len(
            [c for c in framework.controls if c.automation_level == "semi-automated"]
        )
        manual_controls = len(
            [c for c in framework.controls if c.automation_level == "manual"]
        )

        # Count controls with tests
        controls_with_tests = len(control_tests)
        controls_with_rules = len([test for test in control_tests if test.rule_ids])
        controls_sql_only = len(
            [test for test in control_tests if test.sql_queries and not test.rule_ids]
        )

        # Find which rules are used
        used_rules = set()
        for test in control_tests:
            used_rules.update(test.rule_ids)

        total_rules = len(rules)
        framework_rules = len(
            [rule for rule in rules if framework_name in rule.framework_mappings]
        )

        return {
            "framework": framework_name,
            "total_controls": total_controls,
            "automated_controls": automated_controls,
            "semi_automated_controls": semi_automated,
            "manual_controls": manual_controls,
            "controls_with_tests": controls_with_tests,
            "controls_with_rules": controls_with_rules,
            "controls_sql_only": controls_sql_only,
            "coverage_percentage": (
                (controls_with_tests / total_controls) * 100
                if total_controls > 0
                else 0
            ),
            "automation_percentage": (
                (automated_controls / total_controls) * 100 if total_controls > 0 else 0
            ),
            "total_rules_available": total_rules,
            "framework_mapped_rules": framework_rules,
            "used_rules": len(used_rules),
            "rule_utilization": (
                (len(used_rules) / framework_rules) * 100 if framework_rules > 0 else 0
            ),
        }

    def get_control_gaps(self, framework_name: str) -> List[Dict[str, any]]:
        """Identify controls that lack automated testing."""
        framework = get_framework(framework_name)
        if not framework:
            return []

        control_tests = self.create_control_tests_for_framework(framework_name)
        tested_control_ids = {test.control_id for test in control_tests}

        gaps = []
        for control in framework.controls:
            if control.control_id not in tested_control_ids:
                gaps.append(
                    {
                        "control_id": control.control_id,
                        "title": control.title,
                        "category": control.category,
                        "automation_level": control.automation_level,
                        "frequency": control.frequency,
                        "reason": "No rules or SQL queries available",
                        "suggested_actions": self._suggest_gap_remediation(control),
                    }
                )
            elif control.automation_level == "manual":
                test = next(
                    t for t in control_tests if t.control_id == control.control_id
                )
                if not test.rule_ids:
                    gaps.append(
                        {
                            "control_id": control.control_id,
                            "title": control.title,
                            "category": control.category,
                            "automation_level": control.automation_level,
                            "frequency": control.frequency,
                            "reason": "Only SQL queries available, no CEL rules",
                            "suggested_actions": [
                                "Create CEL rule for automated evaluation"
                            ],
                        }
                    )

        return gaps

    def create_rule_to_control_mapping(self) -> Dict[str, Dict[str, List[str]]]:
        """Create a mapping of rules to compliance controls across all frameworks."""
        rules = self.rule_library.get_all_rules()
        mapping = {}

        for rule in rules:
            mapping[rule.name] = rule.framework_mappings

        return mapping

    def suggest_new_rules_for_framework(
        self, framework_name: str
    ) -> List[Dict[str, any]]:
        """Suggest new rules that could be created to improve framework coverage."""
        framework = get_framework(framework_name)
        if not framework:
            return []

        control_tests = self.create_control_tests_for_framework(framework_name)
        covered_controls = {test.control_id for test in control_tests}

        suggestions = []
        for control in framework.controls:
            if control.control_id not in covered_controls:
                suggestion = self._analyze_control_for_rule_creation(
                    control, framework_name
                )
                if suggestion:
                    suggestions.append(suggestion)

        return suggestions

    async def validate_control_test_effectiveness(
        self, framework_name: str, period_days: int = 30
    ) -> Dict[str, any]:
        """Analyze how effective control tests are at detecting issues."""
        control_tests = self.create_control_tests_for_framework(framework_name)

        if not control_tests:
            return {"error": "No control tests available"}

        period_end = datetime.now()
        period_start = period_end - timedelta(days=period_days)

        # Run all tests
        results = await self.test_runner.run_framework_tests(
            framework_name, control_tests, period_start, period_end
        )

        # Analyze effectiveness
        total_tests = len(results)
        passing_tests = len([r for r in results if r.status == TestStatus.PASS])
        failing_tests = len([r for r in results if r.status == TestStatus.FAIL])
        error_tests = len([r for r in results if r.status == TestStatus.ERROR])

        # Calculate metrics
        pass_rate = (passing_tests / total_tests) * 100 if total_tests > 0 else 0
        error_rate = (error_tests / total_tests) * 100 if total_tests > 0 else 0

        # Group by category for detailed analysis
        category_analysis = {}
        for result in results:
            framework = get_framework(framework_name)
            control = framework.get_control(result.control_id) if framework else None
            category = control.category if control else "Unknown"

            if category not in category_analysis:
                category_analysis[category] = {
                    "total": 0,
                    "passing": 0,
                    "failing": 0,
                    "errors": 0,
                }

            category_analysis[category]["total"] += 1
            if result.status == TestStatus.PASS:
                category_analysis[category]["passing"] += 1
            elif result.status == TestStatus.FAIL:
                category_analysis[category]["failing"] += 1
            else:
                category_analysis[category]["errors"] += 1

        return {
            "framework": framework_name,
            "period_days": period_days,
            "total_tests": total_tests,
            "passing_tests": passing_tests,
            "failing_tests": failing_tests,
            "error_tests": error_tests,
            "pass_rate": pass_rate,
            "error_rate": error_rate,
            "category_breakdown": {
                cat: {
                    **data,
                    "pass_rate": (
                        (data["passing"] / data["total"]) * 100
                        if data["total"] > 0
                        else 0
                    ),
                }
                for cat, data in category_analysis.items()
            },
            "recommendations": self._generate_effectiveness_recommendations(
                pass_rate, error_rate, category_analysis
            ),
        }

    def _find_rules_for_control(
        self, control: ComplianceControl, rules: List[RuleTemplate], framework_name: str
    ) -> List[str]:
        """Find rules that map to a specific control."""
        mapped_rules = []

        for rule in rules:
            framework_mappings = rule.framework_mappings.get(framework_name, [])
            if control.control_id in framework_mappings:
                mapped_rules.append(rule.name)

        return mapped_rules

    def _create_control_test(
        self, control: ComplianceControl, framework_name: str, rule_ids: List[str]
    ) -> ControlTest:
        """Create a control test from a compliance control."""
        # Map frequency string to enum
        frequency_mapping = {
            "continuous": ControlFrequency.CONTINUOUS,
            "daily": ControlFrequency.DAILY,
            "weekly": ControlFrequency.WEEKLY,
            "monthly": ControlFrequency.MONTHLY,
            "quarterly": ControlFrequency.QUARTERLY,
            "annually": ControlFrequency.ANNUALLY,
        }
        frequency = frequency_mapping.get(control.frequency, ControlFrequency.QUARTERLY)

        # Create test ID
        test_id = f"{framework_name}_{control.control_id}".replace(".", "_").replace(
            " ", "_"
        )

        return ControlTest(
            id=test_id,
            control_id=control.control_id,
            framework_name=framework_name,
            name=f"{control.control_id}: {control.title}",
            description=control.description,
            rule_ids=rule_ids,
            sql_queries=control.sql_queries,
            frequency=frequency,
            enabled=True,
            pass_threshold=1.0 if control.automation_level == "automated" else 0.8,
        )

    def _suggest_gap_remediation(self, control: ComplianceControl) -> List[str]:
        """Suggest ways to fill control testing gaps."""
        suggestions = []

        if control.control_type.value == "technical":
            suggestions.extend(
                [
                    "Create CEL rules to automatically evaluate technical controls",
                    "Add SQL queries to collect relevant configuration data",
                    "Implement API collectors for related systems",
                ]
            )
        elif control.control_type.value == "administrative":
            suggestions.extend(
                [
                    "Add policy document upload and tracking",
                    "Implement attestation workflows",
                    "Create manual evidence collection procedures",
                ]
            )

        if not control.sql_queries:
            suggestions.append("Add SQL queries to collect evidence")

        if control.automation_level == "manual":
            suggestions.extend(
                [
                    "Consider if control can be partially automated",
                    "Create structured evidence templates",
                ]
            )

        return suggestions

    def _analyze_control_for_rule_creation(
        self, control: ComplianceControl, framework_name: str
    ) -> Optional[Dict[str, any]]:
        """Analyze a control to suggest new rule creation."""
        if control.control_type.value != "technical":
            return None  # Focus on technical controls for rule automation

        # Analyze existing SQL queries for rule potential
        has_queries = bool(control.sql_queries)

        suggestion = {
            "control_id": control.control_id,
            "title": control.title,
            "category": control.category,
            "priority": "high" if control.automation_level == "automated" else "medium",
            "has_sql_queries": has_queries,
            "suggested_providers": self._suggest_providers_for_control(control),
            "rule_template": {
                "name": f"{framework_name.upper()}: {control.title}",
                "description": control.description,
                "severity": "medium",
                "framework_mappings": {framework_name: [control.control_id]},
            },
        }

        return suggestion

    def _suggest_providers_for_control(self, control: ComplianceControl) -> List[str]:
        """Suggest which providers might be relevant for a control."""
        providers = []

        # Keywords that suggest specific providers
        keywords = control.description.lower() + " " + control.title.lower()

        if any(word in keywords for word in ["aws", "s3", "ec2", "iam", "cloud"]):
            providers.append("aws")
        if any(word in keywords for word in ["github", "git", "repository", "code"]):
            providers.append("github")
        if any(
            word in keywords for word in ["okta", "authentication", "sso", "identity"]
        ):
            providers.append("okta")
        if any(word in keywords for word in ["google", "workspace", "gmail"]):
            providers.append("google_workspace")

        return providers if providers else ["aws", "github"]  # Default providers

    def _generate_effectiveness_recommendations(
        self,
        pass_rate: float,
        error_rate: float,
        category_analysis: Dict[str, Dict[str, int]],
    ) -> List[str]:
        """Generate recommendations based on test effectiveness analysis."""
        recommendations = []

        if pass_rate < 50:
            recommendations.append(
                "Overall pass rate is low - review control implementations and remediation processes"
            )
        elif pass_rate < 80:
            recommendations.append(
                "Consider strengthening security controls - pass rate could be improved"
            )

        if error_rate > 20:
            recommendations.append(
                "High error rate indicates test reliability issues - review test configurations"
            )

        # Category-specific recommendations
        for category, data in category_analysis.items():
            cat_pass_rate = (
                (data["passing"] / data["total"]) * 100 if data["total"] > 0 else 0
            )
            cat_error_rate = (
                (data["errors"] / data["total"]) * 100 if data["total"] > 0 else 0
            )

            if cat_pass_rate < 60:
                recommendations.append(
                    f"{category} controls need attention - low pass rate ({cat_pass_rate:.1f}%)"
                )

            if cat_error_rate > 25:
                recommendations.append(
                    f"{category} control tests have reliability issues - high error rate"
                )

        return recommendations
