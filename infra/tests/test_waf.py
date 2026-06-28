from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("waf", Path(__file__).resolve().parents[1] / "aws" / "waf.py")
waf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(waf)


def _to_data(value):
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, list | tuple):
        return [_to_data(item) for item in value]
    if hasattr(value, "__dict__"):
        return {key: _to_data(item) for key, item in vars(value).items()}
    return repr(value)


class WafOAuthLoopbackAllowRuleTest(unittest.TestCase):
    def test_loopback_oauth_allow_rules_precede_managed_rules(self) -> None:
        captured: dict[str, list] = {}

        def fake_web_acl(*_args, **kwargs):
            captured["rules"] = kwargs["rules"]
            return SimpleNamespace(arn="web-acl-arn")

        with (
            patch.object(waf.aws.wafv2, "WebAcl", side_effect=fake_web_acl),
            patch.object(waf.aws.wafv2, "WebAclAssociation", return_value=SimpleNamespace(arn="association-arn")),
        ):
            waf.create_waf("cerebro-test", alb_arn="alb-arn", enable_logging=False)

        rules = captured["rules"]
        self.assertEqual(
            [rule.name for rule in rules],
            [
                "rate-limit",
                "allow-mcp-oauth-loopback-authorize-ipv4",
                "allow-mcp-oauth-loopback-authorize-localhost",
                "allow-mcp-oauth-loopback-authorize-ipv6",
                "allow-mcp-oauth-loopback-token-ipv4",
                "allow-mcp-oauth-loopback-token-localhost",
                "allow-mcp-oauth-loopback-token-ipv6",
                "allow-mcp-oauth-loopback-register-ipv4",
                "allow-mcp-oauth-loopback-register-localhost",
                "allow-mcp-oauth-loopback-register-ipv6",
                "aws-common-rules",
                "aws-bad-inputs",
                "aws-sqli",
            ],
        )
        for rule in rules[1:10]:
            self.assertLess(rule.priority, rules[10].priority)

    def test_loopback_oauth_allow_rules_are_narrowly_scoped(self) -> None:
        rules = waf._mcp_oauth_loopback_allow_rules()
        encoded = json.dumps(_to_data(rules), sort_keys=True)
        self.assertNotIn("or_statement", encoded)

        for expected in (
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/register",
            "GET",
            "POST",
            "redirect_uri",
            "redirect_uris",
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "URL_DECODE",
            "LOWERCASE",
        ):
            self.assertIn(expected, encoded)


class WafManagedRuleOverridesTest(unittest.TestCase):
    def test_common_rule_body_size_restriction_counts_large_json_batches(self) -> None:
        captured: dict[str, list] = {}

        def fake_web_acl(*_args, **kwargs):
            captured["rules"] = kwargs["rules"]
            return SimpleNamespace(arn="web-acl-arn")

        with (
            patch.object(waf.aws.wafv2, "WebAcl", side_effect=fake_web_acl),
            patch.object(waf.aws.wafv2, "WebAclAssociation", return_value=SimpleNamespace(arn="association-arn")),
        ):
            waf.create_waf("cerebro-test", alb_arn="alb-arn", enable_logging=False)

        common_rule = next(rule for rule in captured["rules"] if rule.name == "aws-common-rules")
        encoded = json.dumps(_to_data(common_rule), sort_keys=True)

        self.assertIn("AWSManagedRulesCommonRuleSet", encoded)
        self.assertIn("SizeRestrictions_BODY", encoded)
        self.assertIn("count", encoded)
        self.assertNotIn("allow-source-runtime-writes", encoded)


if __name__ == "__main__":
    unittest.main()
