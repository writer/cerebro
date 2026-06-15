from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("cache", Path(__file__).resolve().parents[1] / "aws" / "cache.py")
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)


class _FakeOutput:
    def __init__(self, value):
        self.value = value

    def apply(self, callback):
        return callback(self.value)


class _FakeResource:
    def __init__(self, resource_name: str, **kwargs):
        self.id = f"{resource_name}-id"
        self.name = kwargs.get("name", resource_name)
        self.kwargs = kwargs


class _FakeServerlessCache(_FakeResource):
    def __init__(self, resource_name: str, **kwargs):
        super().__init__(resource_name, **kwargs)
        self.endpoints = _FakeOutput([{"address": "cache.example.internal", "port": 6379}])


class QueryCacheTest(unittest.TestCase):
    def test_cache_url_uses_tls_scheme(self) -> None:
        self.assertEqual(
            cache._cache_url([{"address": "cache.example.internal", "port": 6379}]),
            "rediss://cache.example.internal:6379",
        )

    def test_cache_engine_must_be_redis_compatible(self) -> None:
        with self.assertRaises(ValueError):
            cache.create_query_cache(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1"],
                app_security_group_id="sg-app",
                kms_key_arn="kms-key",
                secret_name="cerebro-sec-dev/CEREBRO_CACHE_URL",
                engine="memcached",
            )

    def test_create_query_cache_publishes_serverless_url_secret(self) -> None:
        captured_cache_kwargs = {}
        captured_secret_version_kwargs = {}

        def fake_serverless_cache(resource_name: str, **kwargs):
            captured_cache_kwargs.update(kwargs)
            return _FakeServerlessCache(resource_name, **kwargs)

        def fake_secret_version(resource_name: str, **kwargs):
            captured_secret_version_kwargs.update(kwargs)
            return _FakeResource(resource_name, **kwargs)

        with (
            patch.object(cache.aws.ec2, "SecurityGroup", _FakeResource),
            patch.object(cache.aws.ec2, "SecurityGroupIngressArgs", lambda **kwargs: kwargs),
            patch.object(cache.aws.ec2, "SecurityGroupEgressArgs", lambda **kwargs: kwargs),
            patch.object(cache.aws.elasticache, "ServerlessCache", fake_serverless_cache),
            patch.object(cache.aws.secretsmanager, "Secret", _FakeResource),
            patch.object(cache.aws.secretsmanager, "SecretVersion", fake_secret_version),
        ):
            stack = cache.create_query_cache(
                name="cerebro-sec-dev",
                vpc_id="vpc-1",
                subnet_ids=["subnet-1", "subnet-2"],
                app_security_group_id="sg-app",
                kms_key_arn="arn:aws:kms:us-east-1:123456789012:key/example",
                secret_name="cerebro-sec-dev/CEREBRO_CACHE_URL",
                engine="valkey",
                major_engine_version="8",
            )

        self.assertEqual(captured_cache_kwargs["engine"], "valkey")
        self.assertEqual(captured_cache_kwargs["major_engine_version"], "8")
        self.assertEqual(captured_cache_kwargs["subnet_ids"], ["subnet-1", "subnet-2"])
        self.assertEqual(captured_cache_kwargs["security_group_ids"], ["cerebro-sec-dev-cache-sg-id"])
        self.assertEqual(
            captured_secret_version_kwargs["secret_string"],
            "rediss://cache.example.internal:6379",
        )
        self.assertEqual(stack["url"], "rediss://cache.example.internal:6379")


if __name__ == "__main__":
    unittest.main()
