from __future__ import annotations

import pulumi

from runtime import CerebroRuntimeConfig


class CerebroService(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        config: CerebroRuntimeConfig,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("cerebro:cloud:CerebroService", name, None, opts)
        config.validate_guardrails()

        child_opts = pulumi.ResourceOptions(parent=self)
        if config.cloud == "aws":
            from aws_stack import AwsCerebroService

            backend = AwsCerebroService(name, config, opts=child_opts)
        elif config.cloud == "gcp":
            from gcp_stack import GcpCerebroService

            backend = GcpCerebroService(name, config, opts=child_opts)
        elif config.cloud == "azure":
            from azure_stack import AzureCerebroService

            backend = AzureCerebroService(name, config, opts=child_opts)
        else:
            raise ValueError("cerebro:cloud must be one of aws, gcp, or azure")

        self.outputs = backend.outputs
        self.register_outputs(dict(self.outputs))
