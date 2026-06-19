from runtime import CerebroRuntimeConfig


def main() -> None:
    config = CerebroRuntimeConfig.from_pulumi()

    if config.cloud == "aws":
        from aws_stack import deploy
    elif config.cloud == "gcp":
        from gcp_stack import deploy
    elif config.cloud == "azure":
        from azure_stack import deploy
    else:
        raise ValueError("cerebro:cloud must be one of aws, gcp, or azure")

    deploy(config)


main()
