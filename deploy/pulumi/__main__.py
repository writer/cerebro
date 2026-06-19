import pulumi

from components import CerebroService
from runtime import CerebroRuntimeConfig


def main() -> None:
    config = CerebroRuntimeConfig.from_pulumi()
    service = CerebroService(config.name, config)
    for key, value in service.outputs.items():
        pulumi.export(key, value)


main()
