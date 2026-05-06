"""ACM certificate resources."""

import pulumi
import pulumi_aws as aws


def create_certificate(
    name: str,
    domain: str,
    import_arn: str = "",
    tags: dict = None,
) -> dict:
    opts = pulumi.ResourceOptions(import_=import_arn) if import_arn else None
    certificate_tags = {
        "Name": f"{name}-cert",
        "Domain": domain,
        **(tags or {}),
    }
    certificate = aws.acm.Certificate(
        f"{name}-cert",
        domain_name=domain,
        validation_method="DNS",
        tags=certificate_tags,
        opts=opts,
    )

    validation_records = certificate.domain_validation_options.apply(
        lambda options: [
            {
                "record_name": option.resource_record_name,
                "record_type": option.resource_record_type,
                "record_value": option.resource_record_value,
            }
            for option in options
        ]
    )

    return {
        "certificate": certificate,
        "certificate_arn": certificate.arn,
        "validation_records": validation_records,
    }
