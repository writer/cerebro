"""
Persistent storage primitives for Cerebro runtime state.
"""

import pulumi
import pulumi_aws as aws


def create_efs_volume(
    name: str,
    vpc_id: pulumi.Input[str],
    subnet_ids: list[pulumi.Input[str]],
    client_security_group_id: pulumi.Input[str],
    kms_key_arn: pulumi.Input[str],
    access_point_path: str,
    throughput_mode: str | None = None,
    provisioned_throughput_in_mibps: int | None = None,
) -> dict:
    """Create an encrypted EFS filesystem and access point for an ECS service."""
    security_group = aws.ec2.SecurityGroup(
        f"{name}-efs-sg",
        vpc_id=vpc_id,
        description=f"EFS access for {name}",
        ingress=[
            aws.ec2.SecurityGroupIngressArgs(
                protocol="tcp",
                from_port=2049,
                to_port=2049,
                security_groups=[client_security_group_id],
            )
        ],
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                protocol="-1",
                from_port=0,
                to_port=0,
                cidr_blocks=["0.0.0.0/0"],
            )
        ],
        tags={"Name": f"{name}-efs-sg"},
    )

    file_system_args = {
        "encrypted": True,
        "kms_key_id": kms_key_arn,
        "lifecycle_policies": [
            aws.efs.FileSystemLifecyclePolicyArgs(
                transition_to_ia="AFTER_30_DAYS",
            )
        ],
        "tags": {"Name": f"{name}-efs"},
    }
    if throughput_mode:
        file_system_args["throughput_mode"] = throughput_mode
    if provisioned_throughput_in_mibps is not None:
        file_system_args["provisioned_throughput_in_mibps"] = provisioned_throughput_in_mibps

    file_system = aws.efs.FileSystem(f"{name}-efs", **file_system_args)

    mount_targets = []
    for index, subnet_id in enumerate(subnet_ids):
        mount_targets.append(
            aws.efs.MountTarget(
                f"{name}-efs-mount-{index}",
                file_system_id=file_system.id,
                subnet_id=subnet_id,
                security_groups=[security_group.id],
            )
        )

    access_point = aws.efs.AccessPoint(
        f"{name}-efs-ap",
        file_system_id=file_system.id,
        posix_user=aws.efs.AccessPointPosixUserArgs(uid=10001, gid=10001),
        root_directory=aws.efs.AccessPointRootDirectoryArgs(
            path=access_point_path,
            creation_info=aws.efs.AccessPointRootDirectoryCreationInfoArgs(
                owner_uid=10001,
                owner_gid=10001,
                permissions="0750",
            ),
        ),
        tags={"Name": f"{name}-efs-ap"},
    )

    return {
        "file_system": file_system,
        "access_point": access_point,
        "security_group": security_group,
        "mount_targets": mount_targets,
    }
