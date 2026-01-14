"""
Tailscale Subnet Router for VPC access.

Deploys an EC2 instance running Tailscale that advertises the VPC CIDR,
allowing tailnet members to access internal services like the ALB.
"""

import pulumi
import pulumi_aws as aws


def create_tailscale_subnet_router(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_id: pulumi.Output[str],
    advertise_routes: list[str],
    tailscale_auth_key: pulumi.Output[str],
    tailscale_hostname: str,
    tailscale_version: str = "1.76.6",
    instance_type: str = "t3.micro",
    tags: list[str] = None,
) -> dict:
    """
    Create a Tailscale subnet router instance.

    Args:
        name: Resource name prefix
        vpc_id: VPC ID
        subnet_id: Private subnet ID for the instance
        vpc_cidr: VPC CIDR to advertise (e.g., "10.0.0.0/16")
        tailscale_auth_key: Tailscale auth key (reusable, ephemeral)
        tailscale_hostname: Hostname for the Tailscale device
        tailscale_version: Tailscale version to install
        instance_type: EC2 instance type
        tags: Tailscale tags (e.g., ["tag:prod", "tag:exitnode"])
    """
    if tags is None:
        tags = ["tag:exitnode"]

    # Security group - egress only, no ingress needed
    security_group = aws.ec2.SecurityGroup(
        f"{name}-tailscale-sg",
        vpc_id=vpc_id,
        description="Tailscale subnet router - egress only",
        egress=[
            aws.ec2.SecurityGroupEgressArgs(
                from_port=0,
                to_port=0,
                protocol="-1",
                cidr_blocks=["0.0.0.0/0"],
                description="Allow all outbound",
            )
        ],
        tags={"Name": f"{name}-tailscale-sg"},
    )

    # IAM role for SSM access
    assume_role_policy = """{
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Effect": "Allow"
        }]
    }"""

    role = aws.iam.Role(
        f"{name}-tailscale-role",
        name=f"{name}-tailscale-role",
        assume_role_policy=assume_role_policy,
        tags={"Name": f"{name}-tailscale-role"},
    )

    aws.iam.RolePolicyAttachment(
        f"{name}-tailscale-ssm",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    )

    instance_profile = aws.iam.InstanceProfile(
        f"{name}-tailscale-profile",
        name=f"{name}-tailscale-profile",
        role=role.name,
    )

    # Get latest Amazon Linux 2023 AMI
    ami = aws.ec2.get_ami(
        most_recent=True,
        owners=["amazon"],
        filters=[
            aws.ec2.GetAmiFilterArgs(name="name", values=["al2023-ami-2023.*-x86_64"]),
            aws.ec2.GetAmiFilterArgs(name="virtualization-type", values=["hvm"]),
        ],
    )

    # Build routes string
    routes_str = ",".join(advertise_routes)

    # User data script
    user_data = tailscale_auth_key.apply(
        lambda auth_key: f"""#!/bin/bash
set -euo pipefail

LOG_FILE="/var/log/tailscale-userdata.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Tailscale Subnet Router Setup Started at $(date) ==="

# Update system
dnf update -y
dnf install -y jq

# Install Tailscale
rpm --import https://pkgs.tailscale.com/stable/amazon-linux/2023/repo.gpg
dnf config-manager --add-repo https://pkgs.tailscale.com/stable/amazon-linux/2023/tailscale.repo
dnf install -y --setopt=gpgcheck=1 tailscale-{tailscale_version}-1

# Configure tailscaled for memory state
cat > /etc/default/tailscaled << 'EOF'
FLAGS="--state=mem:"
EOF

mkdir -p /etc/systemd/system/tailscaled.service.d
cat > /etc/systemd/system/tailscaled.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/tailscaled --socket=/run/tailscale/tailscaled.sock --port=41641 $FLAGS
EOF

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' | tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' | tee -a /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# Start tailscaled
systemctl daemon-reload
systemctl enable tailscaled
systemctl start tailscaled
sleep 5

# Store config
mkdir -p /etc/tailscale
cat > /etc/tailscale/config << 'TSCONFIG'
TAILSCALE_AUTHKEY="{auth_key}"
TAILSCALE_HOSTNAME="{tailscale_hostname}"
TAILSCALE_ROUTES="{routes_str}"
TSCONFIG
chmod 600 /etc/tailscale/config

# Connect to Tailscale
echo "Connecting to Tailscale..."
tailscale up \\
  --authkey="{auth_key}" \\
  --hostname="{tailscale_hostname}" \\
  --advertise-routes="{routes_str}" \\
  --accept-risk=all

sleep 5

# Verify connection
BACKEND=$(tailscale status --json | jq -r '.BackendState' 2>/dev/null || echo "Unknown")
ONLINE=$(tailscale status --json | jq -r '.Self.Online' 2>/dev/null || echo "Unknown")

if [ "$BACKEND" = "Running" ] && [ "$ONLINE" = "true" ]; then
    echo "SUCCESS: Tailscale connected (Backend: $BACKEND, Online: $ONLINE)"
else
    echo "WARNING: Tailscale may not be fully connected (Backend: $BACKEND, Online: $ONLINE)"
fi

# Create monitor script
cat > /usr/local/bin/tailscale-monitor.sh << 'MONITOR'
#!/bin/bash
source /etc/tailscale/config
BACKEND=$(tailscale status --json | jq -r '.BackendState' 2>/dev/null || echo "Unknown")
ONLINE=$(tailscale status --json | jq -r '.Self.Online' 2>/dev/null || echo "Unknown")

if [ "$BACKEND" != "Running" ] || [ "$ONLINE" != "true" ]; then
    echo "Reconnecting Tailscale..."
    tailscale logout || true
    sleep 5
    systemctl restart tailscaled
    sleep 10
    tailscale up \\
      --authkey="$TAILSCALE_AUTHKEY" \\
      --hostname="$TAILSCALE_HOSTNAME" \\
      --advertise-routes="$TAILSCALE_ROUTES" \\
      --accept-risk=all
fi
MONITOR
chmod +x /usr/local/bin/tailscale-monitor.sh

# Create systemd timer for monitoring
cat > /etc/systemd/system/tailscale-monitor.service << 'EOF'
[Unit]
Description=Tailscale Connection Monitor
[Service]
Type=oneshot
ExecStart=/usr/local/bin/tailscale-monitor.sh
EOF

cat > /etc/systemd/system/tailscale-monitor.timer << 'EOF'
[Unit]
Description=Tailscale Monitor Timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable tailscale-monitor.timer
systemctl start tailscale-monitor.timer

echo "=== Tailscale Setup Completed at $(date) ==="
tailscale status
"""
    )

    # EC2 instance
    instance = aws.ec2.Instance(
        f"{name}-tailscale",
        ami=ami.id,
        instance_type=instance_type,
        subnet_id=subnet_id,
        vpc_security_group_ids=[security_group.id],
        iam_instance_profile=instance_profile.name,
        source_dest_check=False,  # Required for routing
        user_data=user_data,
        user_data_replace_on_change=True,
        root_block_device=aws.ec2.InstanceRootBlockDeviceArgs(
            volume_type="gp3",
            volume_size=20,
            encrypted=True,
        ),
        tags={"Name": f"{name}-tailscale"},
    )

    return {
        "instance": instance,
        "instance_id": instance.id,
        "private_ip": instance.private_ip,
        "security_group": security_group,
    }
