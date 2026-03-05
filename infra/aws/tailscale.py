"""
Tailscale Subnet Router for VPC access.

Deploys an EC2 instance running Tailscale that advertises the VPC CIDR,
allowing tailnet members to access internal services like the ALB.

Auth key is fetched from Secrets Manager (Infisical-synced) at boot.
"""

import json

import pulumi
import pulumi_aws as aws


from typing import Union


def create_tailscale_subnet_router(
    name: str,
    vpc_id: pulumi.Output[str],
    subnet_id: pulumi.Output[str],
    advertise_routes: Union[list[str], pulumi.Output[list[str]]],
    tailscale_hostname: str,
    auth_key_secret_arn: pulumi.Output[str],
    tailscale_version: str = "1.76.6",
    instance_type: str = "t3.micro",
    tags: list[str] = None,
    kms_key_arn: pulumi.Output[str] = None,
) -> dict:
    """
    Create a Tailscale subnet router instance.

    Args:
        name: Resource name prefix
        vpc_id: VPC ID
        subnet_id: Private subnet ID for the instance
        advertise_routes: VPC CIDRs to advertise (e.g., ["10.0.10.0/24", "10.0.11.0/24"])
        tailscale_hostname: Hostname for the Tailscale device
        auth_key_secret_arn: Secrets Manager secret ARN containing the Tailscale auth key
        tailscale_version: Tailscale version to install
        instance_type: EC2 instance type
        tags: Tailscale tags (e.g., ["tag:prod", "tag:exitnode"])
        kms_key_arn: Optional KMS key ARN used by Secrets Manager for decryption
    """
    if tags is None:
        tags = ["tag:exitnode"]

    region = aws.get_region()

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

    # IAM role for Secrets Manager access and SSM Session Manager
    assume_role_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Effect": "Allow",
        }],
    })

    role = aws.iam.Role(
        f"{name}-tailscale-role",
        name=f"{name}-tailscale-role",
        assume_role_policy=assume_role_policy,
        tags={"Name": f"{name}-tailscale-role"},
    )

    # SSM Session Manager access (for debugging/management)
    aws.iam.RolePolicyAttachment(
        f"{name}-tailscale-ssm",
        role=role.name,
        policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    )

    # Secrets Manager access for auth key
    # Build policy with proper Output handling
    def build_secrets_policy(args):
        secret_arn = args[0]
        kms_arn = args[1] if len(args) > 1 else None
        
        statements = [
            {
                "Sid": "GetTailscaleAuthKey",
                "Effect": "Allow",
                "Action": ["secretsmanager:GetSecretValue"],
                "Resource": secret_arn,
            },
        ]
        if kms_arn:
            statements.append({
                "Sid": "DecryptSecret",
                "Effect": "Allow",
                "Action": ["kms:Decrypt"],
                "Resource": kms_arn,
            })
        return json.dumps({
            "Version": "2012-10-17",
            "Statement": statements,
        })

    # Build policy using Output.all to handle both ARNs
    if kms_key_arn is not None:
        secrets_policy = pulumi.Output.all(auth_key_secret_arn, kms_key_arn).apply(build_secrets_policy)
    else:
        secrets_policy = pulumi.Output.all(auth_key_secret_arn).apply(build_secrets_policy)

    aws.iam.RolePolicy(
        f"{name}-tailscale-secrets",
        role=role.name,
        policy=secrets_policy,
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

    # User data script - fetch auth key from Secrets Manager at boot
    def build_user_data(args):
        secret_arn, routes = args
        routes_str = ",".join(routes) if isinstance(routes, list) else routes
        
        return f"""#!/bin/bash
set -euo pipefail

LOG_FILE="/var/log/tailscale-userdata.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== Tailscale Subnet Router Setup Started at $(date) ==="

# Update system
dnf update -y
dnf install -y jq awscli

# Fetch auth key from Secrets Manager (Infisical-synced)
echo "Fetching Tailscale auth key from Secrets Manager..."
SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "{secret_arn}" --query 'SecretString' --output text --region {region.region})

# Try to parse as JSON first (Infisical format), fallback to raw string
if echo "$SECRET_JSON" | jq -e '.TAILSCALE_AUTH_KEY' >/dev/null 2>&1; then
    TAILSCALE_AUTHKEY=$(echo "$SECRET_JSON" | jq -r '.TAILSCALE_AUTH_KEY')
else
    TAILSCALE_AUTHKEY="$SECRET_JSON"
fi

if [ -z "$TAILSCALE_AUTHKEY" ] || [ "$TAILSCALE_AUTHKEY" = "null" ]; then
    echo "ERROR: Failed to fetch Tailscale auth key from Secrets Manager"
    exit 1
fi
echo "Successfully fetched auth key from Secrets Manager"

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

# Store config (secret ARN only, not the actual key)
mkdir -p /etc/tailscale
cat > /etc/tailscale/config << 'TSCONFIG'
SECRET_ARN="{secret_arn}"
AWS_REGION="{region.region}"
TAILSCALE_HOSTNAME="{tailscale_hostname}"
TAILSCALE_ROUTES="{routes_str}"
TSCONFIG
chmod 600 /etc/tailscale/config

# Connect to Tailscale (auth key in memory only, not written to disk)
echo "Connecting to Tailscale..."
tailscale up \\
  --authkey="$TAILSCALE_AUTHKEY" \\
  --hostname="{tailscale_hostname}" \\
  --advertise-routes="{routes_str}" \\
  --accept-risk=all

# Clear auth key from environment
unset TAILSCALE_AUTHKEY
unset SECRET_JSON

sleep 5

# Verify connection
BACKEND=$(tailscale status --json | jq -r '.BackendState' 2>/dev/null || echo "Unknown")
ONLINE=$(tailscale status --json | jq -r '.Self.Online' 2>/dev/null || echo "Unknown")

if [ "$BACKEND" = "Running" ] && [ "$ONLINE" = "true" ]; then
    echo "SUCCESS: Tailscale connected (Backend: $BACKEND, Online: $ONLINE)"
else
    echo "WARNING: Tailscale may not be fully connected (Backend: $BACKEND, Online: $ONLINE)"
fi

# Create monitor script that fetches auth key from Secrets Manager
cat > /usr/local/bin/tailscale-monitor.sh << 'MONITOR'
#!/bin/bash
source /etc/tailscale/config
BACKEND=$(tailscale status --json | jq -r '.BackendState' 2>/dev/null || echo "Unknown")
ONLINE=$(tailscale status --json | jq -r '.Self.Online' 2>/dev/null || echo "Unknown")

if [ "$BACKEND" != "Running" ] || [ "$ONLINE" != "true" ]; then
    echo "Reconnecting Tailscale..."
    
    # Fetch auth key from Secrets Manager
    SECRET_JSON=$(aws secretsmanager get-secret-value --secret-id "$SECRET_ARN" --query 'SecretString' --output text --region "$AWS_REGION")
    
    # Try to parse as JSON first, fallback to raw string
    if echo "$SECRET_JSON" | jq -e '.TAILSCALE_AUTH_KEY' >/dev/null 2>&1; then
        TAILSCALE_AUTHKEY=$(echo "$SECRET_JSON" | jq -r '.TAILSCALE_AUTH_KEY')
    else
        TAILSCALE_AUTHKEY="$SECRET_JSON"
    fi
    
    if [ -z "$TAILSCALE_AUTHKEY" ] || [ "$TAILSCALE_AUTHKEY" = "null" ]; then
        echo "ERROR: Failed to fetch auth key from Secrets Manager"
        exit 1
    fi
    
    tailscale logout || true
    sleep 5
    systemctl restart tailscaled
    sleep 10
    tailscale up \\
      --authkey="$TAILSCALE_AUTHKEY" \\
      --hostname="$TAILSCALE_HOSTNAME" \\
      --advertise-routes="$TAILSCALE_ROUTES" \\
      --accept-risk=all
    
    # Clear auth key from environment
    unset TAILSCALE_AUTHKEY
    unset SECRET_JSON
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

    # Build user_data from secret ARN and routes
    # Use Output.from_input to handle both plain values and Outputs uniformly
    secret_arn_out = pulumi.Output.from_input(auth_key_secret_arn)
    routes_out = pulumi.Output.from_input(advertise_routes)
    user_data = pulumi.Output.all(secret_arn_out, routes_out).apply(build_user_data)

    # EC2 instance with IMDSv2 enforcement
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
        metadata_options=aws.ec2.InstanceMetadataOptionsArgs(
            http_endpoint="enabled",
            http_tokens="required",  # IMDSv2 only
            http_put_response_hop_limit=1,
        ),
        tags={"Name": f"{name}-tailscale"},
    )

    return {
        "instance": instance,
        "instance_id": instance.id,
        "private_ip": instance.private_ip,
        "security_group": security_group,
    }
