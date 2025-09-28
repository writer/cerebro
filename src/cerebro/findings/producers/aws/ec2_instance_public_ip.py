"""Producer for detecting EC2 instances with public IP addresses."""

from typing import List, Set, Optional, Dict, Any

from cerebro.domain.entities import ResourceEntity, ConfigEntity, FindingEntity, Severity
from cerebro.findings.producers.registry import register_producer
from .base import BaseAWSProducer


@register_producer
class EC2InstancePublicIPProducer(BaseAWSProducer):
    """Detects EC2 instances with public IP addresses."""
    
    @property
    def resource_types(self) -> Set[str]:
        return {"aws.ec2.instance"}
    
    @property
    def finding_name(self) -> str:
        return "AWS: EC2 Instance Has Public IP"
    
    @property
    def rule_name(self) -> str:
        return "aws_ec2_instance_public_ip"
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    @property
    def description(self) -> str:
        return "EC2 instance has a public IP address directly assigned"
    
    @property
    def remediation(self) -> str:
        return "Place EC2 instances in private subnets and use NAT Gateway or ALB for internet access"
    
    @property
    def framework_mappings(self) -> Dict[str, List[str]]:
        return {
            "cis": ["4.1"],
            "nist_800_53": ["AC-4", "SC-7"],
        }
    
    def evaluate(
        self,
        resource: ResourceEntity,
        config: ConfigEntity,
        context: Optional[Dict[str, Any]] = None
    ) -> List[FindingEntity]:
        """Evaluate EC2 instance for public IP assignment."""
        findings = []
        
        # Check if instance has public IP
        public_ip = config.normalized_config.get("publicIp")
        instance_state = config.normalized_config.get("state")
        
        # Only flag running instances with public IPs
        if public_ip and instance_state == "running":
            # Get rule ID from context
            rule_id = context.get("rule_id") if context else None
            if not rule_id:
                from cerebro.rules.rule_service import get_rule_by_name
                rule_id = get_rule_by_name(self.rule_name)
            
            # Check security groups for open ports
            security_groups = config.normalized_config.get("securityGroups", [])
            open_to_internet = self._check_security_groups_open(security_groups, context)
            
            # Assess risk level
            risk_factors = []
            if open_to_internet:
                risk_factors.append("security_groups_allow_internet_access")
            
            instance_type = config.normalized_config.get("instanceType")
            if instance_type and instance_type.startswith(("t2.", "t3.", "t4g.")):
                risk_factors.append("burstable_instance_type")
            
            evidence = {
                "instance_id": resource.external_id,
                "instance_name": resource.name,
                "instance_type": instance_type,
                "state": instance_state,
                "public_ip": public_ip,
                "private_ip": config.normalized_config.get("privateIp"),
                "vpc_id": config.normalized_config.get("vpcId"),
                "subnet_id": config.normalized_config.get("subnetId"),
                "security_groups": security_groups,
                "open_to_internet": open_to_internet,
                "risk_factors": risk_factors,
                "tags": config.normalized_config.get("tags", {}),
                "image_id": config.normalized_config.get("imageId"),
                "launch_time": config.normalized_config.get("launchTime"),
            }
            
            # Escalate severity if security groups are open
            severity = Severity.HIGH if open_to_internet else self.severity
            
            finding = self.create_finding(
                resource=resource,
                rule_id=rule_id,
                title=f"EC2 instance {resource.name or resource.external_id} has public IP",
                summary=f"EC2 instance {resource.name or resource.external_id} has public IP {public_ip}" +
                        (f" and open security groups" if open_to_internet else ""),
                evidence=evidence,
                severity=severity
            )
            findings.append(finding)
        
        return findings
    
    def _check_security_groups_open(
        self, 
        security_groups: List[str], 
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Check if security groups allow open internet access."""
        # This would need access to security group rules
        # For now, assume we get this data in context
        if not context or "security_group_rules" not in context:
            return False
        
        sg_rules = context["security_group_rules"]
        
        for sg_id in security_groups:
            rules = sg_rules.get(sg_id, [])
            for rule in rules:
                # Check for 0.0.0.0/0 with common ports
                if (rule.get("cidr") == "0.0.0.0/0" and
                    rule.get("from_port", 0) <= 22 <= rule.get("to_port", 0)):  # SSH
                    return True
                if (rule.get("cidr") == "0.0.0.0/0" and
                    rule.get("from_port", 0) <= 80 <= rule.get("to_port", 0)):  # HTTP
                    return True
                if (rule.get("cidr") == "0.0.0.0/0" and
                    rule.get("from_port", 0) <= 443 <= rule.get("to_port", 0)):  # HTTPS
                    return True
        
        return False
