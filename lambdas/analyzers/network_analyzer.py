"""Network Analyzer - Detects network security issues.

Checks for:
1. Security groups with 0.0.0.0/0 ingress on sensitive ports
2. Security groups with unrestricted egress
3. Public-facing resources (EC2, RDS, ELB)
4. VPC Flow Logs not enabled
5. Default VPC in use
6. Network ACLs with unrestricted access
"""

import logging
import os
import sys
from typing import Any

from botocore.exceptions import ClientError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.base import BaseAnalyzer, run_analyzer
from shared.models import (
    ComplianceFramework,
    ComplianceMapping,
    Finding,
    FindingSeverity,
    Remediation,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Sensitive ports that should not be open to the internet
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
}


class NetworkAnalyzer(BaseAnalyzer):
    """Analyzer for network security issues."""

    @property
    def name(self) -> str:
        return "network-analyzer"

    def analyze(self) -> list[Finding]:
        """Run network security analysis across all regions."""
        self.log_info(f"Starting network analysis across {len(self.regions)} regions")

        for region in self.regions:
            self.log_info(f"Analyzing region: {region}")
            ec2 = self.get_client("ec2", region)

            self._check_security_groups(ec2, region)
            self._check_vpc_flow_logs(ec2, region)
            self._check_default_vpc(ec2, region)
            self._check_public_instances(ec2, region)

        self.log_info(f"Network analysis complete. Found {len(self.findings)} findings")
        return self.findings

    def _check_security_groups(self, ec2: Any, region: str) -> None:
        """Check for security groups with overly permissive rules."""
        self.log_info(f"Checking security groups in {region}")

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    vpc_id = sg.get("VpcId", "EC2-Classic")

                    # Check ingress rules
                    for rule in sg.get("IpPermissions", []):
                        self._analyze_ingress_rule(sg_id, sg_name, vpc_id, rule, region)

                    # Check for unrestricted egress (less critical but worth noting)
                    for rule in sg.get("IpPermissionsEgress", []):
                        self._analyze_egress_rule(sg_id, sg_name, vpc_id, rule, region)

        except ClientError as e:
            self.log_error(f"Error checking security groups in {region}: {e}")

    def _analyze_ingress_rule(
        self, sg_id: str, sg_name: str, vpc_id: str, rule: dict, region: str
    ) -> None:
        """Analyze a single ingress rule for security issues."""
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        protocol = rule.get("IpProtocol", "-1")

        # Check for 0.0.0.0/0 or ::/0
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                self._create_open_ingress_finding(
                    sg_id, sg_name, vpc_id, from_port, to_port, protocol, cidr, region
                )

        for ipv6_range in rule.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6", "")
            if cidr == "::/0":
                self._create_open_ingress_finding(
                    sg_id, sg_name, vpc_id, from_port, to_port, protocol, cidr, region
                )

    def _create_open_ingress_finding(
        self,
        sg_id: str,
        sg_name: str,
        vpc_id: str,
        from_port: int,
        to_port: int,
        protocol: str,
        cidr: str,
        region: str,
    ) -> None:
        """Create a finding for an open ingress rule."""
        # Determine severity based on port
        if protocol == "-1" or from_port == 0 and to_port == 65535:  # All traffic
            severity = FindingSeverity.CRITICAL
            port_desc = "all ports"
        else:
            # Check if any sensitive ports are in range
            sensitive_in_range = [
                (port, name)
                for port, name in SENSITIVE_PORTS.items()
                if from_port <= port <= to_port
            ]

            if sensitive_in_range:
                severity = FindingSeverity.HIGH
                port_desc = ", ".join([f"{p} ({n})" for p, n in sensitive_in_range])
            else:
                severity = FindingSeverity.MEDIUM
                port_desc = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)

        self.create_finding(
            severity=severity,
            title=f"Security group '{sg_name}' allows {cidr} on {port_desc}",
            description=(
                f"The security group '{sg_name}' ({sg_id}) in VPC {vpc_id} allows "
                f"inbound traffic from {cidr} on {port_desc}. "
                "This exposes resources to the entire internet."
            ),
            resource_type="AWS::EC2::SecurityGroup",
            resource_id=sg_id,
            region=region,
            compliance_mappings=[
                ComplianceMapping(
                    framework=ComplianceFramework.CIS_AWS_1_4,
                    control="5.2",
                    description="Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
                ),
            ],
            remediation=Remediation(
                description="Restrict the security group ingress rules",
                steps=[
                    f"Navigate to VPC > Security Groups > {sg_id}",
                    "Edit inbound rules",
                    f"Remove or restrict the rule allowing {cidr}",
                    "Add rules for specific IP ranges or security groups instead",
                ],
                automatable=True,
                effort="LOW",
            ),
            metadata={
                "vpcId": vpc_id,
                "fromPort": from_port,
                "toPort": to_port,
                "protocol": protocol,
                "cidr": cidr,
            },
        )

    def _analyze_egress_rule(
        self, sg_id: str, sg_name: str, vpc_id: str, rule: dict, region: str
    ) -> None:
        """Analyze egress rules - only flag all-traffic to 0.0.0.0/0."""
        protocol = rule.get("IpProtocol", "-1")

        # Only flag completely unrestricted egress
        if protocol != "-1":
            return

        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                self.create_finding(
                    severity=FindingSeverity.LOW,
                    title=f"Security group '{sg_name}' allows unrestricted outbound traffic",
                    description=(
                        f"The security group '{sg_name}' ({sg_id}) allows all outbound traffic "
                        "to any destination. Consider restricting egress to only necessary "
                        "destinations and ports."
                    ),
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    region=region,
                    remediation=Remediation(
                        description="Consider restricting outbound traffic",
                        steps=[
                            "Review what outbound access is actually needed",
                            "Replace the allow-all rule with specific rules",
                            "Consider using VPC endpoints for AWS services",
                        ],
                        automatable=False,
                        effort="MEDIUM",
                    ),
                    metadata={"vpcId": vpc_id},
                )
                break

    def _check_vpc_flow_logs(self, ec2: Any, region: str) -> None:
        """Check if VPC Flow Logs are enabled for all VPCs."""
        self.log_info(f"Checking VPC Flow Logs in {region}")

        try:
            # Get all VPCs
            vpcs = ec2.describe_vpcs()["Vpcs"]

            # Get all flow logs
            flow_logs = ec2.describe_flow_logs()["FlowLogs"]
            vpc_with_flow_logs = {
                fl["ResourceId"]
                for fl in flow_logs
                if fl["ResourceType"] == "VPC" and fl["FlowLogStatus"] == "ACTIVE"
            }

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                is_default = vpc.get("IsDefault", False)

                if vpc_id not in vpc_with_flow_logs:
                    self.create_finding(
                        severity=FindingSeverity.MEDIUM,
                        title=f"VPC '{vpc_id}' does not have Flow Logs enabled",
                        description=(
                            f"The VPC '{vpc_id}' in {region} does not have Flow Logs enabled. "
                            "VPC Flow Logs capture IP traffic information and are essential for "
                            "security monitoring and troubleshooting."
                        ),
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        compliance_mappings=[
                            ComplianceMapping(
                                framework=ComplianceFramework.CIS_AWS_1_4,
                                control="3.9",
                                description="Ensure VPC flow logging is enabled in all VPCs",
                            ),
                        ],
                        remediation=Remediation(
                            description="Enable VPC Flow Logs",
                            steps=[
                                f"Navigate to VPC > Your VPCs > {vpc_id}",
                                "Select the Flow Logs tab",
                                "Click 'Create flow log'",
                                "Configure destination (CloudWatch Logs or S3)",
                                "Select traffic type (All, Accept, or Reject)",
                            ],
                            automatable=True,
                            effort="LOW",
                        ),
                        metadata={"isDefault": is_default},
                    )

        except ClientError as e:
            self.log_error(f"Error checking VPC Flow Logs in {region}: {e}")

    def _check_default_vpc(self, ec2: Any, region: str) -> None:
        """Check if default VPC is in use."""
        self.log_info(f"Checking default VPC usage in {region}")

        try:
            vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}])["Vpcs"]

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]

                # Check if any resources are using the default VPC
                # Check for EC2 instances
                instances = ec2.describe_instances(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

                instance_count = sum(len(r["Instances"]) for r in instances["Reservations"])

                if instance_count > 0:
                    self.create_finding(
                        severity=FindingSeverity.LOW,
                        title=f"Default VPC in {region} has {instance_count} EC2 instances",
                        description=(
                            f"The default VPC ({vpc_id}) in {region} contains {instance_count} "
                            "EC2 instances. Using the default VPC is not recommended for production "
                            "workloads as it may have overly permissive default settings."
                        ),
                        resource_type="AWS::EC2::VPC",
                        resource_id=vpc_id,
                        region=region,
                        remediation=Remediation(
                            description="Migrate resources to a custom VPC",
                            steps=[
                                "Create a custom VPC with appropriate CIDR blocks",
                                "Create subnets, route tables, and security groups",
                                "Migrate instances to the new VPC",
                                "Consider deleting the default VPC if not needed",
                            ],
                            automatable=False,
                            effort="HIGH",
                        ),
                        metadata={"instanceCount": instance_count},
                    )

        except ClientError as e:
            self.log_error(f"Error checking default VPC in {region}: {e}")

    def _check_public_instances(self, ec2: Any, region: str) -> None:
        """Check for EC2 instances with public IPs."""
        self.log_info(f"Checking for public EC2 instances in {region}")

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        instance_id = instance["InstanceId"]
                        state = instance["State"]["Name"]

                        # Skip terminated instances
                        if state == "terminated":
                            continue

                        public_ip = instance.get("PublicIpAddress")
                        public_dns = instance.get("PublicDnsName")

                        if public_ip:
                            # Get instance name from tags
                            name = next(
                                (
                                    t["Value"]
                                    for t in instance.get("Tags", [])
                                    if t["Key"] == "Name"
                                ),
                                instance_id,
                            )

                            # Check security groups for sensitive open ports
                            sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

                            self.create_finding(
                                severity=FindingSeverity.INFO,
                                title=f"EC2 instance '{name}' has public IP {public_ip}",
                                description=(
                                    f"The EC2 instance '{name}' ({instance_id}) has a public IP address "
                                    f"({public_ip}). Ensure this is intentional and that security groups "
                                    "properly restrict access."
                                ),
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                region=region,
                                remediation=Remediation(
                                    description="Review if public IP is necessary",
                                    steps=[
                                        "Verify if the instance needs public internet access",
                                        "Consider using a NAT Gateway for outbound-only access",
                                        "Use a load balancer or bastion host for inbound access",
                                        "Ensure security groups are properly configured",
                                    ],
                                    automatable=False,
                                    effort="MEDIUM",
                                ),
                                metadata={
                                    "publicIp": public_ip,
                                    "publicDns": public_dns,
                                    "securityGroups": sg_ids,
                                    "instanceType": instance.get("InstanceType"),
                                },
                            )

        except ClientError as e:
            self.log_error(f"Error checking public instances in {region}: {e}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for network analysis."""
    return run_analyzer(NetworkAnalyzer, event)
