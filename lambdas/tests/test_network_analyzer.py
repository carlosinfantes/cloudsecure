"""Tests for Network Analyzer."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import boto3
from moto import mock_aws

from analyzers.network_analyzer import NetworkAnalyzer, handler
from shared.models import FindingSeverity


def _make_analyzer(mock_session=None):
    session = mock_session or MagicMock()
    return NetworkAnalyzer(
        assessment_id=uuid4(),
        account_id="123456789012",
        session=session,
        regions=["us-east-1"],
    )


class TestNetworkAnalyzerSecurityGroups:
    def test_open_ssh(self):
        analyzer = _make_analyzer()
        analyzer._create_open_ingress_finding(
            sg_id="sg-123",
            sg_name="test-sg",
            vpc_id="vpc-abc",
            from_port=22,
            to_port=22,
            protocol="tcp",
            cidr="0.0.0.0/0",
            region="us-east-1",
        )

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "SSH" in analyzer.findings[0].title

    def test_open_all_traffic(self):
        analyzer = _make_analyzer()
        analyzer._create_open_ingress_finding(
            sg_id="sg-123",
            sg_name="test-sg",
            vpc_id="vpc-abc",
            from_port=0,
            to_port=65535,
            protocol="-1",
            cidr="0.0.0.0/0",
            region="us-east-1",
        )

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.CRITICAL

    def test_open_non_sensitive_port(self):
        analyzer = _make_analyzer()
        analyzer._create_open_ingress_finding(
            sg_id="sg-123",
            sg_name="test-sg",
            vpc_id="vpc-abc",
            from_port=8080,
            to_port=8080,
            protocol="tcp",
            cidr="0.0.0.0/0",
            region="us-east-1",
        )

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM

    def test_ingress_rule_with_open_cidr(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "test-sg",
                        "VpcId": "vpc-abc",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpProtocol": "tcp",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_security_groups(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1

    def test_ipv6_open(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "test-sg",
                        "VpcId": "vpc-abc",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpProtocol": "tcp",
                                "IpRanges": [],
                                "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_security_groups(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1

    def test_unrestricted_egress(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "test-sg",
                        "VpcId": "vpc-abc",
                        "IpPermissions": [],
                        "IpPermissionsEgress": [
                            {
                                "IpProtocol": "-1",
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_security_groups(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.LOW

    def test_restricted_ingress_no_finding(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-123",
                        "GroupName": "test-sg",
                        "VpcId": "vpc-abc",
                        "IpPermissions": [
                            {
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpProtocol": "tcp",
                                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                                "Ipv6Ranges": [],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_security_groups(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0


class TestNetworkAnalyzerVPC:
    def test_vpc_without_flow_logs(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-123", "IsDefault": False}]}
        mock_ec2.describe_flow_logs.return_value = {"FlowLogs": []}

        analyzer._check_vpc_flow_logs(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM

    def test_vpc_with_flow_logs(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-123", "IsDefault": False}]}
        # Shape as returned by EC2 DescribeFlowLogs: no ResourceType field.
        mock_ec2.describe_flow_logs.return_value = {
            "FlowLogs": [
                {
                    "FlowLogId": "fl-123",
                    "ResourceId": "vpc-123",
                    "FlowLogStatus": "ACTIVE",
                    "TrafficType": "ALL",
                }
            ]
        }

        analyzer._check_vpc_flow_logs(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0

    def test_default_vpc_with_instances(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-default", "IsDefault": True}]
        }
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-123"}]}]
        }

        analyzer._check_default_vpc(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.LOW

    def test_default_vpc_no_instances(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-default", "IsDefault": True}]
        }
        mock_ec2.describe_instances.return_value = {"Reservations": []}

        analyzer._check_default_vpc(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0


class TestNetworkAnalyzerPublicInstances:
    def test_instance_with_public_ip(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-123",
                                "State": {"Name": "running"},
                                "PublicIpAddress": "54.1.2.3",
                                "PublicDnsName": "ec2-54-1-2-3.compute-1.amazonaws.com",
                                "Tags": [{"Key": "Name", "Value": "web-server"}],
                                "SecurityGroups": [{"GroupId": "sg-123"}],
                                "InstanceType": "t3.micro",
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_public_instances(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.INFO

    def test_terminated_instance_skipped(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-term",
                                "State": {"Name": "terminated"},
                                "PublicIpAddress": "54.1.2.3",
                            }
                        ]
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_public_instances(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0


class TestNetworkAnalyzerHandler:
    @patch("analyzers.network_analyzer.run_analyzer")
    def test_handler_delegates(self, mock_run):
        mock_run.return_value = {"success": True}
        handler({"assessmentId": "test"}, None)
        mock_run.assert_called_once_with(NetworkAnalyzer, {"assessmentId": "test"})


class TestVpcFlowLogsAgainstRealApiShape:
    """Flow log checks against moto, which returns the real EC2 response shape.

    Regression guard: the check used to read ``fl["ResourceType"]``, a field
    DescribeFlowLogs does not return, so any account that actually had flow
    logs raised KeyError and lost every network finding.
    """

    @mock_aws
    def test_vpc_with_flow_logs_is_not_reported(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="flow-logs-bucket")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="s3",
            LogDestination="arn:aws:s3:::flow-logs-bucket",
        )

        analyzer = _make_analyzer()
        analyzer._check_vpc_flow_logs(ec2, "us-east-1")

        reported = {f.resource_id for f in analyzer.findings}
        assert vpc_id not in reported

    @mock_aws
    def test_vpc_without_flow_logs_is_reported(self):
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

        analyzer = _make_analyzer()
        analyzer._check_vpc_flow_logs(ec2, "us-east-1")

        reported = {f.resource_id for f in analyzer.findings}
        assert vpc_id in reported
