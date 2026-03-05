"""Tests for Encryption Analyzer."""

from unittest.mock import MagicMock, patch
from uuid import uuid4

from analyzers.encryption_analyzer import EncryptionAnalyzer, handler
from shared.models import FindingSeverity


def _make_analyzer(mock_session=None):
    session = mock_session or MagicMock()
    return EncryptionAnalyzer(
        assessment_id=uuid4(),
        account_id="123456789012",
        session=session,
        regions=["us-east-1"],
    )


class TestEncryptionAnalyzerEBS:
    def test_ebs_default_encryption_disabled(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}

        analyzer._check_ebs_default_encryption(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM

    def test_ebs_default_encryption_enabled(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()
        mock_ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}

        analyzer._check_ebs_default_encryption(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0

    def test_unencrypted_ebs_volume(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-123",
                        "Encrypted": False,
                        "Size": 100,
                        "VolumeType": "gp3",
                        "Attachments": [{"InstanceId": "i-abc"}],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_ebs_volumes(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH

    def test_encrypted_ebs_volume(self):
        analyzer = _make_analyzer()
        mock_ec2 = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Volumes": [
                    {
                        "VolumeId": "vol-456",
                        "Encrypted": True,
                        "Size": 100,
                        "VolumeType": "gp3",
                        "Attachments": [],
                    }
                ]
            }
        ]
        mock_ec2.get_paginator.return_value = mock_paginator

        analyzer._check_ebs_volumes(mock_ec2, "us-east-1")

        assert len(analyzer.findings) == 0


class TestEncryptionAnalyzerRDS:
    def test_unencrypted_rds_instance(self):
        analyzer = _make_analyzer()
        mock_rds = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "mydb",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:mydb",
                        "StorageEncrypted": False,
                        "PubliclyAccessible": False,
                        "Engine": "mysql",
                        "EngineVersion": "8.0",
                        "DBInstanceClass": "db.t3.micro",
                        "MultiAZ": False,
                    }
                ]
            }
        ]
        mock_rds.get_paginator.return_value = mock_paginator

        analyzer._check_rds_instances(mock_rds, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "not encrypted" in analyzer.findings[0].title

    def test_publicly_accessible_rds(self):
        analyzer = _make_analyzer()
        mock_rds = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "publicdb",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:publicdb",
                        "StorageEncrypted": True,
                        "PubliclyAccessible": True,
                        "Engine": "postgres",
                        "EngineVersion": "15",
                        "DBInstanceClass": "db.t3.small",
                    }
                ]
            }
        ]
        mock_rds.get_paginator.return_value = mock_paginator

        analyzer._check_rds_instances(mock_rds, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH
        assert "publicly accessible" in analyzer.findings[0].title

    def test_compliant_rds(self):
        analyzer = _make_analyzer()
        mock_rds = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "gooddb",
                        "StorageEncrypted": True,
                        "PubliclyAccessible": False,
                        "Engine": "mysql",
                    }
                ]
            }
        ]
        mock_rds.get_paginator.return_value = mock_paginator

        analyzer._check_rds_instances(mock_rds, "us-east-1")

        assert len(analyzer.findings) == 0

    def test_unencrypted_rds_snapshot(self):
        analyzer = _make_analyzer()
        mock_rds = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "DBSnapshots": [
                    {
                        "DBSnapshotIdentifier": "snap-123",
                        "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:snap-123",
                        "Encrypted": False,
                        "Engine": "mysql",
                        "DBInstanceIdentifier": "mydb",
                    }
                ]
            }
        ]
        mock_rds.get_paginator.return_value = mock_paginator

        analyzer._check_rds_snapshots(mock_rds, "us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.MEDIUM


class TestEncryptionAnalyzerEFS:
    def test_unencrypted_efs(self):
        analyzer = _make_analyzer()
        mock_efs = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "FileSystems": [
                    {
                        "FileSystemId": "fs-123",
                        "Encrypted": False,
                        "Name": "shared-data",
                        "SizeInBytes": {"Value": 1024},
                        "PerformanceMode": "generalPurpose",
                    }
                ]
            }
        ]
        mock_efs.get_paginator.return_value = mock_paginator

        # Mock get_client to return our mock EFS client
        analyzer.get_client = MagicMock(return_value=mock_efs)

        analyzer._check_efs_filesystems("us-east-1")

        assert len(analyzer.findings) == 1
        assert analyzer.findings[0].severity == FindingSeverity.HIGH

    def test_encrypted_efs(self):
        analyzer = _make_analyzer()
        mock_efs = MagicMock()

        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "FileSystems": [
                    {
                        "FileSystemId": "fs-456",
                        "Encrypted": True,
                        "Name": "secure-data",
                    }
                ]
            }
        ]
        mock_efs.get_paginator.return_value = mock_paginator

        analyzer.get_client = MagicMock(return_value=mock_efs)

        analyzer._check_efs_filesystems("us-east-1")

        assert len(analyzer.findings) == 0


class TestEncryptionAnalyzerHandler:
    @patch("analyzers.encryption_analyzer.run_analyzer")
    def test_handler_delegates(self, mock_run):
        mock_run.return_value = {"success": True}
        result = handler({"assessmentId": "test"}, None)
        mock_run.assert_called_once_with(EncryptionAnalyzer, {"assessmentId": "test"})
