"""Encryption Analyzer - Detects unencrypted resources.

Checks for:
1. Unencrypted EBS volumes
2. Unencrypted RDS instances
3. Unencrypted RDS snapshots
4. EBS default encryption not enabled
5. Unencrypted EFS file systems
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


class EncryptionAnalyzer(BaseAnalyzer):
    """Analyzer for encryption-related security issues."""

    @property
    def name(self) -> str:
        return "encryption-analyzer"

    def analyze(self) -> list[Finding]:
        """Run encryption analysis across all regions."""
        self.log_info(f"Starting encryption analysis across {len(self.regions)} regions")

        for region in self.regions:
            self.log_info(f"Analyzing region: {region}")

            ec2 = self.get_client("ec2", region)
            rds = self.get_client("rds", region)

            self._check_ebs_default_encryption(ec2, region)
            self._check_ebs_volumes(ec2, region)
            self._check_rds_instances(rds, region)
            self._check_rds_snapshots(rds, region)
            self._check_efs_filesystems(region)

        self.log_info(f"Encryption analysis complete. Found {len(self.findings)} findings")
        return self.findings

    def _check_ebs_default_encryption(self, ec2: Any, region: str) -> None:
        """Check if EBS default encryption is enabled for the region."""
        self.log_info(f"Checking EBS default encryption in {region}")

        try:
            response = ec2.get_ebs_encryption_by_default()

            if not response.get("EbsEncryptionByDefault", False):
                self.create_finding(
                    severity=FindingSeverity.MEDIUM,
                    title=f"EBS default encryption is not enabled in {region}",
                    description=(
                        f"EBS default encryption is not enabled in {region}. "
                        "New EBS volumes created in this region will not be automatically encrypted."
                    ),
                    resource_type="AWS::EC2::Volume",
                    resource_id=f"ebs-default-encryption-{region}",
                    region=region,
                    compliance_mappings=[
                        ComplianceMapping(
                            framework=ComplianceFramework.CIS_AWS_1_4,
                            control="2.2.1",
                            description="Ensure EBS volume encryption is enabled by default",
                        ),
                    ],
                    remediation=Remediation(
                        description="Enable EBS default encryption",
                        steps=[
                            f"Navigate to EC2 > Settings (in {region})",
                            "Find 'EBS encryption' section",
                            "Click 'Manage'",
                            "Enable 'Always encrypt new EBS volumes'",
                        ],
                        automatable=True,
                        effort="LOW",
                    ),
                )

        except ClientError as e:
            self.log_error(f"Error checking EBS default encryption in {region}: {e}")

    def _check_ebs_volumes(self, ec2: Any, region: str) -> None:
        """Check for unencrypted EBS volumes."""
        self.log_info(f"Checking EBS volumes in {region}")

        try:
            paginator = ec2.get_paginator("describe_volumes")
            unencrypted_count = 0

            for page in paginator.paginate():
                for volume in page["Volumes"]:
                    volume_id = volume["VolumeId"]
                    encrypted = volume.get("Encrypted", False)

                    if not encrypted:
                        unencrypted_count += 1

                        # Get volume name from tags
                        name = next(
                            (t["Value"] for t in volume.get("Tags", []) if t["Key"] == "Name"),
                            volume_id,
                        )

                        # Check if volume is attached
                        attachments = volume.get("Attachments", [])
                        attached_to = (
                            attachments[0]["InstanceId"] if attachments else "Not attached"
                        )

                        self.create_finding(
                            severity=FindingSeverity.HIGH,
                            title=f"EBS volume '{name}' is not encrypted",
                            description=(
                                f"The EBS volume '{name}' ({volume_id}) in {region} is not encrypted. "
                                f"Volume is attached to: {attached_to}. "
                                "Unencrypted volumes could expose sensitive data if compromised."
                            ),
                            resource_type="AWS::EC2::Volume",
                            resource_id=volume_id,
                            region=region,
                            compliance_mappings=[
                                ComplianceMapping(
                                    framework=ComplianceFramework.CIS_AWS_1_4,
                                    control="2.2.1",
                                    description="Ensure EBS volume encryption is enabled",
                                ),
                            ],
                            remediation=Remediation(
                                description="Encrypt the EBS volume",
                                steps=[
                                    "Create a snapshot of the unencrypted volume",
                                    "Copy the snapshot with encryption enabled",
                                    "Create a new encrypted volume from the encrypted snapshot",
                                    "Stop the instance, detach old volume, attach new volume",
                                    "Verify and delete the old unencrypted volume",
                                ],
                                automatable=True,
                                effort="MEDIUM",
                            ),
                            metadata={
                                "size": volume.get("Size"),
                                "volumeType": volume.get("VolumeType"),
                                "attachedTo": attached_to,
                            },
                        )

            if unencrypted_count > 0:
                self.log_info(f"Found {unencrypted_count} unencrypted EBS volumes in {region}")

        except ClientError as e:
            self.log_error(f"Error checking EBS volumes in {region}: {e}")

    def _check_rds_instances(self, rds: Any, region: str) -> None:
        """Check for unencrypted RDS instances."""
        self.log_info(f"Checking RDS instances in {region}")

        try:
            paginator = rds.get_paginator("describe_db_instances")

            for page in paginator.paginate():
                for instance in page["DBInstances"]:
                    db_id = instance["DBInstanceIdentifier"]
                    encrypted = instance.get("StorageEncrypted", False)

                    if not encrypted:
                        self.create_finding(
                            severity=FindingSeverity.HIGH,
                            title=f"RDS instance '{db_id}' is not encrypted",
                            description=(
                                f"The RDS instance '{db_id}' in {region} does not have storage encryption "
                                "enabled. Database contents could be exposed if storage is compromised."
                            ),
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=instance.get("DBInstanceArn"),
                            region=region,
                            compliance_mappings=[
                                ComplianceMapping(
                                    framework=ComplianceFramework.CIS_AWS_1_4,
                                    control="2.3.1",
                                    description="Ensure RDS instances have encryption at rest enabled",
                                ),
                            ],
                            remediation=Remediation(
                                description="Enable encryption for RDS instance",
                                steps=[
                                    "Create an encrypted snapshot of the database",
                                    "Restore the snapshot to a new encrypted instance",
                                    "Update application connection strings",
                                    "Delete the old unencrypted instance",
                                ],
                                automatable=False,
                                effort="HIGH",
                            ),
                            metadata={
                                "engine": instance.get("Engine"),
                                "engineVersion": instance.get("EngineVersion"),
                                "instanceClass": instance.get("DBInstanceClass"),
                                "multiAZ": instance.get("MultiAZ", False),
                            },
                        )

                    # Also check if instance is publicly accessible
                    if instance.get("PubliclyAccessible", False):
                        self.create_finding(
                            severity=FindingSeverity.HIGH,
                            title=f"RDS instance '{db_id}' is publicly accessible",
                            description=(
                                f"The RDS instance '{db_id}' in {region} is configured as publicly "
                                "accessible. This could expose the database to attacks from the internet."
                            ),
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_id,
                            resource_arn=instance.get("DBInstanceArn"),
                            region=region,
                            remediation=Remediation(
                                description="Disable public accessibility",
                                steps=[
                                    f"Navigate to RDS > Databases > {db_id}",
                                    "Click 'Modify'",
                                    "Disable 'Publicly accessible'",
                                    "Apply changes (may require reboot)",
                                ],
                                automatable=True,
                                effort="LOW",
                            ),
                        )

        except ClientError as e:
            self.log_error(f"Error checking RDS instances in {region}: {e}")

    def _check_rds_snapshots(self, rds: Any, region: str) -> None:
        """Check for unencrypted RDS snapshots."""
        self.log_info(f"Checking RDS snapshots in {region}")

        try:
            paginator = rds.get_paginator("describe_db_snapshots")

            for page in paginator.paginate(SnapshotType="manual"):
                for snapshot in page["DBSnapshots"]:
                    snapshot_id = snapshot["DBSnapshotIdentifier"]
                    encrypted = snapshot.get("Encrypted", False)

                    if not encrypted:
                        self.create_finding(
                            severity=FindingSeverity.MEDIUM,
                            title=f"RDS snapshot '{snapshot_id}' is not encrypted",
                            description=(
                                f"The RDS snapshot '{snapshot_id}' in {region} is not encrypted. "
                                "Snapshots may contain sensitive database data."
                            ),
                            resource_type="AWS::RDS::DBSnapshot",
                            resource_id=snapshot_id,
                            resource_arn=snapshot.get("DBSnapshotArn"),
                            region=region,
                            remediation=Remediation(
                                description="Create an encrypted copy of the snapshot",
                                steps=[
                                    f"Copy snapshot {snapshot_id} with encryption enabled",
                                    "Delete the unencrypted snapshot",
                                ],
                                automatable=True,
                                effort="LOW",
                            ),
                            metadata={
                                "engine": snapshot.get("Engine"),
                                "sourceDBInstance": snapshot.get("DBInstanceIdentifier"),
                            },
                        )

        except ClientError as e:
            self.log_error(f"Error checking RDS snapshots in {region}: {e}")

    def _check_efs_filesystems(self, region: str) -> None:
        """Check for unencrypted EFS file systems."""
        self.log_info(f"Checking EFS file systems in {region}")

        try:
            efs = self.get_client("efs", region)
            paginator = efs.get_paginator("describe_file_systems")

            for page in paginator.paginate():
                for fs in page["FileSystems"]:
                    fs_id = fs["FileSystemId"]
                    encrypted = fs.get("Encrypted", False)
                    name = fs.get("Name", fs_id)

                    if not encrypted:
                        self.create_finding(
                            severity=FindingSeverity.HIGH,
                            title=f"EFS file system '{name}' is not encrypted",
                            description=(
                                f"The EFS file system '{name}' ({fs_id}) in {region} is not encrypted. "
                                "File system contents could be exposed if storage is compromised."
                            ),
                            resource_type="AWS::EFS::FileSystem",
                            resource_id=fs_id,
                            region=region,
                            compliance_mappings=[
                                ComplianceMapping(
                                    framework=ComplianceFramework.CIS_AWS_1_4,
                                    control="2.4.1",
                                    description="Ensure EFS file systems are encrypted at rest",
                                ),
                            ],
                            remediation=Remediation(
                                description="Create encrypted EFS and migrate data",
                                steps=[
                                    "Create a new encrypted EFS file system",
                                    "Use AWS DataSync to copy data to the encrypted file system",
                                    "Update mount targets and applications",
                                    "Delete the unencrypted file system",
                                ],
                                automatable=False,
                                effort="HIGH",
                            ),
                            metadata={
                                "sizeInBytes": fs.get("SizeInBytes", {}).get("Value"),
                                "performanceMode": fs.get("PerformanceMode"),
                            },
                        )

        except ClientError as e:
            self.log_error(f"Error checking EFS in {region}: {e}")


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for encryption analysis."""
    return run_analyzer(EncryptionAnalyzer, event)
