"""CloudSecure shared utilities for Lambda functions."""

from shared.aws_client import get_assumed_role_session, get_boto3_client
from shared.crf_models import (
    Capability,
    ContextEntity,
    EntityType,
    Fact,
    Organization,
    Policy,
    Relationship,
    RelationshipType,
    System,
)
from shared.models import (
    Assessment,
    AssessmentStatus,
    ComplianceFramework,
    Finding,
    FindingSeverity,
)

__all__ = [
    # Assessment models
    "Assessment",
    "AssessmentStatus",
    "Finding",
    "FindingSeverity",
    "ComplianceFramework",
    # CRF models
    "ContextEntity",
    "EntityType",
    "Organization",
    "System",
    "Policy",
    "Fact",
    "Capability",
    "Relationship",
    "RelationshipType",
    # AWS client
    "get_assumed_role_session",
    "get_boto3_client",
]
