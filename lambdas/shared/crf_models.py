"""CRF (Context Reasoning Format) models for customer organizational context.

Based on the CRF specification from reasoning-formats project.
These models represent organizational entities that inform security assessments.
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """CRF entity types."""

    ORGANIZATION = "organization"
    SYSTEM = "system"
    POLICY = "policy"
    FACT = "fact"
    CAPABILITY = "capability"
    ARCHITECTURE = "architecture"


class RelationshipType(str, Enum):
    """CRF relationship types."""

    OWNS = "owns"
    OWNED_BY = "owned_by"
    DEPENDS_ON = "depends_on"
    DEPENDENCY_OF = "dependency_of"
    CONSTRAINS = "constrains"
    CONSTRAINED_BY = "constrained_by"
    INVALIDATES = "invalidates"
    INVALIDATED_BY = "invalidated_by"
    PART_OF = "part_of"
    CONTAINS = "contains"
    PRODUCES = "produces"
    PRODUCED_BY = "produced_by"
    RELATED_TO = "related_to"


class Relationship(BaseModel):
    """Relationship between CRF entities."""

    target_id: UUID
    type: RelationshipType
    description: str | None = None

    class Config:
        use_enum_values = True


class Validity(BaseModel):
    """Temporal validity bounds for an entity."""

    valid_from: datetime | None = None
    valid_until: datetime | None = None

    def is_valid(self, at: datetime | None = None) -> bool:
        """Check if entity is valid at a given time (defaults to now)."""
        check_time = at or datetime.utcnow()
        if self.valid_from and check_time < self.valid_from:
            return False
        if self.valid_until and check_time > self.valid_until:
            return False
        return True


class Provenance(BaseModel):
    """Provenance information for an entity."""

    source: str  # "manual", "decision:uuid", "import:cmdb"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str


class Supersession(BaseModel):
    """Information about entity supersession."""

    entity_id: UUID
    reason: str
    superseded_at: datetime = Field(default_factory=datetime.utcnow)


# ==================== Entity Type Attributes ====================


class OrganizationAttributes(BaseModel):
    """Attributes for organization entity type."""

    org_type: str = "team"  # company, division, department, team, squad
    size: str | None = None  # startup, small, medium, large, enterprise
    headcount: int | None = None
    compliance_frameworks: list[str] = Field(default_factory=list)


class SystemAttributes(BaseModel):
    """Attributes for system entity type."""

    system_type: str = "application"  # application, service, platform, infrastructure
    status: str = "production"  # planned, development, staging, production
    criticality: str = "medium"  # low, medium, high, critical
    technology_stack: list[str] = Field(default_factory=list)
    data_classification: str | None = None  # public, internal, confidential, restricted


class PolicyAttributes(BaseModel):
    """Attributes for policy entity type."""

    policy_type: str = "security"  # governance, security, compliance, architectural
    enforcement: str = "recommended"  # mandatory, recommended, advisory
    scope: str | None = None
    rationale: str | None = None
    owner: str | None = None
    exceptions_process: str | None = None


class FactAttributes(BaseModel):
    """Attributes for fact entity type."""

    fact_type: str  # contract, budget, timeline, metric, status
    value: Any
    confidence: int = Field(ge=0, le=100, default=100)
    verified: bool = False


class CapabilityAttributes(BaseModel):
    """Attributes for capability entity type."""

    capability_type: str = "skill"  # skill, tool, process, practice
    proficiency: str = "intermediate"  # none, beginner, intermediate, advanced, expert
    coverage: int = Field(ge=0, le=100, default=50)  # % of team with this capability
    strategic_importance: str = "medium"  # low, medium, high, critical
    training_available: bool = False


class ArchitectureAttributes(BaseModel):
    """Attributes for architecture entity type."""

    architecture_type: str = "standard"  # pattern, principle, standard, guideline
    domain: str | None = None  # infrastructure, application, data, security
    maturity: str = "established"  # emerging, established, mature, deprecated
    adoption_status: str = "evaluating"  # evaluating, piloting, adopted, retiring


# ==================== Context Entity ====================


class ContextEntity(BaseModel):
    """Base CRF context entity."""

    entity_id: UUID = Field(default_factory=uuid4)
    customer_id: str
    entity_type: EntityType
    name: str
    description: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    relationships: list[Relationship] = Field(default_factory=list)
    validity: Validity | None = None
    provenance: Provenance | None = None
    supersedes: Supersession | None = None
    tags: list[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True

    def is_valid(self, at: datetime | None = None) -> bool:
        """Check if entity is currently valid."""
        if self.validity is None:
            return True
        return self.validity.is_valid(at)

    def to_dynamodb_item(self) -> dict[str, Any]:
        """Convert to DynamoDB item format."""
        item = {
            "customerId": self.customer_id,
            "entityId": str(self.entity_id),
            "entityType": self.entity_type,
            "name": self.name,
            "attributes": self.attributes,
            "relationships": [r.model_dump() for r in self.relationships],
            "tags": self.tags,
        }
        if self.description:
            item["description"] = self.description
        if self.validity:
            item["validity"] = self.validity.model_dump()
        if self.provenance:
            item["provenance"] = self.provenance.model_dump()
        if self.supersedes:
            item["supersedes"] = self.supersedes.model_dump()
        return item

    @classmethod
    def from_dynamodb_item(cls, item: dict[str, Any]) -> "ContextEntity":
        """Create from DynamoDB item."""
        relationships = [
            Relationship(
                target_id=UUID(r["target_id"]),
                type=RelationshipType(r["type"]),
                description=r.get("description"),
            )
            for r in item.get("relationships", [])
        ]

        validity = None
        if item.get("validity"):
            v = item["validity"]
            validity = Validity(
                valid_from=datetime.fromisoformat(v["valid_from"]) if v.get("valid_from") else None,
                valid_until=(
                    datetime.fromisoformat(v["valid_until"]) if v.get("valid_until") else None
                ),
            )

        provenance = None
        if item.get("provenance"):
            p = item["provenance"]
            provenance = Provenance(
                source=p["source"],
                created_at=datetime.fromisoformat(p["created_at"]),
                created_by=p["created_by"],
            )

        supersedes = None
        if item.get("supersedes"):
            s = item["supersedes"]
            supersedes = Supersession(
                entity_id=UUID(s["entity_id"]),
                reason=s["reason"],
                superseded_at=datetime.fromisoformat(s["superseded_at"]),
            )

        return cls(
            entity_id=UUID(item["entityId"]),
            customer_id=item["customerId"],
            entity_type=EntityType(item["entityType"]),
            name=item["name"],
            description=item.get("description"),
            attributes=item.get("attributes", {}),
            relationships=relationships,
            validity=validity,
            provenance=provenance,
            supersedes=supersedes,
            tags=item.get("tags", []),
        )


# ==================== Typed Entity Helpers ====================


class Organization(ContextEntity):
    """Organization entity (company, team, etc.)."""

    entity_type: EntityType = EntityType.ORGANIZATION
    attributes: OrganizationAttributes = Field(default_factory=OrganizationAttributes)


class System(ContextEntity):
    """System entity (application, service, infrastructure)."""

    entity_type: EntityType = EntityType.SYSTEM
    attributes: SystemAttributes = Field(default_factory=SystemAttributes)


class Policy(ContextEntity):
    """Policy entity (security, compliance, architectural rules)."""

    entity_type: EntityType = EntityType.POLICY
    attributes: PolicyAttributes = Field(default_factory=PolicyAttributes)


class Fact(ContextEntity):
    """Fact entity (contracts, budgets, timelines)."""

    entity_type: EntityType = EntityType.FACT
    attributes: FactAttributes


class Capability(ContextEntity):
    """Capability entity (skills, tools, processes)."""

    entity_type: EntityType = EntityType.CAPABILITY
    attributes: CapabilityAttributes = Field(default_factory=CapabilityAttributes)


# ==================== Context Query Helpers ====================


def get_policies_for_system(entities: list[ContextEntity], system_id: UUID) -> list[ContextEntity]:
    """Get all policies that constrain a given system."""
    policies = []
    for entity in entities:
        if entity.entity_type != EntityType.POLICY:
            continue
        for rel in entity.relationships:
            if (
                rel.type == RelationshipType.CONSTRAINS
                and rel.target_id == system_id
                and entity.is_valid()
            ):
                policies.append(entity)
    return policies


def get_active_entities(
    entities: list[ContextEntity], entity_type: EntityType | None = None
) -> list[ContextEntity]:
    """Get all currently valid entities, optionally filtered by type."""
    result = []
    for entity in entities:
        if entity_type and entity.entity_type != entity_type:
            continue
        if entity.is_valid():
            result.append(entity)
    return result
