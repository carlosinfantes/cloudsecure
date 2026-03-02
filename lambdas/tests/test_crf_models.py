"""Tests for CRF (Context Reasoning Format) models."""

from datetime import datetime, timedelta
from uuid import UUID, uuid4

from shared.crf_models import (
    ContextEntity,
    EntityType,
    Organization,
    OrganizationAttributes,
    Policy,
    PolicyAttributes,
    Relationship,
    RelationshipType,
    System,
    SystemAttributes,
    Validity,
    get_active_entities,
    get_policies_for_system,
)


class TestEntityType:
    """Tests for EntityType enum."""

    def test_all_entity_types_exist(self):
        assert EntityType.ORGANIZATION == "organization"
        assert EntityType.SYSTEM == "system"
        assert EntityType.POLICY == "policy"
        assert EntityType.FACT == "fact"
        assert EntityType.CAPABILITY == "capability"
        assert EntityType.ARCHITECTURE == "architecture"


class TestRelationshipType:
    """Tests for RelationshipType enum."""

    def test_common_relationship_types(self):
        assert RelationshipType.OWNS == "owns"
        assert RelationshipType.DEPENDS_ON == "depends_on"
        assert RelationshipType.CONSTRAINS == "constrains"
        assert RelationshipType.PART_OF == "part_of"


class TestValidity:
    """Tests for Validity model."""

    def test_always_valid(self):
        validity = Validity()
        assert validity.is_valid() is True

    def test_valid_from_future(self):
        validity = Validity(valid_from=datetime.utcnow() + timedelta(days=1))
        assert validity.is_valid() is False

    def test_valid_until_past(self):
        validity = Validity(valid_until=datetime.utcnow() - timedelta(days=1))
        assert validity.is_valid() is False

    def test_currently_valid(self):
        validity = Validity(
            valid_from=datetime.utcnow() - timedelta(days=1),
            valid_until=datetime.utcnow() + timedelta(days=1),
        )
        assert validity.is_valid() is True


class TestContextEntity:
    """Tests for ContextEntity base model."""

    def test_create_minimal_entity(self):
        entity = ContextEntity(
            customer_id="cust-123",
            entity_type=EntityType.ORGANIZATION,
            name="Test Organization",
        )
        assert entity.customer_id == "cust-123"
        assert entity.entity_type == EntityType.ORGANIZATION
        assert entity.name == "Test Organization"
        assert isinstance(entity.entity_id, UUID)

    def test_entity_is_valid_by_default(self):
        entity = ContextEntity(
            customer_id="cust-123",
            entity_type=EntityType.SYSTEM,
            name="Test System",
        )
        assert entity.is_valid() is True

    def test_to_dynamodb_item(self):
        entity = ContextEntity(
            customer_id="cust-123",
            entity_type=EntityType.POLICY,
            name="Security Policy",
            description="Test policy",
            tags=["security", "mandatory"],
        )
        item = entity.to_dynamodb_item()

        assert item["customerId"] == "cust-123"
        assert item["entityType"] == "policy"
        assert item["name"] == "Security Policy"
        assert item["description"] == "Test policy"
        assert "security" in item["tags"]

    def test_from_dynamodb_item(self):
        item = {
            "customerId": "cust-456",
            "entityId": str(uuid4()),
            "entityType": "system",
            "name": "Production API",
            "attributes": {"criticality": "high"},
            "relationships": [],
            "tags": ["production"],
        }
        entity = ContextEntity.from_dynamodb_item(item)

        assert entity.customer_id == "cust-456"
        assert entity.entity_type == EntityType.SYSTEM
        assert entity.name == "Production API"

    def test_entity_with_relationships(self):
        org_id = uuid4()
        entity = ContextEntity(
            customer_id="cust-123",
            entity_type=EntityType.SYSTEM,
            name="API Service",
            relationships=[
                Relationship(
                    target_id=org_id,
                    type=RelationshipType.OWNED_BY,
                    description="Owned by Engineering team",
                )
            ],
        )

        assert len(entity.relationships) == 1
        assert entity.relationships[0].target_id == org_id
        assert entity.relationships[0].type == RelationshipType.OWNED_BY


class TestOrganization:
    """Tests for Organization typed entity."""

    def test_create_organization(self):
        org = Organization(
            customer_id="cust-123",
            name="Engineering Team",
            attributes=OrganizationAttributes(
                org_type="team",
                headcount=10,
                compliance_frameworks=["SOC2", "ISO27001"],
            ),
        )

        assert org.entity_type == EntityType.ORGANIZATION
        assert org.attributes.org_type == "team"
        assert org.attributes.headcount == 10
        assert "SOC2" in org.attributes.compliance_frameworks


class TestSystem:
    """Tests for System typed entity."""

    def test_create_system(self):
        system = System(
            customer_id="cust-123",
            name="Payment Service",
            attributes=SystemAttributes(
                system_type="service",
                status="production",
                criticality="critical",
                data_classification="confidential",
                technology_stack=["Python", "PostgreSQL", "Redis"],
            ),
        )

        assert system.entity_type == EntityType.SYSTEM
        assert system.attributes.criticality == "critical"
        assert system.attributes.data_classification == "confidential"


class TestPolicy:
    """Tests for Policy typed entity."""

    def test_create_policy(self):
        policy = Policy(
            customer_id="cust-123",
            name="MFA Required Policy",
            description="All users must have MFA enabled",
            attributes=PolicyAttributes(
                policy_type="security",
                enforcement="mandatory",
                owner="Security Team",
            ),
        )

        assert policy.entity_type == EntityType.POLICY
        assert policy.attributes.enforcement == "mandatory"


class TestQueryHelpers:
    """Tests for CRF query helper functions."""

    def test_get_active_entities_filters_expired(self):
        entities = [
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.SYSTEM,
                name="Active System",
            ),
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.SYSTEM,
                name="Expired System",
                validity=Validity(valid_until=datetime.utcnow() - timedelta(days=1)),
            ),
        ]

        active = get_active_entities(entities)
        assert len(active) == 1
        assert active[0].name == "Active System"

    def test_get_active_entities_filters_by_type(self):
        entities = [
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.SYSTEM,
                name="System 1",
            ),
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.POLICY,
                name="Policy 1",
            ),
        ]

        systems = get_active_entities(entities, EntityType.SYSTEM)
        assert len(systems) == 1
        assert systems[0].entity_type == EntityType.SYSTEM

    def test_get_policies_for_system(self):
        system_id = uuid4()

        entities = [
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.SYSTEM,
                entity_id=system_id,
                name="Target System",
            ),
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.POLICY,
                name="Applicable Policy",
                relationships=[
                    Relationship(
                        target_id=system_id,
                        type=RelationshipType.CONSTRAINS,
                    )
                ],
            ),
            ContextEntity(
                customer_id="cust-123",
                entity_type=EntityType.POLICY,
                name="Unrelated Policy",
                relationships=[
                    Relationship(
                        target_id=uuid4(),
                        type=RelationshipType.CONSTRAINS,
                    )
                ],
            ),
        ]

        policies = get_policies_for_system(entities, system_id)
        assert len(policies) == 1
        assert policies[0].name == "Applicable Policy"
