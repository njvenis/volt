"""Durable G4 episode and GitHub lifecycle records."""

from sqlalchemy import (Boolean, CheckConstraint, Column, DateTime, ForeignKey,
                        Index, Integer, JSON, String, Table, Text, Uuid,
                        UniqueConstraint)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from uvm.persistence.schema import (exposures, groups, occurrences,
                                    uvm_metadata)


class _PortableJSON(TypeDecorator):
    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(JSONB() if dialect.name == "postgresql" else JSON())


_ID = Uuid(as_uuid=False)
_TZ = DateTime(timezone=True)
_JSON = _PortableJSON()

exposure_episodes = Table(
    "assessment_exposure_episodes", uvm_metadata,
    Column("episode_id", _ID, primary_key=True),
    Column("exposure_id", _ID, ForeignKey("exposures.exposure_id"), nullable=False),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("episode_number", Integer, nullable=False),
    Column("state_revision", Integer, nullable=False),
    Column("state", String, nullable=False),
    Column("is_current", Boolean, nullable=False),
    Column("opened_at", _TZ),
    Column("closed_at", _TZ),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("exposure_id", "episode_number", name="uq_episode_number"),
    CheckConstraint("episode_number > 0 AND state_revision > 0", name="episode_positive_revision"),
    CheckConstraint("state IN ('open','partially_remediated','remediated','review')", name="episode_state"),
    Index("ix_episode_group_current", "group_id", "is_current"),
)

exposure_episode_members = Table(
    "assessment_exposure_episode_members", uvm_metadata,
    Column("episode_id", _ID, ForeignKey("assessment_exposure_episodes.episode_id"), primary_key=True),
    Column("occurrence_id", _ID, ForeignKey("occurrences.occurrence_id"), primary_key=True),
    Column("status", String, nullable=False),
    Column("coverage_reason", String, nullable=False),
    Column("original_decision_id", _ID),
    Column("original_confirmed_at", _TZ),
    Column("confirmation_decision_id", _ID),
    Column("confirmed_at", _TZ),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("status IN ('outstanding','confirmed','continuity_covered','review')", name="episode_member_state"),
)

exposure_episode_events = Table(
    "assessment_exposure_episode_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("episode_id", _ID, ForeignKey("assessment_exposure_episodes.episode_id"), nullable=False),
    Column("state_revision", Integer, nullable=False),
    Column("event_type", String, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("origin", String, nullable=False),
    Column("decision_id", _ID),
    Column("occurrence_ids", _JSON, nullable=False),
    Column("source_observation_id", _ID),
    Column("observed_at", _TZ),
    Column("recorded_at", _TZ, nullable=False),
    Column("reason_codes", _JSON, nullable=False),
    Column("details", _JSON, nullable=False),
    UniqueConstraint("episode_id", "state_revision", name="uq_episode_event_revision"),
)

github_repositories = Table(
    "github_repositories", uvm_metadata,
    Column("repository_id", String, primary_key=True),
    Column("github_host", String, nullable=False),
    Column("owner", String, nullable=False),
    Column("name", String, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("audience_revision", Integer, nullable=False),
    Column("audience_document", _JSON, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("github_host", "owner", "name", name="uq_github_repo_name"),
)

github_repository_events = Table(
    "github_repository_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("action", String, nullable=False),
    Column("before_value", _JSON, nullable=False),
    Column("after_value", _JSON, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("control_evidence_ref", Text, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    UniqueConstraint("repository_id", "revision", name="uq_github_repository_revision"),
)

github_identity_links = Table(
    "github_identity_links", uvm_metadata,
    Column("link_id", _ID, primary_key=True),
    Column("github_host", String, nullable=False),
    Column("account_id", String, nullable=False),
    Column("account_login_at_link", String, nullable=False),
    Column("principal_id", String, nullable=False),
    Column("revision", Integer, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("control_evidence_ref", Text, nullable=False),
    Column("created_by", String, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("github_host", "account_id", name="uq_github_actor_link"),
)

github_identity_link_events = Table(
    "github_identity_link_events", uvm_metadata,
    Column("event_id", _ID, primary_key=True),
    Column("link_id", _ID, ForeignKey("github_identity_links.link_id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("actor_id", String, nullable=False),
    Column("action", String, nullable=False),
    Column("before_value", _JSON, nullable=False),
    Column("after_value", _JSON, nullable=False),
    Column("rationale", Text, nullable=False),
    Column("control_evidence_ref", Text, nullable=False),
    Column("occurred_at", _TZ, nullable=False),
    UniqueConstraint("link_id", "revision", name="uq_github_link_revision"),
)

github_group_issues = Table(
    "github_group_issues", uvm_metadata,
    Column("group_id", _ID, ForeignKey("groups.group_id"), primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("issue_node_id", String),
    Column("issue_number", Integer),
    Column("issue_url", Text),
    Column("state", String, nullable=False),
    Column("desired_revision", Integer, nullable=False),
    Column("applied_revision", Integer, nullable=False),
    Column("audience_revision", Integer, nullable=False),
    Column("last_reconciled_at", _TZ),
    Column("discrepancy_codes", _JSON, nullable=False),
    Column("document", _JSON, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("state IN ('unlinked','pending','applied','failed','uncertain','conflict','audience_blocked','needs_resubmission')", name="github_group_issue_state"),
)

github_create_reservations = Table(
    "github_create_reservations", uvm_metadata,
    Column("group_id", _ID, ForeignKey("groups.group_id"), primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("operation_id", _ID, nullable=False, unique=True),
    Column("marker", String, nullable=False, unique=True),
    Column("request_digest", String(64), nullable=False),
    Column("request_payload", _JSON, nullable=False),
    Column("state", String, nullable=False),
    Column("owner_token", String, nullable=False),
    Column("dispatch_started_at", _TZ),
    Column("issue_node_id", String),
    Column("issue_number", Integer),
    Column("issue_url", Text),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    CheckConstraint("state IN ('reserved','dispatching','uncertain','applied','conflict')", name="github_create_state"),
)

github_projection_intents = Table(
    "github_projection_intents", uvm_metadata,
    Column("projection_id", _ID, primary_key=True),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("issue_node_id", String),
    Column("issue_number", Integer),
    Column("desired_revision", Integer, nullable=False),
    Column("payload", _JSON, nullable=False),
    Column("state", String, nullable=False),
    Column("operation_id", _ID),
    Column("attempted_at", _TZ),
    Column("in_flight_step", String),
    Column("created_at", _TZ, nullable=False),
    Column("updated_at", _TZ, nullable=False),
    UniqueConstraint("group_id", "desired_revision", name="uq_github_projection_revision"),
    CheckConstraint("state IN ('pending','dispatching','uncertain','applied','failed','superseded')", name="github_projection_state"),
    Index("ix_github_projection_pending", "state", "created_at"),
)

github_projection_steps = Table(
    "github_projection_steps", uvm_metadata,
    Column("step_id", _ID, primary_key=True),
    Column("projection_id", _ID, ForeignKey("github_projection_intents.projection_id"), nullable=False),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("step_key", String, nullable=False),
    Column("request_digest", String(64), nullable=False),
    Column("request", _JSON, nullable=False),
    Column("state", String, nullable=False),
    Column("response", _JSON),
    Column("attempted_at", _TZ),
    Column("settled_at", _TZ),
    Column("created_at", _TZ, nullable=False),
    UniqueConstraint("projection_id", "step_key", name="uq_github_projection_step"),
    CheckConstraint("state IN ('dispatching','applied','uncertain','failed')",
        name="github_projection_step_state"),
    Index("ix_github_projection_step_group", "group_id", "state"),
)

github_command_previews = Table(
    "github_command_previews", uvm_metadata,
    Column("preview_id", _ID, primary_key=True),
    Column("principal_id", String, nullable=False),
    Column("link_id", _ID, ForeignKey("github_identity_links.link_id"), nullable=False),
    Column("link_revision", Integer, nullable=False),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("issue_number", Integer, nullable=False),
    Column("command", _JSON, nullable=False),
    Column("canonical_digest", String(64), nullable=False),
    Column("signature", Text, nullable=False),
    Column("expires_at", _TZ, nullable=False),
    Column("state", String, nullable=False),
    Column("acknowledged_at", _TZ),
    Column("created_at", _TZ, nullable=False),
    CheckConstraint("state IN ('previewed','acknowledged','executed','needs_resubmission','expired','denied')", name="github_preview_state"),
)

github_inbox_commands = Table(
    "github_inbox_commands", uvm_metadata,
    Column("inbox_id", _ID, primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("group_id", _ID, ForeignKey("groups.group_id"), nullable=False),
    Column("issue_number", Integer, nullable=False),
    Column("comment_id", String, nullable=False),
    Column("account_id", String, nullable=False),
    Column("link_id", _ID, ForeignKey("github_identity_links.link_id")),
    Column("preview_id", _ID, ForeignKey("github_command_previews.preview_id")),
    Column("preview_reference", String),
    Column("connector_command_id", _ID),
    Column("body", Text, nullable=False),
    Column("body_digest", String(64), nullable=False),
    Column("raw_comment", _JSON, nullable=False),
    Column("state", String, nullable=False),
    Column("outcome", _JSON),
    Column("first_seen_at", _TZ, nullable=False),
    Column("processed_at", _TZ),
    UniqueConstraint("repository_id", "comment_id", name="uq_github_comment"),
    CheckConstraint("state IN ('pending','applied','denied','needs_resubmission','conflict','error')", name="github_inbox_state"),
    Index("ix_github_inbox_pending", "state", "first_seen_at"),
)

github_poll_state = Table(
    "github_poll_state", uvm_metadata,
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), primary_key=True),
    Column("comments_checkpoint", String),
    Column("events_checkpoint", String),
    Column("last_full_reconcile_at", _TZ),
    Column("last_poll_at", _TZ),
    Column("updated_at", _TZ, nullable=False),
)

github_webhook_deliveries = Table(
    "github_webhook_deliveries", uvm_metadata,
    Column("delivery_id", String, primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("event_type", String, nullable=False),
    Column("action", String),
    Column("payload", _JSON, nullable=False),
    Column("body_digest", String(64), nullable=False),
    Column("secret_version", String, nullable=False),
    Column("state", String, nullable=False),
    Column("outcome", _JSON),
    Column("received_at", _TZ, nullable=False),
    Column("processed_at", _TZ),
    UniqueConstraint("repository_id", "delivery_id", name="uq_github_webhook_delivery"),
    CheckConstraint("state IN ('accepted','processing','processed','rejected','error')",
        name="github_webhook_delivery_state"),
    Index("ix_github_webhook_pending", "state", "received_at"),
)

github_external_events = Table(
    "github_external_events", uvm_metadata,
    Column("record_id", _ID, primary_key=True),
    Column("repository_id", String, ForeignKey("github_repositories.repository_id"), nullable=False),
    Column("github_event_id", String, nullable=False),
    Column("issue_number", Integer, nullable=False),
    Column("event_type", String, nullable=False),
    Column("actor_account_id", String),
    Column("raw_payload", _JSON, nullable=False),
    Column("payload_digest", String(64), nullable=False),
    Column("created_at", _TZ),
    Column("received_at", _TZ, nullable=False),
    Column("outcome", String, nullable=False),
    UniqueConstraint("repository_id", "github_event_id", name="uq_github_external_event"),
)

ALL_G4_TABLES = (exposure_episodes, exposure_episode_members,
    exposure_episode_events, github_repositories, github_identity_links,
    github_identity_link_events, github_group_issues, github_create_reservations,
    github_projection_intents, github_projection_steps, github_command_previews, github_inbox_commands,
    github_poll_state, github_webhook_deliveries)
