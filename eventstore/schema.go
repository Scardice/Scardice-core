package eventstore

import "time"

const (
	tableDomainEvents        = "domain_events"
	tableEventGlobalSequence = "event_global_sequence"
	tableAggregateHeads      = "aggregate_heads"
	tableProjectionControl   = "projection_control"
	tableProjectionReadModel = "projection_read_models"
	tableOperations          = "operations"
	tableOperationArtifacts  = "operation_artifacts"
	tableLaneHeads           = "lane_heads"
	tableInboxMessages       = "inbox_messages"
	tableOutboxEffects       = "outbox_effects"
	tableAdapterSecrets      = "adapter_secrets"
	tablePluginKV            = "plugin_kv"
	tableRevisionHeads       = "revision_heads"
	tableExecutionReceipts   = "execution_receipts"
	tableStoreReadiness      = "store_readiness"
	tableManagementActivity  = "management_activities"
	tableStoryLogSessions    = "story_log_sessions"
	tableStoryLogStates      = "story_log_states"
	tableStoryLogEntries     = "story_log_entries"
	tableStoryLogIntents     = "story_log_outbound_intents"
	tableStoryLogImports     = "story_log_imports"
)

var requiredEventStoreTables = []string{
	tableDomainEvents, tableEventGlobalSequence, tableAggregateHeads, tableProjectionControl,
	tableProjectionReadModel, tableOperations, tableOperationArtifacts, tableLaneHeads,
	tableInboxMessages, tableOutboxEffects, tableAdapterSecrets, tablePluginKV,
	tableRevisionHeads, tableExecutionReceipts, tableStoreReadiness, tableManagementActivity,
	tableStoryLogSessions, tableStoryLogStates, tableStoryLogEntries, tableStoryLogIntents, tableStoryLogImports,
}

var requiredEventStoreIndexes = map[string]bool{
	tableDomainEvents + ":ux_domain_events_stream_version":          true,
	tableDomainEvents + ":ux_domain_events_event_id":                true,
	tableDomainEvents + ":ux_domain_events_global_position":         true,
	tableDomainEvents + ":ix_domain_events_global_position":         false,
	tableAggregateHeads + ":pk_aggregate_heads":                     true,
	tableProjectionReadModel + ":pk_projection_read_models":         true,
	tableOperations + ":ux_operations_operation_id":                 true,
	tableOperations + ":ux_operations_idempotency":                  true,
	tableOperationArtifacts + ":ux_operation_artifacts_artifact_id": true,
	tableLaneHeads + ":ix_lane_heads_lookup":                        false,
	tableLaneHeads + ":ix_lane_heads_action_ready":                  false,
	tableLaneHeads + ":ix_lane_heads_scheduling_version":            false,
	tableInboxMessages + ":ix_inbox_endpoint_provider":              false,
	tableInboxMessages + ":ux_inbox_lane_sequence":                  true,
	tableInboxMessages + ":ix_inbox_status_lease":                   false,
	tableInboxMessages + ":ix_inbox_lane_status_ordering":           false,
	tableInboxMessages + ":ix_inbox_scheduling_version":             false,
	tableInboxMessages + ":ix_inbox_terminal_retention":             false,
	tableOutboxEffects + ":ux_outbox_effect_id":                     true,
	tableOutboxEffects + ":ux_outbox_lane_sequence":                 true,
	tableOutboxEffects + ":ix_outbox_status_attempt":                false,
	tableOutboxEffects + ":ix_outbox_lane_status_ordering":          false,
	tableOutboxEffects + ":ix_outbox_scheduling_version":            false,
	tableAdapterSecrets + ":ux_adapter_secret_ref_version":          true,
	tablePluginKV + ":ux_plugin_extension_key":                      true,
	tableRevisionHeads + ":ix_revision_heads_lookup":                false,
	tableExecutionReceipts + ":ux_execution_receipts_identity":      true,
	tableManagementActivity + ":ux_management_activities_id":        true,
	tableManagementActivity + ":ix_management_activities_recent":    false,
	tableStoryLogSessions + ":ix_story_log_sessions_dice":           false,
	tableStoryLogSessions + ":ix_story_log_session_lookup":          false,
	tableStoryLogSessions + ":ix_story_log_sessions_updated":        false,
	tableStoryLogStates + ":ix_story_log_state_scope":               false,
	tableStoryLogEntries + ":ix_story_log_entries_scope_session":    false,
	tableStoryLogEntries + ":ix_story_log_entries_raw":              false,
	tableStoryLogIntents + ":ux_story_log_intent_effect":            true,
	tableStoryLogIntents + ":ix_story_log_intent_scope_session":     false,
	tableStoryLogImports + ":ix_story_log_import_owner":             false,
	tableStoryLogImports + ":ix_story_log_import_dice_identity":     false,
}

var requiredEventStoreIndexColumns = map[string][]string{
	tableDomainEvents + ":ux_domain_events_stream_version":          {"aggregate_type", "aggregate_id", "aggregate_version"},
	tableDomainEvents + ":ux_domain_events_event_id":                {"event_id"},
	tableDomainEvents + ":ux_domain_events_global_position":         {"global_position"},
	tableDomainEvents + ":ix_domain_events_global_position":         {"global_position"},
	tableAggregateHeads + ":pk_aggregate_heads":                     {"aggregate_type", "aggregate_id"},
	tableProjectionReadModel + ":pk_projection_read_models":         {"projection_generation", "projection_name", "row_key"},
	tableOperations + ":ux_operations_operation_id":                 {"operation_id"},
	tableOperations + ":ux_operations_idempotency":                  {"principal_id", "idempotency_scope", "idempotency_key"},
	tableOperationArtifacts + ":ux_operation_artifacts_artifact_id": {"artifact_id"},
	tableLaneHeads + ":ix_lane_heads_lookup":                        {"kind", "lookup_digest"},
	tableLaneHeads + ":ix_lane_heads_action_ready":                  {"kind", "ready_action", "ready_at", "active_since", "id"},
	tableLaneHeads + ":ix_lane_heads_scheduling_version":            {"scheduling_version", "id"},
	tableInboxMessages + ":ix_inbox_endpoint_provider":              {"dedupe_lookup"},
	tableInboxMessages + ":ux_inbox_lane_sequence":                  {"lane_id", "ordering_sequence"},
	tableInboxMessages + ":ix_inbox_status_lease":                   {"status", "lease_expiry"},
	tableInboxMessages + ":ix_inbox_lane_status_ordering":           {"lane_id", "status", "ordering_sequence"},
	tableInboxMessages + ":ix_inbox_scheduling_version":             {"scheduling_version", "inbox_id"},
	tableInboxMessages + ":ix_inbox_terminal_retention":             {"status", "completed_at", "inbox_id"},
	tableOutboxEffects + ":ux_outbox_effect_id":                     {"effect_id"},
	tableOutboxEffects + ":ux_outbox_lane_sequence":                 {"lane_id", "ordering_sequence"},
	tableOutboxEffects + ":ix_outbox_status_attempt":                {"status", "next_attempt_at", "lease_expiry"},
	tableOutboxEffects + ":ix_outbox_lane_status_ordering":          {"lane_id", "status", "ordering_sequence"},
	tableOutboxEffects + ":ix_outbox_scheduling_version":            {"scheduling_version", "effect_id"},
	tableAdapterSecrets + ":ux_adapter_secret_ref_version":          {"secret_ref", "secret_version"},
	tablePluginKV + ":ux_plugin_extension_key":                      {"extension_id", "key"},
	tableRevisionHeads + ":ix_revision_heads_lookup":                {"lookup_digest"},
	tableExecutionReceipts + ":ux_execution_receipts_identity":      {"identity"},
	tableManagementActivity + ":ux_management_activities_id":        {"id"},
	tableManagementActivity + ":ix_management_activities_recent":    {"occurred_at_unix_milli", "global_position"},
	tableStoryLogSessions + ":ix_story_log_sessions_dice":           {"dice_lookup"},
	tableStoryLogSessions + ":ix_story_log_session_lookup":          {"lookup_digest"},
	tableStoryLogSessions + ":ix_story_log_sessions_updated":        {"updated_at", "id"},
	tableStoryLogStates + ":ix_story_log_state_scope":               {"scope_lookup"},
	tableStoryLogEntries + ":ix_story_log_entries_scope_session":    {"scope_lookup", "session_id"},
	tableStoryLogEntries + ":ix_story_log_entries_raw":              {"scope_lookup", "session_id", "raw_msg_lookup"},
	tableStoryLogIntents + ":ix_story_log_intent_scope_session":     {"scope_lookup", "session_id"},
	tableStoryLogImports + ":ix_story_log_import_owner":             {"scope_lookup"},
	tableStoryLogImports + ":ix_story_log_import_dice_identity":     {"dice_lookup", "id"},
}

// Binary fields intentionally use GORM's native []byte mapping: PostgreSQL
// becomes bytea, SQLite becomes blob, and MySQL selects varbinary/mediumblob/
// longblob from the declared size. This avoids dialect-invalid type:blob tags
// while retaining the bounded payload capacities required by the contract.
type domainEventRow struct {
	EventID               string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_event_id"`
	AggregateType         string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_stream_version"`
	AggregateID           string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_stream_version"`
	AggregateVersion      uint64    `gorm:"not null;uniqueIndex:ux_domain_events_stream_version"`
	GlobalPosition        uint64    `gorm:"not null;uniqueIndex:ux_domain_events_global_position;index:ix_domain_events_global_position,priority:1"`
	EventType             string    `gorm:"type:varchar(255);not null"`
	SchemaVersion         uint16    `gorm:"not null"`
	Payload               []byte    `gorm:"size:262144"`
	CommandID             string    `gorm:"type:varchar(255)"`
	CorrelationID         string    `gorm:"type:varchar(255)"`
	CausationID           string    `gorm:"type:varchar(255)"`
	PrincipalID           string    `gorm:"type:varchar(255)"`
	Producer              string    `gorm:"type:varchar(255);not null"`
	OccurredAtUnixNanoUTC int64     `gorm:"not null"`
	Checksum              []byte    `gorm:"size:32;not null"`
	CreatedAt             time.Time `gorm:"not null;index"`
}

func (domainEventRow) TableName() string { return tableDomainEvents }

type eventGlobalSequenceRow struct {
	SingletonID  string    `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	NextPosition uint64    `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

func (eventGlobalSequenceRow) TableName() string { return tableEventGlobalSequence }

type aggregateHeadRow struct {
	AggregateType  string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_aggregate_heads,priority:1"`
	AggregateID    string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_aggregate_heads,priority:2"`
	CurrentVersion uint64    `gorm:"not null"`
	UpdatedAt      time.Time `gorm:"not null"`
}

func (aggregateHeadRow) TableName() string { return tableAggregateHeads }

type projectionControlRow struct {
	SingletonID         string    `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	ActiveGeneration    string    `gorm:"type:varchar(255);not null"`
	TerminalPosition    uint64    `gorm:"not null"`
	ProjectorSetVersion string    `gorm:"type:varchar(255);not null"`
	PublicationState    string    `gorm:"type:varchar(32);not null"`
	UpdatedAt           time.Time `gorm:"not null"`
}

func (projectionControlRow) TableName() string { return tableProjectionControl }

type projectionReadModelRow struct {
	ProjectionGeneration string `gorm:"column:projection_generation;type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:1"`
	ProjectionName       string `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:2"`
	RowKey               string `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:3"`
	Payload              []byte
	UpdatedAt            time.Time `gorm:"not null"`
}

func (projectionReadModelRow) TableName() string { return tableProjectionReadModel }

type operationRow struct {
	Version          uint64 `gorm:"not null"`
	Status           string `gorm:"type:varchar(32);not null"`
	OperationID      string `gorm:"type:varchar(255);not null;primaryKey;uniqueIndex:ux_operations_operation_id"`
	Kind             string `gorm:"type:varchar(255);not null"`
	PrincipalID      string `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:1"`
	ResourceType     string `gorm:"type:varchar(255)"`
	ResourceID       string `gorm:"type:varchar(255)"`
	IdempotencyScope string `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:2"`
	IdempotencyKey   string `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:3"`
	RequestID        string `gorm:"type:varchar(255)"`
	RequestDigest    []byte `gorm:"size:32"`
	CorrelationID    string `gorm:"type:varchar(255)"`
	ErrorCode        string `gorm:"type:varchar(255)"`
	ResultCode       string `gorm:"type:varchar(255)"`
	ArtifactRef      string `gorm:"column:artifact_id;type:varchar(255)"`
	PrivateContext   []byte
	CreatedAt        time.Time `gorm:"not null"`
	UpdatedAt        time.Time `gorm:"not null"`
	ExpiresAt        *time.Time
}

func (operationRow) TableName() string { return tableOperations }

type managementActivityRow struct {
	GlobalPosition      uint64 `gorm:"primaryKey;autoIncrement;index:ix_management_activities_recent,priority:2,sort:desc"`
	ID                  string `gorm:"type:varchar(255);not null;uniqueIndex:ux_management_activities_id"`
	OccurredAtUnixMilli int64  `gorm:"not null;index:ix_management_activities_recent,priority:1,sort:desc"`
	Action              string `gorm:"type:varchar(255);not null"`
	Label               string `gorm:"type:varchar(255);not null"`
	Resource            string `gorm:"type:varchar(255);not null"`
	Status              string `gorm:"type:varchar(32);not null"`
	HTTPStatus          int    `gorm:"not null"`
	Actor               string `gorm:"type:varchar(255);not null"`
	SourceIP            string `gorm:"type:varchar(128);not null"`
}

func (managementActivityRow) TableName() string { return tableManagementActivity }

type operationArtifactRow struct {
	ArtifactID       string `gorm:"type:varchar(255);not null;primaryKey;uniqueIndex:ux_operation_artifacts_artifact_id"`
	Version          uint64 `gorm:"not null"`
	OperationID      string `gorm:"type:varchar(255);not null"`
	OwnerPrincipalID string `gorm:"type:varchar(255);not null"`
	MediaType        string `gorm:"type:varchar(255);not null"`
	SafeFilename     string `gorm:"type:varchar(255)"`
	Size             int64  `gorm:"not null"`
	Status           string `gorm:"type:varchar(32);not null"`
	Data             []byte
	ExpiresAt        time.Time `gorm:"not null"`
	ConsumedAt       *time.Time
}

func (operationArtifactRow) TableName() string { return tableOperationArtifacts }

type laneHeadRow struct {
	ID                uint64     `gorm:"primaryKey;autoIncrement;index:ix_lane_heads_action_ready,priority:5;index:ix_lane_heads_scheduling_version,priority:2"`
	Kind              string     `gorm:"type:varchar(32);not null;index:ix_lane_heads_lookup,priority:1;index:ix_lane_heads_action_ready,priority:1"`
	Lane              string     `gorm:"type:text;not null"`
	LookupDigest      []byte     `gorm:"size:32;not null;index:ix_lane_heads_lookup,priority:2"`
	NextSequence      uint64     `gorm:"not null"`
	ActiveID          string     `gorm:"type:varchar(255);not null;default:''"`
	ActiveSequence    uint64     `gorm:"not null;default:0"`
	ActiveSince       *time.Time `gorm:"index:ix_lane_heads_action_ready,priority:4"`
	ReadyAt           *time.Time `gorm:"index:ix_lane_heads_action_ready,priority:3"`
	ReadyAction       string     `gorm:"type:varchar(32);not null;default:'';index:ix_lane_heads_action_ready,priority:2"`
	SchedulingVersion uint8      `gorm:"not null;default:0;index:ix_lane_heads_scheduling_version,priority:1"`
	UpdatedAt         time.Time  `gorm:"not null"`
}

func (*laneHeadRow) TableName() string { return tableLaneHeads }

type inboxMessageRow struct {
	InboxID             string     `gorm:"type:varchar(255);primaryKey;index:ix_inbox_scheduling_version,priority:2;index:ix_inbox_terminal_retention,priority:3"`
	EndpointID          string     `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	ProviderEventKey    string     `gorm:"column:provider_event_id;type:bytes;size:16777217;serializer:raw_string;not null"`
	DedupeLookup        []byte     `gorm:"size:32;not null;index:ix_inbox_endpoint_provider"`
	Lane                string     `gorm:"type:text;not null"`
	LaneID              uint64     `gorm:"not null;uniqueIndex:ux_inbox_lane_sequence,priority:1;index:ix_inbox_lane_status_ordering,priority:1"`
	Subject             string     `gorm:"type:bytes;size:16777217;serializer:raw_string"`
	OrderingSequence    uint64     `gorm:"not null;uniqueIndex:ux_inbox_lane_sequence,priority:2;index:ix_inbox_lane_status_ordering,priority:3"`
	Status              string     `gorm:"type:varchar(32);not null;index:ix_inbox_status_lease,priority:1;index:ix_inbox_lane_status_ordering,priority:2;index:ix_inbox_terminal_retention,priority:1"`
	Version             uint64     `gorm:"not null"`
	LeaseOwner          string     `gorm:"type:varchar(255)"`
	LeaseEpoch          uint64     `gorm:"not null"`
	LeaseExpiry         *time.Time `gorm:"index:ix_inbox_status_lease,priority:2"`
	AttemptID           string     `gorm:"type:varchar(255)"`
	CallbackStartedAt   *time.Time
	CompletedAt         *time.Time `gorm:"index:ix_inbox_terminal_retention,priority:2"`
	Payload             []byte
	ContentDigest       []byte `gorm:"size:32"`
	SchedulingVersion   uint8  `gorm:"not null;default:0;index:ix_inbox_scheduling_version,priority:1"`
	WorkflowID          string `gorm:"type:varchar(255)"`
	ResolutionPrincipal string `gorm:"type:varchar(255)"`
	ResolutionReason    string `gorm:"type:varchar(512)"`
	ResolutionAt        *time.Time
}

func (*inboxMessageRow) TableName() string { return tableInboxMessages }

type outboxEffectRow struct {
	EffectID            string     `gorm:"type:varchar(255);primaryKey;uniqueIndex:ux_outbox_effect_id;index:ix_outbox_scheduling_version,priority:2"`
	Version             uint64     `gorm:"not null"`
	EndpointID          string     `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Lane                string     `gorm:"type:text;not null"`
	LaneID              uint64     `gorm:"not null;uniqueIndex:ux_outbox_lane_sequence,priority:1;index:ix_outbox_lane_status_ordering,priority:1"`
	Subject             string     `gorm:"type:bytes;size:16777217;serializer:raw_string"`
	OrderingSequence    uint64     `gorm:"not null;uniqueIndex:ux_outbox_lane_sequence,priority:2;index:ix_outbox_lane_status_ordering,priority:3"`
	EffectClass         string     `gorm:"type:varchar(64);not null"`
	RiskClass           string     `gorm:"type:varchar(64);not null"`
	Status              string     `gorm:"type:varchar(32);not null;index:ix_outbox_status_attempt,priority:1;index:ix_outbox_lane_status_ordering,priority:2"`
	AttemptID           string     `gorm:"type:varchar(255)"`
	LeaseOwner          string     `gorm:"type:varchar(255)"`
	LeaseEpoch          uint64     `gorm:"not null"`
	LeaseExpiry         *time.Time `gorm:"index:ix_outbox_status_attempt,priority:3"`
	DispatchedAt        *time.Time
	DeadlineAt          *time.Time
	NextAttemptAt       *time.Time `gorm:"index:ix_outbox_status_attempt,priority:2"`
	Payload             []byte
	ContentDigest       []byte `gorm:"size:32"`
	ErrorCode           string `gorm:"type:varchar(255)"`
	ResultCode          string `gorm:"type:varchar(255)"`
	ProviderMessageID   string `gorm:"type:varchar(255)"`
	CompletedAt         *time.Time
	SchedulingVersion   uint8     `gorm:"not null;default:0;index:ix_outbox_scheduling_version,priority:1"`
	CreatedAt           time.Time `gorm:"not null"`
	RetryCount          uint32    `gorm:"not null"`
	ResolutionPrincipal string    `gorm:"type:varchar(255)"`
	ResolutionReason    string    `gorm:"type:varchar(512)"`
	ResolutionAt        *time.Time
}

func (*outboxEffectRow) TableName() string { return tableOutboxEffects }

type adapterSecretRow struct {
	SecretRef     string `gorm:"type:bytes;size:512;serializer:raw_string;not null;uniqueIndex:ux_adapter_secret_ref_version,priority:1"`
	SecretVersion uint64 `gorm:"not null;uniqueIndex:ux_adapter_secret_ref_version,priority:2"`
	EndpointID    string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	AdapterID     string `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	AdapterType   string `gorm:"type:varchar(255);not null"`
	Value         []byte
	RowVersion    uint64    `gorm:"not null"`
	CreatedAt     time.Time `gorm:"not null"`
	UpdatedAt     time.Time `gorm:"not null"`
}

func (adapterSecretRow) TableName() string { return tableAdapterSecrets }

type pluginKVRow struct {
	ExtensionID string `gorm:"type:bytes;size:255;serializer:raw_string;primaryKey;uniqueIndex:ux_plugin_extension_key,priority:1"`
	Key         string `gorm:"type:bytes;size:1024;serializer:raw_string;primaryKey;uniqueIndex:ux_plugin_extension_key,priority:2"`
	Value       []byte
	RowVersion  uint64    `gorm:"not null"`
	CreatedAt   time.Time `gorm:"not null"`
	UpdatedAt   time.Time `gorm:"not null"`
}

func (pluginKVRow) TableName() string { return tablePluginKV }

// revisionHeadRow tracks monotonic changes to catalog/plugin resources.
type revisionHeadRow struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement"`
	LookupDigest []byte    `gorm:"size:32;not null;index:ix_revision_heads_lookup"`
	Kind         string    `gorm:"type:bytes;size:255;serializer:raw_string;not null"`
	Scope        string    `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Member       string    `gorm:"type:bytes;size:16777217;serializer:raw_string;not null"`
	Revision     uint64    `gorm:"not null"`
	Present      bool      `gorm:"not null;default:false"`
	UpdatedAt    time.Time `gorm:"not null"`
}

func (*revisionHeadRow) TableName() string { return tableRevisionHeads }

type executionReceiptRow struct {
	Identity      string `gorm:"type:bytes;size:1024;serializer:raw_string;primaryKey;uniqueIndex:ux_execution_receipts_identity"`
	RequestDigest []byte `gorm:"size:32;not null"`
	AttemptID     string `gorm:"type:varchar(255);not null"`
	Version       uint64 `gorm:"not null"`
	Status        string `gorm:"type:varchar(32);not null"`
	LeaseOwner    string `gorm:"type:varchar(255);not null"`
	LeaseEpoch    uint64 `gorm:"not null"`
	LeaseExpiry   *time.Time
	StartedAt     time.Time `gorm:"not null"`
	CompletedAt   *time.Time
	UpdatedAt     time.Time `gorm:"not null"`
}

func (executionReceiptRow) TableName() string { return tableExecutionReceipts }

type storeReadinessRow struct {
	SingletonID      string `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	Mode             string `gorm:"type:varchar(16);not null"`
	SchemaVersion    string `gorm:"type:varchar(64);not null"`
	DatabaseIdentity string `gorm:"type:varchar(255);not null"`
	CompletedAt      *time.Time
}

func (storeReadinessRow) TableName() string { return tableStoreReadiness }

func schemaModels() []any {
	return []any{
		&domainEventRow{}, &eventGlobalSequenceRow{}, &aggregateHeadRow{},
		&projectionControlRow{}, &projectionReadModelRow{}, &operationRow{},
		&operationArtifactRow{}, &laneHeadRow{}, &inboxMessageRow{},
		&outboxEffectRow{}, &adapterSecretRow{}, &pluginKVRow{}, &revisionHeadRow{}, &executionReceiptRow{},
		&storeReadinessRow{}, &managementActivityRow{},
		&storyLogSessionRow{}, &storyLogStateRow{}, &logArchiveEntryRow{}, &logArchiveIntentRow{}, &storyLogImportRow{},
	}
}

func schemaModelsWithoutOperationArtifacts() []any {
	return []any{
		&domainEventRow{}, &eventGlobalSequenceRow{}, &aggregateHeadRow{},
		&projectionControlRow{}, &projectionReadModelRow{}, &operationRow{},
		&laneHeadRow{}, &inboxMessageRow{}, &outboxEffectRow{},
		&adapterSecretRow{}, &pluginKVRow{}, &revisionHeadRow{}, &executionReceiptRow{},
		&storeReadinessRow{}, &managementActivityRow{},
		&storyLogSessionRow{}, &storyLogStateRow{}, &logArchiveEntryRow{}, &logArchiveIntentRow{}, &storyLogImportRow{},
	}
}
