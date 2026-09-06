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
	tableSubjectFences       = "subject_fences"
	tableStoreReadiness      = "store_readiness"
)

var requiredEventStoreTables = []string{
	tableDomainEvents, tableEventGlobalSequence, tableAggregateHeads,
	tableProjectionControl, tableProjectionReadModel, tableOperations,
	tableOperationArtifacts, tableLaneHeads, tableInboxMessages,
	tableOutboxEffects, tableAdapterSecrets, tablePluginKV,
	tableSubjectFences, tableStoreReadiness,
}

// requiredEventStoreIndexes is keyed as table:index to make the exact table
// that owns an index explicit in schema tests and migration reviews.
var requiredEventStoreIndexes = map[string]bool{
	tableDomainEvents + ":ux_domain_events_stream_version": true,
	tableDomainEvents + ":ux_domain_events_event_id":       true,
	tableDomainEvents + ":ux_domain_events_global_position": true,
	tableDomainEvents + ":ix_domain_events_global_position": false,
	tableAggregateHeads + ":pk_aggregate_heads":              true,
	tableProjectionReadModel + ":pk_projection_read_models":  true,
	tableOperations + ":ux_operations_operation_id":          true,
	tableOperations + ":ux_operations_idempotency":            true,
	tableOperationArtifacts + ":ux_operation_artifacts_artifact_id": true,
	tableLaneHeads + ":pk_lane_heads":                         true,
	tableInboxMessages + ":ux_inbox_endpoint_provider":        true,
	tableInboxMessages + ":ux_inbox_lane_sequence":            true,
	tableInboxMessages + ":ix_inbox_status_lease":             false,
	tableOutboxEffects + ":ux_outbox_effect_id":                true,
	tableOutboxEffects + ":ux_outbox_lane_sequence":            true,
	tableOutboxEffects + ":ix_outbox_status_attempt":           false,
	tableAdapterSecrets + ":ux_adapter_secret_ref_version":    true,
	tablePluginKV + ":ux_plugin_extension_key":                 true,
	tableSubjectFences + ":ux_subject_fence_key_scope":         true,
}

type domainEventRow struct {
	EventID                string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_event_id"`
	AggregateType          string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_stream_version"`
	AggregateID            string    `gorm:"type:varchar(255);not null;uniqueIndex:ux_domain_events_stream_version"`
	AggregateVersion       uint64    `gorm:"not null;uniqueIndex:ux_domain_events_stream_version"`
	GlobalPosition         uint64    `gorm:"not null;uniqueIndex:ux_domain_events_global_position;index:ix_domain_events_global_position,priority:1"`
	EventType              string    `gorm:"type:varchar(255);not null"`
	SchemaVersion          uint16    `gorm:"not null"`
	Payload                []byte    `gorm:"type:blob;not null"`
	CommandID              string    `gorm:"type:varchar(255)"`
	CorrelationID          string    `gorm:"type:varchar(255)"`
	CausationID            string    `gorm:"type:varchar(255)"`
	PrincipalID             string    `gorm:"type:varchar(255)"`
	Producer               string    `gorm:"type:varchar(255);not null"`
	OccurredAtUnixNanoUTC  int64     `gorm:"not null"`
	Checksum               []byte    `gorm:"type:blob;size:32;not null"`
	CreatedAt              time.Time `gorm:"not null;index"`
}

func (domainEventRow) TableName() string { return tableDomainEvents }

type eventGlobalSequenceRow struct {
	SingletonID  string    `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	NextPosition uint64    `gorm:"not null"`
	UpdatedAt    time.Time `gorm:"not null"`
}

func (eventGlobalSequenceRow) TableName() string { return tableEventGlobalSequence }

type aggregateHeadRow struct {
	AggregateType    string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_aggregate_heads,priority:1"`
	AggregateID      string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_aggregate_heads,priority:2"`
	CurrentVersion   uint64    `gorm:"not null"`
	UpdatedAt        time.Time `gorm:"not null"`
}

func (aggregateHeadRow) TableName() string { return tableAggregateHeads }

type projectionControlRow struct {
	SingletonID       string    `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	ActiveGeneration  string    `gorm:"type:varchar(255);not null"`
	TerminalPosition  uint64    `gorm:"not null"`
	ProjectorSetVersion string  `gorm:"type:varchar(255);not null"`
	PublicationState  string    `gorm:"type:varchar(32);not null"`
	UpdatedAt         time.Time `gorm:"not null"`
}

func (projectionControlRow) TableName() string { return tableProjectionControl }

type projectionReadModelRow struct {
	ProjectionGeneration string    `gorm:"column:projection_generation;type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:1"`
	ProjectionName       string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:2"`
	RowKey               string    `gorm:"type:varchar(255);primaryKey;uniqueIndex:pk_projection_read_models,priority:3"`
	Payload              []byte    `gorm:"type:blob;not null"`
	UpdatedAt            time.Time `gorm:"not null"`
}

func (projectionReadModelRow) TableName() string { return tableProjectionReadModel }

type operationRow struct {
	OperationID       string     `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_operation_id"`
	Version           uint64     `gorm:"not null"`
	Status            string     `gorm:"type:varchar(32);not null"`
	Kind              string     `gorm:"type:varchar(255);not null"`
	PrincipalID       string     `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:1"`
	ResourceType      string     `gorm:"type:varchar(255)"`
	ResourceID        string     `gorm:"type:varchar(255)"`
	IdempotencyScope  string     `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:2"`
	IdempotencyKey    string     `gorm:"type:varchar(255);not null;uniqueIndex:ux_operations_idempotency,priority:3"`
	RequestDigest     []byte     `gorm:"type:blob;size:32"`
	CorrelationID     string     `gorm:"type:varchar(255)"`
	ResultCode        string     `gorm:"type:varchar(255)"`
	ErrorCode         string     `gorm:"type:varchar(255)"`
	ArtifactID        string     `gorm:"type:varchar(255)"`
	PrivateContext    []byte     `gorm:"type:blob"`
	PrivateNonce      []byte     `gorm:"type:blob;size:12"`
	PrivateKeyID      string     `gorm:"type:varchar(255)"`
	CreatedAt         time.Time  `gorm:"not null"`
	UpdatedAt         time.Time  `gorm:"not null"`
	ExpiresAt         *time.Time
}

func (operationRow) TableName() string { return tableOperations }

type operationArtifactRow struct {
	ArtifactID   string     `gorm:"type:varchar(255);not null;uniqueIndex:ux_operation_artifacts_artifact_id"`
	OperationID  string     `gorm:"type:varchar(255);not null"`
	OwnerPrincipalID string `gorm:"type:varchar(255);not null"`
	MediaType    string     `gorm:"type:varchar(255);not null"`
	SafeFilename string     `gorm:"type:varchar(255)"`
	Size         int64      `gorm:"not null"`
	Status       string     `gorm:"type:varchar(32);not null"`
	Ciphertext   []byte     `gorm:"type:blob"`
	Nonce        []byte     `gorm:"type:blob;size:12"`
	EncryptionKeyID string   `gorm:"type:varchar(255)"`
	ExpiresAt    time.Time  `gorm:"not null"`
	ConsumedAt   *time.Time
}

func (operationArtifactRow) TableName() string { return tableOperationArtifacts }

type laneHeadRow struct {
	Kind      string    `gorm:"type:varchar(32);primaryKey;uniqueIndex:pk_lane_heads,priority:1"`
	LaneHMAC  []byte    `gorm:"column:lane_hmac;type:blob;size:32;primaryKey;uniqueIndex:pk_lane_heads,priority:2"`
	NextSequence uint64 `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (laneHeadRow) TableName() string { return tableLaneHeads }

type inboxMessageRow struct {
	InboxID string `gorm:"type:varchar(255);primaryKey"`
	EndpointID string `gorm:"type:varchar(255);not null;uniqueIndex:ux_inbox_endpoint_provider,priority:1"`
	ProviderEventKey string `gorm:"column:provider_event_id;type:varchar(255);not null;uniqueIndex:ux_inbox_endpoint_provider,priority:2"`
	LaneHMAC []byte `gorm:"type:blob;size:32;not null;uniqueIndex:ux_inbox_lane_sequence,priority:1"`
	OrderingSequence uint64 `gorm:"not null;uniqueIndex:ux_inbox_lane_sequence,priority:2"`
	Status string `gorm:"type:varchar(32);not null;index:ix_inbox_status_lease,priority:1"`
	Version uint64 `gorm:"not null"`
	LeaseOwner string `gorm:"type:varchar(255)"`
	LeaseEpoch uint64 `gorm:"not null"`
	LeaseExpiry *time.Time `gorm:"index:ix_inbox_status_lease,priority:2"`
	AttemptID string `gorm:"type:varchar(255)"`
	CallbackStartedAt *time.Time
	CompletedAt *time.Time
	PayloadCiphertext []byte `gorm:"type:blob"`
	PayloadNonce []byte `gorm:"type:blob;size:12"`
	EncryptionKeyID string `gorm:"type:varchar(255)"`
	ContentDigest []byte `gorm:"type:blob;size:32"`
	ContentDigestKeyID string `gorm:"type:varchar(255)"`
	PayloadExpiresAt *time.Time
	WorkflowID string `gorm:"type:varchar(255)"`
}

func (inboxMessageRow) TableName() string { return tableInboxMessages }

type outboxEffectRow struct {
	EffectID string `gorm:"type:varchar(255);primaryKey;uniqueIndex:ux_outbox_effect_id"`
	Version uint64 `gorm:"not null"`
	EndpointID string `gorm:"type:varchar(255);not null"`
	LaneHMAC []byte `gorm:"type:blob;size:32;not null;uniqueIndex:ux_outbox_lane_sequence,priority:1"`
	OrderingSequence uint64 `gorm:"not null;uniqueIndex:ux_outbox_lane_sequence,priority:2"`
	EffectClass string `gorm:"type:varchar(64);not null"`
	Status string `gorm:"type:varchar(32);not null;index:ix_outbox_status_attempt,priority:1"`
	AttemptID string `gorm:"type:varchar(255)"`
	LeaseOwner string `gorm:"type:varchar(255)"`
	LeaseEpoch uint64 `gorm:"not null"`
	LeaseExpiry *time.Time `gorm:"index:ix_outbox_status_attempt,priority:3"`
	DispatchedAt *time.Time
	DeadlineAt *time.Time
	NextAttemptAt *time.Time `gorm:"index:ix_outbox_status_attempt,priority:2"`
	PayloadCiphertext []byte `gorm:"type:blob"`
	PayloadNonce []byte `gorm:"type:blob;size:12"`
	EncryptionKeyID string `gorm:"type:varchar(255)"`
	ContentDigest []byte `gorm:"type:blob;size:32"`
	ResultCode string `gorm:"type:varchar(255)"`
	ErrorCode string `gorm:"type:varchar(255)"`
	ProviderMessageID string `gorm:"type:varchar(255)"`
	CreatedAt time.Time `gorm:"not null"`
	ScrubbedAt *time.Time
}

func (outboxEffectRow) TableName() string { return tableOutboxEffects }

type adapterSecretRow struct {
	SecretRef string `gorm:"type:varchar(255);not null;uniqueIndex:ux_adapter_secret_ref_version,priority:1"`
	SecretVersion uint64 `gorm:"not null;uniqueIndex:ux_adapter_secret_ref_version,priority:2"`
	EndpointID string `gorm:"type:varchar(255);not null"`
	AdapterType string `gorm:"type:varchar(255);not null"`
	Ciphertext []byte `gorm:"type:blob;not null"`
	Nonce []byte `gorm:"type:blob;size:12;not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	RowVersion uint64 `gorm:"not null"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (adapterSecretRow) TableName() string { return tableAdapterSecrets }

type pluginKVRow struct {
	ExtensionID string `gorm:"type:varchar(255);primaryKey;uniqueIndex:ux_plugin_extension_key,priority:1"`
	KeyHMAC []byte `gorm:"column:key_hmac;type:blob;size:32;primaryKey;uniqueIndex:ux_plugin_extension_key,priority:2"`
	EncryptedKey []byte `gorm:"type:blob;not null"`
	EncryptedValue []byte `gorm:"type:blob;not null"`
	ValueSize int64 `gorm:"not null"`
	RowVersion uint64 `gorm:"not null"`
	EncryptionKeyID string `gorm:"type:varchar(255);not null"`
	CreatedAt time.Time `gorm:"not null"`
	UpdatedAt time.Time `gorm:"not null"`
}

func (pluginKVRow) TableName() string { return tablePluginKV }

type subjectFenceRow struct {
	SubjectKey []byte `gorm:"column:subject_key;type:blob;size:32;not null;uniqueIndex:ux_subject_fence_key_scope,priority:1"`
	Scope string `gorm:"type:varchar(64);not null;uniqueIndex:ux_subject_fence_key_scope,priority:2"`
	PurgeOperationID string `gorm:"type:varchar(255);not null"`
	CreatedAt time.Time `gorm:"not null"`
	ExpiresAt *time.Time
}

func (subjectFenceRow) TableName() string { return tableSubjectFences }

type storeReadinessRow struct {
	SingletonID string `gorm:"column:singleton_id;type:varchar(32);primaryKey"`
	Mode string `gorm:"type:varchar(16);not null"`
	SchemaVersion string `gorm:"type:varchar(64);not null"`
	DatabaseIdentity string `gorm:"type:varchar(255);not null"`
	IndexRootID string `gorm:"type:varchar(255);not null"`
	EncryptionRootIDs []byte `gorm:"type:blob;not null"`
	SourceManifestDigest []byte `gorm:"type:blob;size:32"`
	TargetManifestDigest []byte `gorm:"type:blob;size:32"`
	TerminalGlobalPosition uint64 `gorm:"not null"`
	TerminalProjectionPosition uint64 `gorm:"not null"`
	CompletedAt *time.Time
}

func (storeReadinessRow) TableName() string { return tableStoreReadiness }

func schemaModels() []any {
	return []any{
		&domainEventRow{}, &eventGlobalSequenceRow{}, &aggregateHeadRow{},
		&projectionControlRow{}, &projectionReadModelRow{}, &operationRow{},
		&operationArtifactRow{}, &laneHeadRow{}, &inboxMessageRow{},
		&outboxEffectRow{}, &adapterSecretRow{}, &pluginKVRow{},
		&subjectFenceRow{}, &storeReadinessRow{},
	}
}
