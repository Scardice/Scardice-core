package model

type OfficialQQIdentityMappingState string

const (
	OfficialQQIdentityMappingPending OfficialQQIdentityMappingState = "pending"
	OfficialQQIdentityMappingApplied OfficialQQIdentityMappingState = "applied"
	OfficialQQIdentityMappingBlocked OfficialQQIdentityMappingState = "blocked"
)

type OfficialQQIdentityMapping struct {
	ID          uint64                         `gorm:"primaryKey;autoIncrement;column:id"`
	MigrationID string                         `gorm:"column:migration_id;size:64;uniqueIndex:idx_official_qq_identity_mapping,priority:1"`
	Account     string                         `gorm:"column:account;size:64;uniqueIndex:idx_official_qq_identity_mapping,priority:2"`
	Store       string                         `gorm:"column:store;size:32;uniqueIndex:idx_official_qq_identity_mapping,priority:3"`
	Keyspace    string                         `gorm:"column:keyspace;size:64;uniqueIndex:idx_official_qq_identity_mapping,priority:4"`
	OldID       string                         `gorm:"column:old_id;size:191;uniqueIndex:idx_official_qq_identity_mapping,priority:5"`
	NewID       string                         `gorm:"column:new_id;size:512"`
	SourceHash  string                         `gorm:"column:source_hash;size:8"`
	State       OfficialQQIdentityMappingState `gorm:"column:state;size:16;index:idx_official_qq_identity_state"`
	CreatedAt   int64                          `gorm:"column:created_at"`
	UpdatedAt   int64                          `gorm:"column:updated_at"`
	Error       string                         `gorm:"column:error;type:text"`
}

func (*OfficialQQIdentityMapping) TableName() string {
	return "official_qq_identity_mappings"
}
