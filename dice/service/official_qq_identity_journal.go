package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/engine"
)

var (
	ErrOfficialQQIdentityMappingState      = errors.New("invalid official QQ identity mapping state")
	ErrOfficialQQIdentityMappingTransition = errors.New("official QQ identity mapping transition rejected")
	ErrOfficialQQIdentityMappingUnverified = errors.New("official QQ identity mapping is not source-verified")
)

type OfficialQQIdentityMappingKey struct {
	MigrationID string
	Account     string
	Store       string
	Keyspace    string
	OldID       string
}

type OfficialQQIdentityMappingSpec struct {
	Key        OfficialQQIdentityMappingKey
	NewID      string
	sourceHash string
}

type OfficialQQIdentityMappingTransition struct {
	Key   OfficialQQIdentityMappingKey
	State model.OfficialQQIdentityMappingState
	Error string
}

type OfficialQQIdentityJournal struct {
	operator engine.DatabaseOperator
	now      func() time.Time
}

func NewOfficialQQIdentityJournal(operator engine.DatabaseOperator, now func() time.Time) *OfficialQQIdentityJournal {
	return &OfficialQQIdentityJournal{operator: operator, now: now}
}

func (j *OfficialQQIdentityJournal) Init(ctx context.Context) error {
	db := j.operator.GetDataDB(constant.WRITE)
	if err := db.WithContext(ctx).AutoMigrate(&model.OfficialQQIdentityMapping{}); err != nil {
		return fmt.Errorf("initialize official QQ identity journal: %w", err)
	}
	return nil
}

func (j *OfficialQQIdentityJournal) CreatePending(ctx context.Context, specs []OfficialQQIdentityMappingSpec) error {
	if len(specs) == 0 {
		return nil
	}
	now := j.now().Unix()
	rows := make([]model.OfficialQQIdentityMapping, len(specs))
	for index, spec := range specs {
		if err := validateOfficialQQIdentityMappingSpec(spec); err != nil {
			return err
		}
		rows[index] = officialQQIdentityMappingRow(spec, now)
	}
	db := j.operator.GetDataDB(constant.WRITE).WithContext(ctx)
	if err := db.Transaction(func(tx *gorm.DB) error {
		return tx.Create(&rows).Error
	}); err != nil {
		return fmt.Errorf("create pending official QQ identity mappings: %w", err)
	}
	return nil
}

func officialQQIdentityMappingRow(spec OfficialQQIdentityMappingSpec, now int64) model.OfficialQQIdentityMapping {
	return model.OfficialQQIdentityMapping{
		MigrationID: spec.Key.MigrationID,
		Account:     spec.Key.Account,
		Store:       spec.Key.Store,
		Keyspace:    spec.Key.Keyspace,
		OldID:       spec.Key.OldID,
		NewID:       spec.NewID,
		SourceHash:  spec.sourceHash,
		State:       model.OfficialQQIdentityMappingPending,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

func (j *OfficialQQIdentityJournal) Get(ctx context.Context, key OfficialQQIdentityMappingKey) (model.OfficialQQIdentityMapping, error) {
	var mapping model.OfficialQQIdentityMapping
	db := j.operator.GetDataDB(constant.READ).WithContext(ctx)
	if err := officialQQIdentityMappingQuery(db, key).Take(&mapping).Error; err != nil {
		return model.OfficialQQIdentityMapping{}, fmt.Errorf("get official QQ identity mapping: %w", err)
	}
	return mapping, nil
}

func (j *OfficialQQIdentityJournal) ResolveApplied(ctx context.Context, key OfficialQQIdentityMappingKey) (string, bool, error) {
	var mapping model.OfficialQQIdentityMapping
	db := j.operator.GetDataDB(constant.READ).WithContext(ctx)
	err := officialQQIdentityMappingQuery(db, key).
		Where("state = ?", model.OfficialQQIdentityMappingApplied).
		Take(&mapping).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return key.OldID, false, nil
	}
	if err != nil {
		return key.OldID, false, fmt.Errorf("resolve applied official QQ identity mapping: %w", err)
	}
	return mapping.NewID, true, nil
}

func (j *OfficialQQIdentityJournal) Transition(ctx context.Context, transition OfficialQQIdentityMappingTransition) error {
	db := j.operator.GetDataDB(constant.WRITE).WithContext(ctx)
	return j.transitionDB(db, transition)
}

func (j *OfficialQQIdentityJournal) transitionDB(db *gorm.DB, transition OfficialQQIdentityMappingTransition) error {
	var source model.OfficialQQIdentityMappingState
	switch transition.State {
	case model.OfficialQQIdentityMappingApplied, model.OfficialQQIdentityMappingBlocked:
		source = model.OfficialQQIdentityMappingPending
	case model.OfficialQQIdentityMappingPending:
		source = model.OfficialQQIdentityMappingBlocked
	default:
		return fmt.Errorf("state %q: %w", transition.State, ErrOfficialQQIdentityMappingState)
	}

	updates := map[string]any{
		"state":      transition.State,
		"updated_at": j.now().Unix(),
		"error":      transition.Error,
	}
	result := officialQQIdentityMappingQuery(db.Model(&model.OfficialQQIdentityMapping{}), transition.Key).
		Where("state = ?", source).
		Updates(updates)
	if result.Error != nil {
		return fmt.Errorf("transition official QQ identity mapping: %w", result.Error)
	}
	if result.RowsAffected != 1 {
		return ErrOfficialQQIdentityMappingTransition
	}
	return nil
}

func officialQQIdentityMappingQuery(db *gorm.DB, key OfficialQQIdentityMappingKey) *gorm.DB {
	return db.Where(
		"migration_id = ? AND account = ? AND store = ? AND keyspace = ? AND old_id = ?",
		key.MigrationID,
		key.Account,
		key.Store,
		key.Keyspace,
		key.OldID,
	)
}
