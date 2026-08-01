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

const (
	OfficialQQExplicitIdentityMigrationID       = "official-qq-explicit-identity-v1"
	OfficialQQIdentityStoreGroupInfo            = "group_info"
	OfficialQQIdentityStoreDelegate             = "delegate"
	OfficialQQIdentityKeyspaceID                = "id"
	OfficialQQIdentityKeyspacePlayerUserID      = "player_user_id"
	OfficialQQIdentityMigrationDefaultBatchSize = 200
)

type OfficialQQIdentityMigrator struct {
	operator engine.DatabaseOperator
	journal  *OfficialQQIdentityJournal
}

func NewOfficialQQIdentityMigrator(operator engine.DatabaseOperator, now func() time.Time) *OfficialQQIdentityMigrator {
	return &OfficialQQIdentityMigrator{
		operator: operator,
		journal:  NewOfficialQQIdentityJournal(operator, now),
	}
}

func (m *OfficialQQIdentityMigrator) ApplyPending(ctx context.Context, account string, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = OfficialQQIdentityMigrationDefaultBatchSize
	}
	var mappings []model.OfficialQQIdentityMapping
	db := m.operator.GetDataDB(constant.READ).WithContext(ctx)
	err := db.Where(
		"migration_id = ? AND account = ? AND state = ?",
		OfficialQQExplicitIdentityMigrationID,
		account,
		model.OfficialQQIdentityMappingPending,
	).Order("id").Limit(batchSize).Find(&mappings).Error
	if err != nil {
		return 0, fmt.Errorf("list pending official QQ identity mappings: %w", err)
	}

	for index, mapping := range mappings {
		if err := m.applyMapping(ctx, mapping); err != nil {
			return index, fmt.Errorf("apply official QQ identity mapping %d: %w", mapping.ID, err)
		}
	}
	return len(mappings), nil
}

func (m *OfficialQQIdentityMigrator) applyMapping(ctx context.Context, mapping model.OfficialQQIdentityMapping) error {
	spec := OfficialQQIdentityMappingSpec{
		Key: OfficialQQIdentityMappingKey{
			MigrationID: mapping.MigrationID,
			Account:     mapping.Account,
			Store:       mapping.Store,
			Keyspace:    mapping.Keyspace,
			OldID:       mapping.OldID,
		},
		NewID:      mapping.NewID,
		sourceHash: mapping.SourceHash,
	}
	if err := validateOfficialQQIdentityMappingSpec(spec); err != nil {
		return err
	}
	switch {
	case mapping.Store == OfficialQQIdentityStoreGroupInfo && mapping.Keyspace == OfficialQQIdentityKeyspaceID:
		return m.applyGroupInfoMapping(ctx, mapping)
	case mapping.Store == OfficialQQIdentityStoreDelegate && mapping.Keyspace == OfficialQQIdentityKeyspacePlayerUserID:
		return m.journal.Transition(ctx, OfficialQQIdentityMappingTransition{
			Key: spec.Key, State: model.OfficialQQIdentityMappingApplied,
		})
	default:
		return fmt.Errorf("mapping store %q keyspace %q: %w", mapping.Store, mapping.Keyspace, ErrOfficialQQIdentityMappingUnverified)
	}
}

func (m *OfficialQQIdentityMigrator) applyGroupInfoMapping(ctx context.Context, mapping model.OfficialQQIdentityMapping) error {
	db := m.operator.GetDataDB(constant.WRITE).WithContext(ctx)
	return db.Transaction(func(tx *gorm.DB) error {
		key := OfficialQQIdentityMappingKey{
			MigrationID: mapping.MigrationID,
			Account:     mapping.Account,
			Store:       mapping.Store,
			Keyspace:    mapping.Keyspace,
			OldID:       mapping.OldID,
		}
		var source model.GroupInfo
		if err := tx.Where("id = ?", mapping.OldID).Take(&source).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return m.journal.transitionDB(tx, OfficialQQIdentityMappingTransition{
					Key: key, State: model.OfficialQQIdentityMappingBlocked, Error: "source row does not exist",
				})
			}
			return fmt.Errorf("read source group_info row: %w", err)
		}

		var target model.GroupInfo
		err := tx.Where("id = ?", mapping.NewID).Take(&target).Error
		if err == nil {
			return m.journal.transitionDB(tx, OfficialQQIdentityMappingTransition{
				Key: key, State: model.OfficialQQIdentityMappingBlocked, Error: "target row already exists",
			})
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("check target group_info row: %w", err)
		}

		target = source
		target.ID = mapping.NewID
		if err := tx.Create(&target).Error; err != nil {
			return fmt.Errorf("copy group_info row: %w", err)
		}
		return m.journal.transitionDB(tx, OfficialQQIdentityMappingTransition{
			Key: key, State: model.OfficialQQIdentityMappingApplied,
		})
	})
}
