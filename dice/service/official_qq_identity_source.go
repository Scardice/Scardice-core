package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

const (
	officialQQGroupIdentitySourceHash    = "bb8e1496"
	officialQQDelegateIdentitySourceHash = "f3c16a62"
)

type OfficialQQVerifiedIdentitySource struct {
	AppID       uint64
	VerifiedUIN string
	Groups      []OfficialQQGroupIdentitySource
}

type OfficialQQGroupIdentitySource struct {
	GroupOpenID   string
	MemberOpenIDs []string
}

type OfficialQQIdentityMigrationResult struct {
	Deferred  bool
	Declared  int
	Processed int
}

func (m *OfficialQQIdentityMigrator) MigrateVerifiedSource(
	ctx context.Context,
	source OfficialQQVerifiedIdentitySource,
	batchSize int,
) (OfficialQQIdentityMigrationResult, error) {
	if source.VerifiedUIN == "" {
		return OfficialQQIdentityMigrationResult{Deferred: true}, nil
	}
	if batchSize <= 0 {
		batchSize = OfficialQQIdentityMigrationDefaultBatchSize
	}
	specs, err := officialQQIdentitySpecsFromVerifiedSource(source)
	if err != nil {
		return OfficialQQIdentityMigrationResult{}, err
	}
	if err := m.journal.Init(ctx); err != nil {
		return OfficialQQIdentityMigrationResult{}, err
	}
	declared := 0
	for start := 0; start < len(specs); start += batchSize {
		end := min(start+batchSize, len(specs))
		created, err := m.journal.createPendingIfAbsent(ctx, specs[start:end])
		if err != nil {
			return OfficialQQIdentityMigrationResult{}, err
		}
		declared += created
	}
	processed, err := m.ApplyPending(ctx, strconv.FormatUint(source.AppID, 10), batchSize)
	if err != nil {
		return OfficialQQIdentityMigrationResult{}, err
	}
	return OfficialQQIdentityMigrationResult{Declared: declared, Processed: processed}, nil
}

func officialQQIdentitySpecsFromVerifiedSource(source OfficialQQVerifiedIdentitySource) ([]OfficialQQIdentityMappingSpec, error) {
	account := strconv.FormatUint(source.AppID, 10)
	uin, err := canonicalOfficialQQUIN(source.VerifiedUIN)
	if source.AppID == 0 || err != nil {
		return nil, fmt.Errorf("verified official QQ account: %w", ErrOfficialQQIdentityMappingUnverified)
	}
	specs := make([]OfficialQQIdentityMappingSpec, 0, len(source.Groups))
	seen := map[OfficialQQIdentityMappingKey]struct{}{}
	for _, group := range source.Groups {
		if !isOfficialQQOpenID(group.GroupOpenID) {
			return nil, fmt.Errorf("group OpenID %q: %w", group.GroupOpenID, ErrOfficialQQIdentityMappingUnverified)
		}
		groupSpec := OfficialQQIdentityMappingSpec{
			Key: OfficialQQIdentityMappingKey{
				MigrationID: OfficialQQExplicitIdentityMigrationID,
				Account:     account,
				Store:       OfficialQQIdentityStoreGroupInfo,
				Keyspace:    OfficialQQIdentityKeyspaceID,
				OldID:       "OpenQQ-Group-T:" + account + "-" + group.GroupOpenID,
			},
			NewID:      "OpenQQ-Group:" + uin + "-" + group.GroupOpenID,
			sourceHash: officialQQGroupIdentitySourceHash,
		}
		specs = append(specs, groupSpec)
		seen[groupSpec.Key] = struct{}{}
		for _, memberOpenID := range group.MemberOpenIDs {
			if !isOfficialQQOpenID(memberOpenID) {
				return nil, fmt.Errorf("member OpenID %q: %w", memberOpenID, ErrOfficialQQIdentityMappingUnverified)
			}
			delegateSpec := OfficialQQIdentityMappingSpec{
				Key: OfficialQQIdentityMappingKey{
					MigrationID: OfficialQQExplicitIdentityMigrationID,
					Account:     account,
					Store:       OfficialQQIdentityStoreDelegate,
					Keyspace:    OfficialQQIdentityKeyspacePlayerUserID,
					OldID:       "OpenQQ:" + memberOpenID,
				},
				NewID:      "OpenQQ:" + uin + "-" + memberOpenID,
				sourceHash: officialQQDelegateIdentitySourceHash,
			}
			if _, exists := seen[delegateSpec.Key]; exists {
				continue
			}
			specs = append(specs, delegateSpec)
			seen[delegateSpec.Key] = struct{}{}
		}
	}
	return specs, nil
}

func (j *OfficialQQIdentityJournal) createPendingIfAbsent(ctx context.Context, specs []OfficialQQIdentityMappingSpec) (int, error) {
	created := 0
	db := j.operator.GetDataDB(constant.WRITE).WithContext(ctx)
	err := db.Transaction(func(tx *gorm.DB) error {
		for _, spec := range specs {
			if err := validateOfficialQQIdentityMappingSpec(spec); err != nil {
				return err
			}
			var existing model.OfficialQQIdentityMapping
			err := officialQQIdentityMappingQuery(tx, spec.Key).Take(&existing).Error
			if err == nil {
				if existing.NewID != spec.NewID || existing.SourceHash != spec.sourceHash {
					return fmt.Errorf("mapping %q conflicts with verified source: %w", spec.Key.OldID, ErrOfficialQQIdentityMappingUnverified)
				}
				continue
			}
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return fmt.Errorf("read declared official QQ mapping: %w", err)
			}
			if err := tx.Create(&[]model.OfficialQQIdentityMapping{officialQQIdentityMappingRow(spec, j.now().Unix())}).Error; err != nil {
				return fmt.Errorf("declare verified official QQ mapping: %w", err)
			}
			created++
		}
		return nil
	})
	return created, err
}

func validateOfficialQQIdentityMappingSpec(spec OfficialQQIdentityMappingSpec) error {
	if spec.Key.MigrationID != OfficialQQExplicitIdentityMigrationID {
		return nil
	}
	accountPrefix := "OpenQQ-Group-T:" + spec.Key.Account + "-"
	switch spec.sourceHash {
	case officialQQGroupIdentitySourceHash:
		groupOpenID, ok := strings.CutPrefix(spec.Key.OldID, accountPrefix)
		return requireOfficialQQIdentityShape(ok && isOfficialQQOpenID(groupOpenID) && spec.Key.Store == OfficialQQIdentityStoreGroupInfo && spec.Key.Keyspace == OfficialQQIdentityKeyspaceID && hasOfficialQQTargetSuffix(spec.NewID, "OpenQQ-Group:", groupOpenID), spec.Key.OldID)
	case officialQQDelegateIdentitySourceHash:
		memberOpenID, ok := strings.CutPrefix(spec.Key.OldID, "OpenQQ:")
		return requireOfficialQQIdentityShape(ok && isOfficialQQOpenID(memberOpenID) && spec.Key.Store == OfficialQQIdentityStoreDelegate && spec.Key.Keyspace == OfficialQQIdentityKeyspacePlayerUserID && hasOfficialQQTargetSuffix(spec.NewID, "OpenQQ:", memberOpenID), spec.Key.OldID)
	default:
		return fmt.Errorf("mapping %q: %w", spec.Key.OldID, ErrOfficialQQIdentityMappingUnverified)
	}
}

func hasOfficialQQTargetSuffix(target, prefix, sourceOpenID string) bool {
	raw, ok := strings.CutPrefix(target, prefix)
	if !ok {
		return false
	}
	uin, suffix, ok := strings.Cut(raw, "-")
	_, err := canonicalOfficialQQUIN(uin)
	return ok && err == nil && suffix == sourceOpenID
}

func canonicalOfficialQQUIN(raw string) (string, error) {
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
		return "", ErrOfficialQQIdentityMappingUnverified
	}
	return raw, nil
}

func isOfficialQQOpenID(raw string) bool {
	return raw != "" && strings.TrimSpace(raw) == raw
}

func requireOfficialQQIdentityShape(valid bool, oldID string) error {
	if !valid {
		return fmt.Errorf("mapping %q: %w", oldID, ErrOfficialQQIdentityMappingUnverified)
	}
	return nil
}
