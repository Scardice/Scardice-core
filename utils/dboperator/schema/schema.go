package schema

import (
	"fmt"

	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

// EnsureDataSchema creates core data tables if missing.
// Safe to call on every startup; GORM AutoMigrate is additive.
func EnsureDataSchema(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("data db is nil")
	}
	if err := db.AutoMigrate(
		&model.GroupPlayerInfoBase{},
		&model.GroupInfo{},
		&model.BanInfo{},
		&model.EndpointInfo{},
		&model.AttributesItemModel{},
		&model.OfficialQQIdentityMapping{},
	); err != nil {
		return fmt.Errorf("ensure data schema: %w", err)
	}
	return nil
}

// EnsureLogSchema creates log tables if missing.
// MySQL uses hook models to avoid full-length indexes that require prefix indexes.
func EnsureLogSchema(db *gorm.DB, engineType string) error {
	if db == nil {
		return fmt.Errorf("log db is nil")
	}
	var err error
	switch engineType {
	case constant.MYSQL:
		err = db.AutoMigrate(&model.LogInfoHookMySQL{}, &model.LogOneItemHookMySQL{})
	default:
		err = db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{})
	}
	if err != nil {
		return fmt.Errorf("ensure log schema: %w", err)
	}
	return nil
}

// EnsureCensorSchema creates censor_log if missing.
func EnsureCensorSchema(db *gorm.DB) error {
	if db == nil {
		return fmt.Errorf("censor db is nil")
	}
	if err := db.AutoMigrate(&model.CensorLog{}); err != nil {
		return fmt.Errorf("ensure censor schema: %w", err)
	}
	return nil
}
