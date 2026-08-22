package v2

import (
	"os"
	"path/filepath"
	_ "time"

	v120 "Scardice-core/migrate/v2/v120"
	v131 "Scardice-core/migrate/v2/v131"
	v141 "Scardice-core/migrate/v2/v141"
	v144 "Scardice-core/migrate/v2/v144"
	v150 "Scardice-core/migrate/v2/v150"
	v151 "Scardice-core/migrate/v2/v151"
	v160 "Scardice-core/migrate/v2/v160"
	v161 "Scardice-core/migrate/v2/v161"
	v162 "Scardice-core/migrate/v2/v162"
	operator "Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
	"Scardice-core/utils/upgrader/store"
)

func upgradeMetadataPath() string {
	const name = "upgrade_metadata.json"
	dataDir := os.Getenv("DATADIR")
	if dataDir == "" {
		return name
	}
	underData := filepath.Join(dataDir, name)
	if _, err := os.Stat(underData); err == nil {
		return underData
	}
	if _, err := os.Stat(name); err == nil {
		return name
	}
	return underData
}

func InitUpgrader(operator operator.DatabaseOperator) error {
	storer := store.NewJSONStore(upgradeMetadataPath())
	mgr := &upgrade.Manager{Store: storer, Database: operator}
	// V120注册
	mgr.Register(v120.V120Migration)
	mgr.Register(v120.V120LogMessageMigration)
	// V131注册
	mgr.Register(v131.V131ConfigUpdateMigration)
	// V141注册
	mgr.Register(v141.V141ConfigUpdateMigration)
	// v144注册
	mgr.Register(v144.V144RemoveOldHelpDocMigration)
	// v150注册
	mgr.Register(v150.V150UpgradeAttrsMigration)
	mgr.Register(v150.V150FixGroupInfoMigration)
	// v151注册
	mgr.Register(v151.V151GORMCleanMigration)
	// v160注册
	mgr.Register(v160.V160LogIDZeroCleanMigration)
	mgr.Register(v160.V160LogRawMsgIDIndexMigration)
	mgr.Register(v160.V160LogSizeRepairMigration)
	mgr.Register(v161.V161NoticeIDsMigration)
	mgr.Register(v161.V161CopyDiceMastersToNoticeIDsMigration)
	mgr.Register(v162.V162AddLogSeqMigration)
	err := mgr.ApplyAll()
	if err != nil {
		return err
	}
	return nil
}
