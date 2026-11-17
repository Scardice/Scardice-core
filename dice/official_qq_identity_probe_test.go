package dice

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	seallogger "Scardice-core/logger"
	"Scardice-core/model"
)

const officialQQIdentityProbeTestAppID = "1906026444"

func newOfficialQQIdentityProbeTestOperator(t *testing.T) (*officialQQIdentityMigration, *mockDatabaseOperator) {
	t.Helper()
	op, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "official-qq-probe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	if err := op.db.AutoMigrate(&model.GroupInfo{}, &model.AttributesItemModel{}); err != nil {
		t.Fatal(err)
	}
	m := &officialQQIdentityMigration{
		appID:       officialQQIdentityProbeTestAppID,
		uin:         "1",
		oldEndpoint: "OpenQQ:legacy",
		groups:      map[string]string{},
		users:       map[string]string{},
	}
	return m, op
}

// 拆成三条单列查询后，命中的行集合必须与旧版单条 OR 查询完全一致；
// 同一行同时命中 id 与 owner_id 时要按 id 去重，否则指纹会漂移。
func TestOfficialQQIdentityFingerprintCountsUnionOfAttrsProbes(t *testing.T) {
	m, op := newOfficialQQIdentityProbeTestOperator(t)
	groupID := "OpenQQ-Group-T:" + officialQQIdentityProbeTestAppID + "-g"
	memberID := "OpenQQ-Member-T:" + officialQQIdentityProbeTestAppID + "-g-m"
	overlappingID := "OpenQQ-Member-T:" + officialQQIdentityProbeTestAppID + "-g-m2"

	rows := []model.AttributesItemModel{
		{Id: groupID},                           // 只命中 id 的群区间
		{Id: memberID},                          // 只命中 id 的成员区间
		{Id: "nanoid-plain", OwnerId: memberID}, // 只命中 owner_id 区间
		{Id: overlappingID, OwnerId: memberID},  // id 与 owner_id 同时命中
		{Id: "nanoid-unrelated", OwnerId: "QQ:UID_1", AttrsType: "character"}, // 无关行
	}
	// 逐条插入：attrs_type 带 default:NULL，批量插入混合有无该字段的行时
	// GORM 会生成 SQLite 不接受的 VALUES (..., DEFAULT, ...)。
	for i := range rows {
		if err := op.db.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}

	count, fingerprint, err := m.legacyRowFingerprint(op)
	if err != nil {
		t.Fatalf("legacyRowFingerprint() error = %v", err)
	}
	if count != 4 {
		t.Fatalf("fingerprint count = %d, want 4 (overlapping row must be deduplicated)", count)
	}

	// 指纹必须与旧版单条 OR 查询逐字节一致，否则升级后会误判“旧行变了”
	// 而重跑一次身份迁移。这里用仍保留的 legacyAttrsQuery 作为参照实现。
	var referenceIDs []string
	if refErr := m.legacyAttrsQuery(op.db.Model(&model.AttributesItemModel{})).Order("id").Pluck("id", &referenceIDs).Error; refErr != nil {
		t.Fatal(refErr)
	}
	sort.Strings(referenceIDs)
	referenceHash := sha256.New()
	_, _ = referenceHash.Write([]byte("group_info"))
	_, _ = referenceHash.Write([]byte{0})
	_, _ = referenceHash.Write([]byte("attributes"))
	_, _ = referenceHash.Write([]byte{0})
	for _, id := range referenceIDs {
		_, _ = referenceHash.Write([]byte(id))
		_, _ = referenceHash.Write([]byte{0})
	}
	if want := hex.EncodeToString(referenceHash.Sum(nil)); fingerprint != want {
		t.Fatalf("fingerprint drifted from legacy OR query:\n got %s\nwant %s", fingerprint, want)
	}

	rowCount, err := m.legacyRowCount(op)
	if err != nil {
		t.Fatalf("legacyRowCount() error = %v", err)
	}
	if rowCount != count {
		t.Fatalf("legacyRowCount() = %d, fingerprint count = %d, want equal", rowCount, count)
	}

	countAgain, fingerprintAgain, err := m.legacyRowFingerprint(op)
	if err != nil {
		t.Fatal(err)
	}
	if countAgain != count || fingerprintAgain != fingerprint {
		t.Fatalf("fingerprint not stable: (%d,%s) -> (%d,%s)", count, fingerprint, countAgain, fingerprintAgain)
	}

	if deleteErr := op.db.Delete(&model.AttributesItemModel{}, "id = ?", "nanoid-plain").Error; deleteErr != nil {
		t.Fatal(deleteErr)
	}
	countAfterDelete, fingerprintAfterDelete, err := m.legacyRowFingerprint(op)
	if err != nil {
		t.Fatal(err)
	}
	if countAfterDelete != count-1 || fingerprintAfterDelete == fingerprint {
		t.Fatalf("fingerprint should change after delete: count %d -> %d, fingerprint %s -> %s",
			count, countAfterDelete, fingerprint, fingerprintAfterDelete)
	}
}

// 探测 SQL 必须保持单列范围扫描：不能再拼出跨列 OR，也不需要 SQL 侧排序
// （结果在 Go 侧排序），否则 SQLite 会退化成 MULTI-INDEX OR + 临时 B 树。
func TestOfficialQQIdentityAttrsProbeQueriesAreSingleRangeScans(t *testing.T) {
	m, op := newOfficialQQIdentityProbeTestOperator(t)
	queries := m.legacyAttrsFingerprintQueries(op.db)
	if len(queries) != 3 {
		t.Fatalf("attrs probe query count = %d, want 3", len(queries))
	}
	for i, query := range queries {
		sql := query.ToSQL(func(tx *gorm.DB) *gorm.DB {
			return tx.Find(&[]model.AttributesItemModel{})
		})
		upper := strings.ToUpper(sql)
		if strings.Contains(upper, "ORDER BY") {
			t.Fatalf("attrs probe query %d should not sort in SQL: %s", i, sql)
		}
		if strings.Contains(upper, " OR ") {
			t.Fatalf("attrs probe query %d should not use cross-column OR: %s", i, sql)
		}
	}
}

// 回归：启动阶段 IO 抖动曾让这些探测在 database.log 里刷出 SLOW SQL。
// 控制组用同一条 attrs 查询确认告警链路本身有效，再断言探测不会再触发它。
func TestOfficialQQIdentityProbesSuppressSlowSQLWarning(t *testing.T) {
	m, op := newOfficialQQIdentityProbeTestOperator(t)
	db := op.db
	if err := db.Create(&model.AttributesItemModel{
		Id: "OpenQQ-Member-T:" + officialQQIdentityProbeTestAppID + "-g-m",
	}).Error; err != nil {
		t.Fatal(err)
	}

	core, logs := observer.New(zapcore.WarnLevel)
	db.Logger = seallogger.GORMLogger{
		ZapLogger:                 zap.New(core),
		LogLevel:                  gormlogger.Warn,
		SlowThreshold:             time.Nanosecond,
		IgnoreRecordNotFoundError: true,
	}

	var control int64
	if err := db.Model(&model.AttributesItemModel{}).Count(&control).Error; err != nil {
		t.Fatal(err)
	}
	if !hasSlowSQLWarnForAttrs(logs.TakeAll()) {
		t.Fatal("control query should have produced a SLOW SQL warning")
	}

	if _, _, err := m.legacyRowFingerprint(op); err != nil {
		t.Fatal(err)
	}
	if hasSlowSQLWarnForAttrs(logs.TakeAll()) {
		t.Fatal("legacyRowFingerprint() should suppress SLOW SQL warnings for probe queries")
	}

	if _, err := m.legacyRowCount(op); err != nil {
		t.Fatal(err)
	}
	if hasSlowSQLWarnForAttrs(logs.TakeAll()) {
		t.Fatal("legacyRowCount() should suppress SLOW SQL warnings for probe queries")
	}
}

func hasSlowSQLWarnForAttrs(entries []observer.LoggedEntry) bool {
	for _, entry := range entries {
		if entry.Level != zapcore.WarnLevel || !strings.Contains(entry.Message, "SLOW SQL") {
			continue
		}
		if strings.Contains(entry.Message, "FROM `attrs`") {
			return true
		}
	}
	return false
}
