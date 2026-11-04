package dice

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"Scardice-core/logger"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/engine"
)

// errOfficialQQIdentityTargetExists 表示目标 ID 已存在。
// 单条冲突不应回滚整批迁移；调用方会保留旧记录并继续。
var errOfficialQQIdentityTargetExists = errors.New("official qq identity migration target already exists")

// errOfficialQQAttrsNotMergeable 表示该属性行在语义上无法合并（绑卡/非 user 类型），
// 调用方应保留旧行继续，而不是让整个事务回滚。数据损坏等可修复问题仍返回普通错误。
var errOfficialQQAttrsNotMergeable = errors.New("official qq attrs row is not mergeable")

type officialQQIdentityMigration struct {
	appID          string
	uin            string
	oldEndpoint    string
	newEndpoint    string
	groups         map[string]string
	users          map[string]string
	characterNames map[string]string
	// logNames 记录因 (group_id,name) 冲突而重命名的旧日志，key 为 oldGroupID+"\x00"+oldName。
	logNames map[string]string
}

const officialQQIdentityMigrationBatchSize = 200

func officialQQIdentityMigrationFindInBatches[T any](query *gorm.DB, process func([]T) error) error {
	var rows []T
	query = officialQQIdentityMigrationWithoutCache(query)
	return query.FindInBatches(&rows, officialQQIdentityMigrationBatchSize, func(_ *gorm.DB, _ int) error {
		return process(rows)
	}).Error
}

func officialQQIdentityMigrationWithoutCache(db *gorm.DB) *gorm.DB {
	return db
}

func officialQQIdentityMigrationForEachChunk[T any](items []T, process func([]T) error) error {
	for start := 0; start < len(items); start += officialQQIdentityMigrationBatchSize {
		end := min(start+officialQQIdentityMigrationBatchSize, len(items))
		if err := process(items[start:end]); err != nil {
			return err
		}
	}
	return nil
}

type officialQQIdentityMigrationError struct {
	cause error
}

func (e *officialQQIdentityMigrationError) Error() string {
	return e.cause.Error()
}

func (e *officialQQIdentityMigrationError) Unwrap() error {
	return e.cause
}

func migratedCharacterName(baseName string, suffix int) string {
	if baseName == "" {
		baseName = "未命名角色"
	}
	suffixText := fmt.Sprintf(" (%d)", suffix)
	const maxNameBytes = 90
	maxBaseBytes := maxNameBytes - len(suffixText)
	if len(baseName) > maxBaseBytes {
		baseName = baseName[:maxBaseBytes]
		for !utf8.ValidString(baseName) {
			baseName = baseName[:len(baseName)-1]
		}
	}
	return baseName + suffixText
}

func ensureOfficialQQIdentity(d *Dice, pa *PlatformAdapterOfficialQQ, botID, uin string) error {
	return ensureOfficialQQIdentityWithMigration(d, pa, botID, uin, true)
}

// ensureOfficialQQIdentityWithMigration 在 allowMigration=false 时只写入运行时身份，
// 把旧数据迁移延后到下一次连接。用于旧 handler 未能及时停止的场合，避免迁移与
// handler 并发修改同一批内存/数据库状态。
func ensureOfficialQQIdentityWithMigration(d *Dice, pa *PlatformAdapterOfficialQQ, botID, uin string, allowMigration bool) error {
	if d == nil || pa == nil || pa.EndPoint == nil {
		return errors.New("QQ 官方机器人运行时未初始化")
	}
	if strings.TrimSpace(uin) == "" {
		return errors.New("QQ 官方机器人 UIN 为空")
	}

	expectedEndpoint := formatDiceIDOfficialQQ(uin)
	oldEndpoint := formatDiceIDOfficialQQ(botID)
	pa.sessionMu.Lock()
	currentEndpoint := pa.EndPoint.UserID
	pa.sessionMu.Unlock()
	if currentEndpoint != "" && currentEndpoint != oldEndpoint && currentEndpoint != expectedEndpoint {
		return fmt.Errorf("无法识别旧账号 ID %q，期望 %q", currentEndpoint, oldEndpoint)
	}
	// The verified runtime identity is required even when the optional legacy
	// data migration is disabled or fails.
	pa.setUIN(uin)
	pa.sessionMu.Lock()
	pa.EndPoint.UserID = expectedEndpoint
	pa.sessionMu.Unlock()

	if allowMigration && d.Config.OfficialQQMigrationEnable {
		migration := &officialQQIdentityMigration{
			appID:       pa.getAppID().String(),
			uin:         uin,
			oldEndpoint: oldEndpoint,
			newEndpoint: expectedEndpoint,
			groups:      map[string]string{},
			users:       map[string]string{},
			logNames:    map[string]string{},
		}
		// fix5 的冲突策略会故意保留一部分旧行；如果每次连接都据此重跑全量迁移，
		// 会给大库带来明显的启动开销并反复输出冲突告警。这里记录“剩余旧行数量
		// + 主键集合哈希”，两者都不变时只做内存合并和角色卡缓存同步。
		if d.DBOperator != nil && pa.getMigrationState() != "" {
			if count, fingerprint, err := migration.legacyRowFingerprint(d.DBOperator); err == nil &&
				pa.getMigrationState() == migration.stateValue(count, fingerprint) {
				if d.AttrsManager != nil {
					if err := d.AttrsManager.CheckForSave(); err != nil {
						return fmt.Errorf("迁移前保存属性数据失败: %w", err)
					}
				}
				if err := migration.syncCharacterCache(d, d.DBOperator); err != nil {
					return &officialQQIdentityMigrationError{cause: fmt.Errorf("同步角色卡缓存失败: %w", err)}
				}
				migration.collectMemory(d)
				migration.migrateMemory(d)
				d.LastUpdatedTime = time.Now().Unix()
				d.Save(false)
				return nil
			}
		}
		if err := migration.run(d); err != nil {
			return &officialQQIdentityMigrationError{cause: err}
		}
		if d.DBOperator != nil {
			if count, fingerprint, err := migration.legacyRowFingerprint(d.DBOperator); err == nil {
				pa.setMigrationState(migration.stateValue(count, fingerprint))
			} else {
				pa.setMigrationState("")
			}
		}
	}

	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
	return nil
}

func (m *officialQQIdentityMigration) oldGroupPrefix() string {
	return "OpenQQ-Group-T:" + m.appID + "-"
}

func officialQQIdentityMigrationPrefixBounds(prefix string) (string, string) {
	// All legacy identity prefixes are ASCII and end in '-'. Replacing that
	// byte with '.' gives the smallest exclusive upper bound for the prefix.
	return prefix, strings.TrimSuffix(prefix, "-") + "."
}

func (m *officialQQIdentityMigration) oldGroupBounds() (string, string) {
	return officialQQIdentityMigrationPrefixBounds(m.oldGroupPrefix())
}

func (m *officialQQIdentityMigration) oldMemberRootPrefix() string {
	return "OpenQQ-Member-T:" + m.appID + "-"
}

func (m *officialQQIdentityMigration) oldMemberBounds() (string, string) {
	return officialQQIdentityMigrationPrefixBounds(m.oldMemberRootPrefix())
}

func (m *officialQQIdentityMigration) oldMemberPrefix(groupOpenID string) string {
	return "OpenQQ-Member-T:" + m.appID + "-" + groupOpenID + "-"
}

func (m *officialQQIdentityMigration) addGroup(groupID string) bool {
	groupOpenID, ok := strings.CutPrefix(groupID, m.oldGroupPrefix())
	if !ok {
		return false
	}
	// Some old releases persisted one synthetic group with an empty GroupOpenID.
	// Keep its data under a deterministic non-QQ placeholder instead of dropping it.
	if groupOpenID == "" {
		groupOpenID = "legacy-empty-" + m.appID
	}
	m.groups[groupID] = formatDiceIDOfficialQQGroupOpenID(m.uin, groupOpenID)
	return true
}

func (m *officialQQIdentityMigration) groupOpenID(groupID string) (string, bool) {
	groupOpenID, ok := strings.CutPrefix(groupID, m.oldGroupPrefix())
	return groupOpenID, ok
}

func (m *officialQQIdentityMigration) addMember(groupID, userID string) bool {
	groupOpenID, ok := m.groupOpenID(groupID)
	if !ok {
		return false
	}
	memberOpenID, ok := strings.CutPrefix(userID, m.oldMemberPrefix(groupOpenID))
	if !ok || memberOpenID == "" {
		return false
	}
	m.users[userID] = formatDiceIDOfficialQQMemberOpenID(m.uin, groupOpenID, memberOpenID)
	return true
}

func (m *officialQQIdentityMigration) addMemberID(userID string) bool {
	if _, exists := m.users[userID]; exists {
		return true
	}
	rest, ok := strings.CutPrefix(userID, "OpenQQ-Member-T:"+m.appID+"-")
	if !ok {
		return false
	}
	for _, oldGroupID := range m.sortedOldGroups() {
		groupOpenID, exists := m.groupOpenID(oldGroupID)
		if !exists {
			continue
		}
		memberOpenID, matches := strings.CutPrefix(rest, groupOpenID+"-")
		if matches && memberOpenID != "" {
			m.users[userID] = formatDiceIDOfficialQQMemberOpenID(m.uin, groupOpenID, memberOpenID)
			return true
		}
	}
	separator := strings.LastIndexByte(rest, '-')
	if separator <= 0 || separator == len(rest)-1 {
		return false
	}
	memberOpenID := rest[separator+1:]
	m.users[userID] = formatDiceIDOfficialQQMemberOpenID(m.uin, rest[:separator], memberOpenID)
	return true
}

func (m *officialQQIdentityMigration) migrateGroupID(id string) string {
	if value, ok := m.groups[id]; ok {
		return value
	}
	return id
}

func (m *officialQQIdentityMigration) migrateUserID(id string) string {
	if value, ok := m.users[id]; ok {
		return value
	}
	if m.addMemberID(id) {
		return m.users[id]
	}
	return id
}

func (m *officialQQIdentityMigration) migrateAnyID(id string) string {
	if id == m.oldEndpoint {
		return m.newEndpoint
	}
	if value := m.migrateGroupID(id); value != id {
		return value
	}
	return m.migrateUserID(id)
}

func (m *officialQQIdentityMigration) migrateContextUserID(groupID, userID string) string {
	if _, ok := m.users[userID]; !ok {
		m.addMember(groupID, userID)
	}
	return m.migrateUserID(userID)
}

func (m *officialQQIdentityMigration) sortedOldGroups() []string {
	groups := make([]string, 0, len(m.groups))
	for groupID := range m.groups {
		groups = append(groups, groupID)
	}
	sort.Slice(groups, func(i, j int) bool { return len(groups[i]) > len(groups[j]) })
	return groups
}

func (m *officialQQIdentityMigration) migrateAttrsID(id, attrsType string) string {
	if attrsType == "character" {
		return id
	}
	if value := m.migrateAnyID(id); value != id {
		return value
	}
	if attrsType != "" && attrsType != "group_user" {
		return id
	}
	for _, oldGroupID := range m.sortedOldGroups() {
		userID, ok := strings.CutPrefix(id, oldGroupID+"-")
		if !ok || userID == "" {
			continue
		}
		newUserID := m.migrateContextUserID(oldGroupID, userID)
		if newUserID == userID {
			return id
		}
		return m.groups[oldGroupID] + "-" + newUserID
	}
	return id
}

func (m *officialQQIdentityMigration) run(d *Dice) error {
	if d.DBOperator != nil {
		shouldMigrate, err := m.shouldRunIdentityMigration(d.DBOperator)
		if err != nil {
			return fmt.Errorf("检查 QQ 官方旧群组数据失败: %w", err)
		}
		if !shouldMigrate {
			if err := m.syncCharacterCache(d, d.DBOperator); err != nil {
				return fmt.Errorf("同步角色卡缓存失败: %w", err)
			}
			// 数据库里没有旧数据时，内存中仍可能残留旧 ID 的群组/缓存。
			m.collectMemory(d)
			m.migrateMemory(d)
			return nil
		}
		if err := m.collectDatabase(d.DBOperator); err != nil {
			return err
		}
	}
	m.collectMemory(d)

	if d.AttrsManager != nil {
		if err := d.AttrsManager.CheckForSave(); err != nil {
			return fmt.Errorf("迁移前保存属性数据失败: %w", err)
		}
	}
	if d.DBOperator != nil {
		if err := m.migrateLogDB(d.DBOperator); err != nil {
			return fmt.Errorf("迁移日志数据库失败: %w", err)
		}
		if err := m.migrateCensorDB(d.DBOperator); err != nil {
			return fmt.Errorf("迁移敏感词数据库失败: %w", err)
		}
		if err := m.migrateDataDB(d.DBOperator); err != nil {
			return fmt.Errorf("迁移主数据库失败: %w", err)
		}
		if err := m.syncCharacterCache(d, d.DBOperator); err != nil {
			return fmt.Errorf("同步角色卡缓存失败: %w", err)
		}
	}
	m.migrateMemory(d)
	return nil
}

func (m *officialQQIdentityMigration) syncCharacterCache(d *Dice, operator engine.DatabaseOperator) error {
	if d.AttrsManager == nil {
		return nil
	}
	var ids []string
	d.AttrsManager.m.Range(func(id string, _ *AttributesItem) bool {
		ids = append(ids, id)
		return true
	})
	if len(ids) == 0 {
		return nil
	}

	db := operator.GetDataDB(constant.READ)
	if !hasTable(db, &model.AttributesItemModel{}) {
		return nil
	}
	db = officialQQIdentityMigrationWithoutCache(db)
	return officialQQIdentityMigrationForEachChunk(ids, func(batchIDs []string) error {
		var rows []model.AttributesItemModel
		if err := db.Select("id, name").Where("attrs_type = ? AND id IN ?", "character", batchIDs).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if item, ok := d.AttrsManager.m.Load(row.Id); ok && item != nil {
				item.Name = row.Name
				item.IsSaved = true
			}
		}
		return nil
	})
}

func hasTable(db *gorm.DB, value any) bool {
	return db != nil && db.Migrator().HasTable(value)
}

func (m *officialQQIdentityMigration) stateKey() string {
	return m.appID + "\x00" + m.uin + "\x00" + m.oldEndpoint
}

func (m *officialQQIdentityMigration) stateValue(count int64, fingerprint string) string {
	return m.stateKey() + "|" + strconv.FormatInt(count, 10) + "|" + fingerprint
}

// legacyRowFingerprint 统计旧行数量并对其主键集合做哈希。
// 仅用数量会在“删一条、加一条”时误判为已完成迁移；主键集合哈希能
// 在同样的扫描成本下准确识别行集合变化。
func (m *officialQQIdentityMigration) legacyRowFingerprint(operator engine.DatabaseOperator) (int64, string, error) {
	type probe struct {
		name    string
		query   *gorm.DB
		column  string
		numeric bool
	}
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	memberPrefix, memberUpperBound := m.oldMemberBounds()

	var probes []probe
	dataDB := operator.GetDataDB(constant.READ)
	if dataDB != nil && hasTable(dataDB, &model.GroupInfo{}) {
		probes = append(probes, probe{
			name:   "group_info",
			query:  dataDB.Model(&model.GroupInfo{}).Where("id >= ? AND id < ?", groupPrefix, groupUpperBound).Order("id"),
			column: "id",
		})
	}
	logDB := operator.GetLogDB(constant.READ)
	if logDB != nil && hasTable(logDB, &model.LogInfo{}) {
		probes = append(probes, probe{
			name:    "log_info",
			query:   logDB.Model(&model.LogInfo{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound).Order("id"),
			column:  "id",
			numeric: true,
		})
	}
	if logDB != nil && hasTable(logDB, &model.LogOneItem{}) {
		probes = append(probes, probe{
			name:    "log_one_item",
			query:   logDB.Model(&model.LogOneItem{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound).Order("id"),
			column:  "id",
			numeric: true,
		})
	}
	if dataDB != nil && hasTable(dataDB, &model.GroupPlayerInfoBase{}) {
		probes = append(probes, probe{
			name:    "group_player_info",
			query:   dataDB.Model(&model.GroupPlayerInfoBase{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound).Order("id"),
			column:  "id",
			numeric: true,
		})
	}
	if dataDB != nil && hasTable(dataDB, &model.AttributesItemModel{}) {
		probes = append(probes, probe{
			name:   "attributes",
			query:  m.legacyAttrsQuery(dataDB.Model(&model.AttributesItemModel{})).Order("id"),
			column: "id",
		})
	}
	if dataDB != nil && hasTable(dataDB, &model.BanInfo{}) {
		probes = append(probes, probe{
			name: "ban_info",
			query: dataDB.Model(&model.BanInfo{}).Where(
				"(id >= ? AND id < ?) OR (id >= ? AND id < ?)",
				groupPrefix, groupUpperBound, memberPrefix, memberUpperBound,
			).Order("id"),
			column: "id",
		})
	}
	if dataDB != nil && hasTable(dataDB, &model.EndpointInfo{}) {
		probes = append(probes, probe{
			name:   "endpoint_info",
			query:  dataDB.Model(&model.EndpointInfo{}).Where("user_id = ?", m.oldEndpoint).Order("user_id"),
			column: "user_id",
		})
	}
	censorDB := operator.GetCensorDB(constant.READ)
	if censorDB != nil && hasTable(censorDB, &model.CensorLog{}) {
		probes = append(probes, probe{
			name:    "censor_log",
			query:   censorDB.Model(&model.CensorLog{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound).Order("id"),
			column:  "id",
			numeric: true,
		})
	}

	var total int64
	hash := sha256.New()
	for _, item := range probes {
		var ids []string
		if item.numeric {
			var numericIDs []int64
			if err := item.query.Pluck(item.column, &numericIDs).Error; err != nil {
				return 0, "", err
			}
			ids = make([]string, 0, len(numericIDs))
			for _, id := range numericIDs {
				ids = append(ids, strconv.FormatInt(id, 10))
			}
		} else if err := item.query.Pluck(item.column, &ids).Error; err != nil {
			return 0, "", err
		}
		sort.Strings(ids)
		total += int64(len(ids))
		_, _ = hash.Write([]byte(item.name))
		_, _ = hash.Write([]byte{0})
		for _, id := range ids {
			_, _ = hash.Write([]byte(id))
			_, _ = hash.Write([]byte{0})
		}
	}
	return total, fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// legacyRowCount 统计各表中仍带旧身份前缀的行数。
// shouldRunIdentityMigration 只关心“是否大于 0”，而迁移完成标记需要精确数量。
func (m *officialQQIdentityMigration) legacyRowCount(operator engine.DatabaseOperator) (int64, error) {
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	memberPrefix, memberUpperBound := m.oldMemberBounds()

	probes := []*gorm.DB{}
	dataDB := operator.GetDataDB(constant.READ)
	if !hasTable(dataDB, &model.GroupInfo{}) {
		// 无法用数据库探测排除仅存在于内存中的旧身份，返回非零强制走一次完整流程。
		return 1, nil
	}
	probes = append(probes, dataDB.Model(&model.GroupInfo{}).Where("id >= ? AND id < ?", groupPrefix, groupUpperBound))

	logDB := operator.GetLogDB(constant.READ)
	if hasTable(logDB, &model.LogInfo{}) {
		probes = append(probes, logDB.Model(&model.LogInfo{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound))
	}
	if hasTable(logDB, &model.LogOneItem{}) {
		probes = append(probes, logDB.Model(&model.LogOneItem{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound))
	}

	if hasTable(dataDB, &model.GroupPlayerInfoBase{}) {
		probes = append(probes, dataDB.Model(&model.GroupPlayerInfoBase{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound))
	}
	if hasTable(dataDB, &model.AttributesItemModel{}) {
		probes = append(probes, m.legacyAttrsQuery(dataDB.Model(&model.AttributesItemModel{})))
	}
	if hasTable(dataDB, &model.BanInfo{}) {
		probes = append(probes, dataDB.Model(&model.BanInfo{}).Where(
			"(id >= ? AND id < ?) OR (id >= ? AND id < ?)",
			groupPrefix,
			groupUpperBound,
			memberPrefix,
			memberUpperBound,
		))
	}
	if hasTable(dataDB, &model.EndpointInfo{}) {
		probes = append(probes, dataDB.Model(&model.EndpointInfo{}).Where("user_id = ?", m.oldEndpoint))
	}

	censorDB := operator.GetCensorDB(constant.READ)
	if hasTable(censorDB, &model.CensorLog{}) {
		probes = append(probes, censorDB.Model(&model.CensorLog{}).Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound))
	}

	var total int64
	for _, probe := range probes {
		var count int64
		result := officialQQIdentityMigrationWithoutCache(probe).Count(&count)
		if result.Error != nil {
			return 0, result.Error
		}
		total += count
	}
	return total, nil
}

func (m *officialQQIdentityMigration) shouldRunIdentityMigration(operator engine.DatabaseOperator) (bool, error) {
	count, err := m.legacyRowCount(operator)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (m *officialQQIdentityMigration) collectDatabase(operator engine.DatabaseOperator) error {
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	memberPrefix, memberUpperBound := m.oldMemberBounds()
	dataDB := operator.GetDataDB(constant.READ)
	if hasTable(dataDB, &model.GroupInfo{}) {
		err := officialQQIdentityMigrationFindInBatches(
			dataDB.Select("id").Where("id >= ? AND id < ?", groupPrefix, groupUpperBound),
			func(rows []model.GroupInfo) error {
				for _, row := range rows {
					m.addGroup(row.ID)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}
	if hasTable(dataDB, &model.GroupPlayerInfoBase{}) {
		err := officialQQIdentityMigrationFindInBatches(
			dataDB.Select("id, group_id, user_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
			func(rows []model.GroupPlayerInfoBase) error {
				for _, row := range rows {
					m.addGroup(row.GroupID)
					m.addMember(row.GroupID, row.UserID)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}

	logDB := operator.GetLogDB(constant.READ)
	if hasTable(logDB, &model.LogInfo{}) {
		err := officialQQIdentityMigrationFindInBatches(
			logDB.Select("id, group_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
			func(rows []model.LogInfo) error {
				for _, row := range rows {
					m.addGroup(row.GroupID)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}
	if hasTable(logDB, &model.LogOneItem{}) {
		err := officialQQIdentityMigrationFindInBatches(
			logDB.Select("id, group_id, im_userid, user_uniform_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
			func(rows []model.LogOneItem) error {
				for _, row := range rows {
					m.addGroup(row.GroupID)
					m.addMember(row.GroupID, row.IMUserID)
					m.addMember(row.GroupID, row.UniformID)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}

	censorDB := operator.GetCensorDB(constant.READ)
	if hasTable(censorDB, &model.CensorLog{}) {
		err := officialQQIdentityMigrationFindInBatches(
			censorDB.Select("id, group_id, user_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
			func(rows []model.CensorLog) error {
				for _, row := range rows {
					m.addGroup(row.GroupID)
					m.addMember(row.GroupID, row.UserID)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}

	if hasTable(dataDB, &model.AttributesItemModel{}) {
		groupUserMarker := "-OpenQQ-Member-T:" + m.appID + "-"
		err := officialQQIdentityMigrationFindInBatches(
			m.legacyAttrsQuery(dataDB.Select("id, owner_id")),
			func(rows []model.AttributesItemModel) error {
				for _, row := range rows {
					if marker := strings.Index(row.Id, groupUserMarker); marker > 0 {
						oldGroupID := row.Id[:marker]
						if m.addGroup(oldGroupID) {
							m.addMember(oldGroupID, row.Id[marker+1:])
						}
					} else if strings.HasPrefix(row.Id, m.oldGroupPrefix()) {
						m.addGroup(row.Id)
					}
					m.addMemberID(row.Id)
					m.addMemberID(row.OwnerId)
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}

	if hasTable(dataDB, &model.BanInfo{}) {
		err := officialQQIdentityMigrationFindInBatches(
			dataDB.Select("id, data").Where(
				"(id >= ? AND id < ?) OR (id >= ? AND id < ?)",
				groupPrefix,
				groupUpperBound,
				memberPrefix,
				memberUpperBound,
			),
			func(rows []model.BanInfo) error {
				for _, row := range rows {
					var item BanListInfoItem
					if json.Unmarshal(row.Data, &item) != nil {
						continue
					}
					for _, place := range item.Places {
						m.addGroup(place)
						m.addMember(place, row.ID)
					}
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *officialQQIdentityMigration) collectMemory(d *Dice) {
	if d.ImSession != nil && d.ImSession.ServiceAtNew != nil {
		d.ImSession.ServiceAtNew.Range(func(groupID string, group *GroupInfo) bool {
			if !m.addGroup(groupID) {
				return true
			}
			if group != nil {
				m.addMember(groupID, group.InviteUserID)
				if group.Players != nil {
					group.Players.Range(func(userID string, _ *GroupPlayerInfo) bool {
						m.addMember(groupID, userID)
						return true
					})
				}
			}
			return true
		})
	}
	if d.Config.BanList != nil && d.Config.BanList.Map != nil {
		d.Config.BanList.Map.Range(func(id string, item *BanListInfoItem) bool {
			if item != nil {
				for _, place := range item.Places {
					m.addGroup(place)
					m.addMember(place, id)
				}
			}
			return true
		})
	}
}

func ensureNoTarget(db *gorm.DB, value any, where string, args ...any) error {
	var count int64
	if err := db.Model(value).Where(where, args...).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("%w: %s %v", errOfficialQQIdentityTargetExists, where, args)
	}
	return nil
}

func logOfficialQQIdentityConflict(kind string, oldID any, newID string) {
	zap.S().Named(logger.LogKeyAdapter).Warnf(
		"official qq identity migration: %s %v -> %s already exists, keep old row and continue",
		kind, oldID, newID,
	)
}

func logOfficialQQIdentityMergeSkipped(target string, err error) {
	zap.S().Named(logger.LogKeyAdapter).Warnf(
		"official qq identity migration: merge attrs %s failed, keep old rows and continue: %v",
		target, err,
	)
}

// uniqueOfficialQQLogName 为冲突日志生成一个在新群组内唯一的名称，
// 让旧日志仍能在新群组下被 .log list 访问，而不是永久留在旧 ID 下。
func uniqueOfficialQQLogName(tx *gorm.DB, groupID, name string) (string, error) {
	for suffix := 1; suffix <= 1000; suffix++ {
		candidate := name + " (旧)"
		if suffix > 1 {
			candidate = fmt.Sprintf("%s (旧 %d)", name, suffix)
		}
		var count int64
		if err := tx.Model(&model.LogInfo{}).Where("group_id = ? AND name = ?", groupID, candidate).Count(&count).Error; err != nil {
			return "", err
		}
		if count == 0 {
			return candidate, nil
		}
	}
	return fmt.Sprintf("%s (旧 %d)", name, time.Now().UnixNano()), nil
}

func (m *officialQQIdentityMigration) legacyAttrsQuery(db *gorm.DB) *gorm.DB {
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	memberPrefix, memberUpperBound := m.oldMemberBounds()
	return db.Where(
		"(id >= ? AND id < ?) OR (id >= ? AND id < ?) OR (owner_id >= ? AND owner_id < ?)",
		groupPrefix,
		groupUpperBound,
		memberPrefix,
		memberUpperBound,
		memberPrefix,
		memberUpperBound,
	)
}

const officialQQIdentityMigrationAttrsMetadataColumns = "id, attrs_type, binding_sheet_id, name, owner_id, sheet_type, is_hidden, created_at, updated_at"

func mergeOfficialQQUserAttrs(tx *gorm.DB, rows []model.AttributesItemModel) (model.AttributesItemModel, error) {
	if len(rows) == 0 {
		return model.AttributesItemModel{}, errors.New("没有可合并的 QQ 官方用户属性")
	}

	ordered := append([]model.AttributesItemModel(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].UpdatedAt != ordered[j].UpdatedAt {
			return ordered[i].UpdatedAt < ordered[j].UpdatedAt
		}
		if ordered[i].CreatedAt != ordered[j].CreatedAt {
			return ordered[i].CreatedAt < ordered[j].CreatedAt
		}
		return ordered[i].Id < ordered[j].Id
	})

	merged := &ds.ValueMap{}
	createdAt := ordered[0].CreatedAt
	updatedAt := ordered[0].UpdatedAt
	for _, row := range ordered {
		if row.AttrsType != "" && row.AttrsType != "user" {
			return model.AttributesItemModel{}, fmt.Errorf("%w: 属性 %s attrs_type=%q", errOfficialQQAttrsNotMergeable, row.Id, row.AttrsType)
		}
		if row.BindingSheetId != "" {
			return model.AttributesItemModel{}, fmt.Errorf("%w: 属性 %s 带有角色绑定", errOfficialQQAttrsNotMergeable, row.Id)
		}
		if row.CreatedAt < createdAt {
			createdAt = row.CreatedAt
		}
		if row.UpdatedAt > updatedAt {
			updatedAt = row.UpdatedAt
		}
	}
	tx = officialQQIdentityMigrationWithoutCache(tx)
	if err := officialQQIdentityMigrationForEachChunk(ordered, func(batch []model.AttributesItemModel) error {
		ids := make([]string, 0, len(batch))
		for _, row := range batch {
			ids = append(ids, row.Id)
		}
		var dataRows []model.AttributesItemModel
		if err := tx.Select("id, data").Where("id IN ?", ids).Find(&dataRows).Error; err != nil {
			return err
		}
		dataByID := make(map[string][]byte, len(dataRows))
		for _, row := range dataRows {
			dataByID[row.Id] = row.Data
		}
		for _, row := range batch {
			data, exists := dataByID[row.Id]
			if !exists {
				return fmt.Errorf("QQ 官方用户属性 %s 在合并期间不存在", row.Id)
			}
			value, err := ds.VMValueFromJSON(data)
			if err != nil {
				return fmt.Errorf("解析 QQ 官方用户属性 %s 失败: %w", row.Id, err)
			}
			dict, ok := value.ReadDictData()
			if !ok {
				return fmt.Errorf("QQ 官方用户属性 %s 不是字典", row.Id)
			}
			if dict.Dict != nil {
				dict.Dict.Range(func(key string, value *ds.VMValue) bool {
					merged.Store(key, value)
					return true
				})
			}
		}
		return nil
	}); err != nil {
		return model.AttributesItemModel{}, err
	}

	data, err := ds.NewDictVal(merged).V().ToJSON()
	if err != nil {
		return model.AttributesItemModel{}, fmt.Errorf("序列化合并后的 QQ 官方用户属性失败: %w", err)
	}
	result := ordered[len(ordered)-1]
	result.Data = data
	result.AttrsType = "user"
	result.BindingSheetId = ""
	result.CreatedAt = createdAt
	result.UpdatedAt = updatedAt
	return result, nil
}

func (m *officialQQIdentityMigration) mergeCollidingUserAttrs(tx *gorm.DB) error {
	tx = officialQQIdentityMigrationWithoutCache(tx)
	byTarget := map[string][]model.AttributesItemModel{}
	err := officialQQIdentityMigrationFindInBatches(
		m.legacyAttrsQuery(tx).Select(officialQQIdentityMigrationAttrsMetadataColumns),
		func(rows []model.AttributesItemModel) error {
			for _, row := range rows {
				newID := m.migrateUserID(row.Id)
				if newID == row.Id {
					continue
				}
				byTarget[newID] = append(byTarget[newID], row)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}

	targets := make([]string, 0, len(byTarget))
	for target, sources := range byTarget {
		if len(sources) > 1 {
			targets = append(targets, target)
			continue
		}
		// 单个旧记录也可能与新 ID 的现有记录冲突，此时同样需要合并，
		// 否则后续主键更新会被 ensureNoTarget 拒绝。
		var existing model.AttributesItemModel
		result := tx.Select("id").Where("id = ?", target).Limit(1).Find(&existing)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 0 {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)

	for _, target := range targets {
		sources := byTarget[target]
		var existing model.AttributesItemModel
		result := tx.Select(officialQQIdentityMigrationAttrsMetadataColumns).Where("id = ?", target).Limit(1).Find(&existing)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 0 {
			sources = append(sources, existing)
		}

		merged, err := mergeOfficialQQUserAttrs(tx, sources)
		if err != nil {
			if errors.Is(err, errOfficialQQAttrsNotMergeable) {
				// 绑卡/非 user 类型的单条冲突保留旧行，不影响其他表和其他行。
				logOfficialQQIdentityMergeSkipped(target, err)
				continue
			}
			// 数据损坏/解析失败通常是可修复问题，保持事务回滚，下次连接重试。
			return err
		}
		merged.Id = target
		merged.OwnerId = m.migrateUserID(merged.OwnerId)

		ids := make([]string, 0, len(sources))
		for _, source := range sources {
			ids = append(ids, source.Id)
		}
		if err := officialQQIdentityMigrationForEachChunk(ids, func(batchIDs []string) error {
			return tx.Where("id IN ?", batchIDs).Delete(&model.AttributesItemModel{}).Error
		}); err != nil {
			return err
		}
		if err := tx.Create(&merged).Error; err != nil {
			return err
		}
	}
	return nil
}

func (m *officialQQIdentityMigration) planCharacterNames(tx *gorm.DB) (map[string]string, error) {
	tx = officialQQIdentityMigrationWithoutCache(tx)
	type ownerName struct {
		owner string
		name  string
	}
	type candidate struct {
		id        string
		owner     string
		name      string
		createdAt int64
	}

	owners := map[string]struct{}{}
	groups := map[ownerName][]candidate{}
	err := officialQQIdentityMigrationFindInBatches(
		m.legacyAttrsQuery(tx).Select("id, attrs_type, name, owner_id, created_at"),
		func(rows []model.AttributesItemModel) error {
			for _, row := range rows {
				newOwnerID := m.migrateUserID(row.OwnerId)
				if row.AttrsType != "character" || newOwnerID == row.OwnerId {
					continue
				}
				owners[newOwnerID] = struct{}{}
				key := ownerName{owner: newOwnerID, name: row.Name}
				groups[key] = append(groups[key], candidate{
					id:        row.Id,
					owner:     newOwnerID,
					name:      row.Name,
					createdAt: row.CreatedAt,
				})
			}
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if len(owners) == 0 {
		return map[string]string{}, nil
	}

	ownerIDs := make([]string, 0, len(owners))
	for ownerID := range owners {
		ownerIDs = append(ownerIDs, ownerID)
	}

	usedNames := map[string]map[string]struct{}{}
	for ownerID := range owners {
		usedNames[ownerID] = map[string]struct{}{}
	}
	if err := officialQQIdentityMigrationForEachChunk(ownerIDs, func(batchOwnerIDs []string) error {
		return officialQQIdentityMigrationFindInBatches(
			tx.Select("id, owner_id, name").Where("attrs_type = ? AND owner_id IN ?", "character", batchOwnerIDs),
			func(rows []model.AttributesItemModel) error {
				for _, row := range rows {
					usedNames[row.OwnerId][row.Name] = struct{}{}
				}
				return nil
			},
		)
	}); err != nil {
		return nil, err
	}

	keys := make([]ownerName, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].owner != keys[j].owner {
			return keys[i].owner < keys[j].owner
		}
		return keys[i].name < keys[j].name
	})

	var duplicates []candidate
	for _, key := range keys {
		items := groups[key]
		sort.Slice(items, func(i, j int) bool {
			if items[i].createdAt != items[j].createdAt {
				return items[i].createdAt < items[j].createdAt
			}
			return items[i].id < items[j].id
		})
		if _, exists := usedNames[key.owner][key.name]; !exists {
			usedNames[key.owner][key.name] = struct{}{}
			items = items[1:]
		}
		duplicates = append(duplicates, items...)
	}

	sort.Slice(duplicates, func(i, j int) bool {
		if duplicates[i].owner != duplicates[j].owner {
			return duplicates[i].owner < duplicates[j].owner
		}
		if duplicates[i].createdAt != duplicates[j].createdAt {
			return duplicates[i].createdAt < duplicates[j].createdAt
		}
		return duplicates[i].id < duplicates[j].id
	})

	renames := map[string]string{}
	for _, item := range duplicates {
		for suffix := 2; ; suffix++ {
			newName := migratedCharacterName(item.name, suffix)
			if _, exists := usedNames[item.owner][newName]; exists {
				continue
			}
			usedNames[item.owner][newName] = struct{}{}
			renames[item.id] = newName
			break
		}
	}
	m.characterNames = renames
	return renames, nil
}

func mergeOfficialQQPlayerRows(target, source model.GroupPlayerInfoBase) model.GroupPlayerInfoBase {
	if target.Name == "" {
		target.Name = source.Name
	}
	if target.AutoSetNameTemplate == "" {
		target.AutoSetNameTemplate = source.AutoSetNameTemplate
	}
	if target.DiceSideNum == 0 {
		target.DiceSideNum = source.DiceSideNum
	}
	if source.LastCommandTime > target.LastCommandTime {
		target.LastCommandTime = source.LastCommandTime
	}
	if target.CreatedAt == 0 || (source.CreatedAt != 0 && source.CreatedAt < target.CreatedAt) {
		target.CreatedAt = source.CreatedAt
	}
	if source.UpdatedAt > target.UpdatedAt {
		target.UpdatedAt = source.UpdatedAt
	}
	return target
}

// mergeGroupIntoExisting 把旧 group_info 行合并进已存在的新行，然后删除旧行。
func (m *officialQQIdentityMigration) mergeGroupIntoExisting(tx *gorm.DB, oldRow model.GroupInfo, newID string) error {
	var targetRow model.GroupInfo
	result := tx.Select("id, data").Where("id = ?", newID).Limit(1).Find(&targetRow)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("目标群组 %s 不存在", newID)
	}
	var oldGroup, targetGroup GroupInfo
	if err := json.Unmarshal(oldRow.Data, &oldGroup); err != nil {
		return fmt.Errorf("解析旧群组 %s 失败: %w", oldRow.ID, err)
	}
	if err := json.Unmarshal(targetRow.Data, &targetGroup); err != nil {
		return fmt.Errorf("解析目标群组 %s 失败: %w", newID, err)
	}
	m.migrateGroup(&oldGroup, oldRow.ID)
	targetGroup.GroupID = newID
	mergeOfficialQQGroupMemory(&targetGroup, &oldGroup, nil)
	data, err := json.Marshal(&targetGroup)
	if err != nil {
		return err
	}
	if err := tx.Model(&model.GroupInfo{}).Where("id = ?", newID).Update("data", data).Error; err != nil {
		return err
	}
	return tx.Where("id = ?", oldRow.ID).Delete(&model.GroupInfo{}).Error
}

func (m *officialQQIdentityMigration) migrateDataDB(operator engine.DatabaseOperator) error {
	db := operator.GetDataDB(constant.WRITE)
	if db == nil {
		return nil
	}
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	return db.Transaction(func(tx *gorm.DB) error {
		if hasTable(tx, &model.GroupInfo{}) {
			err := officialQQIdentityMigrationFindInBatches(
				tx.Select("id, data").Where("id >= ? AND id < ?", groupPrefix, groupUpperBound),
				func(rows []model.GroupInfo) error {
					for _, row := range rows {
						newID := m.migrateGroupID(row.ID)
						if newID == row.ID {
							continue
						}
						if err := ensureNoTarget(tx, &model.GroupInfo{}, "id = ?", newID); err != nil {
							if errors.Is(err, errOfficialQQIdentityTargetExists) {
								// 新旧群组同时存在：把旧群组的设置/扩展并入规范 ID 下的新群组，
								// 再删除旧行，避免旧数据永久不可达。
								if mergeErr := m.mergeGroupIntoExisting(tx, row, newID); mergeErr != nil {
									return mergeErr
								}
								logOfficialQQIdentityConflict("group_info (merged)", row.ID, newID)
								continue
							}
							return err
						}
						var group GroupInfo
						if err := json.Unmarshal(row.Data, &group); err != nil {
							return fmt.Errorf("解析群组 %s 失败: %w", row.ID, err)
						}
						m.migrateGroup(&group, row.ID)
						data, err := json.Marshal(&group)
						if err != nil {
							return err
						}
						if err := tx.Model(&model.GroupInfo{}).Where("id = ?", row.ID).Updates(map[string]any{"id": newID, "data": data}).Error; err != nil {
							return err
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}

		if hasTable(tx, &model.GroupPlayerInfoBase{}) {
			err := officialQQIdentityMigrationFindInBatches(
				tx.Select("id, group_id, user_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
				func(rows []model.GroupPlayerInfoBase) error {
					for _, row := range rows {
						newGroupID := m.migrateGroupID(row.GroupID)
						newUserID := m.migrateContextUserID(row.GroupID, row.UserID)
						if newGroupID == row.GroupID && newUserID == row.UserID {
							continue
						}
						// group_player_info 有 (group_id,user_id) 唯一索引。目标行已存在时
						// 不能直接 UPDATE；按玩家合并后删除旧行，保留两边较新的数据。
						var target model.GroupPlayerInfoBase
						targetResult := tx.Where("group_id = ? AND user_id = ?", newGroupID, newUserID).Limit(1).Find(&target)
						if targetResult.Error != nil {
							return targetResult.Error
						}
						if targetResult.RowsAffected != 0 {
							var oldPlayer model.GroupPlayerInfoBase
							if loadErr := tx.Where("id = ?", row.ID).Limit(1).Find(&oldPlayer).Error; loadErr != nil {
								return loadErr
							}
							merged := mergeOfficialQQPlayerRows(target, oldPlayer)
							updates := map[string]any{
								"name":                   merged.Name,
								"last_command_time":      merged.LastCommandTime,
								"auto_set_name_template": merged.AutoSetNameTemplate,
								"dice_side_num":          merged.DiceSideNum,
								"created_at":             merged.CreatedAt,
								"updated_at":             merged.UpdatedAt,
							}
							if updateErr := tx.Model(&model.GroupPlayerInfoBase{}).Where("id = ?", target.ID).Updates(updates).Error; updateErr != nil {
								return updateErr
							}
							if deleteErr := tx.Where("id = ?", row.ID).Delete(&model.GroupPlayerInfoBase{}).Error; deleteErr != nil {
								return deleteErr
							}
							logOfficialQQIdentityConflict("group_player_info (merged)", row.ID, fmt.Sprintf("%s/%s", newGroupID, newUserID))
							continue
						}
						if err := tx.Model(&model.GroupPlayerInfoBase{}).Where("id = ?", row.ID).Updates(map[string]any{"group_id": newGroupID, "user_id": newUserID}).Error; err != nil {
							return err
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}

		if hasTable(tx, &model.AttributesItemModel{}) {
			characterNames, err := m.planCharacterNames(tx)
			if err != nil {
				return err
			}
			if mergeErr := m.mergeCollidingUserAttrs(tx); mergeErr != nil {
				return mergeErr
			}
			err = officialQQIdentityMigrationFindInBatches(
				m.legacyAttrsQuery(tx).Select("id, attrs_type, owner_id"),
				func(rows []model.AttributesItemModel) error {
					for _, row := range rows {
						newID := m.migrateAttrsID(row.Id, row.AttrsType)
						newOwnerID := m.migrateUserID(row.OwnerId)
						newName, rename := characterNames[row.Id]
						if newID == row.Id && newOwnerID == row.OwnerId && !rename {
							continue
						}
						if newID != row.Id {
							if targetErr := ensureNoTarget(tx, &model.AttributesItemModel{}, "id = ?", newID); targetErr != nil {
								if errors.Is(targetErr, errOfficialQQIdentityTargetExists) {
									logOfficialQQIdentityConflict("attributes", row.Id, newID)
									continue
								}
								return targetErr
							}
						}
						updates := map[string]any{"id": newID, "owner_id": newOwnerID}
						if rename {
							updates["name"] = newName
						}
						if updateErr := tx.Model(&model.AttributesItemModel{}).Where("id = ?", row.Id).Updates(updates).Error; updateErr != nil {
							return updateErr
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}

		if hasTable(tx, &model.BanInfo{}) {
			err := officialQQIdentityMigrationFindInBatches(
				tx.Select("id, data"),
				func(rows []model.BanInfo) error {
					for _, row := range rows {
						newID := m.migrateAnyID(row.ID)
						var item BanListInfoItem
						if unmarshalErr := json.Unmarshal(row.Data, &item); unmarshalErr != nil {
							// 数据本身损坏时也要迁移主键，避免旧 ID 永久残留。
							if newID == row.ID {
								continue
							}
							var target model.BanInfo
							targetResult := tx.Where("id = ?", newID).Limit(1).Find(&target)
							if targetResult.Error != nil {
								return targetResult.Error
							}
							if targetResult.RowsAffected == 0 {
								if updateErr := tx.Model(&model.BanInfo{}).Where("id = ?", row.ID).Update("id", newID).Error; updateErr != nil {
									return updateErr
								}
							} else if deleteErr := tx.Where("id = ?", row.ID).Delete(&model.BanInfo{}).Error; deleteErr != nil {
								return deleteErr
							}
							continue
						}

						changed := m.migrateBanItem(&item) || newID != row.ID
						if !changed {
							continue
						}
						data, marshalErr := json.Marshal(&item)
						if marshalErr != nil {
							return marshalErr
						}
						if newID == row.ID {
							if updateErr := tx.Model(&model.BanInfo{}).Where("id = ?", row.ID).Update("data", data).Error; updateErr != nil {
								return updateErr
							}
							continue
						}

						var target model.BanInfo
						targetResult := tx.Where("id = ?", newID).Limit(1).Find(&target)
						if targetResult.Error != nil {
							return targetResult.Error
						}
						if targetResult.RowsAffected == 0 {
							if updateErr := tx.Model(&model.BanInfo{}).Where("id = ?", row.ID).Updates(map[string]any{"id": newID, "data": data}).Error; updateErr != nil {
								return updateErr
							}
							continue
						}

						// 新旧记录同时存在：合并内容，删除旧行。
						mergedData := data
						var targetItem BanListInfoItem
						if unmarshalErr := json.Unmarshal(target.Data, &targetItem); unmarshalErr == nil {
							merged := mergeOfficialQQBanInfoItems(&targetItem, &item)
							encoded, encodeErr := json.Marshal(merged)
							if encodeErr != nil {
								return encodeErr
							}
							mergedData = encoded
						}
						if updateErr := tx.Model(&model.BanInfo{}).Where("id = ?", newID).Update("data", mergedData).Error; updateErr != nil {
							return updateErr
						}
						if deleteErr := tx.Where("id = ?", row.ID).Delete(&model.BanInfo{}).Error; deleteErr != nil {
							return deleteErr
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}

		if hasTable(tx, &model.EndpointInfo{}) {
			var old model.EndpointInfo
			result := tx.Where("user_id = ?", m.oldEndpoint).Limit(1).Find(&old)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 0 {
				var target model.EndpointInfo
				targetResult := tx.Where("user_id = ?", m.newEndpoint).Limit(1).Find(&target)
				if targetResult.Error != nil {
					return targetResult.Error
				}
				if targetResult.RowsAffected == 0 {
					if err := tx.Model(&model.EndpointInfo{}).Where("user_id = ?", m.oldEndpoint).Update("user_id", m.newEndpoint).Error; err != nil {
						return err
					}
				} else {
					updates := map[string]any{
						"cmd_num":       max(old.CmdNum, target.CmdNum),
						"cmd_last_time": max(old.CmdLastTime, target.CmdLastTime),
						"online_time":   max(old.OnlineTime, target.OnlineTime),
						"updated_at":    max(old.UpdatedAt, target.UpdatedAt),
					}
					if err := tx.Model(&model.EndpointInfo{}).Where("user_id = ?", m.newEndpoint).Updates(updates).Error; err != nil {
						return err
					}
					if err := tx.Where("user_id = ?", m.oldEndpoint).Delete(&model.EndpointInfo{}).Error; err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func (m *officialQQIdentityMigration) migrateLogDB(operator engine.DatabaseOperator) error {
	db := operator.GetLogDB(constant.WRITE)
	if db == nil {
		return nil
	}
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	return db.Transaction(func(tx *gorm.DB) error {
		if hasTable(tx, &model.LogInfo{}) {
			err := officialQQIdentityMigrationFindInBatches(
				tx.Select("id, name, group_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
				func(rows []model.LogInfo) error {
					for _, row := range rows {
						newGroupID := m.migrateGroupID(row.GroupID)
						if err := ensureNoTarget(tx, &model.LogInfo{}, "group_id = ? AND name = ?", newGroupID, row.Name); err != nil {
							if errors.Is(err, errOfficialQQIdentityTargetExists) {
								newName, nameErr := uniqueOfficialQQLogName(tx, newGroupID, row.Name)
								if nameErr != nil {
									return nameErr
								}
								if m.logNames == nil {
									m.logNames = map[string]string{}
								}
								m.logNames[row.GroupID+"\x00"+row.Name] = newName
								if updateErr := tx.Model(&model.LogInfo{}).Where("id = ?", row.ID).Updates(map[string]any{
									"group_id": newGroupID,
									"name":     newName,
								}).Error; updateErr != nil {
									return updateErr
								}
								logOfficialQQIdentityConflict("log_info (renamed)", row.ID, newGroupID)
								continue
							}
							return err
						}
						if err := tx.Model(&model.LogInfo{}).Where("id = ?", row.ID).UpdateColumn("group_id", newGroupID).Error; err != nil {
							return err
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}
		if hasTable(tx, &model.LogOneItem{}) {
			err := officialQQIdentityMigrationFindInBatches(
				tx.Select("id, group_id, im_userid, user_uniform_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
				func(rows []model.LogOneItem) error {
					for _, row := range rows {
						updates := map[string]any{
							"group_id":        m.migrateGroupID(row.GroupID),
							"im_userid":       m.migrateContextUserID(row.GroupID, row.IMUserID),
							"user_uniform_id": m.migrateContextUserID(row.GroupID, row.UniformID),
						}
						if err := tx.Model(&model.LogOneItem{}).Where("id = ?", row.ID).Updates(updates).Error; err != nil {
							return err
						}
					}
					return nil
				},
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (m *officialQQIdentityMigration) migrateCensorDB(operator engine.DatabaseOperator) error {
	db := operator.GetCensorDB(constant.WRITE)
	if db == nil || !hasTable(db, &model.CensorLog{}) {
		return nil
	}
	groupPrefix, groupUpperBound := m.oldGroupBounds()
	return db.Transaction(func(tx *gorm.DB) error {
		err := officialQQIdentityMigrationFindInBatches(
			tx.Select("id, group_id, user_id").Where("group_id >= ? AND group_id < ?", groupPrefix, groupUpperBound),
			func(rows []model.CensorLog) error {
				for _, row := range rows {
					updates := map[string]any{
						"group_id": m.migrateGroupID(row.GroupID),
						"user_id":  m.migrateContextUserID(row.GroupID, row.UserID),
					}
					if err := tx.Model(&model.CensorLog{}).Where("id = ?", row.ID).Updates(updates).Error; err != nil {
						return err
					}
				}
				return nil
			},
		)
		if err != nil {
			return err
		}
		return nil
	})
}

func migrateBoolMapKeys(values *SyncMap[string, bool], migrate func(string) string) {
	if values == nil {
		return
	}
	type entry struct {
		old   string
		value bool
	}
	var entries []entry
	values.Range(func(key string, value bool) bool {
		if newKey := migrate(key); newKey != key {
			entries = append(entries, entry{old: key, value: value})
		}
		return true
	})
	for _, item := range entries {
		values.Delete(item.old)
		values.Store(migrate(item.old), item.value)
	}
}

func (m *officialQQIdentityMigration) migrateGroup(group *GroupInfo, oldGroupID string) {
	if group == nil {
		return
	}
	group.GroupID = m.migrateGroupID(oldGroupID)
	if newName, ok := m.logNames[oldGroupID+"\x00"+group.LogCurName]; ok {
		group.LogCurName = newName
	}
	group.GuildID = m.migrateAnyID(group.GuildID)
	group.ChannelID = m.migrateAnyID(group.ChannelID)
	group.InviteUserID = m.migrateContextUserID(oldGroupID, group.InviteUserID)
	migrateBoolMapKeys(group.DiceIDActiveMap, m.migrateAnyID)
	migrateBoolMapKeys(group.DiceIDExistsMap, m.migrateAnyID)
	migrateBoolMapKeys(group.BotList, m.migrateAnyID)

	if group.Players != nil {
		type playerEntry struct {
			old    string
			player *GroupPlayerInfo
		}
		var players []playerEntry
		group.Players.Range(func(userID string, player *GroupPlayerInfo) bool {
			players = append(players, playerEntry{old: userID, player: player})
			return true
		})
		for _, item := range players {
			newUserID := m.migrateContextUserID(oldGroupID, item.old)
			if item.player != nil {
				item.player.UserID = newUserID
				item.player.GroupID = group.GroupID
			}
			if newUserID != item.old {
				group.Players.Delete(item.old)
				group.Players.Store(newUserID, item.player)
			}
		}
	}

	if group.PlayerGroups != nil {
		type teamEntry struct {
			old    string
			values []string
		}
		var teams []teamEntry
		group.PlayerGroups.Range(func(key string, values []string) bool {
			teams = append(teams, teamEntry{old: key, values: values})
			return true
		})
		for _, item := range teams {
			newKey := m.migrateAnyID(item.old)
			for index, value := range item.values {
				item.values[index] = m.migrateAnyID(value)
			}
			if newKey != item.old {
				group.PlayerGroups.Delete(item.old)
			}
			group.PlayerGroups.Store(newKey, item.values)
		}
	}
}

func (m *officialQQIdentityMigration) migrateBanItem(item *BanListInfoItem) bool {
	if item == nil {
		return false
	}
	changed := false
	newID := m.migrateAnyID(item.ID)
	if newID != item.ID {
		item.ID = newID
		changed = true
	}
	for index, place := range item.Places {
		newPlace := m.migrateAnyID(place)
		if newPlace != place {
			item.Places[index] = newPlace
			changed = true
		}
	}
	return changed
}

func appendUniqueStrings(values []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(extra))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range extra {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func appendUniqueInt64(values []int64, extra ...int64) []int64 {
	seen := make(map[int64]struct{}, len(values)+len(extra))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range extra {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

// mergeOfficialQQBanInfoItems 合并新旧 ID 指向同一条目的黑名单记录，保留两边信息。
func mergeOfficialQQBanInfoItems(target, source *BanListInfoItem) *BanListInfoItem {
	if target == nil {
		return source
	}
	if source == nil {
		return target
	}
	if source.Rank < target.Rank {
		target.Rank = source.Rank
	}
	if source.Score > target.Score {
		target.Score = source.Score
	}
	if target.Name == "" || (source.Name != "" && source.BanUpdatedAt > target.BanUpdatedAt) {
		target.Name = source.Name
	}
	target.Times = appendUniqueInt64(target.Times, source.Times...)
	target.Reasons = appendUniqueStrings(target.Reasons, source.Reasons...)
	target.Places = appendUniqueStrings(target.Places, source.Places...)
	if source.BanTime > target.BanTime {
		target.BanTime = source.BanTime
	}
	if source.BanUpdatedAt > target.BanUpdatedAt {
		target.BanUpdatedAt = source.BanUpdatedAt
	}
	if source.UpdatedAt > target.UpdatedAt {
		target.UpdatedAt = source.UpdatedAt
	}
	return target
}

// mergeOfficialQQAttrItems 合并同一个人物卡在旧/新 ID 下的内存缓存，
// 以较新的记录为准，只补齐缺失字段，避免直接覆盖丢数据。
func mergeOfficialQQAttrItems(target, source *AttributesItem) *AttributesItem {
	if target == nil {
		return source
	}
	if source == nil {
		return target
	}
	older, newer := target, source
	if target.LastModifiedTime > source.LastModifiedTime {
		older, newer = source, target
	}
	if newer.valueMap == nil {
		newer.valueMap = &ds.ValueMap{}
	}
	if older.valueMap != nil {
		older.valueMap.Range(func(key string, value *ds.VMValue) bool {
			if _, exists := newer.valueMap.Load(key); !exists {
				newer.valueMap.Store(key, value)
			}
			return true
		})
	}
	if newer.Name == "" {
		newer.Name = older.Name
	}
	if newer.SheetType == "" {
		newer.SheetType = older.SheetType
	}
	if newer.LastUsedTime < older.LastUsedTime {
		newer.LastUsedTime = older.LastUsedTime
	}
	if newer.LastModifiedTime < older.LastModifiedTime {
		newer.LastModifiedTime = older.LastModifiedTime
	}
	return newer
}

// mergeOfficialQQGroupMemory 把旧群组对象并入已存在的新群组对象。
// 以新对象（规范 ID 下的现网数据）为主，只补齐缺失字段和玩家，避免旧对象整体覆盖新对象。
func mergeOfficialQQGroupMemory(target, source *GroupInfo, d *Dice) bool {
	if target == nil || source == nil || target == source {
		return false
	}
	changed := false
	if target.GroupName == "" && source.GroupName != "" {
		target.GroupName = source.GroupName
		changed = true
	}
	if target.GuildID == "" && source.GuildID != "" {
		target.GuildID = source.GuildID
		changed = true
	}
	if target.ChannelID == "" && source.ChannelID != "" {
		target.ChannelID = source.ChannelID
		changed = true
	}
	if target.InviteUserID == "" && source.InviteUserID != "" {
		target.InviteUserID = source.InviteUserID
		changed = true
	}
	if target.EnteredTime == 0 && source.EnteredTime != 0 {
		target.EnteredTime = source.EnteredTime
		changed = true
	}
	if target.DiceSideNum == 0 && source.DiceSideNum != 0 {
		target.DiceSideNum = source.DiceSideNum
		changed = true
	}
	if target.DiceSideExpr == "" && source.DiceSideExpr != "" {
		target.DiceSideExpr = source.DiceSideExpr
		changed = true
	}
	if target.System == "" && source.System != "" {
		target.System = source.System
		changed = true
	}
	if target.DefaultHelpGroup == "" && source.DefaultHelpGroup != "" {
		target.DefaultHelpGroup = source.DefaultHelpGroup
		changed = true
	}
	if target.ExtAppliedVersion == 0 && source.ExtAppliedVersion != 0 {
		target.ExtAppliedVersion = source.ExtAppliedVersion
		changed = true
	}
	// 这些群设置同样只存在于旧群时会被删除；补齐零值字段，避免迁移后
	// 群失去启用状态、欢迎语、帮助包、COC 规则或日志开关。
	if !target.Active && source.Active {
		target.Active = true
		changed = true
	}
	if !target.ShowGroupWelcome && source.ShowGroupWelcome {
		target.ShowGroupWelcome = true
		changed = true
	}
	if target.GroupWelcomeMessage == "" && source.GroupWelcomeMessage != "" {
		target.GroupWelcomeMessage = source.GroupWelcomeMessage
		changed = true
	}
	if target.CocRuleIndex == 0 && source.CocRuleIndex != 0 {
		target.CocRuleIndex = source.CocRuleIndex
		changed = true
	}
	if len(source.HelpPackages) > 0 {
		merged := appendUniqueStrings(append([]string(nil), target.HelpPackages...), source.HelpPackages...)
		if len(merged) != len(target.HelpPackages) {
			target.HelpPackages = merged
			changed = true
		}
	}
	if !target.LogOn && source.LogOn {
		target.LogOn = true
		changed = true
	}
	if target.LogCurName == "" && source.LogCurName != "" {
		target.LogCurName = source.LogCurName
		changed = true
	}
	if target.LogCurID == 0 && source.LogCurID != 0 {
		target.LogCurID = source.LogCurID
		changed = true
	}
	if source.RecentDiceSendTime > target.RecentDiceSendTime {
		target.RecentDiceSendTime = source.RecentDiceSendTime
		changed = true
	}
	if target.Players == nil {
		target.Players = new(SyncMap[string, *GroupPlayerInfo])
	}
	if source.Players != nil {
		source.Players.Range(func(userID string, player *GroupPlayerInfo) bool {
			if player == nil {
				return true
			}
			current, ok := target.Players.Load(userID)
			if !ok || current == nil {
				target.Players.Store(userID, player)
				changed = true
				return true
			}
			if current == player {
				return true
			}
			if player.LastCommandTime > current.LastCommandTime || player.UpdatedAtTime > current.UpdatedAtTime {
				if player.Name == "" {
					player.Name = current.Name
				}
				if player.AutoSetNameTemplate == "" {
					player.AutoSetNameTemplate = current.AutoSetNameTemplate
				}
				if player.DiceSideNum == 0 {
					player.DiceSideNum = current.DiceSideNum
				}
				target.Players.Store(userID, player)
				changed = true
			}
			return true
		})
	}
	if target.PlayerGroups == nil {
		target.PlayerGroups = new(SyncMap[string, []string])
	}
	if source.PlayerGroups != nil {
		source.PlayerGroups.Range(func(key string, values []string) bool {
			current, ok := target.PlayerGroups.Load(key)
			if !ok {
				target.PlayerGroups.Store(key, append([]string(nil), values...))
				changed = true
				return true
			}
			merged := appendUniqueStrings(append([]string(nil), current...), values...)
			if len(merged) != len(current) {
				target.PlayerGroups.Store(key, merged)
				changed = true
			}
			return true
		})
	}
	if target.DiceIDActiveMap == nil {
		target.DiceIDActiveMap = new(SyncMap[string, bool])
	}
	if target.DiceIDExistsMap == nil {
		target.DiceIDExistsMap = new(SyncMap[string, bool])
	}
	if target.BotList == nil {
		target.BotList = new(SyncMap[string, bool])
	}
	mergeBool := func(dst **SyncMap[string, bool], src *SyncMap[string, bool]) {
		if src == nil {
			return
		}
		src.Range(func(key string, value bool) bool {
			if value {
				if current, exists := (*dst).Load(key); !exists || !current {
					(*dst).Store(key, true)
					changed = true
				}
				return true
			}
			if _, exists := (*dst).Load(key); !exists {
				(*dst).Store(key, false)
				changed = true
			}
			return true
		})
	}
	mergeBool(&target.DiceIDActiveMap, source.DiceIDActiveMap)
	mergeBool(&target.DiceIDExistsMap, source.DiceIDExistsMap)
	mergeBool(&target.BotList, source.BotList)
	if target.InactivatedExtSet == nil {
		target.InactivatedExtSet = StringSet{}
	}
	for name, value := range source.InactivatedExtSet {
		if _, exists := target.InactivatedExtSet[name]; !exists {
			target.InactivatedExtSet[name] = value
			changed = true
		}
	}
	// 旧群已启用的扩展也一并并入新群，避免迁移后扩展被静默关闭。
	targetExts := target.GetActivatedExtListRaw()
	sourceExts := source.GetActivatedExtListRaw()
	if len(sourceExts) > 0 {
		seen := make(map[string]struct{}, len(targetExts))
		for _, ext := range targetExts {
			if ext != nil {
				seen[ext.Name] = struct{}{}
			}
		}
		merged := append([]*ExtInfo(nil), targetExts...)
		extChanged := false
		for _, ext := range sourceExts {
			if ext == nil {
				continue
			}
			if _, exists := seen[ext.Name]; exists {
				continue
			}
			seen[ext.Name] = struct{}{}
			merged = append(merged, ext)
			extChanged = true
		}
		if extChanged {
			target.SetActivatedExtList(merged, d)
			changed = true
		}
	}
	if changed {
		target.MarkDirty(d)
	}
	return changed
}

func (m *officialQQIdentityMigration) migrateMemory(d *Dice) {
	if d.ImSession != nil && d.ImSession.ServiceAtNew != nil {
		type groupEntry struct {
			old   string
			group *GroupInfo
		}
		var groups []groupEntry
		d.ImSession.ServiceAtNew.Range(func(groupID string, group *GroupInfo) bool {
			if _, ok := m.groups[groupID]; ok {
				groups = append(groups, groupEntry{old: groupID, group: group})
			}
			return true
		})
		for _, item := range groups {
			m.migrateGroup(item.group, item.old)
			newID := m.groups[item.old]
			d.ImSession.ServiceAtNew.Delete(item.old)
			// fix5 的冲突策略会让旧、新群组同时存在；此时旧对象不能整体覆盖新对象，
			// 只把旧对象中缺失的玩家/映射并入规范 ID 下的新对象。
			if existing, ok := d.ImSession.ServiceAtNew.Load(newID); ok && existing != nil && existing != item.group {
				mergeOfficialQQGroupMemory(existing, item.group, d)
				continue
			}
			d.ImSession.ServiceAtNew.Store(newID, item.group)
		}
	}
	if d.ImSession != nil && d.ImSession.PendingQuits != nil {
		type pendingQuitEntry struct {
			old  string
			info *PendingQuitInfo
		}
		var entries []pendingQuitEntry
		d.ImSession.PendingQuits.Range(func(key string, info *PendingQuitInfo) bool {
			groupID, endpointID, ok := strings.Cut(key, "\x00")
			if !ok {
				return true
			}
			newKey := makePendingQuitKey(m.migrateGroupID(groupID), m.migrateAnyID(endpointID))
			if newKey != key {
				entries = append(entries, pendingQuitEntry{old: key, info: info})
			}
			return true
		})
		for _, entry := range entries {
			groupID, endpointID, _ := strings.Cut(entry.old, "\x00")
			d.ImSession.PendingQuits.Delete(entry.old)
			d.ImSession.PendingQuits.Store(makePendingQuitKey(m.migrateGroupID(groupID), m.migrateAnyID(endpointID)), entry.info)
		}
	}

	if d.DirtyGroups != nil {
		type dirtyEntry struct {
			old   string
			value int64
		}
		var entries []dirtyEntry
		d.DirtyGroups.Range(func(groupID string, value int64) bool {
			if _, ok := m.groups[groupID]; ok {
				entries = append(entries, dirtyEntry{old: groupID, value: value})
			}
			return true
		})
		for _, item := range entries {
			d.DirtyGroups.Delete(item.old)
			d.DirtyGroups.Store(m.groups[item.old], item.value)
		}
	}

	if d.AttrsManager != nil {
		type attrsEntry struct {
			old  string
			item *AttributesItem
		}
		var entries []attrsEntry
		d.AttrsManager.m.Range(func(id string, item *AttributesItem) bool {
			if newName, ok := m.characterNames[id]; ok && item != nil {
				item.Name = newName
				item.IsSaved = true
			}
			newID := m.migrateAttrsID(id, "group_user")
			if newID != id {
				entries = append(entries, attrsEntry{old: id, item: item})
			}
			return true
		})
		for _, entry := range entries {
			newID := m.migrateAttrsID(entry.old, "group_user")
			d.AttrsManager.m.Delete(entry.old)
			if entry.item == nil {
				continue
			}
			entry.item.ID = newID
			if existing, ok := d.AttrsManager.m.Load(newID); ok && existing != nil && existing != entry.item {
				entry.item = mergeOfficialQQAttrItems(existing, entry.item)
				entry.item.ID = newID
			}
			d.AttrsManager.m.Store(newID, entry.item)
		}
	}

	if d.Config.BanList != nil && d.Config.BanList.Map != nil {
		type banEntry struct {
			old  string
			item *BanListInfoItem
		}
		var entries []banEntry
		d.Config.BanList.Map.Range(func(id string, item *BanListInfoItem) bool {
			if newID := m.migrateAnyID(id); newID != id {
				entries = append(entries, banEntry{old: id, item: item})
			} else {
				m.migrateBanItem(item)
			}
			return true
		})
		for _, entry := range entries {
			newID := m.migrateAnyID(entry.old)
			d.Config.BanList.Map.Delete(entry.old)
			if entry.item == nil {
				continue
			}
			m.migrateBanItem(entry.item)
			if existing, ok := d.Config.BanList.Map.Load(newID); ok && existing != nil && existing != entry.item {
				entry.item = mergeOfficialQQBanInfoItems(existing, entry.item)
			}
			d.Config.BanList.Map.Store(newID, entry.item)
		}
	}

	for index, id := range d.DiceMasters {
		d.DiceMasters[index] = m.migrateAnyID(id)
	}
	for index, rawTarget := range d.Config.NoticeIDs {
		target := ParseNoticeTarget(rawTarget)
		target.ID = m.migrateAnyID(target.ID)
		d.Config.NoticeIDs[index] = target.String()
	}
	d.Config.UpgradeWindowID = m.migrateAnyID(d.Config.UpgradeWindowID)

	if d.Parent != nil {
		m.migrateNameCache(&d.Parent.GroupNameCache, m.migrateGroupID)
		m.migrateNameCache(&d.Parent.UserNameCache, m.migrateUserID)
	}
}

func (m *officialQQIdentityMigration) migrateNameCache(cache *SyncMap[string, *GroupNameCacheItem], migrate func(string) string) {
	if cache == nil {
		return
	}
	type cacheEntry struct {
		old  string
		item *GroupNameCacheItem
	}
	var entries []cacheEntry
	cache.Range(func(id string, item *GroupNameCacheItem) bool {
		if newID := migrate(id); newID != id {
			entries = append(entries, cacheEntry{old: id, item: item})
		}
		return true
	})
	for _, entry := range entries {
		cache.Delete(entry.old)
		cache.Store(migrate(entry.old), entry.item)
	}
}
