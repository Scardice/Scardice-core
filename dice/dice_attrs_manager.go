package dice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"Scardice-core/core/attributestate"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/model"
	"Scardice-core/utils"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/engine"
)

var errInvalidatedAttributeCache = errors.New("attribute item invalidated")

const (
	durableAttributeRestoreBatchSize   = 5000
	cacheGenerationCompactionThreshold = 256
)

// cacheGenerationToken has pointer identity and a non-zero size so an
// invalidated generation can never alias a later generation for the same key.
// owners counts cache residency plus in-flight load/save ownership; a caller
// may keep the token reachable through an old item without keeping its slot active.
// Every field is protected by AttrsManager.cacheMu.
type cacheGenerationToken struct {
	owners      uint64
	invalidated bool
}

type AttrsManager struct {
	db                   engine.DatabaseOperator
	durable              *attributestate.Repository
	store                eventstore.Store
	diceID               string
	logger               *zap.SugaredLogger
	cancel               context.CancelFunc
	wg                   sync.WaitGroup
	saveMu               sync.Mutex
	callbackGate         sync.Mutex
	cacheMu              sync.Mutex
	cacheGenerations     map[string]*cacheGenerationToken
	cacheGenerationWaste uint64
	coldLoads            singleflight.Group
	m                    SyncMap[string, *AttributesItem]
	states               SyncMap[string, attributestate.State]
}

func (am *AttrsManager) Stop() {
	logger.M().Info("结束数据库保存程序...")
	if am == nil || am.cancel == nil {
		return
	}
	am.cancel()
	am.wg.Wait()
}

// LoadByCtx 获取当前角色，如有绑定，则获取绑定的角色，若无绑定，获取群内默认卡
func (am *AttrsManager) LoadByCtx(ctx *MsgContext) (*AttributesItem, error) {
	if ctx != nil && ctx.callbackTransaction != nil {
		return am.callbackLoadByCtx(ctx)
	}
	// 如果是兼容性测试环境，跳过绑定查询以避免不必要的数据库操作
	if ctx.IsCompatibilityTest {
		return am.LoadByIdDirect(ctx.Group.GroupID, ctx.Player.UserID)
	}
	return am.Load(ctx.Group.GroupID, ctx.Player.UserID)
}

func (am *AttrsManager) callbackLoadByID(ctx *MsgContext, id string) (*AttributesItem, error) {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.LoadById(id)
	}
	if am == nil || am.durable == nil || am.diceID == "" {
		return nil, errors.New("durable callback attributes are unavailable")
	}
	state, data, err := am.durable.Load(context.Background(), am.diceID, id)
	if errors.Is(err, eventstore.ErrNotFound) {
		now := time.Now().Unix()
		state = attributestate.State{DiceID: am.diceID, ID: id, AttrsType: inferDurableAttrsType(id), SecretRef: attributestate.SecretRef(am.diceID, id), CreatedAt: now, UpdatedAt: now}
		source := am.uncachedItemFromState(state, &ds.ValueMap{})
		source.IsSaved = true
		return ctx.callbackTransaction.AttributeOverlay(state, source, ctx.callbackMetadata)
	}
	if err != nil {
		return nil, err
	}
	value, err := ds.VMValueFromJSON(data)
	if err != nil {
		return nil, err
	}
	dict, ok := value.ReadDictData()
	if !ok {
		return nil, errors.New("角色数据类型不正确")
	}
	return ctx.callbackTransaction.AttributeOverlay(state, am.uncachedItemFromState(state, dict.Dict), ctx.callbackMetadata)
}

// LoadByIdForCtx 在 durable callback 中提供 transaction-local 属性视图。
func (am *AttrsManager) LoadByIdForCtx(ctx *MsgContext, id string) (*AttributesItem, error) {
	return am.callbackLoadByID(ctx, id)
}

func (am *AttrsManager) callbackLoadByCtx(ctx *MsgContext) (*AttributesItem, error) {
	if ctx == nil || ctx.Group == nil || ctx.Player == nil {
		return nil, errors.New("durable callback attributes are unavailable")
	}
	id := fmt.Sprintf("%s-%s", ctx.Group.GroupID, am.UIDConvert(ctx.Player.UserID))
	item, err := am.callbackLoadByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if state, ok := ctx.callbackTransaction.AttributeState(am.diceID, id); ok && state.BindingSheetID != "" {
		return am.callbackLoadByID(ctx, state.BindingSheetID)
	}
	return item, nil
}

func (am *AttrsManager) Load(groupId string, userId string) (*AttributesItem, error) {
	userId = am.UIDConvert(userId)
	gid := fmt.Sprintf("%s-%s", groupId, userId)
	if am.durable != nil {
		state, exists := am.states.Load(gid)
		if !exists {
			if _, err := am.LoadById(gid); err != nil {
				return nil, err
			}
			state, _ = am.states.Load(gid)
		}
		if state.BindingSheetID != "" {
			return am.LoadById(state.BindingSheetID)
		}
		return am.LoadById(gid)
	}
	id, err := service.AttrsGetBindingSheetIdByGroupId(am.db, gid)
	if err != nil {
		return nil, err
	}
	if id == "" {
		id = gid
	}
	return am.LoadById(id)
}

// LoadByIdDirect 直接使用组合ID加载数据，跳过绑定查询（用于兼容性测试）
func (am *AttrsManager) LoadByIdDirect(groupId string, userId string) (*AttributesItem, error) {
	userId = am.UIDConvert(userId)
	// 直接使用组合ID，跳过绑定查询
	id := fmt.Sprintf("%s-%s", groupId, userId)
	return am.LoadById(id)
}

func (am *AttrsManager) UIDConvert(userId string) string {
	// 如果存在一个虚拟id，那么返回虚拟id，不存在原样返回
	return userId
}

func (am *AttrsManager) GetCharacterList(userId string) ([]*model.AttributesItemModel, error) {
	userId = am.UIDConvert(userId)
	if am.durable != nil {
		states, err := attributestate.ListProjected(context.Background(), am.store, am.diceID)
		if err != nil {
			return nil, err
		}
		result := make([]*model.AttributesItemModel, 0)
		for _, state := range states {
			if state.AttrsType == service.AttrsTypeCharacter && state.OwnerID == userId {
				result = append(result, &model.AttributesItemModel{
					Id: state.ID, AttrsType: state.AttrsType, BindingSheetId: state.BindingSheetID,
					Name: state.Name, OwnerId: state.OwnerID, SheetType: state.SheetType, IsHidden: state.Hidden,
				})
			}
		}
		return result, nil
	}
	return service.AttrsGetCharacterListByUserId(am.db, userId)
}

func (am *AttrsManager) CharNewForCtx(ctx *MsgContext, userID, name, sheetType string) (*model.AttributesItemModel, error) {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.CharNew(userID, name, sheetType)
	}
	userID = am.UIDConvert(userID)
	dict := &ds.ValueMap{}
	jsonData, err := ds.NewDictVal(dict).V().ToJSON()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	id := utils.NewID()
	state := attributestate.State{
		DiceID: am.diceID, ID: id, AttrsType: service.AttrsTypeCharacter, Name: name, OwnerID: userID,
		SheetType: sheetType, SecretRef: attributestate.SecretRef(am.diceID, id), CreatedAt: now, UpdatedAt: now,
	}
	source := am.uncachedItemFromState(state, dict)
	source.IsSaved = true
	item, err := ctx.callbackTransaction.AttributeOverlay(state, source, ctx.callbackMetadata)
	if err != nil {
		return nil, err
	}
	item.SetModified()
	return &model.AttributesItemModel{Id: id, AttrsType: state.AttrsType, Name: name, OwnerId: userID, SheetType: sheetType, Data: jsonData}, nil
}

func (am *AttrsManager) CharNew(userId string, name string, sheetType string) (*model.AttributesItemModel, error) {
	userId = am.UIDConvert(userId)
	dict := &ds.ValueMap{}
	jsonData, err := ds.NewDictVal(dict).V().ToJSON()
	if err != nil {
		return nil, err
	}
	if am.durable != nil {
		id := utils.NewID()
		state := attributestate.State{DiceID: am.diceID, ID: id, AttrsType: service.AttrsTypeCharacter, Name: name, OwnerID: userId, SheetType: sheetType}
		state, err = am.durable.Save(context.Background(), state, jsonData)
		if err != nil {
			return nil, err
		}
		item := am.itemFromState(state, dict)
		am.cacheMu.Lock()
		if am.itemCacheGenerationCurrentLocked(item, item.cacheIDKey, item.cacheGroupKey) {
			am.states.Store(id, state)
			am.m.Store(id, item)
		} else {
			am.releaseItemCacheGenerationLocked(item)
		}
		am.cacheMu.Unlock()
		return &model.AttributesItemModel{Id: id, AttrsType: state.AttrsType, Name: name, OwnerId: userId, SheetType: sheetType, Data: jsonData}, nil
	}
	return service.AttrsNewItem(am.db, &model.AttributesItemModel{
		Name: name, OwnerId: userId, AttrsType: service.AttrsTypeCharacter, SheetType: sheetType, Data: jsonData,
	})
}

func (am *AttrsManager) CharDeleteForCtx(ctx *MsgContext, id string) error {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.CharDelete(id)
	}
	if _, err := am.callbackLoadByID(ctx, id); err != nil {
		return err
	}
	return ctx.callbackTransaction.DeleteAttribute(am.diceID, id)
}

func (am *AttrsManager) CharDelete(id string) error {
	if am.durable != nil {
		am.saveMu.Lock()
		defer am.saveMu.Unlock()
		if _, err := am.LoadById(id); err != nil {
			return err
		}
		state, exists := am.states.Load(id)
		if !exists {
			return eventstore.ErrNotFound
		}
		state.AttrsType = ""
		state.Name = ""
		state.SheetType = ""
		am.invalidateCachedAttribute(id)
		item := am.itemFromState(state, &ds.ValueMap{})
		defer am.releaseItemCacheGeneration(item)
		if err := am.saveItemWithStateLocked(item, nil, &state, false); err != nil {
			return err
		}
		am.invalidateCachedAttribute(id)
		return nil
	}
	if err := service.AttrsDeleteById(am.db, id); err != nil {
		return err
	}
	am.m.Delete(id)
	return nil
}

func (am *AttrsManager) DeleteCachedGroupData(groupID string, includeGroupAttrs bool, includeGroupUserAttrs bool) {
	if am == nil || (!includeGroupAttrs && !includeGroupUserAttrs) {
		return
	}
	am.cacheMu.Lock()
	defer am.cacheMu.Unlock()
	if includeGroupAttrs {
		am.invalidateCacheGenerationLocked(groupCacheKeyFor(groupID, service.AttrsTypeGroup))
		am.invalidateCachedAttributeLocked(groupID)
	}
	if includeGroupUserAttrs {
		am.invalidateCacheGenerationLocked(groupCacheKeyFor(groupID, service.AttrsTypeGroupUser))
		prefix := groupID + "-"
		// In-flight loads need not have a resident item yet. Let requests
		// after invalidation start afresh instead of waiting on old I/O.
		for key := range am.cacheGenerations {
			if id, ok := strings.CutPrefix(key, "attribute\x00"); ok && strings.HasPrefix(id, prefix) {
				am.coldLoads.Forget(id)
			}
		}
		am.m.Range(func(key string, _ *AttributesItem) bool {
			if strings.HasPrefix(key, prefix) {
				am.invalidateCachedAttributeLocked(key)
			}
			return true
		})
		am.states.Range(func(key string, _ attributestate.State) bool {
			if strings.HasPrefix(key, prefix) {
				am.invalidateCachedAttributeLocked(key)
			}
			return true
		})
	}
}

func (am *AttrsManager) InvalidateCachedAttributes(ids []string) {
	if am == nil || len(ids) == 0 {
		return
	}
	am.cacheMu.Lock()
	defer am.cacheMu.Unlock()
	for _, id := range ids {
		am.invalidateCachedAttributeLocked(id)
	}
}

func (am *AttrsManager) invalidateCachedAttribute(id string) {
	if am == nil {
		return
	}
	am.cacheMu.Lock()
	am.invalidateCachedAttributeLocked(id)
	am.cacheMu.Unlock()
}

func (am *AttrsManager) invalidateCachedAttributeLocked(id string) {
	if id == "" {
		return
	}
	am.coldLoads.Forget(id)
	am.invalidateCacheGenerationLocked(attributeCacheKey(id))
	item, loaded := am.m.LoadAndDelete(id)
	am.states.Delete(id)
	if loaded {
		am.releaseItemCacheGenerationLocked(item)
	}
}

func (am *AttrsManager) retainCurrentCacheGenerationLocked(key string) *cacheGenerationToken {
	if key == "" {
		return nil
	}
	if am.cacheGenerations == nil {
		am.cacheGenerations = make(map[string]*cacheGenerationToken)
	}
	token := am.cacheGenerations[key]
	if token == nil || token.invalidated {
		token = &cacheGenerationToken{}
		am.cacheGenerations[key] = token
	}
	token.owners++
	return token
}

func (am *AttrsManager) cacheGenerationCurrentLocked(key string, token *cacheGenerationToken) bool {
	if key == "" {
		return token == nil
	}
	return token != nil && !token.invalidated && am.cacheGenerations[key] == token
}

func (am *AttrsManager) retainCacheGenerationLocked(key string, token *cacheGenerationToken) bool {
	if !am.cacheGenerationCurrentLocked(key, token) {
		return false
	}
	if token != nil {
		token.owners++
	}
	return true
}

func (am *AttrsManager) retainCacheGenerationPairLocked(
	idKey string,
	idToken *cacheGenerationToken,
	groupKey string,
	groupToken *cacheGenerationToken,
) bool {
	if !am.retainCacheGenerationLocked(idKey, idToken) {
		return false
	}
	if am.retainCacheGenerationLocked(groupKey, groupToken) {
		return true
	}
	am.releaseCacheGenerationLocked(idKey, idToken)
	return false
}

func (am *AttrsManager) releaseCacheGenerationLocked(key string, token *cacheGenerationToken) {
	if key == "" || token == nil {
		return
	}
	if token.owners == 0 {
		return
	}
	token.owners--
	if token.owners == 0 && am.cacheGenerations[key] == token {
		token.invalidated = true
		am.removeCacheGenerationSlotLocked(key, token)
	}
}

func (am *AttrsManager) releaseCacheGenerationPairLocked(
	idKey string,
	idToken *cacheGenerationToken,
	groupKey string,
	groupToken *cacheGenerationToken,
) {
	am.releaseCacheGenerationLocked(idKey, idToken)
	am.releaseCacheGenerationLocked(groupKey, groupToken)
}

func (am *AttrsManager) invalidateCacheGenerationLocked(key string) {
	if key == "" {
		return
	}
	token := am.cacheGenerations[key]
	if token == nil {
		return
	}
	token.invalidated = true
	am.removeCacheGenerationSlotLocked(key, token)
}

func (am *AttrsManager) removeCacheGenerationSlotLocked(key string, token *cacheGenerationToken) {
	if am.cacheGenerations[key] != token {
		return
	}
	delete(am.cacheGenerations, key)
	am.cacheGenerationWaste++
	if len(am.cacheGenerations) == 0 {
		if am.cacheGenerationWaste >= cacheGenerationCompactionThreshold {
			am.cacheGenerations = nil
			am.cacheGenerationWaste = 0
		}
		return
	}
	if am.cacheGenerationWaste < cacheGenerationCompactionThreshold ||
		am.cacheGenerationWaste <= uint64(len(am.cacheGenerations))*2 {
		return
	}
	active := make(map[string]*cacheGenerationToken, len(am.cacheGenerations))
	for activeKey, activeToken := range am.cacheGenerations {
		active[activeKey] = activeToken
	}
	am.cacheGenerations = active
	am.cacheGenerationWaste = 0
}

func (am *AttrsManager) releaseItemCacheGenerationLocked(item *AttributesItem) {
	if item == nil || !item.cacheGenerationRetained {
		return
	}
	item.cacheGenerationRetained = false
	am.releaseCacheGenerationPairLocked(
		item.cacheIDKey,
		item.cacheIDGeneration,
		item.cacheGroupKey,
		item.cacheGroupGeneration,
	)
}

func (am *AttrsManager) releaseItemCacheGeneration(item *AttributesItem) {
	am.cacheMu.Lock()
	am.releaseItemCacheGenerationLocked(item)
	am.cacheMu.Unlock()
}

func (am *AttrsManager) itemCacheGenerationCurrentLocked(item *AttributesItem, idKey, groupKey string) bool {
	return item != nil &&
		item.cacheGenerationRetained &&
		item.cacheIDKey == idKey &&
		item.cacheGroupKey == groupKey &&
		am.cacheGenerationCurrentLocked(idKey, item.cacheIDGeneration) &&
		am.cacheGenerationCurrentLocked(groupKey, item.cacheGroupGeneration)
}

func attributeCacheKey(id string) string {
	return "attribute\x00" + id
}

// groupCacheKey selects the cache invalidation scope for one durable state.
func groupCacheKey(state attributestate.State) string {
	groupID, attrsType := groupIDForState(state)
	return groupCacheKeyFor(groupID, attrsType)
}

func groupCacheKeyFor(groupID, attrsType string) string {
	if groupID == "" || attrsType == "" {
		return ""
	}
	return "group\x00" + groupID + "\x00" + attrsType
}

func groupIDForState(state attributestate.State) (string, string) {
	attrsType := state.AttrsType
	if attrsType == "" {
		attrsType = inferDurableAttrsType(state.ID)
	}
	switch attrsType {
	case service.AttrsTypeGroup:
		return state.ID, attrsType
	case service.AttrsTypeGroupUser:
		groupID, userID, ok := UnpackGroupUserId(state.ID)
		if ok && userID != "" {
			return groupID, attrsType
		}
	}
	return "", ""
}

func (am *AttrsManager) resolvePrivacySubjectKey(state *attributestate.State) error {
	state.PrivacySubjectKey = nil
	groupID, _ := groupIDForState(*state)
	if groupID == "" {
		return nil
	}
	resolver, ok := am.store.(eventstore.PrivacySubjectKeyResolver)
	if !ok {
		return errors.New("group attributes require a privacy subject key resolver")
	}
	subjectKey, err := resolver.PrivacySubjectKey(context.Background(), groupID)
	if err != nil {
		return err
	}
	if len(subjectKey) != 32 {
		return errors.New("privacy subject key has an invalid length")
	}
	state.PrivacySubjectKey = append([]byte(nil), subjectKey...)
	return nil
}

// LoadById 数据加载，负责以下数据
// 1. 群内用户的默认卡(id格式为：群id:用户id)
// 2. 用户创建出的角色卡（指定id）
// 3. 群属性(id为群id)
// 4. 用户全局属性
func (am *AttrsManager) LoadById(id string) (*AttributesItem, error) {
	// 1. 如果当前有缓存，那么从缓存中返回。
	// 但是。。如果有人把这个对象一直持有呢？
	i, exists := am.m.Load(id)
	if exists {
		return i, nil
	}
	if am.durable != nil {
		value, err, _ := am.coldLoads.Do(id, func() (any, error) {
			groupKey := groupCacheKey(attributestate.State{ID: id, AttrsType: inferDurableAttrsType(id)})
			idKey := attributeCacheKey(id)
			for {
				am.cacheMu.Lock()
				if cached, ok := am.m.Load(id); ok {
					am.cacheMu.Unlock()
					return cached, nil
				}
				idGeneration := am.retainCurrentCacheGenerationLocked(idKey)
				groupGeneration := am.retainCurrentCacheGenerationLocked(groupKey)
				am.cacheMu.Unlock()

				state, data, loadErr := am.durable.Load(context.Background(), am.diceID, id)
				if loadErr == nil {
					actualGroupKey := groupCacheKey(state)
					if actualGroupKey != groupKey {
						am.cacheMu.Lock()
						am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
						am.cacheMu.Unlock()
						groupKey = actualGroupKey
						continue
					}
				}

				var item *AttributesItem
				var resultErr error
				if loadErr == nil {
					value, decodeErr := ds.VMValueFromJSON(data)
					if decodeErr != nil {
						resultErr = decodeErr
					} else if dict, ok := value.ReadDictData(); ok {
						item = am.uncachedItemFromState(state, dict.Dict)
					} else {
						resultErr = errors.New("角色数据类型不正确")
					}
				} else if errors.Is(loadErr, eventstore.ErrNotFound) {
					now := time.Now().Unix()
					state = attributestate.State{
						DiceID: am.diceID, ID: id, AttrsType: inferDurableAttrsType(id),
						SecretRef: attributestate.SecretRef(am.diceID, id), CreatedAt: now, UpdatedAt: now,
					}
					if actualGroupKey := groupCacheKey(state); actualGroupKey != groupKey {
						am.cacheMu.Lock()
						am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
						am.cacheMu.Unlock()
						groupKey = actualGroupKey
						continue
					}
					item = am.uncachedItemFromState(state, &ds.ValueMap{})
					item.IsSaved = false
				} else {
					resultErr = loadErr
				}

				am.cacheMu.Lock()
				current := am.cacheGenerationCurrentLocked(idKey, idGeneration) &&
					am.cacheGenerationCurrentLocked(groupKey, groupGeneration)
				if !current {
					am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
					am.cacheMu.Unlock()
					continue
				}
				if resultErr != nil {
					am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
					am.cacheMu.Unlock()
					return nil, resultErr
				}
				if cached, ok := am.m.Load(id); ok {
					am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
					am.cacheMu.Unlock()
					return cached, nil
				}
				item.cacheIDKey = idKey
				item.cacheGroupKey = groupKey
				item.cacheIDGeneration = idGeneration
				item.cacheGroupGeneration = groupGeneration
				item.cacheGenerationRetained = true
				am.states.Store(id, state)
				am.m.Store(id, item)
				am.cacheMu.Unlock()
				return item, nil
			}
		})
		if err != nil {
			return nil, err
		}
		return value.(*AttributesItem), nil
	}

	// 2. 从新数据库加载
	data, err := service.AttrsGetById(am.db, id)
	if err == nil {
		if data.IsDataExists() {
			var v *ds.VMValue
			v, err = ds.VMValueFromJSON(data.Data)
			if err != nil {
				return nil, err
			}
			if dd, ok := v.ReadDictData(); ok {
				i = &AttributesItem{
					ID:           id,
					valueMap:     dd.Dict,
					Name:         data.Name,
					SheetType:    data.SheetType,
					LastUsedTime: time.Now().Unix(),
					IsSaved:      true,
				}
				am.m.Store(id, i)
				return i, nil
			} else {
				return nil, errors.New("角色数据类型不正确")
			}
		}
	}
	// 之前 else 是读不出时返回报错
	// return nil, err
	// 改为创建新数据集。因为遇到一个特别案例：因为clr前会读取当前角色数据，因为读不出来所以无法st clr
	// 从而永久卡死

	// 3. 创建一个新的
	// 注: 缺 created_at、updated_at、sheet_type、owner_id、is_hidden、nickname等各项
	// 可能需要ctx了
	now := time.Now().Unix()
	i = &AttributesItem{
		ID:               id,
		valueMap:         &ds.ValueMap{},
		LastModifiedTime: now,
		LastUsedTime:     now,
		IsSaved:          false,
	}
	am.m.Store(id, i)
	return i, nil
}

func (am *AttrsManager) Init(d *Dice) {
	am.db = d.DBOperator
	am.logger = d.Logger
	am.startSaveLoop(d)
}

func (am *AttrsManager) InitDurable(d *Dice) error {
	if am == nil || d == nil || d.DurableStore == nil || strings.TrimSpace(d.BaseConfig.Name) == "" {
		return errors.New("durable attributes are unavailable")
	}
	repository, err := attributestate.NewRepository(d.DurableStore)
	if err != nil {
		return err
	}
	am.store = d.DurableStore
	am.durable = repository
	am.diceID = d.BaseConfig.Name
	am.logger = d.Logger
	startedAt := time.Now()
	am.logger.Info("开始恢复持久化属性")
	snapshot, err := attributestate.ValidateProjected(context.Background(), d.DurableStore)
	if err != nil {
		return err
	}
	var states []attributestate.State
	cursor := ""
	for {
		page, pageErr := attributestate.ListProjectedPage(context.Background(), d.DurableStore, attributestate.ProjectedPageRequest{
			DiceID: am.diceID, AfterRowKey: cursor, Limit: durableAttributeRestoreBatchSize,
			ExpectedSnapshot: &snapshot,
		})
		if pageErr != nil {
			return pageErr
		}
		states = append(states, page.States...)
		if page.Done {
			break
		}
		cursor = page.NextRowKey
	}
	am.logger.Infof("持久化属性投影读取完成: records=%d elapsed=%s", len(states), time.Since(startedAt).Round(time.Millisecond))
	restored := 0
	for start := 0; start < len(states); start += durableAttributeRestoreBatchSize {
		end := min(start+durableAttributeRestoreBatchSize, len(states))
		loadedStates, loadErr := repository.LoadBatch(context.Background(), states[start:end])
		if loadErr != nil {
			return loadErr
		}
		batchErr := func() error {
			defer func() {
				for index := range loadedStates {
					clear(loadedStates[index].Plaintext)
				}
			}()
			for _, loaded := range loadedStates {
				value, decodeErr := ds.VMValueFromJSON(loaded.Plaintext)
				if decodeErr != nil {
					return decodeErr
				}
				dict, ok := value.ReadDictData()
				if !ok {
					return errors.New("角色数据类型不正确")
				}
				item := am.itemFromState(loaded.State, dict.Dict)
				am.cacheMu.Lock()
				am.states.Store(loaded.State.ID, loaded.State)
				am.m.Store(loaded.State.ID, item)
				am.cacheMu.Unlock()
			}
			return nil
		}()
		if batchErr != nil {
			return batchErr
		}
		restored += len(loadedStates)
	}
	am.logger.Infof("持久化属性密文分批恢复完成: records=%d elapsed=%s", restored, time.Since(startedAt).Round(time.Millisecond))
	am.startSaveLoop(d)
	am.logger.Infof("持久化属性恢复完成: records=%d elapsed=%s", len(states), time.Since(startedAt).Round(time.Millisecond))
	return nil
}

func (am *AttrsManager) uncachedItemFromState(state attributestate.State, values *ds.ValueMap) *AttributesItem {
	return &AttributesItem{
		ID: state.ID, valueMap: values, Name: state.Name, SheetType: state.SheetType,
		LastModifiedTime: state.UpdatedAt, LastUsedTime: time.Now().Unix(), IsSaved: state.Version != 0, owner: am,
		cacheIDKey: attributeCacheKey(state.ID), cacheGroupKey: groupCacheKey(state),
	}
}

func (am *AttrsManager) itemFromState(state attributestate.State, values *ds.ValueMap) *AttributesItem {
	item := am.uncachedItemFromState(state, values)
	am.cacheMu.Lock()
	item.cacheIDGeneration = am.retainCurrentCacheGenerationLocked(item.cacheIDKey)
	item.cacheGroupGeneration = am.retainCurrentCacheGenerationLocked(item.cacheGroupKey)
	item.cacheGenerationRetained = true
	am.cacheMu.Unlock()
	return item
}

func inferDurableAttrsType(id string) string {
	if strings.HasPrefix(id, "PG-") || strings.HasPrefix(id, "OpenQQCH-Channel:") {
		if _, userID, ok := UnpackGroupUserId(id); ok && userID != "" {
			return service.AttrsTypeGroupUser
		}
		return service.AttrsTypeGroup
	}
	if strings.Contains(id, "-Group:") {
		if strings.Count(id, ":") > 1 {
			return service.AttrsTypeGroupUser
		}
		return service.AttrsTypeGroup
	}
	if strings.Contains(id, ":") {
		return service.AttrsTypeUser
	}
	return service.AttrsTypeCharacter
}

func (am *AttrsManager) startSaveLoop(d *Dice) {
	ctx, cancel := context.WithCancel(context.Background())
	am.wg.Add(1)
	go func() {
		defer am.wg.Done()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				d.Logger.Info("正在执行最后一次数据保存...")
				if err := am.CheckForSave(); err != nil {
					d.Logger.Errorf("最终数据保存失败: %v", err)
				}
				return
			case <-ticker.C:
				if err := am.CheckForSave(); err != nil {
					d.Logger.Errorf("数据库保存程序出错: %v", err)
				}
				if err := am.CheckAndFreeUnused(); err != nil {
					d.Logger.Errorf("数据库保存-清理程序出错: %v", err)
				}
			}
		}
	}()
	am.cancel = cancel
}

func (am *AttrsManager) CheckForSave() error {
	log := logger.M()
	if am.durable != nil {
		var saveErr error
		am.m.Range(func(_ string, value *AttributesItem) bool {
			if !value.isSaved() && saveErr == nil {
				saveErr = am.saveItem(value)
			}
			return saveErr == nil
		})
		return saveErr
	}
	if am.db == nil {
		// 尚未初始化
		return errors.New("数据库尚未初始化")
	}
	var resultList []*service.AttributesBatchUpsertModel
	prepareToSave := map[string]int{}
	am.m.Range(func(key string, value *AttributesItem) bool {
		if !value.IsSaved {
			saveModel, err := value.GetBatchSaveModel()
			if err != nil {
				// 打印日志
				log.Errorf("定期写入用户数据出错(获取批量保存模型): %v", err)
				return true
			}
			prepareToSave[key] = 1
			resultList = append(resultList, saveModel)
		}
		return true
	})
	// 整体落盘
	if len(resultList) == 0 {
		return nil
	}

	if err := service.AttrsPutsByIDBatch(am.db, resultList); err != nil {
		log.Errorf("定期写入用户数据出错(批量保存): %v", err)
		return err
	}
	for key := range prepareToSave {
		// 理应不存在这个数据没有的情况
		v, _ := am.m.Load(key)
		v.IsSaved = true
	}
	// 输出日志本次落盘了几个数据

	return nil
}

// CheckAndFreeUnused 此函数会被定期调用，释放最近不用的对象
func (am *AttrsManager) CheckAndFreeUnused() error {
	if am.durable != nil {
		if err := am.CheckForSave(); err != nil {
			return err
		}
		currentTime := time.Now()
		am.m.Range(func(key string, value *AttributesItem) bool {
			value.revisionMu.Lock()
			if value.savesInFlight == 0 && value.IsSaved &&
				currentTime.Sub(time.Unix(value.LastUsedTime, 0)) > 10*time.Minute &&
				currentTime.Sub(time.Unix(value.LastModifiedTime, 0)) > 10*time.Minute {
				am.cacheMu.Lock()
				if current, exists := am.m.Load(key); exists && current == value {
					am.invalidateCachedAttributeLocked(key)
				}
				am.cacheMu.Unlock()
			}
			value.revisionMu.Unlock()
			return true
		})
		return nil
	}
	log := logger.M()
	db := am.db.GetDataDB(constant.WRITE)
	if db == nil {
		// 尚未初始化
		return errors.New("数据库尚未初始化")
	}

	prepareToFree := map[string]int{}
	currentTime := time.Now()
	var resultList []*service.AttributesBatchUpsertModel
	am.m.Range(func(key string, value *AttributesItem) bool {
		lastUsedTime := time.Unix(value.LastUsedTime, 0)
		lastModifiedTime := time.Unix(value.LastModifiedTime, 0)
		// 当且仅当上次修改时间超过10分钟，且上次使用时间超过10分钟的数据才会被释放。
		if currentTime.Sub(lastUsedTime) > 10*time.Minute && currentTime.Sub(lastModifiedTime) > 10*time.Minute {
			saveModel, err := value.GetBatchSaveModel()
			if err != nil {
				// 打印日志
				log.Errorf("定期清理用户数据出错(获取批量保存模型): %v", err)
				return true
			}
			prepareToFree[key] = 1
			resultList = append(resultList, saveModel)
		}
		return true
	})

	// 整体落盘
	if len(resultList) == 0 {
		return nil
	}

	if err := service.AttrsPutsByIDBatch(am.db, resultList); err != nil {
		log.Errorf("定期清理写入用户数据出错(批量保存): %v", err)
		return err
	}

	for key := range prepareToFree {
		// 理应不存在这个数据没有的情况
		v, ok := am.m.LoadAndDelete(key)
		if ok {
			v.IsSaved = true
		}
	}
	return nil
}

func (am *AttrsManager) CharBindForCtx(ctx *MsgContext, charID, groupID, userID string) error {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.CharBind(charID, groupID, userID)
	}
	userID = am.UIDConvert(userID)
	id := fmt.Sprintf("%s-%s", groupID, userID)
	if _, err := am.callbackLoadByID(ctx, id); err != nil {
		return err
	}
	return ctx.callbackTransaction.SetAttributeBinding(am.diceID, id, charID)
}

func (am *AttrsManager) CharGetBindingIdForCtx(ctx *MsgContext, groupID, userID string) (string, error) {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.CharGetBindingId(groupID, userID)
	}
	userID = am.UIDConvert(userID)
	id := fmt.Sprintf("%s-%s", groupID, userID)
	if _, err := am.callbackLoadByID(ctx, id); err != nil {
		return "", err
	}
	state, ok := ctx.callbackTransaction.AttributeState(am.diceID, id)
	if !ok {
		return "", eventstore.ErrNotFound
	}
	return state.BindingSheetID, nil
}

func (am *AttrsManager) CharBind(charId string, groupId string, userId string) error {
	userId = am.UIDConvert(userId)
	id := fmt.Sprintf("%s-%s", groupId, userId)
	if am.durable != nil {
		item, err := am.LoadById(id)
		if err != nil {
			return err
		}
		item.SetModified()
		return am.saveItemWithBinding(item, &charId)
	}
	return service.AttrsBindCharacter(am.db, charId, id)
}

// CharGetBindingId 获取当前群绑定的角色ID
func (am *AttrsManager) CharGetBindingId(groupId string, userId string) (string, error) {
	userId = am.UIDConvert(userId)
	id := fmt.Sprintf("%s-%s", groupId, userId)
	if am.durable != nil {
		if _, err := am.LoadById(id); err != nil {
			return "", err
		}
		state, _ := am.states.Load(id)
		return state.BindingSheetID, nil
	}
	return service.AttrsGetBindingSheetIdByGroupId(am.db, id)
}

func (am *AttrsManager) CharIdGetByName(userId string, name string) (string, error) {
	if am.durable != nil {
		states, err := attributestate.ListProjected(context.Background(), am.store, am.diceID)
		if err != nil {
			return "", err
		}
		for _, state := range states {
			if state.AttrsType == service.AttrsTypeCharacter && state.OwnerID == userId && state.Name == name {
				return state.ID, nil
			}
		}
		return "", nil
	}
	return service.AttrsGetIdByUidAndName(am.db, userId, name)
}

func (am *AttrsManager) CharCheckExists(userId string, name string) bool {
	id, _ := am.CharIdGetByName(userId, name)
	return id != ""
}

func (am *AttrsManager) CharGetBindingGroupIdList(id string) []string {
	if am.durable != nil {
		states, err := attributestate.ListProjected(context.Background(), am.store, am.diceID)
		if err != nil {
			return []string{}
		}
		all := make([]string, 0)
		for _, state := range states {
			if state.BindingSheetID == id {
				groupID, userID, _ := UnpackGroupUserId(state.ID)
				if userID != "" {
					all = append(all, groupID)
				}
			}
		}
		return all
	}
	all, err := service.AttrsCharGetBindingList(am.db, id)
	if err != nil {
		return []string{}
	}
	for index, value := range all {
		groupID, userID, _ := UnpackGroupUserId(value)
		if userID != "" {
			all[index] = groupID
		} else {
			all[index] = userID
		}
	}
	return all
}

func (am *AttrsManager) CharUnbindAllForCtx(ctx *MsgContext, id string) []string {
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.CharUnbindAll(id)
	}
	states, err := attributestate.ListProjected(context.Background(), am.store, am.diceID)
	if err != nil {
		return nil
	}
	ids := make(map[string]struct{})
	for _, state := range states {
		if state.BindingSheetID == id {
			ids[state.ID] = struct{}{}
		}
	}
	for _, attributeID := range ctx.callbackTransaction.AttributeIDsWithBinding(am.diceID, id) {
		ids[attributeID] = struct{}{}
	}
	attributeIDs := make([]string, 0, len(ids))
	for attributeID := range ids {
		attributeIDs = append(attributeIDs, attributeID)
	}
	return am.stageCallbackUnbinds(ctx, attributeIDs)
}

func (am *AttrsManager) stageCallbackUnbinds(ctx *MsgContext, attributeIDs []string) []string {
	if ctx == nil || ctx.callbackTransaction == nil {
		return nil
	}
	sort.Strings(attributeIDs)
	for _, attributeID := range attributeIDs {
		if _, err := am.callbackLoadByID(ctx, attributeID); err != nil {
			return nil
		}
	}
	all := make([]string, 0, len(attributeIDs))
	for _, attributeID := range attributeIDs {
		if err := ctx.callbackTransaction.SetAttributeBinding(am.diceID, attributeID, ""); err != nil {
			return nil
		}
		groupID, userID, _ := UnpackGroupUserId(attributeID)
		if userID != "" {
			all = append(all, groupID)
		}
	}
	sort.Strings(all)
	return all
}

func (am *AttrsManager) CharUnbindAll(id string) []string {
	if am.durable != nil {
		return am.charUnbindAllDurable(id)
	}
	all := am.CharGetBindingGroupIdList(id)
	if _, err := service.AttrsCharUnbindAll(am.db, id); err != nil {
		return []string{}
	}
	return all
}

func (am *AttrsManager) charUnbindAllDurable(id string) []string {
	am.saveMu.Lock()
	defer am.saveMu.Unlock()

	states, err := attributestate.ListProjected(context.Background(), am.store, am.diceID)
	if err != nil {
		return nil
	}
	targets := make([]attributestate.State, 0)
	for _, state := range states {
		if state.BindingSheetID == id {
			targets = append(targets, state)
		}
	}
	if len(targets) == 0 {
		return []string{}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].ID < targets[j].ID })

	type stagedSnapshot struct {
		item            *AttributesItem
		revision        uint64
		idKey           string
		idGeneration    *cacheGenerationToken
		groupKey        string
		groupGeneration *cacheGenerationToken
	}
	staged := make([]stagedSnapshot, 0, len(targets))
	saveSucceeded := false
	defer func() {
		for _, snapshot := range staged {
			snapshot.item.finishSave(snapshot.revision, saveSucceeded)
		}
		am.cacheMu.Lock()
		for _, snapshot := range staged {
			am.releaseCacheGenerationPairLocked(
				snapshot.idKey,
				snapshot.idGeneration,
				snapshot.groupKey,
				snapshot.groupGeneration,
			)
		}
		am.cacheMu.Unlock()
	}()
	writes := make([]attributestate.SnapshotWrite, 0, len(targets))
	groups := make([]string, 0, len(targets))
	updatedAt := time.Now().Unix()
	for _, state := range targets {
		item, err := am.LoadById(state.ID)
		if err != nil {
			return nil
		}
		cachedState, exists := am.states.Load(state.ID)
		if !exists || cachedState.Version != state.Version {
			return nil
		}
		revision := item.beginSave()
		staged = append(staged, stagedSnapshot{item: item, revision: revision})
		plaintext, err := ds.NewDictVal(item.valueMap).V().ToJSON()
		if err != nil {
			return nil
		}
		state.BindingSheetID = ""
		state.Name = item.Name
		state.SheetType = item.SheetType
		state.UpdatedAt = updatedAt
		if err := am.resolvePrivacySubjectKey(&state); err != nil {
			return nil
		}
		idKey := attributeCacheKey(state.ID)
		groupKey := groupCacheKey(state)
		am.cacheMu.Lock()
		valid := am.itemCacheGenerationCurrentLocked(item, idKey, groupKey)
		idGeneration := item.cacheIDGeneration
		groupGeneration := item.cacheGroupGeneration
		if valid {
			valid = am.retainCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
		}
		am.cacheMu.Unlock()
		if !valid {
			return nil
		}
		staged[len(staged)-1].idKey = idKey
		staged[len(staged)-1].idGeneration = idGeneration
		staged[len(staged)-1].groupKey = groupKey
		staged[len(staged)-1].groupGeneration = groupGeneration
		writes = append(writes, attributestate.SnapshotWrite{State: state, Plaintext: plaintext})
		if groupID, userID, _ := UnpackGroupUserId(state.ID); userID != "" {
			groups = append(groups, groupID)
		}
	}
	saved, err := am.durable.SaveBatch(context.Background(), writes)
	if err != nil {
		return nil
	}
	saveSucceeded = true
	am.cacheMu.Lock()
	for index, snapshot := range staged {
		if am.cacheGenerationCurrentLocked(snapshot.idKey, snapshot.idGeneration) &&
			am.cacheGenerationCurrentLocked(snapshot.groupKey, snapshot.groupGeneration) {
			am.states.Store(targets[index].ID, saved[index])
		}
	}
	am.cacheMu.Unlock()
	sort.Strings(groups)
	return groups
}

func (am *AttrsManager) SaveForCtx(ctx *MsgContext, item *AttributesItem) error {
	if item == nil {
		return errors.New("durable attributes are unavailable")
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		return am.saveItem(item)
	}
	return ctx.callbackTransaction.SetAttributeMetadata(am.diceID, item.ID, item.Name, item.SheetType)
}

func (am *AttrsManager) saveItem(item *AttributesItem) error {
	return am.saveItemWithBinding(item, nil)
}

func (am *AttrsManager) saveItemWithBinding(item *AttributesItem, bindingOverride *string) error {
	return am.saveItemWithState(item, bindingOverride, nil, true)
}

func (am *AttrsManager) saveItemWithState(item *AttributesItem, bindingOverride *string, stateOverride *attributestate.State, publishState bool) error {
	if am == nil || am.durable == nil || item == nil {
		return errors.New("durable attributes are unavailable")
	}
	am.saveMu.Lock()
	defer am.saveMu.Unlock()
	return am.saveItemWithStateLocked(item, bindingOverride, stateOverride, publishState)
}

func (am *AttrsManager) saveItemWithStateLocked(item *AttributesItem, bindingOverride *string, stateOverride *attributestate.State, publishState bool) error {
	if am == nil || am.durable == nil || item == nil {
		return errors.New("durable attributes are unavailable")
	}
	saveSucceeded := false
	revision := item.beginSave()
	defer func() {
		item.finishSave(revision, saveSucceeded)
	}()
	am.cacheMu.Lock()
	state, exists := am.states.Load(item.ID)
	if stateOverride != nil {
		state, exists = *stateOverride, true
	}
	if !exists {
		now := time.Now().Unix()
		state = attributestate.State{DiceID: am.diceID, ID: item.ID, AttrsType: inferDurableAttrsType(item.ID), SecretRef: attributestate.SecretRef(am.diceID, item.ID), CreatedAt: now}
	}
	if bindingOverride != nil {
		state.BindingSheetID = *bindingOverride
	}
	idKey := attributeCacheKey(item.ID)
	groupKey := groupCacheKey(state)
	idGeneration := item.cacheIDGeneration
	groupGeneration := item.cacheGroupGeneration
	if !am.itemCacheGenerationCurrentLocked(item, idKey, groupKey) ||
		!am.retainCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration) {
		am.cacheMu.Unlock()
		return errInvalidatedAttributeCache
	}
	am.cacheMu.Unlock()
	defer func() {
		am.cacheMu.Lock()
		am.releaseCacheGenerationPairLocked(idKey, idGeneration, groupKey, groupGeneration)
		am.cacheMu.Unlock()
	}()

	if err := am.resolvePrivacySubjectKey(&state); err != nil {
		return err
	}

	rawData, err := ds.NewDictVal(item.valueMap).V().ToJSON()
	if err != nil {
		return err
	}
	state.Name = item.Name
	state.SheetType = item.SheetType
	state.UpdatedAt = time.Now().Unix()
	state, err = am.durable.Save(context.Background(), state, rawData)
	if err != nil {
		return err
	}
	saveSucceeded = true
	am.cacheMu.Lock()
	if publishState &&
		am.cacheGenerationCurrentLocked(idKey, idGeneration) &&
		am.cacheGenerationCurrentLocked(groupKey, groupGeneration) {
		am.states.Store(item.ID, state)
	}
	am.cacheMu.Unlock()
	return nil
}

// AttributesItem 这是一个人物卡对象
type AttributesItem struct {
	ID                      string
	valueMap                *ds.ValueMap // SyncMap[string, *ds.VMValue] 这种类型更好吗？我得确认一下js兼容性
	LastModifiedTime        int64        // 上次修改时间
	LastUsedTime            int64        // 上次使用时间
	IsSaved                 bool
	cacheGenerationRetained bool
	savesInFlight           uint32
	Name                    string
	SheetType               string
	owner                   *AttrsManager
	revisionMu              sync.Mutex
	revision                uint64
	cacheIDKey              string
	cacheIDGeneration       *cacheGenerationToken
	cacheGroupKey           string
	cacheGroupGeneration    *cacheGenerationToken
}

func (i *AttributesItem) SaveToDB(db engine.DatabaseOperator) {
	if i.owner != nil && i.owner.durable != nil {
		if err := i.owner.saveItem(i); err != nil {
			logger.M().Error("保存数据失败", err.Error())
		}
		return
	}
	// 使用事务写入
	rawData, err := ds.NewDictVal(i.valueMap).V().ToJSON()
	if err != nil {
		return
	}
	err = service.AttrsPutById(db, i.ID, rawData, i.Name, i.SheetType)
	if err != nil {
		logger.M().Error("保存数据失败", err.Error())
		return
	}
	i.IsSaved = true
}

func (i *AttributesItem) GetBatchSaveModel() (*service.AttributesBatchUpsertModel, error) {
	rawData, err := ds.NewDictVal(i.valueMap).V().ToJSON()
	if err != nil {
		return nil, err
	}
	return &service.AttributesBatchUpsertModel{
		Id:        i.ID,
		Data:      rawData,
		Name:      i.Name,
		SheetType: i.SheetType,
	}, nil
}

func (i *AttributesItem) Load(name string) *ds.VMValue {
	i.revisionMu.Lock()
	v, _ := i.valueMap.Load(name)
	i.LastUsedTime = time.Now().Unix()
	i.revisionMu.Unlock()
	return v
}

func (i *AttributesItem) LoadX(name string) (*ds.VMValue, bool) {
	i.revisionMu.Lock()
	v, exists := i.valueMap.Load(name)
	i.LastUsedTime = time.Now().Unix()
	i.revisionMu.Unlock()
	return v, exists
}

func (i *AttributesItem) Delete(name string) {
	i.revisionMu.Lock()
	i.valueMap.Delete(name)
	i.LastModifiedTime = time.Now().Unix()
	i.markModifiedLocked()
	i.revisionMu.Unlock()
}

func (i *AttributesItem) SetModified() {
	i.revisionMu.Lock()
	i.LastModifiedTime = time.Now().Unix()
	i.markModifiedLocked()
	i.revisionMu.Unlock()
}

func (i *AttributesItem) markModifiedLocked() {
	i.revision++
	i.IsSaved = false
}

func (i *AttributesItem) beginSave() uint64 {
	i.revisionMu.Lock()
	defer i.revisionMu.Unlock()
	i.savesInFlight++
	return i.revision
}

func (i *AttributesItem) finishSave(revision uint64, persisted bool) {
	i.revisionMu.Lock()
	defer i.revisionMu.Unlock()
	if i.savesInFlight > 0 {
		i.savesInFlight--
	}
	if persisted && i.revision == revision {
		i.IsSaved = true
	}
}

func (i *AttributesItem) isSaved() bool {
	i.revisionMu.Lock()
	defer i.revisionMu.Unlock()
	return i.IsSaved
}

func (i *AttributesItem) Store(name string, value *ds.VMValue) {
	i.revisionMu.Lock()
	i.valueMap.Store(name, value)
	i.LastModifiedTime = time.Now().Unix()
	i.LastUsedTime = i.LastModifiedTime
	i.markModifiedLocked()
	i.revisionMu.Unlock()
}

func (i *AttributesItem) Clear() int {
	i.revisionMu.Lock()
	size := i.valueMap.Length()
	i.valueMap.Clear()
	i.LastModifiedTime = time.Now().Unix()
	i.markModifiedLocked()
	i.revisionMu.Unlock()
	return size
}

func (i *AttributesItem) ToArrayKeys() []*ds.VMValue {
	var items []*ds.VMValue
	i.valueMap.Range(func(key string, value *ds.VMValue) bool {
		items = append(items, ds.NewStrVal(key))
		return true
	})
	return items
}

func (i *AttributesItem) ToArrayValues() []*ds.VMValue {
	var items []*ds.VMValue
	i.valueMap.Range(func(key string, value *ds.VMValue) bool {
		items = append(items, value)
		return true
	})
	return items
}

func (i *AttributesItem) ToArrayItems() []*ds.VMValue {
	var items []*ds.VMValue
	i.valueMap.Range(func(key string, value *ds.VMValue) bool {
		items = append(
			items,
			ds.NewArrayVal(ds.NewStrVal(key), value),
		)
		return true
	})
	return items
}

func (i *AttributesItem) Range(f func(key string, value *ds.VMValue) bool) {
	i.valueMap.Range(f)
}

func (i *AttributesItem) SetSheetType(system string) {
	i.revisionMu.Lock()
	i.SheetType = system
	i.LastModifiedTime = time.Now().Unix()
	i.markModifiedLocked()
	i.revisionMu.Unlock()
}

func (i *AttributesItem) Len() int {
	return i.valueMap.Length()
}
