package dice

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/tidwall/buntdb"
	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
)

const (
	maxChainDepth = 10
)

// ActivateReason 用于区分扩展开启的触发来源（手动、首次消息自动、脚本重载等）。
type ActivateReason string

// DeactivateReason 用于区分扩展关闭的触发来源。
type DeactivateReason string

const (
	ActivateReasonManual       ActivateReason   = "manual"
	ActivateReasonFirstMessage ActivateReason   = "first_message_auto"
	ActivateReasonReload       ActivateReason   = "reload"
	DeactivateReasonManual     DeactivateReason = "manual"
	DeactivateReasonSystem     DeactivateReason = "system"
)

// ActiveWithGraph 描述扩展伴随关系：A -> [B,C] 表示激活 A 时需要附带 B、C。
type ActiveWithGraph map[string][]string

func (d *Dice) rebuildActiveWithGraph() {
	d.ActiveWithGraphMu.Lock()
	defer d.ActiveWithGraphMu.Unlock()
	d.rebuildActiveWithGraphLocked()
}

func (d *Dice) rebuildActiveWithGraphLocked() {
	d.ActiveWithGraph = BuildActiveWithGraph(d.ExtList)
}

func (d *Dice) activeWithGraph() *SyncMap[string, []string] {
	d.ActiveWithGraphMu.RLock()
	graph := d.ActiveWithGraph
	d.ActiveWithGraphMu.RUnlock()
	if graph != nil {
		return graph
	}

	d.ActiveWithGraphMu.Lock()
	defer d.ActiveWithGraphMu.Unlock()
	if d.ActiveWithGraph == nil {
		d.rebuildActiveWithGraphLocked()
	}
	return d.ActiveWithGraph
}

// BuildActiveWithGraph 根据扩展列表构建伴随激活图。
// 返回反向图：A -> [B,C] 表示 B、C 跟随 A（当 A 开启时，B、C 也开启）
func BuildActiveWithGraph(exts []*ExtInfo) *SyncMap[string, []string] {
	graph := new(SyncMap[string, []string])
	// 构建反向图：如果 ext 跟随 target，则在 graph[target] 中加入 ext
	for _, ext := range exts {
		for _, target := range ext.ActiveWith {
			followers, _ := graph.Load(target)
			followers = append(followers, ext.Name)
			graph.Store(target, followers)
		}
	}
	return graph
}

// collectChainedNames 收集所有跟随 base 扩展的伴随扩展（递归查找，返回拓扑顺序）。
func collectChainedNames(logger *zap.SugaredLogger, graph *SyncMap[string, []string], base string, depthLimit int) []string {
	visited := map[string]bool{}
	visiting := map[string]bool{}
	var order []string

	if graph == nil {
		return order
	}

	var dfs func(name string, depth int)
	dfs = func(name string, depth int) {
		if depth > depthLimit {
			logger.Warnf("扩展 %s 的 ActiveWith 链深度超过 %d，停止展开", name, depthLimit)
			return
		}
		if visiting[name] {
			logger.Warnf("检测到扩展 %s 的 ActiveWith 存在循环，跳过连带操作", name)
			return
		}
		if visited[name] {
			return
		}
		visiting[name] = true
		followers, _ := graph.Load(name)
		for _, follower := range followers {
			dfs(follower, depth+1)
		}
		visiting[name] = false
		visited[name] = true
		if name != base {
			order = append(order, name)
		}
	}

	dfs(base, 0)
	return order
}

// RegisterBuiltinExt 注册所有内置扩展。
func (d *Dice) RegisterBuiltinExt() {
	RegisterBuiltinExtCoc7(d)
	RegisterBuiltinExtLog(d)
	RegisterBuiltinExtFun(d)
	RegisterBuiltinExtDeck(d)
	RegisterBuiltinExtReply(d)
	RegisterBuiltinExtDnd5e(d)
	RegisterBuiltinStory(d)
	RegisterBuiltinExtExp(d)
	RegisterBuiltinExtCore(d)

	d.RegisterBuiltinSystemTemplate()
}

func (d *Dice) RegisterBuiltinSystemTemplate() {
	for _, asset := range []string{"coc7.yaml", "dnd5e.yaml"} {
		tmpl, err := loadBuiltinTemplate(asset)
		if err != nil {
			if d.Logger != nil {
				d.Logger.Errorf("failed to load builtin game template %s: %v", asset, err)
			}
			continue
		}
		d.addGameSystemTemplateEx(tmpl, false)
	}
}

// RegisterExtension 注册扩展并刷新伴随激活图/版本号。
//
// panic 当扩展的 Name/Aliases 与现有扩展冲突。
func (d *Dice) RegisterExtension(extInfo *ExtInfo) {
	for _, name := range append(extInfo.Aliases, extInfo.Name) {
		if collide := d.ExtFind(name, false); collide != nil {
			panicMsg := fmt.Sprintf("扩展<%s>的名称%q与扩展<%s>冲突", extInfo.Name, name, collide.Name)
			panic(panicMsg)
		}
	}

	extInfo.dice = d
	d.ExtList = append(d.ExtList, extInfo)
	if d.ExtRegistry == nil {
		d.ExtRegistry = new(SyncMap[string, *ExtInfo])
	}
	registerKey := func(key string) {
		if key == "" {
			return
		}
		d.ExtRegistry.Store(key, extInfo)
		lower := strings.ToLower(key)
		if lower != key {
			d.ExtRegistry.Store(lower, extInfo)
		}
	}
	registerKey(extInfo.Name)
	for _, alias := range extInfo.Aliases {
		registerKey(alias)
	}
	atomic.AddInt64(&d.ExtRegistryVersion, 1)
	d.ActiveWithGraphMu.Lock()
	d.ActiveWithGraph = nil
	d.ActiveWithGraphMu.Unlock()
}

func (d *Dice) GetExtDataDir(extName string) string {
	p := path.Join(d.BaseConfig.DataDir, "extensions", extName)
	_ = os.MkdirAll(p, 0o755)
	return p
}

func (d *Dice) GetDiceDataPath(name string) string {
	return path.Join(d.BaseConfig.DataDir, name)
}

func (d *Dice) GetExtConfigFilePath(extName string, filename string) string {
	return path.Join(d.GetExtDataDir(extName), filename)
}

// ClearExtStorage 删除扩展 storage.db 并重新初始化。
func ClearExtStorage(d *Dice, ext *ExtInfo, name string) error {
	if d != nil && d.DurableStore != nil {
		return d.clearDurableExtensionStorage(name)
	}
	err := ext.StorageClose()
	if err != nil {
		return err
	}

	dbPath := filepath.Join(d.BaseConfig.DataDir, "extensions", name, "storage.db")
	err = os.Remove(dbPath)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return err
	}

	return ext.StorageInit()
}

func GetExtensionDesc(ei *ExtInfo) string {
	var text strings.Builder
	text.WriteString("> ")
	text.WriteString(ei.Brief)
	text.WriteString("\n提供指令:\n")

	cmdMap := ei.GetCmdMap()
	keys := make([]string, 0, len(cmdMap))

	valueMap := map[*CmdItemInfo]bool{}

	for k := range cmdMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, name := range keys {
		item := cmdMap[name]
		if valueMap[item] {
			continue
		}
		valueMap[item] = true
		if item.ShortHelp == "" {
			text.WriteString(".")
			text.WriteString(item.Name)
			text.WriteString("\n")
		} else {
			text.WriteString(item.ShortHelp)
			text.WriteString("\n")
		}
	}

	return text.String()
}

// GetRealExt 获取真实扩展（处理 wrapper 代理）
// 如果不是 wrapper，返回自身
// 如果是有效的 wrapper，返回 JsExtRegistry 中的真实扩展
// 如果是无效的 wrapper 或找不到真实扩展，返回 nil
func (i *ExtInfo) GetRealExt() *ExtInfo {
	if !i.IsWrapper {
		return i // 非 wrapper，返回自身
	}
	if i.IsDeleted {
		return nil // 已删除的 wrapper
	}
	if i.dice == nil || i.dice.JsExtRegistry == nil {
		return nil // 未初始化
	}
	if realExt, ok := i.dice.JsExtRegistry.Load(i.TargetName); ok {
		return realExt
	}
	return nil // 找不到真实扩展
}

// CmdMapLock guards dynamic JavaScript command-map mutations.
func (i *ExtInfo) CmdMapLock() *sync.RWMutex {
	return &i.cmdMapMu
}

// CmdMapSnapshot returns a stable command-map view for concurrent command resolution.
func (i *ExtInfo) CmdMapSnapshot() CmdMapCls {
	if i == nil {
		return CmdMapCls{}
	}
	i.cmdMapMu.RLock()
	defer i.cmdMapMu.RUnlock()
	result := make(CmdMapCls, len(i.CmdMap))
	for name, command := range i.CmdMap {
		result[name] = command
	}
	return result
}

// GetCmdMap 获取命令映射（处理 wrapper 代理）
// 如果是 wrapper，返回真实扩展的 CmdMap
// 如果正在重载或无法获取真实扩展，返回空 CmdMap
// TODO(局部重载/通用): 重载期间 wrapper 的 CmdMap 由全局 JsReloading 一刀切地清空，所有 JS 插件的指令都会暂时不可用。
// subTODO(局部重载): 改为按插件的“加载中”状态，只屏蔽正在重载的插件及其依赖闭包。
func (i *ExtInfo) GetCmdMap() CmdMapCls {
	// 重载期间，wrapper 的真实扩展可能还未注册，返回空 CmdMap
	// 注意：如果 i.dice 为 nil（理论上不应发生），会走到 GetRealExt()
	// GetRealExt() 内部已处理 dice==nil 的情况，会返回 nil，最终返回空 CmdMap
	if i.IsWrapper && i.dice != nil && i.dice.JsReloading {
		return CmdMapCls{}
	}
	ext := i.GetRealExt()
	if ext == nil {
		return CmdMapCls{}
	}
	return ext.CmdMapSnapshot()
}

type messagePreprocessAction int

const (
	messagePreprocessNoop messagePreprocessAction = iota
	messagePreprocessRewrite
	messagePreprocessIntercept
)

type messagePreprocessDecision struct {
	action  messagePreprocessAction
	message string
	reason  string
}

func parseMessagePreprocessValue(vm *goja.Runtime, value goja.Value) messagePreprocessDecision {
	return parseMessagePreprocessEngineValue(gojaEngineValue{vm: vm, value: value})
}

func parseMessagePreprocessEngineValue(value jsengine.Value) messagePreprocessDecision {
	decision, _ := parseMessagePreprocessEngineValueWithError(value)
	return decision
}

func parseMessagePreprocessEngineValueWithError(value jsengine.Value) (messagePreprocessDecision, error) {
	noOp := messagePreprocessDecision{action: messagePreprocessNoop}
	if value == nil {
		return noOp, nil
	}
	object := value.Object()
	if object == nil {
		primitive, err := value.ExportPrimitive()
		if errors.Is(err, jsengine.ErrNoPrimitiveValue) || errors.Is(err, jsengine.ErrPrimitiveExportUnsupported) {
			return noOp, nil
		}
		if err != nil {
			return noOp, err
		}
		if primitive == nil {
			return noOp, nil
		}
		text, ok := primitive.(string)
		if !ok {
			return noOp, nil
		}
		if text == "" {
			return messagePreprocessDecision{action: messagePreprocessIntercept}, nil
		}
		return messagePreprocessDecision{action: messagePreprocessRewrite, message: text}, nil
	}
	if !object.Has("message") {
		return noOp, nil
	}
	reason := ""
	reasonValue, err := getEngineObjectProperty(object, "reason")
	if err != nil {
		return noOp, err
	}
	if reasonValue != nil {
		if primitive, err := reasonValue.ExportPrimitive(); err == nil {
			if text, ok := primitive.(string); ok {
				reason = text
			}
		}
	}
	messageValue, err := getEngineObjectProperty(object, "message")
	if err != nil {
		return noOp, err
	}
	if messageValue == nil {
		return messagePreprocessDecision{action: messagePreprocessIntercept, reason: reason}, nil
	}
	primitive, err := messageValue.ExportPrimitive()
	if err == nil {
		if text, ok := primitive.(string); ok {
			if text == "" {
				return messagePreprocessDecision{action: messagePreprocessIntercept, reason: reason}, nil
			}
			return messagePreprocessDecision{action: messagePreprocessRewrite, message: text, reason: reason}, nil
		}
		if primitive == nil || !messageValue.ToBoolean() {
			return messagePreprocessDecision{action: messagePreprocessIntercept, reason: reason}, nil
		}
		return messagePreprocessDecision{action: messagePreprocessNoop, reason: reason}, nil
	}
	if !messageValue.ToBoolean() {
		return messagePreprocessDecision{action: messagePreprocessIntercept, reason: reason}, nil
	}
	return messagePreprocessDecision{action: messagePreprocessNoop, reason: reason}, nil
}

func messagePreprocessDecisionWithLocalRewrite(
	value jsengine.Value,
	originalText string,
	callbackMessage *Message,
) (messagePreprocessDecision, error) {
	decision, err := parseMessagePreprocessEngineValueWithError(value)
	if err != nil || callbackMessage == nil || callbackMessage.Message == originalText {
		return decision, err
	}
	nullish := value == nil
	if value != nil && value.Object() == nil {
		primitive, exportErr := value.ExportPrimitive()
		nullish = errors.Is(exportErr, jsengine.ErrNoPrimitiveValue) ||
			(exportErr == nil && primitive == nil)
	}
	if !nullish {
		return decision, nil
	}
	return messagePreprocessDecision{
		action: messagePreprocessRewrite, message: callbackMessage.Message,
	}, nil
}

func getEngineObjectProperty(object jsengine.Object, name string) (jsengine.Value, error) {
	if fallible, ok := object.(jsengine.FallibleObject); ok {
		return fallible.GetWithError(name)
	}
	return object.Get(name), nil
}

func cloneMessageForPreprocess(msg *Message) *Message {
	if msg == nil {
		return nil
	}
	cloned := *msg
	if msg.Segment != nil {
		cloned.Segment = slices.Clone(msg.Segment)
	}
	return &cloned
}

// runEngineCallback converts callback panics into errors for dispatcher logging.
func runEngineCallback(callback func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("JavaScript callback panic: %v", recovered)
		}
	}()
	return callback()
}

// CallOnMessagePreprocess 调用 OnMessagePreprocess 回调（处理 wrapper 代理）。
func (i *ExtInfo) CallOnMessagePreprocess(d *Dice, ctx *MsgContext, msg *Message) messagePreprocessDecision {
	ext := i.GetRealExt()
	decision := messagePreprocessDecision{action: messagePreprocessNoop}
	if ext == nil || !ext.HasOnMessagePreprocess() {
		return decision
	}
	callbackMessage := cloneMessageForPreprocess(msg)
	originalText := ""
	if msg != nil {
		originalText = msg.Message
	}

	if !ext.IsJsExt && ext.OnMessagePreprocessEngine == nil && ext.OnMessagePreprocessCallback == nil {
		value := gojaEngineValue{value: ext.OnMessagePreprocess(ctx, callbackMessage)}
		decision, _ = messagePreprocessDecisionWithLocalRewrite(value, originalText, callbackMessage)
		return decision
	}

	var callback jsHookValueCallback
	switch {
	case ext.OnMessagePreprocessEngine != nil:
		callback = func(runtime jsengine.Runtime) (jsengine.Value, error) {
			return ext.OnMessagePreprocessEngine(runtime, ctx, callbackMessage)
		}
	case ext.OnMessagePreprocessCallback != nil:
		callback = func(jsengine.Runtime) (jsengine.Value, error) {
			return ext.OnMessagePreprocessCallback(ctx, callbackMessage)
		}
	case ext.OnMessagePreprocess != nil:
		callback = selectJSHookValueCallback(
			false,
			nil,
			true,
			func() goja.Value { return ext.OnMessagePreprocess(ctx, callbackMessage) },
		)
	}
	_ = ext.dispatchValueWithJsCheckFiltered(d, jsCallbackPreprocess, callbackEventIDForMessage(ctx, msg), false, callback, func(value jsengine.Value) error {
		var err error
		decision, err = messagePreprocessDecisionWithLocalRewrite(value, originalText, callbackMessage)
		return err
	}, ctx, jsHookScopeExpired)
	return decision
}

// callWithJsCheck 保留旧行为：JS 扩展需要切回事件循环，避免并发问题。
// 它会等待回调结束，因此只能在事件循环之外调用；事后通知类回调请用
// notifyWithJsCheck。
func (i *ExtInfo) callWithJsCheck(d *Dice, f func(), details ...jsCallbackDispatch) {
	i.runWithJsCheck(d, f, false, details...)
}

// notifyWithJsCheck 把事后通知排入 JS 事件循环但不等待它完成。
// seal.replyToSender 等宿主函数会在事件循环内触发这类通知，等待会自锁。
func (i *ExtInfo) notifyWithJsCheck(d *Dice, f func(), details ...jsCallbackDispatch) {
	i.runWithJsCheck(d, f, true, details...)
}

func (i *ExtInfo) runWithJsCheck(d *Dice, f func(), schedule bool, details ...jsCallbackDispatch) {
	if len(details) == 0 {
		i.dispatchWithJsCheck(d, jsCallbackMessage, "", schedule, f, nil)
		return
	}
	detail := details[0]
	i.dispatchWithJsCheck(d, detail.kind, detail.providerEventID, schedule, f, detail.message)
}

// StorageInit 与旧版一致：使用互斥锁确保只初始化一次。
func (i *ExtInfo) StorageInit() error {
	var err error
	if i == nil || i.dice == nil {
		return errors.New("[扩展]:必须先把扩展注册到 Dice")
	}
	d := i.dice

	i.dbMu.Lock()
	defer i.dbMu.Unlock()
	if i.init {
		return nil
	}
	if d.DurableStore != nil {
		i.Storage = nil
		i.init = true
		return nil
	}

	dir := d.GetExtDataDir(i.Name)
	fn := path.Join(dir, "storage.db")
	i.Storage, err = buntdb.Open(fn)
	if err != nil {
		d.Logger.Errorf("[扩展]:初始化扩展数据库失败，原因: %v，路径为：%s", err, fn)
		return err
	}
	i.init = true
	return nil
}

// StorageClose 与旧逻辑一致：先判断 init，再关闭数据库并回收状态。
func (i *ExtInfo) StorageClose() error {
	if i == nil {
		return nil
	}
	i.dbMu.Lock()
	defer i.dbMu.Unlock()
	if !i.init {
		return nil
	}
	if i.Storage == nil {
		i.init = false
		return nil
	}
	err := i.Storage.Close()
	if err != nil {
		i.dice.Logger.Errorf("[扩展]:关闭扩展数据库失败，原因: %v", err)
		return err
	}
	i.Storage = nil
	i.init = false
	return nil
}

// StorageSet/StorageGet 只是辅助函数，原注释无变更。
func (i *ExtInfo) StorageSet(k, v string) error {
	target := i.GetRealExt()
	if target == nil {
		return errors.New("[扩展]:目标扩展不存在")
	}
	if target.dice != nil && target.dice.DurableStore != nil {
		return target.dice.durableStorageSet(target.Name, k, v)
	}
	if err := target.StorageInit(); err != nil {
		return err
	}
	db := target.Storage
	return db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(k, v, nil)
		return err
	})
}

// StorageGet 与旧实现保持一致，出现 ErrNotFound 时直接返回空字符串。
func (i *ExtInfo) StorageGet(k string) (string, error) {
	target := i.GetRealExt()
	if target == nil {
		return "", errors.New("[扩展]:目标扩展不存在")
	}
	if target.dice != nil && target.dice.DurableStore != nil {
		return target.dice.durableStorageGet(target.Name, k)
	}
	if err := target.StorageInit(); err != nil {
		return "", err
	}

	var val string
	var err error
	db := target.Storage
	err = db.View(func(tx *buntdb.Tx) error {
		val, err = tx.Get(k)
		if err != nil && !errors.Is(err, buntdb.ErrNotFound) {
			return err
		}
		return nil
	})
	return val, err
}

// StorageList 列出扩展存储中的所有 key。
func (i *ExtInfo) StorageList() ([]string, error) {
	target := i.GetRealExt()
	if target == nil {
		return nil, errors.New("[扩展]:目标扩展不存在")
	}
	if target.dice != nil && target.dice.DurableStore != nil {
		return target.dice.durableStorageList(target.Name)
	}
	if err := target.StorageInit(); err != nil {
		return nil, err
	}

	keys := make([]string, 0)
	db := target.Storage
	err := db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys("*", func(k, _ string) bool {
			keys = append(keys, k)
			return true
		})
	})
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (i *ExtInfo) GetPackageConfig() map[string]interface{} {
	target := i.GetRealExt()
	if target == nil {
		return map[string]interface{}{}
	}

	if target.Source == nil || target.Source.PackageID == "" {
		return map[string]interface{}{}
	}

	if target.dice == nil || target.dice.PackageManager == nil {
		return map[string]interface{}{}
	}

	config, err := target.dice.PackageManager.GetConfig(target.Source.PackageID)
	if err != nil {
		return map[string]interface{}{}
	}

	return config
}

// -------------------- 群扩展状态管理 --------------------

var extPlaceholderPool = new(SyncMap[string, *ExtInfo])

func extNamePlaceholder(name string) *ExtInfo {
	if placeholder, ok := extPlaceholderPool.Load(name); ok && placeholder != nil {
		return placeholder
	}
	placeholder, _ := extPlaceholderPool.LoadOrStore(name, &ExtInfo{Name: name})
	return placeholder
}

func (group *GroupInfo) GetActivatedExtList(d *Dice) []*ExtInfo {
	if group == nil || group.requireRuntimeAuthority() != nil {
		return nil
	}
	ids := group.ActivatedExtensionIDs()
	version := group.Version()
	registryVersion := int64(0)
	appliedTime := int64(1)
	if d != nil {
		registryVersion = atomic.LoadInt64(&d.ExtRegistryVersion)
		if updateTime := atomic.LoadInt64(&d.ExtUpdateTime); updateTime != 0 {
			appliedTime = updateTime
		}
	}

	group.extensionCacheMu.Lock()
	localMatch := group.extensionCacheStateVersion == version &&
		slices.Equal(group.activatedExtensionIDs, ids) &&
		(d == nil || group.extensionCacheRegistryVersion == registryVersion)
	if localMatch {
		resolved := slices.Clone(group.activatedExtensions)
		group.extensionCacheMu.Unlock()
		return resolved
	}
	group.extensionCacheMu.Unlock()

	resources := group.runtime
	resources.extensionMu.Lock()
	cacheEpoch := resources.extensionCacheEpoch
	sharedMatch := resources.extensionStateVersion == version &&
		slices.Equal(resources.activatedExtensionIDs, ids) &&
		(d == nil || resources.extensionRegistryVersion == registryVersion)
	shared := slices.Clone(resources.activatedExtensions)
	resources.extensionMu.Unlock()
	if sharedMatch {
		group.extensionCacheMu.Lock()
		group.activatedExtensions = slices.Clone(shared)
		group.activatedExtensionIDs = slices.Clone(ids)
		group.extensionCacheStateVersion = version
		group.extensionCacheRegistryVersion = registryVersion
		group.extensionCacheMu.Unlock()
		return shared
	}

	resolved := make([]*ExtInfo, 0, len(ids))
	for _, name := range ids {
		var extension *ExtInfo
		if d != nil {
			extension = d.ExtFind(name, false)
		} else {
			for _, current := range shared {
				if current != nil && current.Name == name {
					extension = current
					break
				}
			}
		}
		if extension == nil {
			extension = extNamePlaceholder(name)
		}
		resolved = append(resolved, extension)
	}
	group.extensionCacheMu.Lock()
	group.activatedExtensions = slices.Clone(resolved)
	group.activatedExtensionIDs = slices.Clone(ids)
	group.extensionCacheStateVersion = version
	group.extensionCacheRegistryVersion = registryVersion
	group.extensionCacheMu.Unlock()

	if d != nil && group.transaction != nil {
		publishedExtensions := slices.Clone(resolved)
		publishedIDs := slices.Clone(ids)
		_ = group.transaction.AfterCommit(func() {
			if resources.revoked.Load() || group.Version() != version {
				return
			}
			resources.extensionMu.Lock()
			defer resources.extensionMu.Unlock()
			if resources.revoked.Load() || resources.extensionCacheEpoch != cacheEpoch {
				return
			}
			resources.activatedExtensions = slices.Clone(publishedExtensions)
			resources.activatedExtensionIDs = slices.Clone(publishedIDs)
			resources.extensionStateVersion = version
			resources.extensionRegistryVersion = registryVersion
			// A nonzero marker is required even before the registry has an
			// update timestamp, otherwise every message rebuilds this list.
			resources.extensionAppliedTime = appliedTime
		})
	}
	return slices.Clone(resolved)
}

func (group *GroupInfo) TriggerExtHook(d *Dice, getHook func(*ExtInfo) func()) {
	for _, wrapper := range group.GetActivatedExtList(d) {
		extension := wrapper.GetRealExt()
		if extension == nil {
			continue
		}
		if hook := getHook(extension); hook != nil {
			hook()
		}
	}
}

// SyncWrapperStatus refreshes the derived extension pointer cache. Durable
// enabled IDs remain canonical even while a plugin is uninstalled.
func (group *GroupInfo) SyncWrapperStatus(d *Dice) bool {
	if group == nil || group.requireRuntimeAuthority() != nil {
		return false
	}
	resources := group.runtime
	resources.extensionMu.Lock()
	beforeVersion := resources.extensionRegistryVersion
	resources.extensionMu.Unlock()
	_ = group.GetActivatedExtList(d)
	return d != nil && beforeVersion != atomic.LoadInt64(&d.ExtRegistryVersion)
}

func (group *GroupInfo) ExtActive(extension *ExtInfo) error {
	return group.extActivateInternal(extension, ActivateReasonManual)
}

func (group *GroupInfo) ExtActivateBatch(extInfos []*ExtInfo, isFirstTimeLoad map[string]bool) error {
	if err := group.requireRuntimeAuthority(); err != nil {
		return err
	}
	for _, extension := range extInfos {
		if extension == nil || extension.Name == "" || group.ExtensionActive(extension.Name) || group.ExtensionInactivated(extension.Name) {
			continue
		}
		first := isFirstTimeLoad[extension.Name]
		if first || extension.AutoActive || (extension.DefaultSetting != nil && extension.DefaultSetting.AutoActive) {
			if err := group.extActivateInternal(extension, ActivateReasonFirstMessage); err != nil {
				return err
			}
		} else if err := group.SetExtension(extension.Name, false); err != nil {
			return err
		}
	}
	return nil
}

func (group *GroupInfo) ExtInactive(extension *ExtInfo) (*ExtInfo, error) {
	return group.extDeactivateInternal(extension, DeactivateReasonManual, true)
}

func (group *GroupInfo) invalidateExtensionPointerCache() {
	if group == nil {
		return
	}
	group.extensionCacheMu.Lock()
	group.activatedExtensions = nil
	group.activatedExtensionIDs = nil
	group.extensionCacheStateVersion = 0
	group.extensionCacheRegistryVersion = -1
	group.extensionCacheMu.Unlock()
	if group.runtime == nil {
		return
	}
	group.runtime.extensionMu.Lock()
	group.runtime.activatedExtensions = nil
	group.runtime.activatedExtensionIDs = nil
	group.runtime.extensionStateVersion = 0
	group.runtime.extensionRegistryVersion = -1
	group.runtime.extensionCacheEpoch++
	group.runtime.extensionMu.Unlock()
}

// ExtInactiveSystem invalidates only the resolved pointer cache. The enabled
// durable ID is retained as a tombstone so reinstalling the plugin restores
// the group's selection.
func (group *GroupInfo) ExtInactiveSystem(extension *ExtInfo) (*ExtInfo, error) {
	if err := group.requireRuntimeAuthority(); err != nil {
		return nil, err
	}
	group.invalidateExtensionPointerCache()
	return extension, nil
}

func (group *GroupInfo) ExtInactiveByName(name string) (*ExtInfo, error) {
	if group == nil {
		return nil, ErrGroupHandleUnavailable
	}
	var extension *ExtInfo
	for _, candidate := range group.GetActivatedExtList(nil) {
		if candidate != nil && candidate.Name == name {
			extension = candidate
			break
		}
	}
	if extension == nil {
		extension = extNamePlaceholder(name)
	}
	return group.extDeactivateInternal(extension, DeactivateReasonManual, true)
}

func (group *GroupInfo) ExtGetActive(name string) *ExtInfo {
	if group == nil || group.requireRuntimeAuthority() != nil || !group.ExtensionActive(name) {
		return nil
	}
	for _, extension := range group.GetActivatedExtList(nil) {
		if extension != nil && extension.Name == name {
			return extension
		}
	}
	return extNamePlaceholder(name)
}

func (group *GroupInfo) extActivateInternal(extension *ExtInfo, _ ActivateReason) error {
	if group == nil {
		return ErrGroupHandleUnavailable
	}
	if extension == nil || extension.Name == "" || extension.dice == nil {
		return errors.New("dice: extension activation target unavailable")
	}
	d := extension.dice
	followers := collectChainedNames(d.Logger, d.activeWithGraph(), extension.Name, maxChainDepth)
	names := append([]string{extension.Name}, followers...)
	for _, name := range names {
		if err := group.SetExtension(name, true); err != nil {
			return err
		}
	}
	priority := append(append([]string(nil), followers...), extension.Name)
	if err := group.promoteExtensions(priority); err != nil {
		return err
	}
	_ = group.GetActivatedExtList(d)
	return nil
}

func (group *GroupInfo) extDeactivateInternal(extension *ExtInfo, _ DeactivateReason, markInactivated bool) (*ExtInfo, error) {
	if group == nil {
		return nil, ErrGroupHandleUnavailable
	}
	if extension == nil || extension.Name == "" {
		return nil, errors.New("dice: extension deactivation target unavailable")
	}
	d := extension.dice
	names := []string{extension.Name}
	if d != nil {
		names = append(names, collectChainedNames(d.Logger, d.activeWithGraph(), extension.Name, maxChainDepth)...)
	}
	var removed *ExtInfo
	for _, name := range names {
		if markInactivated {
			if err := group.SetExtension(name, false); err != nil {
				return removed, err
			}
		}
		if d != nil {
			if ext := d.ExtFind(name, false); ext != nil {
				if target := ext.GetRealExt(); target != nil && target.Storage != nil {
					_ = target.StorageClose()
				}
				if removed == nil {
					removed = ext
				}
			}
		}
	}
	if group.runtime != nil {
		group.runtime.extensionMu.Lock()
		group.runtime.extensionStateVersion = 0
		group.runtime.extensionMu.Unlock()
	}
	return removed, nil
}

func (group *GroupInfo) SyncExtensionsOnMessage(d *Dice) error {
	if err := group.requireRuntimeAuthority(); err != nil {
		return err
	}
	if d == nil {
		return errors.New("dice: extension registry unavailable")
	}
	registryVersion := atomic.LoadInt64(&d.ExtRegistryVersion)
	resetEpoch := group.runtime.currentExtensionDefaultsEpoch()
	group.runtime.extensionMu.Lock()
	alreadyApplied := group.runtime.extensionDefaultsInitialized &&
		group.runtime.extensionDefaultsVersion == registryVersion &&
		group.runtime.extensionResetEpoch >= resetEpoch
	resetPending := group.runtime.extensionResetEpoch < resetEpoch
	group.runtime.extensionMu.Unlock()
	if alreadyApplied {
		return nil
	}
	for _, extension := range d.ExtList {
		if extension == nil || extension.Name == "" || group.ExtensionActive(extension.Name) {
			continue
		}
		enabled := extension.AutoActive || (extension.DefaultSetting != nil && extension.DefaultSetting.AutoActive)
		// A recorded deactivation survives registry changes such as incremental
		// plugin loads. Only a full defaults apply made after this group was
		// cached re-enables AutoActive extensions over it.
		if group.ExtensionInactivated(extension.Name) && (!resetPending || !enabled) {
			continue
		}
		if err := group.SetExtension(extension.Name, enabled); err != nil {
			return err
		}
	}
	resources := group.runtime
	if group.transaction == nil {
		return ErrDomainTxUnavailable
	}
	if err := group.transaction.AfterCommit(func() {
		if resources.revoked.Load() {
			return
		}
		resources.extensionMu.Lock()
		resources.extensionDefaultsInitialized = true
		resources.extensionDefaultsVersion = registryVersion
		if resources.extensionResetEpoch < resetEpoch {
			resources.extensionResetEpoch = resetEpoch
		}
		resources.extensionMu.Unlock()
	}); err != nil {
		return err
	}
	_ = group.GetActivatedExtList(d)
	return nil
}
