package dice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"Scardice-core/message"
	"Scardice-core/utils/jsengine"
)

func jsExtensionSourceDescription(source *JsScriptInfo) string {
	if source == nil {
		return "<unknown>"
	}
	return fmt.Sprintf("name=%q filename=%q packageID=%q homepage=%q", source.Name, source.Filename, source.PackageID, source.HomePage)
}

// jsExtensionResource is the VM-facing extension receiver. It keeps normal
// ExtInfo fields and callbacks reflectable while routing storage through the
// invocation proven by the loop that created or returned the receiver.
type jsExtensionResource struct {
	*ExtInfo
	loop jsengine.Loop
}

func newJSExtensionResource(extension *ExtInfo, loop jsengine.Loop) *jsExtensionResource {
	if extension == nil {
		return nil
	}
	return &jsExtensionResource{ExtInfo: extension, loop: loop}
}

func (r *jsExtensionResource) target() (*ExtInfo, error) {
	if r == nil || r.ExtInfo == nil {
		return nil, errors.New("[扩展]:目标扩展不存在")
	}
	target := r.ExtInfo.GetRealExt()
	if target == nil {
		return nil, errors.New("[扩展]:目标扩展不存在")
	}
	return target, nil
}

func (r *jsExtensionResource) registered() (*ExtInfo, error) {
	if r == nil || r.ExtInfo == nil || r.dice == nil {
		return nil, errors.New("请先完成此扩展的注册")
	}
	return r.ExtInfo, nil
}

func (r *jsExtensionResource) transaction() (*DurableCallbackTransaction, context.Context, error) {
	execution, domainCtx := jsDomainExecutionFor(r.loop)
	if execution == nil || execution.Transaction == nil {
		return nil, domainCtx, ErrJSInvocationExpired
	}
	if err := execution.ExecutionContext().Err(); err != nil {
		return nil, domainCtx, errors.Join(ErrJSInvocationExpired, err)
	}
	domain := execution.Transaction.Domain()
	if domain == nil {
		return nil, domainCtx, ErrJSInvocationExpired
	}
	if err := domain.CheckOpen(); err != nil {
		return nil, domainCtx, errors.Join(ErrJSInvocationExpired, err)
	}
	return execution.Transaction, domainCtx, nil
}

func (r *jsExtensionResource) StorageSet(key, value string) error {
	target, err := r.target()
	if err != nil {
		return err
	}
	transaction, domainCtx, err := r.transaction()
	if err != nil {
		return err
	}
	return transaction.StorageSet(domainCtx, target.Name, key, value)
}

func (r *jsExtensionResource) StorageGet(key string) (string, error) {
	target, err := r.target()
	if err != nil {
		return "", err
	}
	transaction, domainCtx, err := r.transaction()
	if err != nil {
		return "", err
	}
	return transaction.StorageGet(domainCtx, target.Name, key)
}

func (r *jsExtensionResource) StorageList() ([]string, error) {
	target, err := r.target()
	if err != nil {
		return nil, err
	}
	transaction, domainCtx, err := r.transaction()
	if err != nil {
		return nil, err
	}
	return transaction.StorageList(domainCtx, target.Name)
}

func (r *jsExtensionResource) GetRealExt() *jsExtensionResource {
	if r == nil || r.ExtInfo == nil {
		return nil
	}
	return newJSExtensionResource(r.ExtInfo.GetRealExt(), r.loop)
}

func jsHostMessageContext(d *Dice, loop jsengine.Loop) *MsgContext {
	execution, _ := jsDomainExecutionFor(loop)
	if execution == nil {
		return nil
	}
	if execution.Message != nil {
		return execution.Message
	}
	transaction := execution.Transaction
	if transaction == nil {
		return nil
	}
	return &MsgContext{
		Dice:                d,
		callbackTransaction: transaction,
		callbackMetadata:    transaction.metadata,
		executionContext:    transaction.executionContext,
	}
}

// jsCreateTempContext creates a message authority for message-less roots so
// cron, task, and persistent async callbacks retain their proven DomainTx.
func jsCreateTempContext(
	execution *jsExecutionContext,
	d *Dice,
	ep *EndPointInfo,
	msg *Message,
) (*MsgContext, error) {
	if execution == nil {
		return nil, ErrJSInvocationExpired
	}
	if d == nil || (execution.Dice != nil && execution.Dice != d) {
		return nil, ErrJSInvocationCrossRealm
	}
	if ep != nil && ep.Session != nil && ep.Session.Parent != nil && ep.Session.Parent != d {
		return nil, ErrJSInvocationCrossRealm
	}
	authority := execution.Message
	if authority == nil {
		registry := execution.invocationRegistry()
		registry.mu.Lock()
		authority = registry.message
		if authority == nil {
			authority = &MsgContext{
				Dice:                d,
				callbackTransaction: execution.Transaction,
				executionContext:    execution.ExecutionContext(),
				jsExecution:         execution.executionScope(),
			}
			if execution.Transaction != nil {
				authority.callbackMetadata = execution.Transaction.metadata
				if execution.Transaction.executionContext != nil {
					authority.executionContext = execution.Transaction.executionContext
				}
			}
			registry.message = authority
		}
		registry.mu.Unlock()
		execution.Message = authority
	}
	if execution.Transaction != nil {
		return CreateTempCtxInExecution(authority, ep, msg)
	}
	temporary, err := CreateTempCtxInExecution(nil, ep, msg)
	if err != nil {
		return nil, err
	}
	temporary.executionParent = authority
	temporary.executionContext = authority.domainContext()
	return temporary, nil
}

// installJSHostAPI exposes the engine-neutral base of the seal host object.
// installJSExtHostAPI adds extension registration and callbacks once the
// runtime generation is known.
func (d *Dice) installJSHostAPI(runtime jsengine.Runtime, loop jsengine.Loop) error {
	seal := runtime.NewObject()

	vars := runtime.NewObject()
	if err := setJSHostObject(seal, "vars", vars); err != nil {
		return err
	}
	for _, binding := range []struct {
		name  string
		value interface{}
	}{
		{name: "intGet", value: VarGetValueInt64},
		{name: "intSet", value: VarSetValueInt64},
		{name: "strGet", value: VarGetValueStr},
		{name: "strSet", value: VarSetValueStr},
		{name: "computedSet", value: VarSetValueComputed},
		{name: "computedGet", value: VarGetValueComputed},
	} {
		if err := setJSHostObject(vars, binding.name, binding.value); err != nil {
			return err
		}
	}

	ban := runtime.NewObject()
	if err := setJSHostObject(seal, "ban", ban); err != nil {
		return err
	}
	for _, binding := range []struct {
		name  string
		value interface{}
	}{
		{name: "addBan", value: func(ctx *MsgContext, id string, place string, reason string) error {
			config := d.Config()
			if config == nil || config.BanList == nil {
				return errors.New("黑白名单服务不可用")
			}
			if ctx == nil {
				ctx = jsHostMessageContext(d, loop)
			}
			settings, err := config.BanList.settingsForContext(ctx)
			if err != nil {
				return err
			}
			_, err = config.BanList.AddScoreBaseWithError(id, settings.ThresholdBan, place, reason, ctx)
			return err
		}},
		{name: "addTrust", value: func(ctx *MsgContext, id string, place string, reason string) error {
			config := d.Config()
			if config == nil || config.BanList == nil {
				return errors.New("黑白名单服务不可用")
			}
			if ctx == nil {
				ctx = jsHostMessageContext(d, loop)
			}
			return config.BanList.SetTrustByIDForContext(ctx, id, place, reason)
		}},
		{name: "remove", value: func(ctx *MsgContext, id string) error {
			config := d.Config()
			if config == nil || config.BanList == nil {
				return errors.New("黑白名单服务不可用")
			}
			// 显式 ctx 优先；否则继承当前 JS 执行的 DomainTx；二者都没有时
			// DeleteByIDForContext 会开启独立的 moderation-delete typed root。
			if ctx == nil {
				ctx = jsHostMessageContext(d, loop)
			}
			_, ok, err := config.BanList.GetByIDForContext(ctx, id)
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
			return config.BanList.DeleteByIDForContext(ctx, d, id)
		}},
		{name: "getList", value: func() ([]BanListInfoItem, error) {
			config := d.Config()
			if config == nil || config.BanList == nil {
				return nil, nil
			}
			message := jsHostMessageContext(d, loop)
			snapshots, err := config.BanList.SnapshotForContext(message)
			if err != nil {
				return nil, err
			}
			list := make([]BanListInfoItem, 0, len(snapshots))
			for _, item := range snapshots {
				if item != nil {
					list = append(list, *item)
				}
			}
			return list, nil
		}},
		{name: "getUser", value: func(id string) (*BanListInfoItem, error) {
			// Missing services and subjects are intentional JS null values.
			// A repository failure remains a JavaScript exception.
			var result *BanListInfoItem
			if config := d.Config(); config != nil && config.BanList != nil {
				item, found, err := config.BanList.GetByIDForContext(jsHostMessageContext(d, loop), id)
				if err != nil {
					return nil, err
				}
				if found && item != nil {
					itemCopy := *item
					result = &itemCopy
				}
			}
			return result, nil
		}},
	} {
		if err := setJSHostObject(ban, binding.name, binding.value); err != nil {
			return err
		}
	}

	coc := runtime.NewObject()
	if err := setJSHostObject(coc, "newRule", d.newJSCocRule); err != nil {
		return err
	}
	if err := setJSHostObject(coc, "newRuleCheckResult", func() *CocRuleCheckRet { return &CocRuleCheckRet{} }); err != nil {
		return err
	}
	if err := setJSHostObject(coc, "registerRule", d.registerJSCocRule); err != nil {
		return err
	}
	if err := setJSHostObject(seal, "coc", coc); err != nil {
		return err
	}

	deck := runtime.NewObject()
	if err := setJSHostObject(deck, "draw", func(ctx *MsgContext, deckName string, isShuffle bool) map[string]interface{} {
		exists, result, err := deckDraw(ctx, deckName, isShuffle)
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		return map[string]interface{}{"exists": exists, "err": errText, "result": result}
	}); err != nil {
		return err
	}
	if err := setJSHostObject(deck, "reload", func() { DeckReload(d) }); err != nil {
		return err
	}
	if err := setJSHostObject(seal, "deck", deck); err != nil {
		return err
	}

	for _, binding := range []struct {
		name  string
		value interface{}
	}{
		{name: "replyGroup", value: ReplyGroup},
		{name: "replyPerson", value: ReplyPerson},
		{name: "replyToSender", value: ReplyToSender},
		{name: "replyForward", value: ReplyForward},
		{name: "newForwardNode", value: func(senderID string, senderName string, text string) *message.ForwardNode {
			return &message.ForwardNode{
				SenderID:   senderID,
				SenderName: senderName,
				Elements:   message.ConvertStringMessage(text),
			}
		}},
		{name: "newForwardElement", value: func() *message.ForwardElement {
			return &message.ForwardElement{Kind: "forward"}
		}},
		{name: "memberBan", value: MemberBan},
		{name: "memberKick", value: MemberKick},
		{name: "format", value: DiceFormat},
		{name: "formatTmpl", value: DiceFormatTmpl},
		{name: "getCtxProxyFirst", value: GetCtxProxyFirst},
		{name: "newMessage", value: func() *Message { return &Message{} }},
		{name: "createTempCtx", value: func(ep *EndPointInfo, msg *Message) (*MsgContext, error) {
			execution, _ := jsDomainExecutionFor(loop)
			return jsCreateTempContext(execution, d, ep, msg)
		}},
		{name: "applyPlayerGroupCardByTemplate", value: func(ctx *MsgContext, tmpl string) (string, error) {
			if ctx == nil || ctx.Player == nil {
				return "", ErrPlayerHandleUnavailable
			}
			if tmpl != "" {
				if err := ctx.Player.SetAutoSetNameTemplate(tmpl); err != nil {
					return "", err
				}
			}
			current := ctx.Player.AutoSetNameTemplate()
			if current == "" {
				return "", nil
			}
			return SetPlayerGroupCardByTemplate(ctx, current)
		}},
		{name: "getCtxProxyAtPos", value: GetCtxProxyAtPos},
		{name: "getVersion", value: jsHostVersion},
		{name: "getEndPoints", value: func() []*EndPointInfo {
			return d.ImSession.EndPointsReadOnly()
		}},
		{name: "setPlayerGroupCard", value: SetPlayerGroupCardByTemplate},
		{name: "base64ToImage", value: Base64ToImageFunc()},
	} {
		if err := setJSHostObject(seal, binding.name, binding.value); err != nil {
			return err
		}
	}

	gameSystem := runtime.NewObject()
	if err := setJSHostObject(gameSystem, "newTemplate", func(data string) error {
		return d.addJSGameSystemTemplate(data, "json")
	}); err != nil {
		return err
	}
	if err := setJSHostObject(gameSystem, "newTemplateByYaml", func(data string) error {
		return d.addJSGameSystemTemplate(data, "yaml")
	}); err != nil {
		return err
	}
	if err := setJSHostObject(seal, "gameSystem", gameSystem); err != nil {
		return err
	}

	if err := runtime.Set("atob", jsHostAtob); err != nil {
		return fmt.Errorf("set atob: %w", err)
	}
	if err := runtime.Set("btoa", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }); err != nil {
		return fmt.Errorf("set btoa: %w", err)
	}
	if err := runtime.Set("seal", seal); err != nil {
		return fmt.Errorf("set seal: %w", err)
	}
	return nil
}

func configValueTypeMismatch(ei *ExtInfo, key string, config *ConfigItem) string {
	pluginName := ""
	if ei != nil {
		pluginName = ei.Name
	}
	declaredType := ""
	var value any
	if config != nil {
		declaredType = config.Type
		value = config.Value
	}
	return fmt.Sprintf(
		"配置值类型不匹配: plugin=%q key=%q declared=%q actual=%q",
		pluginName,
		key,
		declaredType,
		fmt.Sprintf("%T", value),
	)
}

func jsDomainExecutionFor(loop jsengine.Loop) (*jsExecutionContext, context.Context) {
	execution := jsExecutionContextFor(loop)
	if execution.persistentScope() {
		if active, err := execution.persistentInvocation(); err == nil {
			execution = active
		}
	}
	if execution != nil && execution.Message != nil {
		return execution, execution.Message.domainContext()
	}
	if execution != nil && execution.Transaction != nil && execution.Transaction.executionContext != nil {
		return execution, execution.Transaction.executionContext
	}
	return execution, context.Background()
}

func (d *Dice) installJSExtHostAPI(runtime jsengine.Runtime, loop jsengine.Loop, seal jsengine.Object, versionID int64, sourceLocation func() string) error {
	ext := runtime.NewObject()
	if err := seal.Set("ext", ext); err != nil {
		return err
	}
	if sourceLocation == nil {
		sourceLocation = func() string { return "" }
	}
	registerPluginConfig := func(ei *ExtInfo, items ...*ConfigItem) error {
		execution, domainCtx := jsDomainExecutionFor(loop)
		if execution != nil && execution.Transaction != nil {
			return d.ConfigManager.RegisterPluginConfigInDomain(
				domainCtx, execution.Transaction, ei.Name, items...,
			)
		}
		if d.DurableStore != nil {
			return ErrJSInvocationExpired
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, items...)
	}
	unregisterPluginConfig := func(ei *ExtInfo, keys ...string) error {
		execution, domainCtx := jsDomainExecutionFor(loop)
		if execution != nil && execution.Transaction != nil {
			return d.ConfigManager.UnregisterConfigInDomain(
				domainCtx, execution.Transaction, ei.Name, keys...,
			)
		}
		if d.DurableStore != nil {
			return ErrJSInvocationExpired
		}
		return d.ConfigManager.UnregisterConfig(ei.Name, keys...)
	}
	configItem := func(ei *ExtInfo, key string) (*ConfigItem, error) {
		execution, domainCtx := jsDomainExecutionFor(loop)
		if execution != nil && execution.Transaction != nil {
			return d.configItemForDomain(domainCtx, execution.Transaction, ei.Name, key)
		}
		if d.DurableStore != nil {
			return nil, ErrJSInvocationExpired
		}
		return d.compatibilityConfigItemWithError(ei, key)
	}
	pluginConfigItems := func(ei *ExtInfo) (map[string]*ConfigItem, bool, error) {
		execution, domainCtx := jsDomainExecutionFor(loop)
		if execution != nil && execution.Transaction != nil {
			state, err := d.ExtensionStateForDomain(domainCtx, execution.Transaction.Domain())
			if err != nil {
				return nil, false, err
			}
			definitions, found := state.ConfigDefinitions[ei.Name]
			if !found {
				return nil, false, nil
			}
			items := make(map[string]*ConfigItem, len(definitions))
			for key := range definitions {
				item, itemErr := d.configItemForDomain(domainCtx, execution.Transaction, ei.Name, key)
				if itemErr != nil {
					return nil, false, itemErr
				}
				items[key] = item
			}
			return items, true, nil
		}
		if d.DurableStore != nil {
			return nil, false, ErrJSInvocationExpired
		}
		configs, err := d.ConfigManager.PluginConfigs(domainCtx)
		if err != nil {
			return nil, false, err
		}
		if config := configs[ei.Name]; config != nil {
			return config.Configs, true, nil
		}
		return nil, false, nil
	}
	_ = ext.Set("newCmdItemInfo", func() *CmdItemInfo {
		return &CmdItemInfo{
			IsJsSolveFunc:  true,
			JSLoopVersion:  versionID,
			SourceLocation: sourceLocation(),
		}
	})
	_ = ext.Set("newCmdExecuteResult", func(solved bool) CmdExecuteResult {
		return CmdExecuteResult{
			Matched: true,
			Solved:  solved,
		}
	})
	_ = ext.Set("new", func(name, author, version string) *jsExtensionResource {
		execution := jsExecutionContextFor(loop)
		source := jsContextScript(execution)
		var official bool
		if source != nil {
			official = source.Official
		}
		return newJSExtensionResource(&ExtInfo{
			Name: name, Author: author, Version: version,
			GetDescText:   GetExtensionDesc,
			AutoActive:    true,
			IsJsExt:       true,
			Brief:         "一个JS自定义扩展",
			Official:      official,
			CmdMap:        CmdMapCls{},
			Source:        source,
			JSLoopVersion: versionID,
		}, loop)
	})
	// TODO(局部重载/更新同名插件): 这里是“谁观察了谁”的天然采集点。依赖方可能持有 find 返回的旧 ExtInfo，
	//   局部更新时需要整链重载；应在此记录“调用方脚本 -> 被查找扩展”的边，补充 @depends 未声明的耦合。
	//   subTODO(局部重载): 调用方脚本取自 jsExecutionContextFor(loop)；跨插件 storage 访问同理。
	_ = ext.Set("find", func(name string) *jsExtensionResource {
		return newJSExtensionResource(d.ExtFind(name, true), loop)
	})
	_ = ext.Set("register", func(resource *jsExtensionResource) (returnErr error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				returnErr = fmt.Errorf("注册扩展失败: %v", recovered)
			}
		}()
		if resource == nil || resource.ExtInfo == nil {
			return errors.New("注册扩展失败: 扩展为空")
		}
		realExt := resource.ExtInfo

		if strings.EqualFold(realExt.Name, "help") || strings.EqualFold(realExt.Name, "all") {
			return errors.New("help 和 all 为保留关键字，无法作为插件名使用")
		}

		extName := realExt.Name
		if realExt.Source == nil {
			realExt.Source = jsContextScript(jsExecutionContextFor(loop))
		}
		if existing, ok := d.ExtRegistry.Load(extName); ok && existing != nil && !existing.IsWrapper {
			return fmt.Errorf("注册扩展失败: 扩展名 %q 已被占用", extName)
		}
		if d.DurableStore != nil {
			execution, domainCtx := jsDomainExecutionFor(loop)
			if execution == nil || execution.Transaction == nil {
				return ErrJSInvocationExpired
			}
			if err := d.ensureExtensionInDomain(
				domainCtx, execution.Transaction.Domain(), execution.Transaction.metadata, realExt,
			); err != nil {
				return fmt.Errorf("注册扩展 %q 的持久身份失败: %w", extName, err)
			}
		}

		// 1. 查找或创建 wrapper
		var wrapper *ExtInfo
		if existingWrapper, ok := d.ExtRegistry.Load(extName); ok && existingWrapper != nil && existingWrapper.IsWrapper {
			// 重载：复用已有 wrapper
			wrapper = existingWrapper
			wrapper.Author = realExt.Author
			wrapper.Version = realExt.Version
			wrapper.IsDeleted = false         // 重新激活（清除删除标记）
			wrapper.dice = d                  // 确保 dice 引用正确（可能从配置恢复时为 nil）
			wrapper.JSLoopVersion = versionID // 同步新的 loop 版本号，避免 callWithJsCheck 时版本不匹配
			wrapper.Source = realExt.Source
			d.ActiveWithGraphMu.Lock()
			wrapper.ActiveWith = append([]string(nil), realExt.ActiveWith...)
			d.ActiveWithGraph = nil
			d.ActiveWithGraphMu.Unlock()
		} else {
			// 首次加载：创建新 wrapper
			wrapper = &ExtInfo{
				Name:          extName,
				Author:        realExt.Author,
				Version:       realExt.Version,
				IsWrapper:     true,
				TargetName:    extName,
				IsDeleted:     false,
				GetDescText:   GetExtensionDesc,
				AutoActive:    realExt.AutoActive, // 复制真实扩展的 AutoActive 设置
				IsJsExt:       true,               // 标记为 JS 扩展
				Brief:         "一个JS自定义扩展",
				Official:      realExt.Official,
				ActiveWith:    append([]string(nil), realExt.ActiveWith...),
				CmdMap:        CmdMapCls{},
				Source:        realExt.Source,
				JSLoopVersion: versionID,
				dice:          d,
			}
			// 注册 wrapper 到 ExtRegistry 和 ExtList
			d.RegisterExtension(wrapper)
		}

		// 2. 注册真实 ExtInfo 到 JsExtRegistry
		if d.JsExtRegistry == nil {
			d.JsExtRegistry = new(SyncMap[string, *ExtInfo])
		}
		if incumbent, ok := d.JsExtRegistry.Load(extName); ok && incumbent != nil && incumbent != realExt && d.Logger != nil {
			d.Logger.Warnf("JS 扩展 %q 正在替换同名扩展；请确认来源：现有[%s]，替换[%s]",
				extName, jsExtensionSourceDescription(incumbent.Source), jsExtensionSourceDescription(realExt.Source))
		}
		realExt.dice = d
		realExt.JSLoopVersion = versionID
		d.JsExtRegistry.Store(extName, realExt)

		// 4. 更新全局扩展变更时间戳
		atomic.StoreInt64(&d.ExtUpdateTime, time.Now().Unix())

		// 5. 触发 OnLoad 回调
		if realExt.OnLoad != nil {
			realExt.OnLoad()
		}
		return nil
	})
	_ = ext.Set("registerStringConfig", func(resource *jsExtensionResource, key string, defaultValue string, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "string",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("registerIntConfig", func(resource *jsExtensionResource, key string, defaultValue int64, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "int",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("registerBoolConfig", func(resource *jsExtensionResource, key string, defaultValue bool, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "bool",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("registerFloatConfig", func(resource *jsExtensionResource, key string, defaultValue float64, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "float",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("registerTemplateConfig", func(resource *jsExtensionResource, key string, defaultValue []string, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "template",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("registerOptionConfig", func(resource *jsExtensionResource, key string, defaultValue string, option []string, description string, group string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "option",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Option:       option,
			Description:  description,
		}
		return registerPluginConfig(ei, config)
	})
	_ = ext.Set("newConfigItem", func(resource *jsExtensionResource, key string, defaultValue interface{}, description string) *ConfigItem {
		if _, err := resource.registered(); err != nil {
			panic(err)
		}
		return d.ConfigManager.NewConfigItem(key, defaultValue, description)
	})
	_ = ext.Set("registerConfig", func(resource *jsExtensionResource, config ...*ConfigItem) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		return registerPluginConfig(ei, config...)
	})
	_ = ext.Set("getConfig", func(resource *jsExtensionResource, key string) *ConfigItem {
		ei, err := resource.registered()
		if err != nil {
			return nil
		}
		item, err := configItem(ei, key)
		if err != nil {
			panic(err)
		}
		return item
	})
	_ = ext.Set("getStringConfig", func(resource *jsExtensionResource, key string) (string, error) {
		ei, err := resource.registered()
		if err != nil {
			return "", err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return "", err
		}
		if cfg == nil || cfg.Type != "string" {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(string)
		if !ok {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getIntConfig", func(resource *jsExtensionResource, key string) (int64, error) {
		ei, err := resource.registered()
		if err != nil {
			return 0, err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return 0, err
		}
		if cfg == nil || cfg.Type != "int" {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(int64)
		if !ok {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getBoolConfig", func(resource *jsExtensionResource, key string) (bool, error) {
		ei, err := resource.registered()
		if err != nil {
			return false, err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return false, err
		}
		if cfg == nil || cfg.Type != "bool" {
			return false, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(bool)
		if !ok {
			return false, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getFloatConfig", func(resource *jsExtensionResource, key string) (float64, error) {
		ei, err := resource.registered()
		if err != nil {
			return 0, err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return 0, err
		}
		if cfg == nil || cfg.Type != "float" {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(float64)
		if !ok {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getTemplateConfig", func(resource *jsExtensionResource, key string) ([]string, error) {
		ei, err := resource.registered()
		if err != nil {
			return nil, err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return nil, err
		}
		if cfg == nil || cfg.Type != "template" {
			return nil, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.([]string)
		if !ok {
			return nil, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return append([]string(nil), value...), nil
	})
	_ = ext.Set("getOptionConfig", func(resource *jsExtensionResource, key string) (string, error) {
		ei, err := resource.registered()
		if err != nil {
			return "", err
		}
		cfg, err := configItem(ei, key)
		if err != nil {
			return "", err
		}
		if cfg == nil || cfg.Type != "option" {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(string)
		if !ok {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("unregisterConfig", func(resource *jsExtensionResource, key ...string) error {
		ei, err := resource.registered()
		if err != nil {
			return err
		}
		return unregisterPluginConfig(ei, key...)
	})
	_ = ext.Set("storageList", func(resource *jsExtensionResource) []string {
		keys, err := resource.StorageList()
		if err != nil {
			panic(err)
		}
		return keys
	})

	runAfterDomainCommit := func(run func()) error {
		execution, _ := jsDomainExecutionFor(loop)
		if execution != nil && execution.Transaction != nil {
			return execution.Transaction.AfterCommit(run)
		}
		if d.DurableStore != nil {
			return ErrJSInvocationExpired
		}
		run()
		return nil
	}
	_ = ext.Set("registerTask", func(resource *jsExtensionResource, taskType string, value string, fn func(taskCtx JsScriptTaskCtx) (jsengine.Value, error), key string, desc string, group string) *JsScriptTask {
		ei, err := resource.registered()
		if err != nil {
			panic(err)
		}
		owner := ei.dice
		owner.jsScriptCronMu.Lock()
		scriptCron := owner.JsScriptCron
		owner.jsScriptCronMu.Unlock()
		if scriptCron == nil {
			panic(errors.New("插件cron未成功初始化"))
		}

		task := &JsScriptTask{cron: scriptCron, key: key, taskCallback: fn, lock: owner.JsScriptCronLock, logger: owner.Logger, dice: owner, ext: ei}
		expr := value
		var previous *JsScriptTask
		if key != "" && taskType != "once" {
			config, configErr := configItem(ei, key)
			if configErr != nil {
				panic(configErr)
			}
			if config != nil {
				configured, ok := config.Value.(string)
				if !ok {
					panic(configValueTypeMismatch(ei, key, config))
				}
				expr = configured
				previous = config.task
			}
		}

		switch taskType {
		case "cron":
			cronExpr, parseErr := parseTaskCronExpr(expr)
			if parseErr != nil {
				panic("插件注册定时任务失败：" + parseErr.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = cronExpr
			expr = cronExpr
		case "daily":
			cronExpr, parseErr := parseTaskTime(expr)
			if parseErr != nil {
				panic("插件注册定时任务失败：" + parseErr.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = cronExpr
		case "once":
			onceAt, normalizedExpr, parseErr := parseTaskOnceExpr(expr)
			if parseErr != nil {
				panic("插件注册定时任务失败：" + parseErr.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.onceAt = onceAt
			expr = normalizedExpr
		default:
			panic(fmt.Sprintf("错误的任务类型：%s，当前仅支持 cron|daily|once", taskType))
		}

		if key != "" && taskType != "once" {
			config := &ConfigItem{
				Key:          key,
				Type:         "task:" + taskType,
				Group:        group,
				Value:        expr,
				DefaultValue: value,
				Description:  desc,
				task:         task,
			}
			if err := registerPluginConfig(ei, config); err != nil {
				panic("插件注册定时任务配置失败：" + err.Error())
			}
		}

		if err := runAfterDomainCommit(func() {
			if previous != nil {
				previous.Off()
				ei.taskList = removeTaskFromList(ei.taskList, previous)
			}
			if !task.On() {
				if owner.Logger != nil {
					owner.Logger.Errorf("插件注册定时任务提交后激活失败：type=%s key=%s value=%s", taskType, key, expr)
				}
				return
			}
			ei.taskList = append(ei.taskList, task)
			if owner.Logger != nil {
				owner.Logger.Infof("插件注册定时任务：%s=%s", taskType, expr)
			}
		}); err != nil {
			panic("插件注册定时任务提交失败：" + err.Error())
		}

		return task
	})
	_ = ext.Set("removeTask", func(resource *jsExtensionResource, taskType string, key string) (int, error) {
		ei, err := resource.registered()
		if err != nil {
			return 0, err
		}

		taskType, key = normalizeTaskSelector(taskType, key)
		taskSet := make(map[*JsScriptTask]struct{})
		configKeySet := make(map[string]struct{})

		for _, task := range ei.taskList {
			if matchTaskSelector(task, taskType, key) {
				taskSet[task] = struct{}{}
				if task.key != "" && task.taskType != "once" {
					configKeySet[task.key] = struct{}{}
				}
			}
		}

		pluginConfig, found, err := pluginConfigItems(ei)
		if err != nil {
			return 0, err
		}
		if found {
			for cfgKey, cfgItem := range pluginConfig {
				if cfgItem == nil {
					continue
				}
				cfgTaskType, isTask := configTypeToTaskType(cfgItem.Type)
				if !isTask || !taskTypeMatched(taskType, cfgTaskType) || !keyMatched(key, cfgKey) {
					continue
				}
				configKeySet[cfgKey] = struct{}{}
				if cfgItem.task != nil {
					taskSet[cfgItem.task] = struct{}{}
				}
			}
		}

		if len(configKeySet) > 0 {
			keys := make([]string, 0, len(configKeySet))
			for cfgKey := range configKeySet {
				keys = append(keys, cfgKey)
			}
			sort.Strings(keys)
			if err := unregisterPluginConfig(ei, keys...); err != nil {
				return 0, err
			}
		}

		if err := runAfterDomainCommit(func() {
			for task := range taskSet {
				_ = task.Off()
			}
			if len(taskSet) == 0 {
				return
			}
			filtered := make([]*JsScriptTask, 0, len(ei.taskList))
			for _, task := range ei.taskList {
				if _, hit := taskSet[task]; !hit {
					filtered = append(filtered, task)
				}
			}
			ei.taskList = filtered
		}); err != nil {
			return 0, err
		}

		return len(taskSet), nil
	})
	_ = ext.Set("listTasks", func(resource *jsExtensionResource) []*JsScriptTaskInfo {
		ei, err := resource.registered()
		if err != nil {
			panic(err)
		}

		tasks := make([]*JsScriptTaskInfo, 0, len(ei.taskList))
		for _, task := range ei.taskList {
			if task == nil {
				continue
			}
			tasks = append(tasks, &JsScriptTaskInfo{
				TaskType: task.taskType,
				Key:      task.key,
				Value:    task.rawValue,
				Active:   task.IsActive(),
			})
		}
		return tasks
	})
	return d.installJSAdapterHostAPI(runtime, loop, seal, versionID)
}

func setJSHostObject(object jsengine.Object, name string, value interface{}) error {
	if err := object.Set(name, value); err != nil {
		return fmt.Errorf("set host API %s: %w", name, err)
	}
	return nil
}

func (d *Dice) addJSGameSystemTemplate(data string, format string) error {
	template, err := loadGameSystemTemplateFromData([]byte(data), format)
	if err != nil {
		return errors.New("解析失败:" + err.Error())
	}
	if !d.addJSGameSystemTemplateObject(template, true, true) {
		return errors.New("已存在同名模板")
	}
	return nil
}

func (d *Dice) addJSGameSystemTemplateObject(template *GameSystemTemplate, overwrite bool, ignoreFileTemplateCollision bool) bool {
	if template == nil {
		return false
	}
	d.jsGameSystemTemplatesMu.Lock()
	defer d.jsGameSystemTemplatesMu.Unlock()

	previousJSTemplate := d.jsGameSystemTemplates[template.Name]
	currentTemplate, hasCurrentTemplate := d.GameSystemMap.Load(template.Name)
	jsOwnsCurrentTemplate := previousJSTemplate != nil && hasCurrentTemplate && currentTemplate == previousJSTemplate
	if d.preferFileBackedGameSystemTemplates && d.JsReloading && hasCurrentTemplate && !jsOwnsCurrentTemplate {
		if ignoreFileTemplateCollision {
			if d.jsGameSystemTemplates == nil {
				d.jsGameSystemTemplates = make(map[string]*GameSystemTemplate)
			}
			d.jsGameSystemTemplates[template.Name] = template
		}
		return ignoreFileTemplateCollision
	}
	if !d.addGameSystemTemplateEx(template, overwrite) {
		return false
	}
	if d.jsGameSystemTemplates == nil {
		d.jsGameSystemTemplates = make(map[string]*GameSystemTemplate)
	}
	d.jsGameSystemTemplates[template.Name] = template
	return true
}

// TODO(局部重载/禁用与删除): JS 注册的规则模板只按模板名保存，没有脚本归属，只能整体清空。
// subTODO(局部重载): 记录模板的注册脚本，卸载时只摘除该脚本注册的模板。
func (d *Dice) clearJSTemplates() {
	d.jsGameSystemTemplatesMu.Lock()
	d.jsGameSystemTemplates = nil
	d.jsGameSystemTemplatesMu.Unlock()
}

func (d *Dice) restoreJSTemplates() {
	d.jsGameSystemTemplatesMu.Lock()
	templates := make([]*GameSystemTemplate, 0, len(d.jsGameSystemTemplates))
	for _, template := range d.jsGameSystemTemplates {
		templates = append(templates, template)
	}
	d.jsGameSystemTemplatesMu.Unlock()

	for _, template := range templates {
		d.addGameSystemTemplateEx(template, false)
	}
}

func jsHostAtob(s string) (string, error) {
	s = strings.ReplaceAll(s, "data:text/plain;base64,", "")
	s = strings.ReplaceAll(s, " ", "")
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", errors.New("atob: 不合法的base64字串")
	}
	return string(decoded), nil
}

func jsHostVersion() map[string]interface{} {
	return map[string]interface{}{
		"versionCode":   VERSION_CODE,
		"version":       VERSION.String(),
		"versionSimple": VERSION_MAIN + VERSION_PRERELEASE,
		"versionDetail": map[string]interface{}{
			"major":         VERSION.Major(),
			"minor":         VERSION.Minor(),
			"patch":         VERSION.Patch(),
			"prerelease":    VERSION.Prerelease(),
			"buildMetaData": VERSION.Metadata(),
		},
	}
}
