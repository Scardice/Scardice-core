package dice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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

// installJSHostAPI exposes the engine-neutral base of the seal host object.
// installJSExtHostAPI adds extension registration and callbacks once the
// runtime generation is known.
func (d *Dice) installJSHostAPI(runtime jsengine.Runtime) error {
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
		{name: "addBan", value: func(ctx *MsgContext, id string, place string, reason string) {
			(&d.Config).BanList.AddScoreBase(id, d.Config.BanList.ThresholdBan, place, reason, ctx)
		}},
		{name: "addTrust", value: func(ctx *MsgContext, id string, place string, reason string) {
			(&d.Config).BanList.SetTrustByID(id, place, reason)
		}},
		{name: "remove", value: func(ctx *MsgContext, id string) {
			if _, ok := (&d.Config).BanList.GetByID(id); ok {
				(&d.Config).BanList.DeleteByID(d, id)
			}
		}},
		{name: "getList", value: func() []BanListInfoItem {
			var list []BanListInfoItem
			for _, value := range (&d.Config).BanList.Snapshot() {
				list = append(list, *value)
			}
			return list
		}},
		{name: "getUser", value: func(id string) *BanListInfoItem {
			i, ok := (&d.Config).BanList.GetByID(id)
			if !ok {
				return nil
			}
			itemCopy := *i
			return &itemCopy
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
		{name: "createTempCtx", value: CreateTempCtx},
		{name: "applyPlayerGroupCardByTemplate", value: func(ctx *MsgContext, tmpl string) string {
			if tmpl != "" {
				ctx.Player.AutoSetNameTemplate = tmpl
			}
			if ctx.Player.AutoSetNameTemplate == "" {
				return ""
			}
			text, _ := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
			return text
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

func (d *Dice) installJSExtHostAPI(runtime jsengine.Runtime, loop jsengine.Loop, seal jsengine.Object, versionID int64, sourceLocation func() string) error {
	ext := runtime.NewObject()
	if err := seal.Set("ext", ext); err != nil {
		return err
	}
	if sourceLocation == nil {
		sourceLocation = func() string { return "" }
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
	_ = ext.Set("new", func(name, author, version string) *ExtInfo {
		context := jsExecutionContextFor(loop)
		source := jsContextScript(context)
		var official bool
		if source != nil {
			official = source.Official
		}
		return &ExtInfo{
			Name: name, Author: author, Version: version,
			GetDescText:   GetExtensionDesc,
			AutoActive:    true,
			IsJsExt:       true,
			Brief:         "一个JS自定义扩展",
			Official:      official,
			CmdMap:        CmdMapCls{},
			Source:        source,
			JSLoopVersion: versionID,
		}
	})
	// TODO(局部重载/更新同名插件): 这里是“谁观察了谁”的天然采集点。依赖方可能持有 find 返回的旧 ExtInfo，
	//   局部更新时需要整链重载；应在此记录“调用方脚本 -> 被查找扩展”的边，补充 @depends 未声明的耦合。
	//   subTODO(局部重载): 调用方脚本取自 jsExecutionContextFor(loop)；跨插件 storage 访问同理。
	_ = ext.Set("find", func(name string) *ExtInfo {
		return d.ExtFind(name, true)
	})
	_ = ext.Set("register", func(realExt *ExtInfo) (returnErr error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				returnErr = fmt.Errorf("注册扩展失败: %v", recovered)
			}
		}()
		if realExt == nil {
			return errors.New("注册扩展失败: 扩展为空")
		}

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
			if err := d.DurableDiscoverExtension(context.Background(), realExt); err != nil {
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
		d.ExtUpdateTime = time.Now().Unix()

		// 5. 触发 OnLoad 回调
		if realExt.OnLoad != nil {
			realExt.OnLoad()
		}
		return nil
	})
	_ = ext.Set("registerStringConfig", func(ei *ExtInfo, key string, defaultValue string, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "string",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("registerIntConfig", func(ei *ExtInfo, key string, defaultValue int64, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "int",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("registerBoolConfig", func(ei *ExtInfo, key string, defaultValue bool, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "bool",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("registerFloatConfig", func(ei *ExtInfo, key string, defaultValue float64, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "float",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("registerTemplateConfig", func(ei *ExtInfo, key string, defaultValue []string, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		config := &ConfigItem{
			Key:          key,
			Type:         "template",
			Group:        group,
			Value:        defaultValue,
			DefaultValue: defaultValue,
			Description:  description,
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("registerOptionConfig", func(ei *ExtInfo, key string, defaultValue string, option []string, description string, group string) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
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
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config)
	})
	_ = ext.Set("newConfigItem", func(ei *ExtInfo, key string, defaultValue interface{}, description string) *ConfigItem {
		if ei.dice == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		return d.ConfigManager.NewConfigItem(key, defaultValue, description)
	})
	_ = ext.Set("registerConfig", func(ei *ExtInfo, config ...*ConfigItem) error {
		if ei.dice == nil {
			return errors.New("请先完成此扩展的注册")
		}
		return d.ConfigManager.RegisterPluginConfig(ei.Name, config...)
	})
	_ = ext.Set("getConfig", func(ei *ExtInfo, key string) *ConfigItem {
		if ei == nil || ei.dice == nil {
			return nil
		}
		return d.compatibilityConfigItem(ei, key)
	})
	_ = ext.Set("getStringConfig", func(ei *ExtInfo, key string) (string, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return "", err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "string" {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(string)
		if !ok {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getIntConfig", func(ei *ExtInfo, key string) (int64, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return 0, err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "int" {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(int64)
		if !ok {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getBoolConfig", func(ei *ExtInfo, key string) (bool, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return false, err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "bool" {
			return false, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(bool)
		if !ok {
			return false, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getFloatConfig", func(ei *ExtInfo, key string) (float64, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return 0, err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "float" {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(float64)
		if !ok {
			return 0, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("getTemplateConfig", func(ei *ExtInfo, key string) ([]string, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return nil, err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "template" {
			return nil, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.([]string)
		if !ok {
			return nil, errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return append([]string(nil), value...), nil
	})
	_ = ext.Set("getOptionConfig", func(ei *ExtInfo, key string) (string, error) {
		cfg, err := d.compatibilityConfigItemWithError(ei, key)
		if err != nil {
			return "", err
		}
		if ei == nil || ei.dice == nil || cfg == nil || cfg.Type != "option" {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		value, ok := cfg.Value.(string)
		if !ok {
			return "", errors.New(configValueTypeMismatch(ei, key, cfg))
		}
		return value, nil
	})
	_ = ext.Set("unregisterConfig", func(ei *ExtInfo, key ...string) {
		if ei.dice == nil {
			return
		}
		d.ConfigManager.UnregisterConfig(ei.Name, key...)
	})
	_ = ext.Set("storageList", func(ei *ExtInfo) []string {
		keys, err := ei.StorageList()
		if err != nil {
			panic(err)
		}
		return keys
	})

	_ = ext.Set("registerTask", func(ei *ExtInfo, taskType string, value string, fn func(taskCtx JsScriptTaskCtx), key string, desc string, group string) *JsScriptTask {
		if ei.dice == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		owner := ei.dice
		owner.jsScriptCronMu.Lock()
		defer owner.jsScriptCronMu.Unlock()
		scriptCron := owner.JsScriptCron
		if scriptCron == nil {
			panic(errors.New("插件cron未成功初始化")) // 按理是不会发生的
		}

		task := JsScriptTask{cron: scriptCron, key: key, task: fn, lock: owner.JsScriptCronLock, logger: owner.Logger, dice: owner, ext: ei}
		expr := value
		if key != "" && taskType != "once" {
			if config := d.compatibilityConfigItem(ei, key); config != nil {
				expr = config.Value.(string)
				// Stop old task
				if config.task != nil {
					config.task.Off()
					ei.taskList = removeTaskFromList(ei.taskList, config.task)
				}
			}
		}

		switch taskType {
		case "cron":
			cronExpr, err := parseTaskCronExpr(expr)
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}

			entryID, err := scriptCron.AddFunc(cronExpr, func() {
				task.run()
			})
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = cronExpr
			expr = cronExpr // 保持配置值为规范化后的有效表达式
			task.entryID = &entryID
			scriptCron.Start()
			ei.dice.Logger.Infof("插件注册定时任务：cron=%s", cronExpr)
		case "daily":
			// 支持每天定时触发，24 小时表示
			cronExpr, err := parseTaskTime(expr)
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}

			entryID, err := scriptCron.AddFunc(cronExpr, func() {
				task.run()
			})
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = cronExpr
			task.entryID = &entryID
			ei.dice.Logger.Infof("插件注册定时任务：daily=%s", expr)
			scriptCron.Start()
		case "once":
			onceAt, normalizedExpr, err := parseTaskOnceExpr(expr)
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.onceAt = onceAt
			expr = normalizedExpr // 保存为绝对执行时间戳，避免重载后延迟重复计算
			if !task.on() {
				panic("插件注册定时任务失败：一次任务注册失败")
			}
			ei.dice.Logger.Infof("插件注册定时任务：once=%s", expr)
		default:
			panic(fmt.Sprintf("错误的任务类型：%s，当前仅支持 cron|daily|once", taskType))
		}

		if key != "" && taskType != "once" {
			config := d.compatibilityConfigItem(ei, key)

			switch taskType {
			case "cron":
				config = &ConfigItem{
					Key:          key,
					Type:         "task:cron",
					Group:        group,
					Value:        expr,
					DefaultValue: value,
					Description:  desc,
					task:         &task,
				}
			case "daily":
				config = &ConfigItem{
					Key:          key,
					Type:         "task:daily",
					Group:        group,
					Value:        expr,
					DefaultValue: value,
					Description:  desc,
					task:         &task,
				}
			}
			if err := d.ConfigManager.RegisterPluginConfig(ei.Name, config); err != nil {
				panic("插件注册定时任务配置失败：" + err.Error())
			}
		}

		if ei.taskList == nil {
			ei.taskList = make([]*JsScriptTask, 0)
		}
		ei.taskList = append(ei.taskList, &task)

		return &task
	})
	_ = ext.Set("removeTask", func(ei *ExtInfo, taskType string, key string) int {
		if ei.dice == nil {
			panic(errors.New("请先完成此扩展的注册"))
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

		cm := d.ConfigManager
		cm.lock.RLock()
		pluginConfig := cm.Plugins[ei.Name]
		if pluginConfig != nil {
			for cfgKey, cfgItem := range pluginConfig.Configs {
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
		cm.lock.RUnlock()

		for task := range taskSet {
			_ = task.Off()
		}

		if len(taskSet) > 0 {
			filtered := make([]*JsScriptTask, 0, len(ei.taskList))
			for _, task := range ei.taskList {
				if _, hit := taskSet[task]; !hit {
					filtered = append(filtered, task)
				}
			}
			ei.taskList = filtered
		}

		if len(configKeySet) > 0 {
			keys := make([]string, 0, len(configKeySet))
			for cfgKey := range configKeySet {
				keys = append(keys, cfgKey)
			}
			d.ConfigManager.UnregisterConfig(ei.Name, keys...)
		}

		return len(taskSet)
	})
	_ = ext.Set("listTasks", func(ei *ExtInfo) []*JsScriptTaskInfo {
		if ei.dice == nil {
			panic(errors.New("请先完成此扩展的注册"))
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
