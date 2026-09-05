package dice

import (
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
			(&d.Config).BanList.SaveChanged(d)
		}},
		{name: "addTrust", value: func(ctx *MsgContext, id string, place string, reason string) {
			(&d.Config).BanList.SetTrustByID(id, place, reason)
			(&d.Config).BanList.SaveChanged(d)
		}},
		{name: "remove", value: func(ctx *MsgContext, id string) {
			if _, ok := (&d.Config).BanList.GetByID(id); ok {
				(&d.Config).BanList.DeleteByID(d, id)
			}
		}},
		{name: "getList", value: func() []BanListInfoItem {
			var list []BanListInfoItem
			(&d.Config).BanList.Map.Range(func(_ string, value *BanListInfoItem) bool {
				list = append(list, *value)
				return true
			})
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
	if err := setJSHostObject(coc, "newRule", func() *CocRuleInfo { return &CocRuleInfo{} }); err != nil {
		return err
	}
	if err := setJSHostObject(coc, "newRuleCheckResult", func() *CocRuleCheckRet { return &CocRuleCheckRet{} }); err != nil {
		return err
	}
	if err := setJSHostObject(coc, "registerRule", func(rule *CocRuleInfo) bool { return d.CocExtraRulesAdd(rule) }); err != nil {
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
			src := d.ImSession.EndPoints
			dst := make([]*EndPointInfo, len(src))
			copy(dst, src)
			return dst
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
	_ = ext.Set("find", func(name string) *ExtInfo {
		return d.ExtFind(name, true)
	})
	_ = ext.Set("register", func(realExt *ExtInfo) {
		defer func() {
			// 增加recover, 以免在scripts目录中存在名字冲突扩展时导致启动崩溃
			if e := recover(); e != nil {
				d.Logger.Error(e)
			}
		}()

		if strings.ToLower(realExt.Name) == "help" || strings.ToLower(realExt.Name) == "all" {
			panic("help 和 all 为保留关键字，无法作为插件名使用")
		}

		extName := realExt.Name
		if realExt.Source == nil {
			realExt.Source = jsContextScript(jsExecutionContextFor(loop))
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
		d.JsExtRegistry.Store(extName, realExt)

		// 3. 设置真实 ExtInfo 的属性
		realExt.dice = d
		realExt.JSLoopVersion = versionID

		// 4. 更新全局扩展变更时间戳
		d.ExtUpdateTime = time.Now().Unix()

		// 5. 触发 OnLoad 回调
		if realExt.OnLoad != nil {
			realExt.OnLoad()
		}
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config)
		return nil
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
		d.ConfigManager.RegisterPluginConfig(ei.Name, config...)
		return nil
	})
	_ = ext.Set("getConfig", func(ei *ExtInfo, key string) *ConfigItem {
		if ei.dice == nil {
			return nil
		}
		return d.ConfigManager.getConfig(ei.Name, key)
	})
	_ = ext.Set("getStringConfig", func(ei *ExtInfo, key string) string {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "string" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(string)
	})
	_ = ext.Set("getIntConfig", func(ei *ExtInfo, key string) int64 {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "int" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(int64)
	})
	_ = ext.Set("getBoolConfig", func(ei *ExtInfo, key string) bool {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "bool" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(bool)
	})
	_ = ext.Set("getFloatConfig", func(ei *ExtInfo, key string) float64 {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "float" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(float64)
	})
	_ = ext.Set("getTemplateConfig", func(ei *ExtInfo, key string) []string {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "template" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.([]string)
	})
	_ = ext.Set("getOptionConfig", func(ei *ExtInfo, key string) string {
		cfg := d.ConfigManager.getConfig(ei.Name, key)
		if ei.dice == nil || cfg == nil || cfg.Type != "option" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(string)
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
		scriptCron := ei.dice.JsScriptCron
		if scriptCron == nil {
			panic(errors.New("插件cron未成功初始化")) // 按理是不会发生的
		}

		task := JsScriptTask{cron: scriptCron, key: key, task: fn, lock: ei.dice.JsScriptCronLock, logger: ei.dice.Logger, dice: ei.dice, ext: ei}
		expr := value
		if key != "" && taskType != "once" {
			if config := d.ConfigManager.getConfig(ei.Name, key); config != nil {
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
		case "once":
			onceAt, normalizedExpr, err := parseTaskOnceExpr(expr)
			if err != nil {
				panic("插件注册定时任务失败：" + err.Error())
			}
			task.taskType = taskType
			task.rawValue = expr
			task.onceAt = onceAt
			expr = normalizedExpr // 保存为绝对执行时间戳，避免重载后延迟重复计算
			if !task.On() {
				panic("插件注册定时任务失败：一次任务注册失败")
			}
			ei.dice.Logger.Infof("插件注册定时任务：once=%s", expr)
		default:
			panic(fmt.Sprintf("错误的任务类型：%s，当前仅支持 cron|daily|once", taskType))
		}

		if key != "" && taskType != "once" {
			config := d.ConfigManager.getConfig(ei.Name, key)

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
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
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
	return nil
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
	if !d.GameSystemTemplateAddEx(template, true) {
		return errors.New("已存在同名模板")
	}
	return nil
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
