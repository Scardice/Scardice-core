package dice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	esbuild "github.com/evanw/esbuild/pkg/api"
	fetch "github.com/fy0/gojax/fetch"
	"github.com/golang-module/carbon"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"gopkg.in/elazarl/goproxy.v1"

	"Scardice-core/dice/jsengine"
	_ "Scardice-core/dice/jsengine/quickjs"
	"Scardice-core/static"
	"Scardice-core/utils/crypto"

	sealcrypto "Scardice-core/utils/plugin/crypto"
	sealws "Scardice-core/utils/plugin/websocket"
)

var jsTaskCronParser = cron.NewParser(
	cron.SecondOptional |
		cron.Minute |
		cron.Hour |
		cron.Dom |
		cron.Month |
		cron.Dow |
		cron.Descriptor,
)

var (
	// OfficialModPublicKey 官方 Mod 公钥
	OfficialModPublicKey = ``

	signRe = regexp.MustCompile(`^// sign\s+([^\r\n]+)?[\r\n]+$`)
)

var taskTimeRe = regexp.MustCompile(`^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$`)

type PrinterFunc struct {
	d        *Dice
	isRecord bool
	recorder []string
}

func (p *PrinterFunc) doRecord(_ string, s string) {
	if p.isRecord {
		p.recorder = append(p.recorder, s)
	}
}

func (p *PrinterFunc) RecordStart() { p.recorder = []string{}; p.isRecord = true }
func (p *PrinterFunc) RecordEnd() []string {
	r := p.recorder
	p.recorder = []string{}
	return r
}

func (p *PrinterFunc) Log(s string) {
	p.doRecord("log", s)
	p.d.Logger.Info(s)
}

func (p *PrinterFunc) Warn(s string) { p.doRecord("warn", s); p.d.Logger.Warn(s) }

// Error 表示插件业务侧的错误输出（例如 console.error），不打印 Go 运行栈。
func (p *PrinterFunc) Error(s string) { p.doRecord("error", s); p.d.Logger.Warn("[JS] " + s) }

// InternalError 表示引擎内部异常，保留 error 级别与调用栈。
func (p *PrinterFunc) InternalError(s string) { p.doRecord("error", s); p.d.Logger.Error(s) }

func (d *Dice) JsInit() {
	// 读取官方 Mod 公钥
	if pub, err := static.Scripts.ReadFile("scripts/seal_mod.public.pem"); err == nil && len(pub) > 0 {
		OfficialModPublicKey = string(pub)
	}
	engineName := strings.ToLower(strings.TrimSpace(d.Config.JsEngine))
	if engineName == "" {
		engineName = "goja"
		d.Config.JsEngine = engineName
	}
	d.JsEngineEffective = ""
	d.JsEngineFallback = ""
	if engineName == "quickjs" {
		d.Logger.Infof("JS引擎: quickjs（迁移阶段）")
		if err := d.jsInitQuickJSCore(); err != nil {
			d.JsEngineEffective = "goja"
			d.JsEngineFallback = err.Error()
			d.Logger.Warnf("QuickJS核心链路未就绪，回退Goja执行链路: %v", err)
			d.jsInitGojaCore()
		}
		return
	}
	d.JsEngineEffective = "goja"
	d.jsInitGojaCore()
}

func (d *Dice) jsInitGojaCore() {
	// 允许在 JsEnable=false 的启动状态下通过 API 重启 JS：
	// 此时 ExtLoopManager 尚未初始化，需要在这里补齐。
	if d.ExtLoopManager == nil {
		d.ExtLoopManager = NewJsLoopManager()
	}
	// 清理目前的js相关
	d.jsClear()

	// 重建js vm
	reg := new(require.Registry)

	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false),
		eventloop.WithRegistry(reg),
		eventloop.WithDebugLog(true),
		eventloop.WithLogger(d.Logger))
	_ = fetch.Enable(loop, goproxy.NewProxyHttpServer())
	versionID := d.ExtLoopManager.SetLoop(loop)

	printer := &PrinterFunc{d, false, []string{}}
	d.JsPrinter = printer
	reg.RegisterNativeModule("console", console.RequireWithPrinter(printer))
	reg.RegisterNativeModule("crypto", sealcrypto.Require)

	d.JsScriptCron = cron.New(cron.WithParser(jsTaskCronParser))
	d.JsScriptCronLock = &sync.Mutex{}
	d.JsScriptCron.Start()
	// 单独给WebSocket一个Logger
	sealws.SetLogger(d.Logger)
	// 关闭之前的所有WebSocket
	sealws.GlobalConnManager.CloseAll()
	// 初始化
	loop.Run(func(vm *goja.Runtime) {
		vm.SetFieldNameMapper(goja.TagFieldNameMapper("jsbind", true))

		// console 模块
		console.Enable(vm)

		sealws.Enable(vm, loop)
		// require 模块
		reg.Enable(vm)
		sealcrypto.Enable(vm)

		seal := vm.NewObject()

		vars := vm.NewObject()
		_ = seal.Set("vars", vars)
		_ = vars.Set("intGet", VarGetValueInt64)
		_ = vars.Set("intSet", VarSetValueInt64)
		_ = vars.Set("strGet", VarGetValueStr)
		_ = vars.Set("strSet", VarSetValueStr)
		_ = vars.Set("computedSet", VarSetValueComputed)
		_ = vars.Set("computedGet", VarGetValueComputed)

		ban := vm.NewObject()
		_ = seal.Set("ban", ban)
		_ = ban.Set("addBan", func(ctx *MsgContext, id string, place string, reason string) {
			(&d.Config).BanList.AddScoreBase(id, d.Config.BanList.ThresholdBan, place, reason, ctx)
			(&d.Config).BanList.SaveChanged(d)
		})
		_ = ban.Set("addTrust", func(ctx *MsgContext, id string, place string, reason string) {
			(&d.Config).BanList.SetTrustByID(id, place, reason)
			(&d.Config).BanList.SaveChanged(d)
		})
		_ = ban.Set("remove", func(ctx *MsgContext, id string) {
			_, ok := (&d.Config).BanList.GetByID(id)
			if !ok {
				return
			}
			(&d.Config).BanList.DeleteByID(d, id)
		})
		_ = ban.Set("getList", func() []BanListInfoItem {
			var list []BanListInfoItem
			(&d.Config).BanList.Map.Range(func(key string, value *BanListInfoItem) bool {
				list = append(list, *value)
				return true
			})
			return list
		})
		_ = ban.Set("getUser", func(id string) *BanListInfoItem {
			i, ok := (&d.Config).BanList.GetByID(id)
			if !ok {
				return nil
			}
			cp := *i
			return &cp
		})

		ext := vm.NewObject()
		_ = seal.Set("ext", ext)
		_ = ext.Set("newCmdItemInfo", func() *CmdItemInfo {
			return &CmdItemInfo{IsJsSolveFunc: true, JSLoopVersion: versionID}
		})
		_ = ext.Set("newCmdExecuteResult", func(solved bool) CmdExecuteResult {
			return CmdExecuteResult{
				Matched: true,
				Solved:  solved,
			}
		})
		_ = ext.Set("new", func(name, author, version string) *ExtInfo {
			var official bool
			if d.JsLoadingScript != nil {
				official = d.JsLoadingScript.Official
			}
			return &ExtInfo{
				Name: name, Author: author, Version: version,
				GetDescText:   GetExtensionDesc,
				AutoActive:    true,
				IsJsExt:       true,
				Brief:         "一个JS自定义扩展",
				Official:      official,
				CmdMap:        CmdMapCls{},
				Source:        d.JsLoadingScript,
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
					CmdMap:        CmdMapCls{},
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
		_ = ext.Set("registerStringConfig", func(ei *ExtInfo, key string, defaultValue string, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "string",
				Value:        defaultValue,
				DefaultValue: defaultValue,
				Description:  description,
			}
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			return nil
		})
		_ = ext.Set("registerIntConfig", func(ei *ExtInfo, key string, defaultValue int64, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "int",
				Value:        defaultValue,
				DefaultValue: defaultValue,
				Description:  description,
			}
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			return nil
		})
		_ = ext.Set("registerBoolConfig", func(ei *ExtInfo, key string, defaultValue bool, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "bool",
				Value:        defaultValue,
				DefaultValue: defaultValue,
				Description:  description,
			}
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			return nil
		})
		_ = ext.Set("registerFloatConfig", func(ei *ExtInfo, key string, defaultValue float64, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "float",
				Value:        defaultValue,
				DefaultValue: defaultValue,
				Description:  description,
			}
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			return nil
		})
		_ = ext.Set("registerTemplateConfig", func(ei *ExtInfo, key string, defaultValue []string, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "template",
				Value:        defaultValue,
				DefaultValue: defaultValue,
				Description:  description,
			}
			d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			return nil
		})
		_ = ext.Set("registerOptionConfig", func(ei *ExtInfo, key string, defaultValue string, option []string, description string) error {
			if ei.dice == nil {
				return errors.New("请先完成此扩展的注册")
			}
			config := &ConfigItem{
				Key:          key,
				Type:         "option",
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
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "string" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.(string)
		})
		_ = ext.Set("getIntConfig", func(ei *ExtInfo, key string) int64 {
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "int" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.(int64)
		})
		_ = ext.Set("getBoolConfig", func(ei *ExtInfo, key string) bool {
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "bool" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.(bool)
		})
		_ = ext.Set("getFloatConfig", func(ei *ExtInfo, key string) float64 {
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "float" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.(float64)
		})
		_ = ext.Set("getTemplateConfig", func(ei *ExtInfo, key string) []string {
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "template" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.([]string)
		})
		_ = ext.Set("getOptionConfig", func(ei *ExtInfo, key string) string {
			if ei.dice == nil || d.ConfigManager.getConfig(ei.Name, key).Type != "option" {
				panic("配置不存在或类型不匹配")
			}
			return d.ConfigManager.getConfig(ei.Name, key).Value.(string)
		})
		_ = ext.Set("unregisterConfig", func(ei *ExtInfo, key ...string) {
			if ei.dice == nil {
				return
			}
			d.ConfigManager.UnregisterConfig(ei.Name, key...)
		})

		_ = ext.Set("registerTask", func(ei *ExtInfo, taskType string, value string, fn func(taskCtx JsScriptTaskCtx), key string, desc string) *JsScriptTask {
			if ei.dice == nil {
				d.Logger.Errorf("插件注册定时任务失败：请先完成此扩展的注册")
				return nil
			}
			scriptCron := ei.dice.ensureJsScriptCron()

			task := JsScriptTask{cron: scriptCron, key: key, task: fn, lock: ei.dice.JsScriptCronLock, logger: ei.dice.Logger}
			expr := value
			if key != "" {
				if config := d.ConfigManager.getConfig(ei.Name, key); config != nil {
					expr = config.Value.(string)
					// Stop old task
					if config.task != nil {
						config.task.Off()
					}
				}
			}

			switch taskType {
			case "cron":
				entryID, err := scriptCron.AddFunc(expr, func() {
					task.run()
				})
				if err != nil {
					d.Logger.Errorf("插件注册定时任务失败：%v", err)
					return nil
				}
				task.taskType = taskType
				task.rawValue = expr
				task.cronExpr = expr
				task.entryID = &entryID
				ei.dice.Logger.Infof("插件注册定时任务：cron=%s", expr)
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
					d.Logger.Errorf("插件注册定时任务失败：%v", err)
					return nil
				}
				task.taskType = taskType
				task.rawValue = expr
				task.cronExpr = cronExpr
				task.entryID = &entryID
				ei.dice.Logger.Infof("插件注册定时任务：daily=%s", expr)
			default:
				d.Logger.Errorf("插件注册定时任务失败：错误的任务类型：%s，当前仅支持 cron|daily", taskType)
				return nil
			}

			if key != "" {
				config := d.ConfigManager.getConfig(ei.Name, key)

				switch taskType {
				case "cron":
					config = &ConfigItem{
						Key:          key,
						Type:         "task:cron",
						Value:        expr,
						DefaultValue: value,
						Description:  desc,
						task:         &task,
					}
				case "daily":
					config = &ConfigItem{
						Key:          key,
						Type:         "task:daily",
						Value:        expr,
						DefaultValue: value,
						Description:  desc,
						task:         &task,
					}
				}
				d.ConfigManager.RegisterPluginConfig(ei.Name, config)
			}

			if key == "" {
				// 如果不提供 key，手动避免 task 失去引用
				if ei.taskList == nil {
					ei.taskList = make([]*JsScriptTask, 0)
					ei.taskList = append(ei.taskList, &task)
				} else {
					ei.taskList = append(ei.taskList, &task)
				}
			}

			return &task
		})

		// COC规则自定义
		coc := vm.NewObject()
		_ = coc.Set("newRule", func() *CocRuleInfo {
			return &CocRuleInfo{}
		})
		_ = coc.Set("newRuleCheckResult", func() *CocRuleCheckRet {
			return &CocRuleCheckRet{}
		})
		_ = coc.Set("registerRule", func(rule *CocRuleInfo) bool {
			return d.CocExtraRulesAdd(rule)
		})
		_ = seal.Set("coc", coc)

		deck := vm.NewObject()
		_ = deck.Set("draw", func(ctx *MsgContext, deckName string, isShuffle bool) map[string]interface{} {
			exists, result, err := deckDraw(ctx, deckName, isShuffle)
			var errText string
			if err != nil {
				errText = err.Error()
			}
			return map[string]interface{}{
				"exists": exists,
				"err":    errText,
				"result": result,
			}
		})
		_ = deck.Set("reload", func() {
			DeckReload(d)
		})
		_ = seal.Set("deck", deck)

		_ = seal.Set("replyGroup", ReplyGroup)
		_ = seal.Set("replyPerson", ReplyPerson)
		_ = seal.Set("replyToSender", ReplyToSender)
		_ = seal.Set("memberBan", MemberBan)
		_ = seal.Set("memberKick", MemberKick)
		_ = seal.Set("format", DiceFormat)
		_ = seal.Set("formatTmpl", DiceFormatTmpl)
		_ = seal.Set("getCtxProxyFirst", GetCtxProxyFirst)

		// 1.2新增
		_ = seal.Set("newMessage", func() *Message {
			return &Message{}
		})
		_ = seal.Set("createTempCtx", CreateTempCtx)
		_ = seal.Set("applyPlayerGroupCardByTemplate", func(ctx *MsgContext, tmpl string) string {
			if tmpl != "" {
				ctx.Player.AutoSetNameTemplate = tmpl
			}
			if ctx.Player.AutoSetNameTemplate != "" {
				text, _ := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
				return text
			}
			return ""
		})
		gameSystem := vm.NewObject()
		_ = gameSystem.Set("newTemplate", func(data string) error {
			tmpl, err := loadGameSystemTemplateFromData([]byte(data), "json")
			if err != nil {
				return errors.New("解析失败:" + err.Error())
			}
			ret := d.GameSystemTemplateAddEx(tmpl, true)
			if !ret {
				return errors.New("已存在同名模板")
			}
			return nil
		})
		_ = gameSystem.Set("newTemplateByYaml", func(data string) error {
			tmpl, err := loadGameSystemTemplateFromData([]byte(data), "yaml")
			if err != nil {
				return errors.New("解析失败:" + err.Error())
			}
			ret := d.GameSystemTemplateAddEx(tmpl, true)
			if !ret {
				return errors.New("已存在同名模板")
			}
			return nil
		})
		_ = seal.Set("gameSystem", gameSystem)
		_ = seal.Set("getCtxProxyAtPos", GetCtxProxyAtPos)
		_ = seal.Set("getVersion", func() map[string]interface{} {
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
		})
		_ = seal.Set("getEndPoints", func() []*EndPointInfo {
			return d.ImSession.EndPoints
		})

		_ = vm.Set("atob", func(s string) (string, error) {
			// Remove data URI scheme and any whitespace from the string.
			s = strings.ReplaceAll(s, "data:text/plain;base64,", "")
			s = strings.ReplaceAll(s, " ", "")

			// Decode the base64-encoded string.
			b, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return "", errors.New("atob: 不合法的base64字串")
			}
			return string(b), nil
		})
		_ = vm.Set("btoa", func(s string) string {
			// 编码
			return base64.StdEncoding.EncodeToString([]byte(s))
		})
		// 1.2新增结束
		_ = seal.Set("setPlayerGroupCard", SetPlayerGroupCardByTemplate)
		_ = seal.Set("base64ToImage", Base64ToImageFunc())

		// Note: Szzrain 暴露dice对象给js会导致js可以调用dice的所有Export的方法
		// 这是不安全的, 所有需要用到dice实例的函数都可以以传入ctx作为替代
		// _ = seal.Set("inst", d)
		_ = vm.Set("__dirname", "")
		_ = vm.Set("seal", seal)

		// Note(Szzrain): 不要修改原型链, 会导致一些奇怪的问题，比如无法使用某些 TS 库
		//		_, _ = vm.RunString(`
		// let e = seal.ext.new('_', '', '');
		// e.__proto__.storageSet = function(k, v) {
		//  try {
		//    // 这里goja会强行抛出异常，等于是将返回error的函数转写成throw形式
		//    this.storageSetRaw(k, v)
		//  } catch (error) {
		//    throw error;
		//  }
		// }
		// e.__proto__.storageGet = function(k, v) {
		//  try {
		//    return this.storageGetRaw(k, v);
		//  } catch (error) {
		//    if (error.value.toString() !== 'not found') {
		//      throw error;
		//    }
		//  }
		// }
		// `)
		_, _ = vm.RunString(`Object.freeze(seal);Object.freeze(seal.deck);Object.freeze(seal.coc);Object.freeze(seal.ext);Object.freeze(seal.vars);`)
	})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				d.Logger.Errorf("JS核心执行异常: %v 堆栈: %v", r, string(debug.Stack()))
			}
		}()
		loop.StartInForeground()
	}()
	// loop.Start()
	(&d.Config).JsEnable = true
	d.Logger.Info("已加载JS环境，当前JS引擎: goja")
	d.MarkModified()
	d.Save(false)
}

func (d *Dice) ensureJsScriptCron() *cron.Cron {
	if d.JsScriptCron == nil {
		d.JsScriptCron = cron.New(cron.WithParser(jsTaskCronParser))
		d.JsScriptCron.Start()
	}
	if d.JsScriptCronLock == nil {
		d.JsScriptCronLock = &sync.Mutex{}
	}
	return d.JsScriptCron
}

func (d *Dice) jsInitQuickJSCore() error {
	d.jsClear()
	// QuickJS 路径同样需要控制台记录器，供 WebUI /js/get_record 轮询读取。
	d.JsPrinter = &PrinterFunc{d: d, isRecord: false, recorder: []string{}}

	engine, err := jsengine.New(jsengine.Config{
		Name:      jsengine.EngineQuickJS,
		ModuleDir: filepath.Join(d.BaseConfig.DataDir, "scripts"),
	})
	if err != nil {
		return err
	}
	if err = engine.Init(context.Background(), jsengine.Config{
		Name:      jsengine.EngineQuickJS,
		ModuleDir: filepath.Join(d.BaseConfig.DataDir, "scripts"),
	}); err != nil {
		return err
	}

	// 先注册最核心的插件生命周期 API，后续逐步补齐其余能力。
	if err = d.jsRegisterQuickJSHostAPIs(engine); err != nil {
		_ = engine.Dispose()
		return err
	}

	d.ScriptEngine = engine
	d.JsEngineEffective = "quickjs"
	d.JsEngineFallback = ""
	(&d.Config).JsEnable = true
	d.Logger.Info("已加载JS环境，当前JS引擎: quickjs")
	d.MarkModified()
	d.Save(false)
	return nil
}

func (d *Dice) jsRegisterQuickJSHostAPIs(engine jsengine.Engine) error {
	if engine == nil {
		return errors.New("QuickJS 引擎实例为空")
	}
	register := func(name string, handler any) error {
		return engine.RegisterHostAPI(jsengine.HostAPI{Name: name, Handler: handler})
	}
	formatConsoleArgs := func(args ...any) string {
		ss := make([]string, 0, len(args))
		for _, a := range args {
			ss = append(ss, fmt.Sprint(a))
		}
		return strings.Join(ss, " ")
	}
	logConsole := func(args ...any) {
		if d.JsPrinter != nil {
			d.JsPrinter.Log(formatConsoleArgs(args...))
		}
	}
	warnConsole := func(args ...any) {
		if d.JsPrinter != nil {
			d.JsPrinter.Warn(formatConsoleArgs(args...))
		}
	}
	errorConsole := func(args ...any) {
		if d.JsPrinter != nil {
			d.JsPrinter.Error(formatConsoleArgs(args...))
		}
	}
	if err := register("console.log", logConsole); err != nil {
		return err
	}
	if err := register("console.info", logConsole); err != nil {
		return err
	}
	if err := register("console.debug", logConsole); err != nil {
		return err
	}
	if err := register("console.warn", warnConsole); err != nil {
		return err
	}
	if err := register("console.error", errorConsole); err != nil {
		return err
	}
	if err := register("console.dir", func(v any) {
		logConsole(v)
	}); err != nil {
		return err
	}
	if err := register("console.assert", func(cond bool, args ...any) {
		if cond {
			return
		}
		if len(args) == 0 {
			errorConsole("Assertion failed")
			return
		}
		errorConsole(append([]any{"Assertion failed:"}, args...)...)
	}); err != nil {
		return err
	}
	consoleTimers := map[string]time.Time{}
	consoleTimersLock := sync.Mutex{}
	if err := register("console.time", func(label string) {
		if strings.TrimSpace(label) == "" {
			label = "default"
		}
		consoleTimersLock.Lock()
		consoleTimers[label] = time.Now()
		consoleTimersLock.Unlock()
	}); err != nil {
		return err
	}
	if err := register("console.timeLog", func(label string, args ...any) {
		if strings.TrimSpace(label) == "" {
			label = "default"
		}
		consoleTimersLock.Lock()
		start, ok := consoleTimers[label]
		consoleTimersLock.Unlock()
		if !ok {
			warnConsole(fmt.Sprintf("Timer '%s' does not exist", label))
			return
		}
		prefix := fmt.Sprintf("%s: %v", label, time.Since(start))
		if len(args) == 0 {
			logConsole(prefix)
			return
		}
		logConsole(append([]any{prefix}, args...)...)
	}); err != nil {
		return err
	}
	if err := register("console.timeEnd", func(label string) {
		if strings.TrimSpace(label) == "" {
			label = "default"
		}
		consoleTimersLock.Lock()
		start, ok := consoleTimers[label]
		if ok {
			delete(consoleTimers, label)
		}
		consoleTimersLock.Unlock()
		if !ok {
			warnConsole(fmt.Sprintf("Timer '%s' does not exist", label))
			return
		}
		logConsole(fmt.Sprintf("%s: %v", label, time.Since(start)))
	}); err != nil {
		return err
	}
	if err := register("console.clear", func() {
		logConsole("[console] clear")
	}); err != nil {
		return err
	}
	if err := register("console.trace", func(args ...any) {
		errorConsole(append([]any{"Trace:"}, args...)...)
	}); err != nil {
		return err
	}

	// vars
	if err := register("seal.vars.intGet", VarGetValueInt64); err != nil {
		return err
	}
	if err := register("seal.vars.intSet", VarSetValueInt64); err != nil {
		return err
	}
	if err := register("seal.vars.strGet", VarGetValueStr); err != nil {
		return err
	}
	if err := register("seal.vars.strSet", VarSetValueStr); err != nil {
		return err
	}
	if err := register("seal.vars.computedSet", VarSetValueComputed); err != nil {
		return err
	}
	if err := register("seal.vars.computedGet", VarGetValueComputed); err != nil {
		return err
	}

	// ban
	if err := register("seal.ban.addBan", func(ctx *MsgContext, id string, place string, reason string) {
		(&d.Config).BanList.AddScoreBase(id, d.Config.BanList.ThresholdBan, place, reason, ctx)
		(&d.Config).BanList.SaveChanged(d)
	}); err != nil {
		return err
	}
	if err := register("seal.ban.addTrust", func(ctx *MsgContext, id string, place string, reason string) {
		(&d.Config).BanList.SetTrustByID(id, place, reason)
		(&d.Config).BanList.SaveChanged(d)
	}); err != nil {
		return err
	}
	if err := register("seal.ban.remove", func(_ *MsgContext, id string) {
		_, ok := (&d.Config).BanList.GetByID(id)
		if !ok {
			return
		}
		(&d.Config).BanList.DeleteByID(d, id)
	}); err != nil {
		return err
	}
	if err := register("seal.ban.getList", func() []BanListInfoItem {
		var list []BanListInfoItem
		(&d.Config).BanList.Map.Range(func(_ string, value *BanListInfoItem) bool {
			list = append(list, *value)
			return true
		})
		return list
	}); err != nil {
		return err
	}
	if err := register("seal.ban.getUser", func(id string) *BanListInfoItem {
		i, ok := (&d.Config).BanList.GetByID(id)
		if !ok {
			return nil
		}
		cp := *i
		return &cp
	}); err != nil {
		return err
	}

	// ext
	if err := register("seal.ext.newCmdItemInfo", func() string {
		return cmdItemInfoToJSONString(&CmdItemInfo{IsJsSolveFunc: true})
	}); err != nil {
		return err
	}
	if err := register("seal.ext.newCmdExecuteResult", func(solved bool) string {
		b, _ := json.Marshal(map[string]any{
			"matched": true,
			"solved":  solved,
		})
		return string(b)
	}); err != nil {
		return err
	}

	// 插件创建入口
	if err := register("seal.ext.new", func(name, author, version string) string {
		var official bool
		if d.JsLoadingScript != nil {
			official = d.JsLoadingScript.Official
		}
		ext := &ExtInfo{
			Name: name, Author: author, Version: version,
			GetDescText: GetExtensionDesc,
			AutoActive:  true,
			IsJsExt:     true,
			Brief:       "一个JS自定义扩展",
			Official:    official,
			CmdMap:      CmdMapCls{},
			Source:      d.JsLoadingScript,
		}
		return extInfoToJSONString(ext)
	}); err != nil {
		return err
	}

	// 插件查找入口
	if err := register("seal.ext.find", func(name string) string {
		ext := d.ExtFind(name, true)
		return extInfoToJSONString(ext)
	}); err != nil {
		return err
	}

	// 插件注册入口
	if err := register("seal.ext.register", func(realExtAny any) {
		defer func() {
			// 保持与 Goja 路径一致，避免重复插件名导致进程崩溃。
			if e := recover(); e != nil {
				d.Logger.Error(e)
			}
		}()
		realExt, err := convertJsExtInfo(d, realExtAny)
		if err != nil {
			d.Logger.Errorf("QuickJS 插件注册参数错误: %v", err)
			return
		}
		if realExt == nil {
			return
		}
		if strings.ToLower(realExt.Name) == "help" || strings.ToLower(realExt.Name) == "all" {
			panic("help 和 all 为保留关键字，无法作为插件名使用")
		}

		extName := realExt.Name
		var wrapper *ExtInfo
		if existingWrapper, ok := d.ExtRegistry.Load(extName); ok && existingWrapper != nil && existingWrapper.IsWrapper {
			wrapper = existingWrapper
			wrapper.Author = realExt.Author
			wrapper.Version = realExt.Version
			wrapper.IsDeleted = false
			wrapper.dice = d
		} else {
			wrapper = &ExtInfo{
				Name:        extName,
				Author:      realExt.Author,
				Version:     realExt.Version,
				IsWrapper:   true,
				TargetName:  extName,
				IsDeleted:   false,
				GetDescText: GetExtensionDesc,
				AutoActive:  realExt.AutoActive,
				IsJsExt:     true,
				Brief:       "一个JS自定义扩展",
				Official:    realExt.Official,
				CmdMap:      CmdMapCls{},
				dice:        d,
			}
			d.RegisterExtension(wrapper)
		}

		if d.JsExtRegistry == nil {
			d.JsExtRegistry = new(SyncMap[string, *ExtInfo])
		}
		if realExt.Source == nil {
			realExt.Source = d.JsLoadingScript
		}
		d.JsExtRegistry.Store(extName, realExt)
		// d.Logger.Infof("QuickJS 插件注册完成: %s，初始命令数=%d", extName, len(realExt.CmdMap))
		// 无意义日志
		realExt.dice = d
		d.ExtUpdateTime = time.Now().Unix()
		if realExt.OnLoad != nil {
			realExt.OnLoad()
		}
	}); err != nil {
		return err
	}
	// QuickJS 专用：注册后增量同步单条命令，解决 cmdMap 在 register 之后赋值时命令数为 0 的问题。
	if err := register("seal.ext._syncCmd", func(extName string, cmdName string, rawCmdAny any) {
		extName = strings.TrimSpace(extName)
		cmdName = strings.TrimSpace(cmdName)
		if extName == "" || cmdName == "" {
			return
		}
		toStringAnyMap := func(v any) map[string]any {
			if v == nil {
				return nil
			}
			if m, ok := v.(map[string]any); ok {
				return m
			}
			rv := reflect.ValueOf(v)
			if rv.IsValid() {
				method := rv.MethodByName("Into")
				if method.IsValid() {
					arg := map[string]any{}
					out := method.Call([]reflect.Value{reflect.ValueOf(&arg)})
					if len(out) == 1 && out[0].IsNil() {
						return arg
					}
				}
			}
			return nil
		}

		var jsExt *ExtInfo
		if d.JsExtRegistry != nil {
			if ext, ok := d.JsExtRegistry.Load(extName); ok {
				jsExt = ext
				if jsExt.CmdMap == nil {
					jsExt.CmdMap = CmdMapCls{}
				}
			}
		}
		wrapper, _ := d.ExtRegistry.Load(extName)
		if wrapper != nil && wrapper.CmdMap == nil {
			wrapper.CmdMap = CmdMapCls{}
		}

		rawCmd := toStringAnyMap(rawCmdAny)
		if rawCmd == nil {
			if jsExt != nil {
				delete(jsExt.CmdMap, cmdName)
			}
			if wrapper != nil {
				delete(wrapper.CmdMap, cmdName)
			}
			d.ExtUpdateTime = time.Now().Unix()
			return
		}

		cmdInfo := buildQuickJSCmdInfo(d, extName, cmdName, rawCmd)
		if jsExt != nil {
			jsExt.CmdMap[cmdName] = cmdInfo
		}
		if wrapper != nil {
			wrapper.CmdMap[cmdName] = cmdInfo
		}
		d.ExtUpdateTime = time.Now().Unix()
	}); err != nil {
		return err
	}
	resolveExtName := func(ei *ExtInfo) (string, error) {
		if ei != nil && strings.TrimSpace(ei.Name) != "" {
			return ei.Name, nil
		}
		if d.JsLoadingScript != nil && strings.TrimSpace(d.JsLoadingScript.Name) != "" {
			return d.JsLoadingScript.Name, nil
		}
		return "", errors.New("请先完成此扩展的注册")
	}
	if err := register("seal.ext.registerStringConfig", func(ei *ExtInfo, key string, defaultValue string, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "string", Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerIntConfig", func(ei *ExtInfo, key string, defaultValue int64, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "int", Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerBoolConfig", func(ei *ExtInfo, key string, defaultValue bool, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "bool", Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerFloatConfig", func(ei *ExtInfo, key string, defaultValue float64, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "float", Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerTemplateConfig", func(ei *ExtInfo, key string, defaultValue []string, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "template", Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerOptionConfig", func(ei *ExtInfo, key string, defaultValue string, option []string, description string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "option", Value: defaultValue, DefaultValue: defaultValue, Option: option, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.newConfigItem", func(ei *ExtInfo, key string, defaultValue interface{}, description string) *ConfigItem {
		if _, err := resolveExtName(ei); err != nil {
			panic(err)
		}
		return d.ConfigManager.NewConfigItem(key, defaultValue, description)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerConfig", func(ei *ExtInfo, config ...*ConfigItem) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		d.ConfigManager.RegisterPluginConfig(extName, config...)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getConfig", func(ei *ExtInfo, key string) *ConfigItem {
		extName, err := resolveExtName(ei)
		if err != nil {
			return nil
		}
		return d.ConfigManager.getConfig(extName, key)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getStringConfig", func(ei *ExtInfo, key string) string {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "string" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(string)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getIntConfig", func(ei *ExtInfo, key string) int64 {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "int" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(int64)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getBoolConfig", func(ei *ExtInfo, key string) bool {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "bool" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(bool)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getFloatConfig", func(ei *ExtInfo, key string) float64 {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "float" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(float64)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getTemplateConfig", func(ei *ExtInfo, key string) []string {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "template" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.([]string)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.getOptionConfig", func(ei *ExtInfo, key string) string {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic("配置不存在或类型不匹配")
		}
		cfg := d.ConfigManager.getConfig(extName, key)
		if cfg == nil || cfg.Type != "option" {
			panic("配置不存在或类型不匹配")
		}
		return cfg.Value.(string)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.unregisterConfig", func(ei *ExtInfo, key ...string) {
		extName, err := resolveExtName(ei)
		if err != nil {
			return
		}
		d.ConfigManager.UnregisterConfig(extName, key...)
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerTask", func(ei *ExtInfo, taskType string, value string, fnRef string, key string, desc string) *JsScriptTask {
		extName, err := resolveExtName(ei)
		if err != nil {
			d.Logger.Errorf("插件注册定时任务失败：%v", err)
			return nil
		}
		if strings.TrimSpace(fnRef) == "" {
			d.Logger.Errorf("插件注册定时任务失败：registerTask 缺少任务回调函数")
			return nil
		}
		scriptCron := d.ensureJsScriptCron()
		task := JsScriptTask{
			cron: scriptCron,
			key:  key,
			task: func(taskCtx JsScriptTaskCtx) {
				invoker, ok := d.ScriptEngine.(interface {
					InvokeStoredTask(fnRef string, taskCtx map[string]any) error
				})
				if !ok {
					d.Logger.Errorf("QuickJS 任务执行器不可用: fnRef=%s", fnRef)
					return
				}
				if err := invoker.InvokeStoredTask(fnRef, map[string]any{
					"now": taskCtx.Now,
					"key": taskCtx.Key,
				}); err != nil {
					d.Logger.Errorf("QuickJS 任务回调执行失败 fnRef=%s: %v", fnRef, err)
				}
			},
			lock:   d.JsScriptCronLock,
			logger: d.Logger,
		}
		expr := value
		if key != "" {
			if config := d.ConfigManager.getConfig(extName, key); config != nil {
				expr = config.Value.(string)
				if config.task != nil {
					config.task.Off()
				}
			}
		}

		switch taskType {
		case "cron":
			entryID, err := scriptCron.AddFunc(expr, func() {
				task.run()
			})
			if err != nil {
				d.Logger.Errorf("插件注册定时任务失败：%v", err)
				return nil
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = expr
			task.entryID = &entryID
			d.Logger.Infof("插件注册定时任务：cron=%s", expr)
		case "daily":
			cronExpr, err := parseTaskTime(expr)
			if err != nil {
				d.Logger.Errorf("插件注册定时任务失败：%v", err)
				return nil
			}

			entryID, err := scriptCron.AddFunc(cronExpr, func() {
				task.run()
			})
			if err != nil {
				d.Logger.Errorf("插件注册定时任务失败：%v", err)
				return nil
			}
			task.taskType = taskType
			task.rawValue = expr
			task.cronExpr = cronExpr
			task.entryID = &entryID
			d.Logger.Infof("插件注册定时任务：daily=%s", expr)
		default:
			d.Logger.Errorf("插件注册定时任务失败：错误的任务类型：%s，当前仅支持 cron|daily", taskType)
			return nil
		}

		if key != "" {
			config := d.ConfigManager.getConfig(extName, key)

			switch taskType {
			case "cron":
				config = &ConfigItem{
					Key:          key,
					Type:         "task:cron",
					Value:        expr,
					DefaultValue: value,
					Description:  desc,
					task:         &task,
				}
			case "daily":
				config = &ConfigItem{
					Key:          key,
					Type:         "task:daily",
					Value:        expr,
					DefaultValue: value,
					Description:  desc,
					task:         &task,
				}
			}
			d.ConfigManager.RegisterPluginConfig(extName, config)
		}

		if key == "" {
			if ei != nil {
				if ei.taskList == nil {
					ei.taskList = make([]*JsScriptTask, 0)
					ei.taskList = append(ei.taskList, &task)
				} else {
					ei.taskList = append(ei.taskList, &task)
				}
			} else {
				// 未携带扩展对象时无法持久挂载到 taskList，但任务仍可通过配置项管理。
			}
		}

		return &task
	}); err != nil {
		return err
	}

	// coc
	if err := register("seal.coc.newRule", func() *CocRuleInfo { return &CocRuleInfo{} }); err != nil {
		return err
	}
	if err := register("seal.coc.newRuleCheckResult", func() *CocRuleCheckRet { return &CocRuleCheckRet{} }); err != nil {
		return err
	}
	if err := register("seal.coc.registerRule", func(rule *CocRuleInfo) bool { return d.CocExtraRulesAdd(rule) }); err != nil {
		return err
	}

	// deck
	if err := register("seal.deck.draw", func(ctx *MsgContext, deckName string, isShuffle bool) map[string]interface{} {
		exists, result, err := deckDraw(ctx, deckName, isShuffle)
		var errText string
		if err != nil {
			errText = err.Error()
		}
		return map[string]interface{}{"exists": exists, "err": errText, "result": result}
	}); err != nil {
		return err
	}
	if err := register("seal.deck.reload", func() { DeckReload(d) }); err != nil {
		return err
	}

	// 常用工具函数
	if err := register("seal.replyGroup", ReplyGroup); err != nil {
		return err
	}
	if err := register("seal.replyPerson", ReplyPerson); err != nil {
		return err
	}
	if err := register("seal.replyToSender", ReplyToSender); err != nil {
		return err
	}
	if err := register("seal.memberBan", MemberBan); err != nil {
		return err
	}
	if err := register("seal.memberKick", MemberKick); err != nil {
		return err
	}
	if err := register("seal.format", DiceFormat); err != nil {
		return err
	}
	if err := register("seal.formatTmpl", DiceFormatTmpl); err != nil {
		return err
	}
	if err := register("seal.getCtxProxyFirst", GetCtxProxyFirst); err != nil {
		return err
	}
	if err := register("seal.newMessage", func() *Message { return &Message{} }); err != nil {
		return err
	}
	if err := register("seal.createTempCtx", CreateTempCtx); err != nil {
		return err
	}
	if err := register("seal.applyPlayerGroupCardByTemplate", func(ctx *MsgContext, tmpl string) string {
		if tmpl != "" {
			ctx.Player.AutoSetNameTemplate = tmpl
		}
		if ctx.Player.AutoSetNameTemplate != "" {
			text, _ := SetPlayerGroupCardByTemplate(ctx, ctx.Player.AutoSetNameTemplate)
			return text
		}
		return ""
	}); err != nil {
		return err
	}
	if err := register("seal.gameSystem.newTemplate", func(data string) error {
		tmpl, err := loadGameSystemTemplateFromData([]byte(data), "json")
		if err != nil {
			return errors.New("解析失败:" + err.Error())
		}
		ret := d.GameSystemTemplateAddEx(tmpl, true)
		if !ret {
			return errors.New("已存在同名模板")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.gameSystem.newTemplateByYaml", func(data string) error {
		tmpl, err := loadGameSystemTemplateFromData([]byte(data), "yaml")
		if err != nil {
			return errors.New("解析失败:" + err.Error())
		}
		ret := d.GameSystemTemplateAddEx(tmpl, true)
		if !ret {
			return errors.New("已存在同名模板")
		}
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.getCtxProxyAtPos", GetCtxProxyAtPos); err != nil {
		return err
	}
	if err := register("seal.getVersion", func() map[string]interface{} {
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
	}); err != nil {
		return err
	}
	if err := register("seal.getEndPoints", func() []*EndPointInfo { return d.ImSession.EndPoints }); err != nil {
		return err
	}
	if err := register("atob", func(s string) (string, error) {
		s = strings.ReplaceAll(s, "data:text/plain;base64,", "")
		s = strings.ReplaceAll(s, " ", "")
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", errors.New("atob: 不合法的base64字串")
		}
		return string(b), nil
	}); err != nil {
		return err
	}
	if err := register("btoa", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }); err != nil {
		return err
	}
	if err := register("seal.setPlayerGroupCard", SetPlayerGroupCardByTemplate); err != nil {
		return err
	}
	if err := register("seal.base64ToImage", Base64ToImageFunc()); err != nil {
		return err
	}

	return nil
}

func convertJsExtInfo(d *Dice, v any) (*ExtInfo, error) {
	if v == nil {
		return nil, nil
	}
	if ext, ok := v.(*ExtInfo); ok {
		return ext, nil
	}

	// modernc quickjs 对象通常可通过 Into(any) 反序列化。
	var data map[string]any
	if s, ok := v.(string); ok {
		if strings.TrimSpace(s) == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(s), &data); err != nil {
			return nil, fmt.Errorf("ext JSON 解析失败: %w", err)
		}
	}
	if m, ok := v.(map[string]any); ok {
		data = m
	} else {
		rv := reflect.ValueOf(v)
		if !rv.IsValid() {
			return nil, nil
		}
		method := rv.MethodByName("Into")
		if method.IsValid() {
			arg := map[string]any{}
			out := method.Call([]reflect.Value{reflect.ValueOf(&arg)})
			if len(out) == 1 && !out[0].IsNil() {
				if err, ok := out[0].Interface().(error); ok {
					return nil, err
				}
			}
			data = arg
		}
	}
	if data == nil {
		return nil, fmt.Errorf("不支持的 ext 参数类型: %T", v)
	}

	getString := func(key string) string {
		if val, ok := data[key]; ok {
			if s, ok := val.(string); ok {
				return s
			}
		}
		return ""
	}
	getBool := func(key string, def bool) bool {
		if val, ok := data[key]; ok {
			if b, ok := val.(bool); ok {
				return b
			}
		}
		return def
	}

	name := getString("name")
	if name == "" {
		return nil, fmt.Errorf("ext.name 不能为空")
	}
	ext := &ExtInfo{
		Name:        name,
		Author:      getString("author"),
		Version:     getString("version"),
		GetDescText: GetExtensionDesc,
		AutoActive:  getBool("autoActive", true),
		IsJsExt:     true,
		Brief:       "一个JS自定义扩展",
		Official:    getBool("official", false),
		CmdMap:      CmdMapCls{},
	}
	if brief := getString("brief"); brief != "" {
		ext.Brief = brief
	}

	// 尝试恢复 cmdMap 元数据，并将 solve 回调桥接到 QuickJS 引擎。
	toStringAnyMap := func(v any) map[string]any {
		if v == nil {
			return nil
		}
		// 优先尝试 quickjs.Object 的 Into 反序列化。
		rv := reflect.ValueOf(v)
		if rv.IsValid() {
			method := rv.MethodByName("Into")
			if method.IsValid() {
				arg := map[string]any{}
				out := method.Call([]reflect.Value{reflect.ValueOf(&arg)})
				if len(out) == 1 && out[0].IsNil() {
					return arg
				}
			}
		}
		if m, ok := v.(map[string]any); ok {
			return m
		}
		if !rv.IsValid() || rv.Kind() != reflect.Map {
			return nil
		}
		out := map[string]any{}
		iter := rv.MapRange()
		for iter.Next() {
			out[fmt.Sprint(iter.Key().Interface())] = iter.Value().Interface()
		}
		return out
	}
	if rawCmdMap, ok := data["cmdMap"]; ok {
		if cmdMapObj := toStringAnyMap(rawCmdMap); cmdMapObj != nil {
			for cmdName, rawCmd := range cmdMapObj {
				cmdInfo := buildQuickJSCmdInfo(d, ext.Name, cmdName, toStringAnyMap(rawCmd))
				ext.CmdMap[cmdName] = cmdInfo
			}
		}
	}
	extNameCopy := ext.Name
	ext.OnNotCommandReceived = func(ctx *MsgContext, msg *Message) {
		invoker, ok := d.ScriptEngine.(interface {
			InvokeStoredOnNotCommand(extName string, runtime map[string]any) error
		})
		if !ok {
			d.Logger.Errorf("QuickJS 非指令回调执行器不可用: %s", extNameCopy)
			return
		}
		msgObj := map[string]any{}
		if msg != nil {
			msgObj["message"] = msg.Message
			msgObj["messageType"] = msg.MessageType
			msgObj["platform"] = msg.Platform
			msgObj["groupID"] = msg.GroupID
			msgObj["guildID"] = msg.GuildID
			msgObj["channelID"] = msg.ChannelID
			msgObj["senderUserID"] = msg.Sender.UserID
			msgObj["senderNickname"] = msg.Sender.Nickname
		}
		runtime := map[string]any{
			"msg": msgObj,
		}
		if ctx != nil {
			runtime["privilegeLevel"] = ctx.PrivilegeLevel
		}
		runtime["replyToSender"] = func(text string) {
			if ctx == nil || msg == nil {
				return
			}
			ReplyToSender(ctx, msg, text)
		}
		if err := invoker.InvokeStoredOnNotCommand(extNameCopy, runtime); err != nil {
			d.Logger.Errorf("QuickJS 非指令回调执行失败 %s: %v", extNameCopy, err)
		}
	}
	return ext, nil
}

func buildQuickJSCmdInfo(d *Dice, extName string, cmdName string, rawCmd map[string]any) *CmdItemInfo {
	cmdInfo := &CmdItemInfo{
		Name:          cmdName,
		IsJsSolveFunc: true,
	}
	if rawCmd != nil {
		if help, ok := rawCmd["help"].(string); ok {
			cmdInfo.Help = help
		}
		if raw, ok := rawCmd["raw"].(bool); ok {
			cmdInfo.Raw = raw
		}
		if checkCurrentBotOn, ok := rawCmd["checkCurrentBotOn"].(bool); ok {
			cmdInfo.CheckCurrentBotOn = checkCurrentBotOn
		}
		if checkMentionOthers, ok := rawCmd["checkMentionOthers"].(bool); ok {
			cmdInfo.CheckMentionOthers = checkMentionOthers
		}
	}

	cmdNameCopy := cmdName
	cmdInfo.Solve = func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
		invoker, ok := d.ScriptEngine.(interface {
			InvokeStoredSolve(extName string, cmdName string, runtime map[string]any) (map[string]any, error)
		})
		if !ok {
			d.Logger.Errorf("QuickJS 命令执行器不可用: %s.%s", extName, cmdNameCopy)
			return CmdExecuteResult{Matched: true, Solved: false}
		}
		ret, err := invoker.InvokeStoredSolve(extName, cmdNameCopy, map[string]any{
			"privilegeLevel": ctx.PrivilegeLevel,
			"getArgN": func(n int64) string {
				return cmdArgs.GetArgN(int(n))
			},
			"replyToSender": func(text string) {
				ReplyToSender(ctx, msg, text)
			},
		})
		if err != nil {
			d.Logger.Errorf("QuickJS 命令执行失败 %s.%s: %v", extName, cmdNameCopy, err)
			return CmdExecuteResult{Matched: true, Solved: false}
		}
		result := CmdExecuteResult{Matched: true, Solved: true}
		if ret != nil {
			if matched, ok := ret["matched"].(bool); ok {
				result.Matched = matched
			}
			if solved, ok := ret["solved"].(bool); ok {
				result.Solved = solved
			}
			if showHelp, ok := ret["showHelp"].(bool); ok {
				result.ShowHelp = showHelp
			}
		}
		return result
	}
	return cmdInfo
}

func extInfoToJSMap(ext *ExtInfo) map[string]any {
	if ext == nil {
		return nil
	}
	m := map[string]any{
		"name":       ext.Name,
		"author":     ext.Author,
		"version":    ext.Version,
		"autoActive": ext.AutoActive,
		"isJsExt":    ext.IsJsExt,
		"brief":      ext.Brief,
		"official":   ext.Official,
		"cmdMap":     map[string]any{},
	}
	// 兼容脚本中可能使用的 Source.Official 判断。
	if ext.Source != nil {
		m["source"] = map[string]any{
			"official": ext.Source.Official,
		}
	}
	return m
}

func extInfoToJSONString(ext *ExtInfo) string {
	m := extInfoToJSMap(ext)
	if m == nil {
		return "null"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "null"
	}
	return string(b)
}

func cmdItemInfoToJSONString(ci *CmdItemInfo) string {
	if ci == nil {
		return "null"
	}
	m := map[string]any{
		"name":                    ci.Name,
		"shortHelp":               ci.ShortHelp,
		"help":                    ci.Help,
		"allowDelegate":           ci.AllowDelegate,
		"disabledInPrivate":       ci.DisabledInPrivate,
		"enableExecuteTimesParse": ci.EnableExecuteTimesParse,
		"raw":                     ci.Raw,
		"checkCurrentBotOn":       ci.CheckCurrentBotOn,
		"checkMentionOthers":      ci.CheckMentionOthers,
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "null"
	}
	return string(b)
}

func (d *Dice) JsShutdown() {
	(&d.Config).JsEnable = false
	d.jsClear()
	d.Logger.Info("已关闭JS环境")
	d.MarkModified()
	d.Save(false)
}

func (d *Dice) jsClear() {
	if d.ScriptEngine != nil {
		_ = d.ScriptEngine.Dispose()
		d.ScriptEngine = nil
	}
	d.jsClearStateOnly()
}

func (d *Dice) jsClearStateOnly() {
	// Wrapper 架构：不再调用 ExtRemove，只清空 JsExtRegistry
	// 注意：不标记 wrapper 为 IsDeleted，否则重载期间消息到达会导致 wrapper 被移除
	// IsDeleted 只在 JsDelete/ExtRemove（永久删除脚本）时设置

	// 清空/初始化 JsExtRegistry
	if d.JsExtRegistry != nil {
		d.JsExtRegistry.Range(func(_ string, ext *ExtInfo) bool {
			if ext != nil && ext.Storage != nil {
				_ = ext.StorageClose()
			}
			return true
		})
	}
	d.JsExtRegistry = new(SyncMap[string, *ExtInfo])

	// 清理coc扩展规则
	d.CocExtraRules = map[int]*CocRuleInfo{}
	// 清理脚本列表
	d.JsScriptList = []*JsScriptInfo{}
	// 清理规则模板
	// Pinenutn: 由于切换成了其他的syncMap，所以初始化策略需要修改
	d.GameSystemMap = new(SyncMap[string, *GameSystemTemplate])
	d.RegisterBuiltinSystemTemplate()
	if d.StoreManager != nil {
		d.StoreManager.InstalledPlugins = map[string]bool{}
	}
	// JsEnable=false 的启动状态下 ExtLoopManager 可能尚未初始化
	if d.ExtLoopManager != nil {
		d.ExtLoopManager.SetLoop(nil)
	}
}

func isScriptFile(filename string) bool {
	temp := strings.ToLower(filepath.Ext(filename))
	return temp == ".js" || temp == ".ts"
}

func (d *Dice) JsLoadScripts() {
	d.JsScriptList = []*JsScriptInfo{}

	path := filepath.Join(d.BaseConfig.DataDir, "scripts")
	builtinPath := filepath.Join(path, "_builtin")

	// 导出内置脚本数据
	builtinScripts, _ := fs.ReadDir(static.Scripts, "scripts")
	_ = os.MkdirAll(builtinPath, 0o755)
	for _, script := range builtinScripts {
		if !script.IsDir() && isScriptFile(script.Name()) {
			target := filepath.Join(builtinPath, script.Name())
			data, _ := static.Scripts.ReadFile("scripts/" + script.Name())
			d.JsBuiltinDigestSet[crypto.CalculateSHA512Str(data)] = true
			// 判断是否有更新后的内置脚本
			_, err := os.Stat(target)
			if errors.Is(err, os.ErrNotExist) {
				_ = os.WriteFile(target, data, 0o644)
			} else {
				// 检查同名内置脚本的签名，检查不通过则覆盖
				scriptData, _ := os.ReadFile(target)
				if ok, _ := CheckJsSign(scriptData); !ok {
					d.Logger.Warnf("已存在的内置脚本「%s」未通过校验，进行覆盖", script.Name())
					_ = os.WriteFile(target, scriptData, 0o644)
				}
			}
		}
	}

	var jsInfos []*JsScriptInfo
	// 解析内置脚本
	_ = filepath.Walk(builtinPath, func(path string, info fs.FileInfo, err error) error {
		if isScriptFile(path) {
			d.Logger.Info("正在读取内置脚本: ", path)
			data, err := os.ReadFile(path)
			if err != nil {
				d.Logger.Error("读取内置脚本失败(无法访问): ", err.Error())
				return nil
			}
			// 检查内置脚本签名，检查不通过则拒绝加载
			scriptData, _ := os.ReadFile(path)
			if ok, _ := CheckJsSign(scriptData); ok {
				jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, true)
				if err != nil {
					d.Logger.Error("读取内置脚本失败(错误依赖)", err.Error())
					return nil
				}
				jsInfos = append(jsInfos, jsInfo)
				if len(jsInfo.StoreID) > 0 {
					d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
				}
			} else {
				d.Logger.Warnf("内置脚本「%s」校验未通过，拒绝加载", path)
			}
		}
		return nil
	})

	// 解析第三方脚本
	_ = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if info.IsDir() && info.Name() == "_builtin" {
			return fs.SkipDir
		}
		if isScriptFile(path) {
			d.Logger.Info("正在读取脚本: ", path)
			data, err := os.ReadFile(path)
			if err != nil {
				d.Logger.Error("读取脚本失败(无法访问): ", err.Error())
				return nil
			}
			jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, false)
			if err != nil {
				d.Logger.Error("读取脚本失败(错误依赖)", err.Error())
				return nil
			}
			jsInfos = append(jsInfos, jsInfo)
			if len(jsInfo.StoreID) > 0 {
				d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
			}
		}
		return nil
	})

	// 检查依赖是否满足
	unloadKeySet := make(map[string]bool)
	var unloadInfos []string
	scripts, invalidInfoMap := checkJsScriptsDeps(jsInfos)
	if len(invalidInfoMap) > 0 {
		// 部分插件依赖不满足，不进行加载
		var infos []string
		for k, v := range invalidInfoMap {
			unloadKeySet[k] = true
			infos = append(infos, v...)
		}
		unloadInfos = append(unloadInfos, infos...)
	}
	// 分析加载顺序
	sortedJsInfos, invalidInfoMap := sortJsScripts(scripts)
	if len(invalidInfoMap) != 0 {
		// 部分插件存在循环依赖，不进行加载
		var infos []string
		for k, v := range invalidInfoMap {
			unloadKeySet[k] = true
			infos = append(infos, v...)
		}
		unloadInfos = append(unloadInfos, infos...)
	}
	if len(unloadInfos) > 0 {
		var keys []string
		for key := range unloadKeySet {
			keys = append(keys, key)
		}
		d.Logger.Warnf("插件「%s」拒绝加载：\n%s", strings.Join(keys, "、"), strings.Join(unloadInfos, "\n"))
	}

	// 按顺序加载
	for _, jsInfo := range sortedJsInfos {
		if len(jsInfo.Depends) == 0 {
			d.Logger.Infof("正在加载脚本「%s:%s:%s」", jsInfo.Author, jsInfo.Name, jsInfo.Version)
		} else {
			var depends []string
			for _, dep := range jsInfo.Depends {
				depends = append(depends, dep.RawKey)
			}
			d.Logger.Infof("正在加载脚本「%s:%s:%s」，其依赖：%s", jsInfo.Author, jsInfo.Name, jsInfo.Version, strings.Join(depends, "、"))
		}

		if strings.ToLower(filepath.Ext(jsInfo.Filename)) == ".ts" {
			jsInfo.needCompiled = true
		}

		d.JsLoadScriptRaw(jsInfo)
	}
	// 统一在所有脚本加载完后应用扩展默认设置
	// 新扩展激活采用延迟模式，在群组收到消息时通过 GetActivatedExtList 按需激活
	d.ApplyExtDefaultSettings()
}

func (d *Dice) JsReload() {
	startTime := time.Now()
	d.Logger.Infof("JsReload: 开始重载")
	defer func() {
		if r := recover(); r != nil {
			d.Logger.Errorf("JsReload 发生panic: %v\n堆栈:\n%s", r, string(debug.Stack()))
		}
	}()

	if d.JsScriptCron != nil {
		d.JsScriptCron.Stop()
		d.JsScriptCron = nil
	}

	// Wrapper 架构：设置重载标志，避免重载期间访问无效的 CmdMap
	d.JsReloading = true
	defer func() { d.JsReloading = false }()

	// 仅在“目标引擎仍是 quickjs 且当前也在 quickjs”时走软重置；
	// 如果目标已切到 goja，必须走 JsInit 完整重建，确保引擎切换立即生效。
	if shouldQuickJSSoftResetOnReload(d.Config.JsEngine, d.JsEngineEffective, d.ScriptEngine != nil) {
		d.jsClearStateOnly()
		if err := d.ScriptEngine.Reset(); err != nil {
			d.Logger.Errorf("JsReload: QuickJS Reset 失败，回退全量重建: %v", err)
			d.JsInit()
		}
	} else {
		d.JsInit()
	}
	_ = d.ConfigManager.Load()
	d.JsLoadScripts()

	// 更新扩展变更时间戳，触发延迟更新
	d.ExtUpdateTime = time.Now().Unix()

	d.MarkModified()
	d.Save(false)

	d.Logger.Infof("JsReload: 重载完成，耗时 %dms", time.Since(startTime).Milliseconds())
}

func shouldQuickJSSoftResetOnReload(configEngine string, effectiveEngine string, hasScriptEngine bool) bool {
	desired := strings.ToLower(strings.TrimSpace(configEngine))
	if desired == "" {
		desired = "goja"
	}
	return desired == "quickjs" && effectiveEngine == "quickjs" && hasScriptEngine
}

// JsExtSettingVacuum 清理已被删除的脚本对应的插件配置
//
// Deprecated: bug
func (d *Dice) JsExtSettingVacuum() {
	// NOTE(Xiangze Li): 这里jsInfo中的Name字段是JS文件头中定义的@name,
	// 而ExtDefaultSettings中的Name字段是插件的名称,
	// 这两者的内容没有任何关联, 也没有字段在两者之间建立关系, 因此不能用来匹配.
	//
	// 另外, 对于已经删除/禁用的JS, ExtDefaultSetting中的ExtItem指针可能是nil

	jsMap := map[string]bool{}
	for _, jsInfo := range d.JsScriptList {
		jsMap[jsInfo.Name] = true
	}

	idxToDel := []int{}
	for k, v := range d.Config.ExtDefaultSettings {
		if !v.ExtItem.IsJsExt {
			continue
		}
		if !jsMap[v.Name] {
			idxToDel = append(idxToDel, k)
		}
	}

	for i := len(idxToDel) - 1; i >= 0; i-- {
		idx := idxToDel[i]
		(&d.Config).ExtDefaultSettings = append((&d.Config).ExtDefaultSettings[:idx], (&d.Config).ExtDefaultSettings[idx+1:]...)
	}

	panic("DONT USE ME")
}

type Prop struct {
	Key   string `json:"key"`
	Value string `json:"value"`

	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Required bool   `json:"required"`
	Default  string `json:"default"`
}

type SignStatus int8

const (
	// ErrorSign 错误签名
	ErrorSign SignStatus = -1
	// UnknownSign 无签名
	UnknownSign SignStatus = 0
	// OfficialSign 官方签名
	OfficialSign SignStatus = 1
)

type JsScriptInfo struct {
	/** 名称 */
	Name string `json:"name"`
	/** 是否启用 */
	Enable bool `json:"enable"`
	/** 版本 */
	Version string `json:"version"`
	/** 作者 */
	Author string `json:"author"`
	/** 许可协议 */
	License string `json:"license"`
	/** 网址 */
	HomePage string `json:"homepage"`
	/** 详细描述 */
	Desc string `json:"desc"`
	/** 所需权限 */
	Grant []string `json:"grant"`
	/** 更新时间 */
	UpdateTime int64 `json:"updateTime"`
	/** 安装时间 - 文件创建时间 */
	InstallTime int64 `json:"installTime"`
	/** 最近一条错误文本 */
	ErrText string `json:"errText"`
	/** 实际文件名 */
	Filename string `json:"filename"`
	/** 更新链接 */
	UpdateUrls []string `json:"updateUrls"`
	/** etag */
	Etag string `json:"etag"`
	/** 是否官方插件 */
	Official bool `json:"official"`
	/** 签名状态 */
	signStatus SignStatus
	/** 是否内置插件 */
	Builtin bool `json:"builtin"`
	/** 内容摘要 */
	Digest string `json:"-"`
	/** 依赖项 */
	Depends []JsScriptDepends `json:"depends"`
	/** 需要被编译 */
	needCompiled bool
	/** 扩展商店唯一 ID */
	StoreID string `json:"storeID"`
}

type JsScriptDepends struct {
	/** 作者 */
	Author string `json:"author"`
	/** 名称 */
	Name string `json:"name"`
	/** 版本限制 */
	Constraint *semver.Constraints `json:"constraint"`
	/** 原始依赖Key */
	RawKey string `json:"rawKey"`
}

func (d *Dice) JsParseMeta(s string, installTime time.Time, rawData []byte, builtin bool) (*JsScriptInfo, error) {
	// 读取文件内容填空，类似油猴脚本那种形式
	jsInfo := &JsScriptInfo{
		Name:        filepath.Base(s),
		Filename:    s,
		InstallTime: installTime.Unix(),
	}
	d.JsScriptList = append(d.JsScriptList, jsInfo)

	jsInfo.Builtin = builtin
	jsInfo.Digest = crypto.CalculateSHA512Str(rawData)

	// 解析签名
	official, signStatus := CheckJsSign(rawData)
	jsInfo.Official = official
	jsInfo.signStatus = signStatus

	// 解析信息
	fileText := string(rawData)
	re := regexp.MustCompile(`(?s)//[ \t]*==UserScript==[ \t]*\r?\n(.*)//[ \t]*==/UserScript==`)
	m := re.FindStringSubmatch(fileText)
	var errMsg []string

	if len(m) > 0 {
		text := m[0]
		re2 := regexp.MustCompile(`//[ \t]*@(\S+)\s+([^\r\n]+)`)
		data := re2.FindAllStringSubmatch(text, -1)
		updateUrls := make([]string, 0)

		for _, item := range data {
			v := strings.TrimSpace(item[2])
			switch item[1] {
			case "name":
				jsInfo.Name = v
			case "homepageURL":
				jsInfo.HomePage = v
			case "license":
				jsInfo.License = v
			case "author":
				jsInfo.Author = v
			case "version":
				jsInfo.Version = v
			case "description":
				v = strings.ReplaceAll(v, "\\n", "\n")
				jsInfo.Desc = v
			case "timestamp":
				timestamp, errParse := strconv.ParseInt(v, 10, 64)
				if errParse == nil {
					jsInfo.UpdateTime = timestamp
				} else {
					t := carbon.Parse(v)
					if t.IsValid() {
						jsInfo.UpdateTime = t.Timestamp()
					}
				}
			case "updateUrl":
				updateUrls = append(updateUrls, v)
			case "etag":
				jsInfo.Etag = v
			case "depends":
				dependsStr := strings.SplitN(v, ":", 2)
				if len(dependsStr) != 2 {
					errMsg = append(errMsg, fmt.Sprintf("插件「%s」指定依赖格式不正确，应为 作者:插件名:[SemVer版本约束，可选]，现为「%s」", jsInfo.Name, v))
					continue
				}
				author := dependsStr[0]
				name := dependsStr[1]
				var dependsInfo JsScriptDepends
				dependsInfo.Author = author
				dependsInfo.RawKey = v

				if strings.Contains(name, ":") {
					split := strings.SplitN(name, ":", 2)
					constraint, err := semver.NewConstraint(split[1])
					if err != nil {
						errMsg = append(errMsg, fmt.Sprintf("插件「%s」指定依赖格式不正确，应为 作者:插件名:[SemVer版本约束，可选]，现为「%s」", jsInfo.Name, v))
						continue
					}
					dependsInfo.Name = split[0]
					dependsInfo.Constraint = constraint
				} else {
					dependsInfo.Name = name
					dependsInfo.Constraint, _ = semver.NewConstraint("")
				}
				jsInfo.Depends = append(jsInfo.Depends, dependsInfo)
			case "sealVersion":
				vc, err := semver.NewConstraint(v)
				if err != nil {
					errMsg = append(errMsg, fmt.Sprintf("插件「%s」限制余烬版本的格式不正确，应满足semver版本范围语法，例如「1.4.0, >=1.4.0, 1.4.5-dev」等，当前为「%s」", jsInfo.Name, v))
					continue
				}

				var verOK bool
				// 有特殊符号时，进行严格的版本检查(只检查当前版本)
				if strings.ContainsAny(v, "~*^<=>|") || strings.Contains(v, " - ") {
					verOK = vc.Check(VERSION)
				} else {
					_, verOK = lo.Find(VERSION_JSAPI_COMPATIBLE, func(v *semver.Version) bool {
						return vc.Check(v)
					})
				}

				if !verOK {
					errMsg = append(errMsg, fmt.Sprintf("插件「%s」依赖的余烬版本限制在 %s，与余烬版本(%s)的JSAPI不兼容", jsInfo.Name, v, VERSION.String()))
				}
			case "needCompiled":
				jsInfo.needCompiled = true
			case "storeID":
				jsInfo.StoreID = v
			}
		}
		jsInfo.UpdateUrls = updateUrls
	}

	if len(errMsg) > 0 {
		jsInfo.Enable = false
		jsInfo.ErrText = strings.Join(errMsg, "\n")
		return nil, errors.New(strings.Join(errMsg, "|"))
	}
	jsInfo.Enable = !(&d.Config).DisabledJsScripts[jsInfo.Name]
	return jsInfo, nil
}

func (d *Dice) JsLoadScriptRaw(jsInfo *JsScriptInfo) {
	var err error
	if jsInfo.Enable {
		d.JsLoadingScript = jsInfo
		var targetPath string
		if jsInfo.needCompiled {
			d.Logger.Infof("脚本<%s>正在经过编译处理……", jsInfo.Name)
			targetPath, err = tsScriptCompile(jsInfo.Filename)
			defer func(name string) {
				_ = os.Remove(name)
			}(targetPath)
		} else {
			targetPath = jsInfo.Filename
		}
		if err == nil {
			err = d.jsRequireModule(targetPath)
		}
		d.JsLoadingScript = nil
	} else {
		d.Logger.Infof("脚本<%s>已被禁用，跳过加载", jsInfo.Name)
	}

	if err != nil {
		errText := err.Error()
		jsInfo.ErrText = errText
		jsInfo.Enable = false
		d.Logger.Error("读取脚本失败(解析失败): ", errText)
		return
	}

	// 几乎所有脚本都在 register 后再填充 cmdMap，这里输出加载完成后的最终命令数，避免“初始命令数=0”误导。
	if d.JsEngineEffective == "quickjs" && d.JsExtRegistry != nil {
		d.JsExtRegistry.Range(func(extName string, ext *ExtInfo) bool {
			if ext == nil || ext.Source != jsInfo {
				return true
			}
			cmdCount := 0
			if ext.CmdMap != nil {
				cmdCount = len(ext.CmdMap)
			}
			d.Logger.Infof("QuickJS 插件加载完成: %s，最终命令数=%d", extName, cmdCount)
			return true
		})
	}
}

func (d *Dice) jsRequireModule(targetPath string) error {
	// QuickJS 生效时走统一抽象层；未生效或未接入时回退 Goja 路径。
	if d.JsEngineEffective == "quickjs" && d.ScriptEngine != nil {
		return d.ScriptEngine.Require(targetPath)
	}
	_, err := d.ExtLoopManager.GetWebLoop().RequireModule(targetPath)
	return err
}

func tsScriptCompile(path string) (string, error) {
	script, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	compiled := esbuild.Transform(string(script), esbuild.TransformOptions{
		Loader: esbuild.LoaderTS,
	})
	if len(compiled.Errors) > 0 {
		var msg strings.Builder
		for _, e := range compiled.Errors {
			msg.WriteString(e.Text) // FIXME 优化错误信息展示
		}
		return "", errors.New(msg.String())
	}
	compiledPath, err := os.CreateTemp("", "compiled-*-"+filepath.Base(path))
	if err != nil {
		return "", err
	}
	defer func(compiledPath *os.File) {
		_ = compiledPath.Close()
	}(compiledPath)
	_, err = compiledPath.Write(compiled.Code)
	if err != nil {
		return "", err
	}
	return compiledPath.Name(), nil
}

func CheckJsSign(rawData []byte) (bool, SignStatus) {
	if OfficialModPublicKey == "" || len(rawData) == 0 {
		return false, UnknownSign
	}
	r := bufio.NewReader(bytes.NewReader(rawData))
	// 读取第一行判断签名
	fl, err := r.ReadBytes('\n')
	if err != nil {
		return false, UnknownSign
	}
	matches := signRe.FindSubmatch(fl)
	if len(matches) <= 1 {
		return false, UnknownSign
	}
	sign := string(matches[1])
	// 读取剩余内容
	data, err := io.ReadAll(r)
	if err != nil {
		return false, UnknownSign
	}
	err = crypto.RSAVerify(data, sign, OfficialModPublicKey)
	if err == nil {
		return true, OfficialSign
	}
	return false, ErrorSign
}

func JsDelete(d *Dice, jsInfo *JsScriptInfo) {
	dirpath := filepath.Dir(jsInfo.Filename)
	dirname := filepath.Base(dirpath)

	if strings.HasPrefix(dirname, "_") && strings.HasSuffix(dirname, ".deck") {
		// 可能是zip解压出来的，那么删除目录和压缩包
		_ = os.RemoveAll(dirpath)
		zipFilename := filepath.Join(filepath.Dir(dirpath), dirname[1:])
		_ = os.Remove(zipFilename)
	} else {
		_ = os.Remove(jsInfo.Filename)
	}

	// Wrapper 架构：标记 wrapper 为已删除并更新时间戳
	if d != nil {
		// 标记 wrapper 为已删除
		if d.ExtRegistry != nil {
			if wrapper, ok := d.ExtRegistry.Load(jsInfo.Name); ok && wrapper != nil && wrapper.IsWrapper {
				wrapper.IsDeleted = true
			}
		}

		// 从 JsExtRegistry 移除
		if d.JsExtRegistry != nil {
			if realExt, ok := d.JsExtRegistry.Load(jsInfo.Name); ok && realExt != nil && realExt.Storage != nil {
				_ = realExt.StorageClose()
			}
			d.JsExtRegistry.Delete(jsInfo.Name)
		}

		// 更新时间戳
		d.ExtUpdateTime = time.Now().Unix()
	}
}

func JsEnable(d *Dice, jsInfoName string) {
	delete((&d.Config).DisabledJsScripts, jsInfoName)
	for _, jsInfo := range d.JsScriptList {
		if jsInfo.Name == jsInfoName {
			jsInfo.Enable = true
		}
	}
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
}

func JsDisable(d *Dice, jsInfoName string) {
	(&d.Config).DisabledJsScripts[jsInfoName] = true
	for _, jsInfo := range d.JsScriptList {
		if jsInfo.Name == jsInfoName {
			jsInfo.Enable = false
		}
	}
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
}

func (d *Dice) JsCheckUpdate(jsScriptInfo *JsScriptInfo) (string, string, string, error) {
	// FIXME: dirty, copy from check deck update.
	if len(jsScriptInfo.UpdateUrls) == 0 {
		return "", "", "", errors.New("插件未提供更新链接")
	}

	statusCode, newData, err := GetCloudContent(jsScriptInfo.UpdateUrls, jsScriptInfo.Etag)
	if err != nil {
		return "", "", "", err
	}
	if statusCode == http.StatusNotModified {
		return "", "", "", errors.New("插件没有更新")
	}
	if statusCode != http.StatusOK {
		return "", "", "", errors.New("未获取到插件更新")
	}
	oldData, err := os.ReadFile(jsScriptInfo.Filename)
	if err != nil {
		return "", "", "", err
	}

	// 内容预处理
	if isPrefixWithUtf8Bom(oldData) {
		oldData = oldData[3:]
	}
	oldJs := strings.ReplaceAll(string(oldData), "\r\n", "\n")
	if isPrefixWithUtf8Bom(newData) {
		newData = newData[3:]
	}
	newJs := strings.ReplaceAll(string(newData), "\r\n", "\n")

	temp, err := os.CreateTemp("", "new-*-"+filepath.Base(jsScriptInfo.Filename))
	if err != nil {
		return "", "", "", err
	}
	defer func(temp *os.File) {
		_ = temp.Close()
	}(temp)

	_, err = temp.WriteString(newJs)
	if err != nil {
		return "", "", "", err
	}
	return oldJs, newJs, temp.Name(), nil
}

func (d *Dice) JsUpdate(jsScriptInfo *JsScriptInfo, tempFileName string) error {
	newData, err := os.ReadFile(tempFileName)
	_ = os.Remove(tempFileName)
	if err != nil {
		return err
	}
	if len(newData) == 0 {
		return errors.New("new data is empty")
	}
	// 更新插件
	err = os.WriteFile(jsScriptInfo.Filename, newData, 0o755)
	if err != nil {
		d.Logger.Errorf("插件“%s”更新时保存文件出错，%s", jsScriptInfo.Name, err.Error())
		return err
	}
	d.Logger.Infof("插件“%s”更新成功", jsScriptInfo.Name)
	return nil
}

func checkJsScriptsDeps(jsScripts []*JsScriptInfo) ([]*JsScriptInfo, map[string][]string) {
	canLoad := make([]*JsScriptInfo, 0, len(jsScripts))
	invalidInfoMap := make(map[string][]string)
	scriptMap := make(map[string]*JsScriptInfo)
	for _, jsScript := range jsScripts {
		key := fmt.Sprintf("%s:%s", jsScript.Author, jsScript.Name)
		scriptMap[key] = jsScript
	}

	// 检查依赖是否存在，且是否符合版本要求
	for _, script := range jsScripts {
		key := script.Author + ":" + script.Name
		if len(script.Depends) > 0 {
			for _, dep := range script.Depends {
				// 依赖是否存在
				depKey := fmt.Sprintf("%s:%s", dep.Author, dep.Name)
				depScript, ok := scriptMap[depKey]
				if !ok {
					invalidInfoMap[key] = append(invalidInfoMap[key],
						fmt.Sprintf("「%s」依赖的「%s」不存在，所需版本：%s", key, depKey, dep.Constraint.String()))
					continue
				}
				// 版本是否符合要求
				depVersion, vErr := semver.NewVersion(depScript.Version)
				if vErr != nil {
					invalidInfoMap[key] = append(invalidInfoMap[key],
						fmt.Sprintf(
							"「%s」依赖的「%s」无法正确识别版本，现为：%s",
							key, depKey, depScript.Version,
						))
					continue
				}
				if !dep.Constraint.Check(depVersion) {
					invalidInfoMap[key] = append(invalidInfoMap[key], fmt.Sprintf(
						"「%s」依赖的「%s」版本不满足要求：要求 %s，现为 %s",
						key, depKey, dep.Constraint.String(), depScript.Version,
					))
					continue
				}
			}
		}
		if len(invalidInfoMap[key]) == 0 {
			canLoad = append(canLoad, script)
		} else {
			script.Enable = false
			script.ErrText = strings.Join(invalidInfoMap[key], "\n")
		}
	}
	return canLoad, invalidInfoMap
}

// sortJsScripts 使用 Kahn 算法分析依赖加载顺序，同时保证所有内置脚本均在外置脚本前加载
func sortJsScripts(jsScripts []*JsScriptInfo) ([]*JsScriptInfo, map[string][]string) {
	type boxedScript struct {
		key string
		js  *JsScriptInfo
	}

	var queue []*boxedScript
	relations := make(map[string][]string)
	inDegrees := make(map[string]int)
	vertices := make(map[string]*boxedScript)
	// 为了方便计算，添加一个 builtin 节点作为所有外置插件的依赖，其依赖所有内置插件
	dummy := "sealdice:_builtin"
	vertices[dummy] = &boxedScript{
		key: dummy,
	}
	inDegrees[dummy] = 0
	for _, jsScript := range jsScripts {
		key := fmt.Sprintf("%s:%s", jsScript.Author, jsScript.Name)
		if len(jsScript.Depends) > 0 {
			for _, dep := range jsScript.Depends {
				depKey := fmt.Sprintf("%s:%s", dep.Author, dep.Name)
				relations[depKey] = append(relations[depKey], key)
				inDegrees[key]++
			}
		}
		if jsScript.Builtin {
			relations[key] = append(relations[key], dummy)
			inDegrees[dummy]++
		} else {
			relations[dummy] = append(relations[dummy], key)
			inDegrees[key]++
		}

		vertices[key] = &boxedScript{
			key: key,
			js:  jsScript,
		}
	}

	for key, vertex := range vertices {
		if inDegrees[key] == 0 {
			queue = append(queue, vertex)
		}
	}
	var boxedResult []*boxedScript
	for len(queue) > 0 {
		vertex := queue[0]
		queue = queue[1:]
		boxedResult = append(boxedResult, vertex)
		for _, key := range relations[vertex.key] {
			inDegrees[key]--
			if inDegrees[key] == 0 {
				queue = append(queue, vertices[key])
			}
		}
	}

	// 是否入度都归零了，未归零说明存在循环依赖
	infos := make(map[string][]string)
	for key, inDegree := range inDegrees {
		script := vertices[key].js
		if inDegree != 0 && script != nil {
			var deps []string
			for _, dep := range script.Depends {
				deps = append(deps, dep.RawKey)
			}
			infos[key] = append(infos[key], fmt.Sprintf("「%s」存在循环依赖，请检查，依赖列表：%s", key, strings.Join(deps, "、")))
			script.Enable = false
			script.ErrText = strings.Join(infos[key], "\n")
		}
	}

	var result []*JsScriptInfo
	for _, boxed := range boxedResult {
		if boxed.js != nil {
			result = append(result, boxed.js)
		}
	}
	return result, infos
}

type JsScriptTask struct {
	taskType string
	key      string
	rawValue string

	cron     *cron.Cron
	cronExpr string
	task     func(JsScriptTaskCtx)
	entryID  *cron.EntryID
	lock     *sync.Mutex

	logger *zap.SugaredLogger
}

type JsScriptTaskCtx struct {
	Now int64  `jsbind:"now"`
	Key string `jsbind:"key"`
}

func (t *JsScriptTask) run() {
	defer func() {
		if r := recover(); r != nil {
			t.logger.Errorf("插件定时任务异常: %v", r)
		}
	}()
	taskCtx := JsScriptTaskCtx{
		Now: time.Now().Unix(),
		Key: t.key,
	}
	defer t.lock.Unlock()
	t.lock.Lock()
	t.task(taskCtx)
}

func (t *JsScriptTask) On() bool {
	if t.entryID != nil {
		return true
	}
	entryID, err := t.cron.AddFunc(t.cronExpr, func() {
		t.run()
	})
	if err != nil {
		return false
	}
	t.entryID = &entryID
	return true
}

func (t *JsScriptTask) Off() bool {
	if t.entryID == nil {
		return true
	}
	t.cron.Remove(*t.entryID)
	t.entryID = nil
	return true
}

func (t *JsScriptTask) reset(expr string) error {
	if t.entryID != nil {
		t.Off()
		defer t.On()
	}

	t.rawValue = expr
	switch t.taskType {
	case "cron":
		t.cronExpr = expr
	case "daily":
		cronExpr, err := parseTaskTime(expr)
		if err != nil {
			return err
		}
		t.cronExpr = cronExpr
	default:
		return fmt.Errorf("unknown task type %s", t.taskType)
	}
	return nil
}

// parseTaskTime 将 24 小时时间转换为 cron 表达式
func parseTaskTime(taskTimeStr string) (string, error) {
	match := taskTimeRe.MatchString(taskTimeStr)
	if !match {
		return "", errors.New("仅接受 24 小时表示的时间作为每天的执行时间，如 0:05 13:30")
	}
	time, err := time.Parse("15:04", taskTimeStr)
	if err != nil {
		return "", err
	}
	cronExpr := fmt.Sprintf("%d %d * * *", time.Minute(), time.Hour())
	return cronExpr, nil
}

func (d *Dice) JsDownload(name string, url string, hash map[string]string) error {
	if len(url) == 0 {
		return errors.New("未提供下载链接")
	}
	statusCode, data, err := GetCloudContent([]string{url}, "")
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK {
		return errors.New("无法获取插件内容")
	}

	// TODO 检查 hash

	// 内容预处理
	if isPrefixWithUtf8Bom(data) {
		data = data[3:]
	}
	deck := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))

	// TODO 检查签名

	target := filepath.Join(d.BaseConfig.DataDir, "scripts", name+".js")
	_, err = os.Stat(target)
	if !errors.Is(err, os.ErrNotExist) {
		d.Logger.Errorf("JS 插件“%s”下载时检查到同名文件", name)
		return errors.New("存在文件名相同的 JS 插件")
	}
	err = os.WriteFile(target, deck, 0755)
	if err != nil {
		d.Logger.Errorf("JS 插件“%s”下载时保存文件出错，%s", name, err.Error())
		return err
	}
	d.Logger.Infof("JS 插件“%s”下载成功", name)
	d.JsReload()
	d.MarkModified()
	return nil
}
