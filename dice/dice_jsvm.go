package dice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	esbuild "github.com/evanw/esbuild/pkg/api"
	"github.com/golang-module/carbon"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"Scardice-core/dice/events"
	"Scardice-core/dice/jsengine"
	_ "Scardice-core/dice/jsengine/quickjs"
	"Scardice-core/static"
	"Scardice-core/utils/crypto"
)

var (
	// OfficialModPublicKey 官方 Mod 公钥
	OfficialModPublicKey = ``

	signRe = regexp.MustCompile(`^// sign\s+([^\r\n]+)?[\r\n]+$`)
)

var taskTimeRe = regexp.MustCompile(`^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$`)

var taskCronParser = cron.NewParser(
	cron.SecondOptional |
		cron.Minute |
		cron.Hour |
		cron.Dom |
		cron.Month |
		cron.Dow |
		cron.Descriptor,
)

const (
	jsCacheDir         = "./data/.cache/js"
	jsMetaCacheFile    = "meta.gob.zst"
	jsMetaCacheVersion = 1
	tsCacheDir         = "./data/.cache/js/ts"
	tsCacheVersion     = 1
)

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
func (p *PrinterFunc) Error(s string) {
	p.doRecord("error", s)
	if p.d == nil || p.d.Logger == nil {
		return
	}
	// 避免 Error 级别触发全局堆栈打印
	p.d.Logger.Desugar().WithOptions(zap.AddStacktrace(zapcore.FatalLevel)).Sugar().Error("[JS] " + s)
}

// InternalError 表示引擎内部异常，保留 error 级别与调用栈。
func (p *PrinterFunc) InternalError(s string) { p.doRecord("error", s); p.d.Logger.Error(s) }

func (d *Dice) recoverJSPanic(scope string, resetState bool) {
	if r := recover(); r != nil {
		d.Logger.Errorf("%s 发生panic: %v\n堆栈:\n%s", scope, r, string(debug.Stack()))
		if resetState {
			d.safeJSClearStateOnly(scope + " 清理")
		}
	}
}

func (d *Dice) safeJSClearStateOnly(scope string) {
	defer d.recoverJSPanic(scope, false)
	d.jsClearStateOnly()
}

func (d *Dice) disposeRetiredJSEngines(scope string) {
	if len(d.RetiredJSEngines) == 0 {
		return
	}
	for _, engine := range d.RetiredJSEngines {
		if engine == nil {
			continue
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					d.Logger.Errorf("%s 释放退役JS引擎发生panic: %v\n堆栈:\n%s", scope, r, string(debug.Stack()))
				}
			}()
			if err := engine.Dispose(); err != nil {
				d.Logger.Warnf("%s 释放退役JS引擎失败: %v", scope, err)
			}
		}()
	}
	d.RetiredJSEngines = nil
}

func (d *Dice) JsInit() {
	defer d.recoverJSPanic("JsInit", true)
	// 读取官方 Mod 公钥
	if pub, err := static.Scripts.ReadFile("scripts/seal_mod.public.pem"); err == nil && len(pub) > 0 {
		OfficialModPublicKey = string(pub)
	}
	d.Config.JsEngine = "quickjs"
	d.JsEngineEffective = ""
	d.JsEngineFallback = ""
	d.Logger.Info("JS引擎: quickjs")
	if err := d.jsInitQuickJSCore(); err != nil {
		d.JsEngineEffective = ""
		d.JsEngineFallback = err.Error()
		d.Logger.Errorf("QuickJS 初始化失败: %v", err)
	}
}

func (d *Dice) jsInitGojaCore() {
	d.Logger.Warn("Goja 执行链已移除，自动切换到 QuickJS")
	if err := d.jsInitQuickJSCore(); err != nil {
		d.JsEngineEffective = ""
		d.JsEngineFallback = err.Error()
		d.Logger.Errorf("QuickJS 初始化失败: %v", err)
	}
}

func (d *Dice) ensureJsScriptCron() *cron.Cron {
	if d.JsScriptCron == nil {
		d.JsScriptCron = cron.New(cron.WithParser(taskCronParser))
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
	if err := register("seal.ext._syncField", func(extName string, field string, value any) {
		extName = strings.TrimSpace(extName)
		field = strings.TrimSpace(field)
		if extName == "" || field == "" {
			return
		}
		apply := func(ext *ExtInfo) {
			if ext == nil {
				return
			}
			switch field {
			case "author":
				if s, ok := value.(string); ok {
					ext.Author = s
				}
			case "version":
				if s, ok := value.(string); ok {
					ext.Version = s
				}
			case "brief":
				if s, ok := value.(string); ok {
					ext.Brief = s
				}
			case "autoActive":
				ext.AutoActive = quickJSBoolLike(value, ext.AutoActive)
			case "official":
				ext.Official = quickJSBoolLike(value, ext.Official)
			case "isLoaded":
				ext.IsLoaded = quickJSBoolLike(value, ext.IsLoaded)
			case "aliases":
				ext.Aliases = quickJSStringSliceValue(value)
			case "activeWith":
				ext.ActiveWith = quickJSStringSliceValue(value)
			}
		}
		if d.JsExtRegistry != nil {
			if ext, ok := d.JsExtRegistry.Load(extName); ok {
				apply(ext)
			}
		}
		if wrapper, ok := d.ExtRegistry.Load(extName); ok {
			apply(wrapper)
		}
		if field == "activeWith" {
			d.rebuildActiveWithGraph()
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
	resolveExtByName := func(extName string) *ExtInfo {
		if strings.TrimSpace(extName) == "" || d.JsExtRegistry == nil {
			return nil
		}
		ext, _ := d.JsExtRegistry.Load(extName)
		return ext
	}
	if err := register("seal.ext.registerStringConfig", func(ei *ExtInfo, key string, defaultValue string, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "string", Group: group, Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerIntConfig", func(ei *ExtInfo, key string, defaultValue int64, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "int", Group: group, Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerBoolConfig", func(ei *ExtInfo, key string, defaultValue bool, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "bool", Group: group, Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerFloatConfig", func(ei *ExtInfo, key string, defaultValue float64, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "float", Group: group, Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerTemplateConfig", func(ei *ExtInfo, key string, defaultValue []string, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "template", Group: group, Value: defaultValue, DefaultValue: defaultValue, Description: description}
		d.ConfigManager.RegisterPluginConfig(extName, config)
		return nil
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerOptionConfig", func(ei *ExtInfo, key string, defaultValue string, option []string, description string, group string) error {
		extName, err := resolveExtName(ei)
		if err != nil {
			return err
		}
		config := &ConfigItem{Key: key, Type: "option", Group: group, Value: defaultValue, DefaultValue: defaultValue, Option: option, Description: description}
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
	if err := register("seal.ext.storageSet", func(ei *ExtInfo, key string, value string) {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		if setErr := targetExt.StorageSet(key, value); setErr != nil {
			panic(setErr)
		}
	}); err != nil {
		return err
	}
	if err := register("seal.ext.storageInit", func(ei *ExtInfo) bool {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		if initErr := targetExt.StorageInit(); initErr != nil {
			panic(initErr)
		}
		return true
	}); err != nil {
		return err
	}
	if err := register("seal.ext.storageClose", func(ei *ExtInfo) bool {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		if closeErr := targetExt.StorageClose(); closeErr != nil {
			panic(closeErr)
		}
		return true
	}); err != nil {
		return err
	}
	if err := register("seal.ext.storageGet", func(ei *ExtInfo, key string) string {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		v, getErr := targetExt.StorageGet(key)
		if getErr != nil {
			panic(getErr)
		}
		return v
	}); err != nil {
		return err
	}
	if err := register("seal.ext.storageDel", func(ei *ExtInfo, key string) bool {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		if delErr := targetExt.StorageDel(key); delErr != nil {
			panic(delErr)
		}
		return true
	}); err != nil {
		return err
	}
	if err := register("seal.ext.storageList", func(ei *ExtInfo) []string {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		keys, listErr := targetExt.StorageList()
		if listErr != nil {
			panic(listErr)
		}
		return keys
	}); err != nil {
		return err
	}
	if err := register("seal.ext.listTasks", func(ei *ExtInfo) []*JsScriptTaskInfo {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		targetExt := resolveExtByName(extName)
		if targetExt == nil {
			panic(errors.New("请先完成此扩展的注册"))
		}
		tasks := make([]*JsScriptTaskInfo, 0, len(targetExt.taskList))
		for _, task := range targetExt.taskList {
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
	}); err != nil {
		return err
	}
	if err := register("seal.ext._invokeCmdSolve", func(extName string, cmdName string, ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) map[string]any {
		if runtimeProvider, ok := d.ScriptEngine.(interface{ CurrentRuntimeValues() map[string]any }); ok {
			runtime := runtimeProvider.CurrentRuntimeValues()
			if v, ok := runtime["ctx"].(*MsgContext); ok && v != nil {
				ctx = v
			}
			if v, ok := runtime["msg"].(*Message); ok && v != nil {
				msg = v
			}
			if v, ok := runtime["cmdArgs"].(*CmdArgs); ok && v != nil {
				cmdArgs = v
			}
		}
		ext := d.ExtFind(extName, false)
		if ext == nil {
			return cmdExecuteResultToMap(CmdExecuteResult{Matched: true, Solved: false})
		}
		item := ext.GetCmdMap()[strings.ToLower(strings.TrimSpace(cmdName))]
		if item == nil {
			item = ext.GetCmdMap()[cmdName]
		}
		if item == nil {
			return cmdExecuteResultToMap(CmdExecuteResult{Matched: true, Solved: false})
		}
		ret, solveErr := invokeCmdItemWithJSEngine(d, item, ctx, msg, cmdArgs)
		if solveErr != nil {
			d.Logger.Errorf("QuickJS 调用 ext.find 命令失败 %s.%s: %v", extName, cmdName, solveErr)
			return cmdExecuteResultToMap(CmdExecuteResult{Matched: true, Solved: false})
		}
		return cmdExecuteResultToMap(ret)
	}); err != nil {
		return err
	}
	if err := register("seal.ext._invokeCmdHelp", func(extName string, cmdName string, isShort bool) string {
		ext := d.ExtFind(extName, false)
		if ext == nil {
			return ""
		}
		item := ext.GetCmdMap()[strings.ToLower(strings.TrimSpace(cmdName))]
		if item == nil {
			item = ext.GetCmdMap()[cmdName]
		}
		if item == nil {
			return ""
		}
		if item.HelpFunc != nil {
			return item.HelpFunc(isShort)
		}
		if item.Help != "" {
			return item.Help
		}
		if item.ShortHelp != "" {
			return item.Name + ":\n" + item.ShortHelp
		}
		return ""
	}); err != nil {
		return err
	}
	if err := register("seal.ext.registerTask", func(ei *ExtInfo, taskType string, value string, fnRef string, key string, desc string, group string) *JsScriptTask {
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
		if key != "" && taskType != "once" {
			if config := d.ConfigManager.getConfig(extName, key); config != nil {
				expr = config.Value.(string)
				if config.task != nil {
					config.task.Off()
					if ei != nil {
						ei.taskList = removeTaskFromList(ei.taskList, config.task)
					}
				}
			}
		}

		switch taskType {
		case "cron":
			cronExpr, err := parseTaskCronExpr(expr)
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
			expr = cronExpr
			task.entryID = &entryID
			d.Logger.Infof("插件注册定时任务：cron=%s", cronExpr)
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
		case "once":
			onceAt, normalizedExpr, err := parseTaskOnceExpr(expr)
			if err != nil {
				d.Logger.Errorf("插件注册定时任务失败：%v", err)
				return nil
			}
			task.taskType = taskType
			task.rawValue = expr
			task.onceAt = onceAt
			expr = normalizedExpr
			if !task.On() {
				d.Logger.Errorf("插件注册定时任务失败：一次任务注册失败")
				return nil
			}
			d.Logger.Infof("插件注册定时任务：once=%s", expr)
		default:
			d.Logger.Errorf("插件注册定时任务失败：错误的任务类型：%s，当前仅支持 cron|daily|once", taskType)
			return nil
		}

		if key != "" && taskType != "once" {
			config := d.ConfigManager.getConfig(extName, key)

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
			d.ConfigManager.RegisterPluginConfig(extName, config)
		}

		if ei != nil {
			if ei.taskList == nil {
				ei.taskList = make([]*JsScriptTask, 0)
			}
			ei.taskList = append(ei.taskList, &task)
		}

		return &task
	}); err != nil {
		return err
	}
	if err := register("seal.ext.removeTask", func(ei *ExtInfo, taskType string, key string) int {
		extName, err := resolveExtName(ei)
		if err != nil {
			panic(err)
		}
		taskType, key = normalizeTaskSelector(taskType, key)
		taskSet := make(map[*JsScriptTask]struct{})
		configKeySet := make(map[string]struct{})

		if ei != nil {
			for _, task := range ei.taskList {
				if matchTaskSelector(task, taskType, key) {
					taskSet[task] = struct{}{}
					if task.key != "" && task.taskType != "once" {
						configKeySet[task.key] = struct{}{}
					}
				}
			}
		}

		cm := d.ConfigManager
		cm.lock.RLock()
		pluginConfig := cm.Plugins[extName]
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

		if ei != nil && len(taskSet) > 0 {
			filtered := make([]*JsScriptTask, 0, len(ei.taskList))
			for _, task := range ei.taskList {
				if _, ok := taskSet[task]; ok {
					continue
				}
				filtered = append(filtered, task)
			}
			ei.taskList = filtered
		}

		if len(configKeySet) > 0 {
			keys := make([]string, 0, len(configKeySet))
			for cfgKey := range configKeySet {
				keys = append(keys, cfgKey)
			}
			d.ConfigManager.UnregisterConfig(extName, keys...)
		}

		return len(taskSet)
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

func quickJSJSONValue(v any) any {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func quickJSGroupSnapshot(group *GroupInfo) map[string]any {
	if group == nil {
		return nil
	}
	return map[string]any{
		"active":              group.Active,
		"groupId":             group.GroupID,
		"guildId":             group.GuildID,
		"channelId":           group.ChannelID,
		"groupName":           group.GroupName,
		"diceSideNum":         group.DiceSideNum,
		"diceSideExpr":        group.DiceSideExpr,
		"system":              group.System,
		"cocRuleIndex":        group.CocRuleIndex,
		"logCurName":          group.LogCurName,
		"logOn":               group.LogOn,
		"recentDiceSendTime":  group.RecentDiceSendTime,
		"showGroupWelcome":    group.ShowGroupWelcome,
		"groupWelcomeMessage": group.GroupWelcomeMessage,
		"enteredTime":         group.EnteredTime,
		"inviteUserId":        group.InviteUserID,
		"tmpPlayerNum":        group.TmpPlayerNum,
		"tmpExtList":          append([]string(nil), group.TmpExtList...),
		"defaultHelpGroup":    group.DefaultHelpGroup,
	}
}

func quickJSMessageSnapshot(msg *Message) map[string]any {
	if msg == nil {
		return nil
	}
	return map[string]any{
		"time":        msg.Time,
		"messageType": msg.MessageType,
		"groupId":     msg.GroupID,
		"guildId":     msg.GuildID,
		"channelId":   msg.ChannelID,
		"sender": map[string]any{
			"nickname": msg.Sender.Nickname,
			"userId":   msg.Sender.UserID,
		},
		"message":   msg.Message,
		"rawId":     quickJSJSONValue(msg.RawID),
		"platform":  msg.Platform,
		"groupName": msg.GroupName,
	}
}

func quickJSEndPointSnapshot(ep *EndPointInfo) any {
	if ep == nil {
		return nil
	}
	return quickJSJSONValue(ep.EndPointInfoBase)
}

func quickJSCmdArgsSnapshot(cmdArgs *CmdArgs) map[string]any {
	if cmdArgs == nil {
		return nil
	}
	return map[string]any{
		"command":                    cmdArgs.Command,
		"args":                       append([]string(nil), cmdArgs.Args...),
		"kwargs":                     quickJSJSONValue(cmdArgs.Kwargs),
		"atInfo":                     quickJSJSONValue(cmdArgs.At),
		"rawArgs":                    cmdArgs.RawArgs,
		"amIBeMentioned":             cmdArgs.AmIBeMentioned,
		"amIBeMentionedFirst":        cmdArgs.AmIBeMentionedFirst,
		"someoneBeMentionedButNotMe": cmdArgs.SomeoneBeMentionedButNotMe,
		"isSpaceBeforeArgs":          cmdArgs.IsSpaceBeforeArgs,
		"cleanArgs":                  cmdArgs.CleanArgs,
		"specialExecuteTimes":        cmdArgs.SpecialExecuteTimes,
		"rawText":                    cmdArgs.RawText,
	}
}

func quickJSCtxSnapshot(ctx *MsgContext) map[string]any {
	if ctx == nil {
		return nil
	}
	return map[string]any{
		"messageType":     ctx.MessageType,
		"group":           quickJSGroupSnapshot(ctx.Group),
		"player":          quickJSJSONValue(ctx.Player),
		"endPoint":        quickJSEndPointSnapshot(ctx.EndPoint),
		"isCurGroupBotOn": ctx.IsCurGroupBotOn,
		"isPrivate":       ctx.IsPrivate,
		"commandHideFlag": ctx.CommandHideFlag,
		"privilegeLevel":  ctx.PrivilegeLevel,
		"groupRoleLevel":  ctx.GroupRoleLevel,
		"delegateText":    ctx.DelegateText,
		"aliasPrefixText": ctx.AliasPrefixText,
	}
}

func quickJSBaseRuntime(ctx *MsgContext, msg *Message) map[string]any {
	runtime := map[string]any{
		"ctx":     ctx,
		"ctxData": quickJSCtxSnapshot(ctx),
		"msg":     msg,
		"msgData": quickJSMessageSnapshot(msg),
	}
	runtime["replyToSender"] = func(text string) {
		if ctx == nil || msg == nil {
			return
		}
		ReplyToSender(ctx, msg, text)
	}
	return runtime
}

func quickJSStringSliceValue(v any) []string {
	out := make([]string, 0)
	switch vv := v.(type) {
	case []string:
		for _, item := range vv {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
	case []any:
		for _, item := range vv {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func quickJSCallbackNames(v any) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range quickJSStringSliceValue(v) {
		out[item] = struct{}{}
	}
	return out
}

func bindQuickJSExtCallbacks(d *Dice, ext *ExtInfo, callbackSet map[string]struct{}) {
	if d == nil || ext == nil || len(callbackSet) == 0 {
		return
	}
	invoke := func(callbackName string, runtime map[string]any) {
		invoker, ok := d.ScriptEngine.(interface {
			InvokeStoredExtCallback(extName string, callbackName string, runtime map[string]any) error
		})
		if !ok {
			d.Logger.Errorf("QuickJS 扩展回调执行器不可用: %s.%s", ext.Name, callbackName)
			return
		}
		if err := invoker.InvokeStoredExtCallback(ext.Name, callbackName, runtime); err != nil {
			d.Logger.Errorf("QuickJS 扩展回调执行失败 %s.%s: %v", ext.Name, callbackName, err)
		}
	}
	if _, ok := callbackSet["onNotCommandReceived"]; ok {
		ext.OnNotCommandReceived = func(ctx *MsgContext, msg *Message) {
			invoke("onNotCommandReceived", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onCommandReceived"]; ok {
		ext.OnCommandReceived = func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) {
			runtime := quickJSBaseRuntime(ctx, msg)
			runtime["cmdArgs"] = cmdArgs
			runtime["cmdArgsData"] = quickJSCmdArgsSnapshot(cmdArgs)
			if cmdArgs != nil {
				runtime["getArgN"] = func(n int64) string { return cmdArgs.GetArgN(int(n)) }
				runtime["isArgEqual"] = func(n int64, ss []string) bool { return cmdArgs.IsArgEqual(int(n), ss...) }
				runtime["getKwargJSON"] = func(name string) string {
					raw, _ := json.Marshal(cmdArgs.GetKwarg(name))
					return string(raw)
				}
				runtime["getRestArgsFrom"] = func(index int64) string { return cmdArgs.GetRestArgsFrom(int(index)) }
			}
			invoke("onCommandReceived", runtime)
		}
	}
	if _, ok := callbackSet["onCommandOverride"]; ok {
		ext.OnCommandOverride = func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) bool {
			invoker, ok := d.ScriptEngine.(interface {
				InvokeStoredCommandOverride(extName string, runtime map[string]any) (bool, error)
			})
			if !ok {
				d.Logger.Errorf("QuickJS 指令覆盖执行器不可用: %s.onCommandOverride", ext.Name)
				return false
			}
			runtime := quickJSBaseRuntime(ctx, msg)
			runtime["cmdArgs"] = cmdArgs
			runtime["cmdArgsData"] = quickJSCmdArgsSnapshot(cmdArgs)
			if cmdArgs != nil {
				runtime["getArgN"] = func(n int64) string { return cmdArgs.GetArgN(int(n)) }
				runtime["isArgEqual"] = func(n int64, ss []string) bool { return cmdArgs.IsArgEqual(int(n), ss...) }
				runtime["getKwargJSON"] = func(name string) string {
					raw, _ := json.Marshal(cmdArgs.GetKwarg(name))
					return string(raw)
				}
				runtime["getRestArgsFrom"] = func(index int64) string { return cmdArgs.GetRestArgsFrom(int(index)) }
			}
			ret, err := invoker.InvokeStoredCommandOverride(ext.Name, runtime)
			if err != nil {
				d.Logger.Errorf("QuickJS 指令覆盖执行失败 %s.onCommandOverride: %v", ext.Name, err)
				return false
			}
			return ret
		}
	}
	if _, ok := callbackSet["onMessageReceived"]; ok {
		ext.OnMessageReceived = func(ctx *MsgContext, msg *Message) {
			invoke("onMessageReceived", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onMessageSend"]; ok {
		ext.OnMessageSend = func(ctx *MsgContext, msg *Message, flag string) {
			runtime := quickJSBaseRuntime(ctx, msg)
			runtime["flag"] = flag
			invoke("onMessageSend", runtime)
		}
	}
	if _, ok := callbackSet["onMessageDeleted"]; ok {
		ext.OnMessageDeleted = func(ctx *MsgContext, msg *Message) {
			invoke("onMessageDeleted", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onMessageEdit"]; ok {
		ext.OnMessageEdit = func(ctx *MsgContext, msg *Message) {
			invoke("onMessageEdit", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onGroupJoined"]; ok {
		ext.OnGroupJoined = func(ctx *MsgContext, msg *Message) {
			invoke("onGroupJoined", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onGroupMemberJoined"]; ok {
		ext.OnGroupMemberJoined = func(ctx *MsgContext, msg *Message) {
			invoke("onGroupMemberJoined", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onGuildJoined"]; ok {
		ext.OnGuildJoined = func(ctx *MsgContext, msg *Message) {
			invoke("onGuildJoined", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onBecomeFriend"]; ok {
		ext.OnBecomeFriend = func(ctx *MsgContext, msg *Message) {
			invoke("onBecomeFriend", quickJSBaseRuntime(ctx, msg))
		}
	}
	if _, ok := callbackSet["onPoke"]; ok {
		ext.OnPoke = func(ctx *MsgContext, event *events.PokeEvent) {
			runtime := map[string]any{
				"ctx":       ctx,
				"ctxData":   quickJSCtxSnapshot(ctx),
				"event":     event,
				"eventData": quickJSJSONValue(event),
			}
			invoke("onPoke", runtime)
		}
	}
	if _, ok := callbackSet["onGroupLeave"]; ok {
		ext.OnGroupLeave = func(ctx *MsgContext, event *events.GroupLeaveEvent) {
			runtime := map[string]any{
				"ctx":       ctx,
				"ctxData":   quickJSCtxSnapshot(ctx),
				"event":     event,
				"eventData": quickJSJSONValue(event),
			}
			invoke("onGroupLeave", runtime)
		}
	}
	if _, ok := callbackSet["getDescText"]; ok {
		ext.GetDescText = func(i *ExtInfo) string {
			invoker, ok := d.ScriptEngine.(interface {
				InvokeStoredGetDescText(extName string, extData map[string]any) (string, error)
			})
			if !ok {
				return GetExtensionDesc(i)
			}
			text, err := invoker.InvokeStoredGetDescText(ext.Name, extInfoToJSMap(i))
			if err != nil {
				d.Logger.Errorf("QuickJS 扩展描述回调执行失败 %s.getDescText: %v", ext.Name, err)
				return GetExtensionDesc(i)
			}
			if strings.TrimSpace(text) == "" {
				return GetExtensionDesc(i)
			}
			return text
		}
	}
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
		Aliases:     quickJSStringSliceValue(data["aliases"]),
		Author:      getString("author"),
		Version:     getString("version"),
		GetDescText: GetExtensionDesc,
		AutoActive:  getBool("autoActive", true),
		IsJsExt:     true,
		Brief:       "一个JS自定义扩展",
		Official:    getBool("official", false),
		ActiveWith:  quickJSStringSliceValue(data["activeWith"]),
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
	bindQuickJSExtCallbacks(d, ext, quickJSCallbackNames(data["__sdCallbacks"]))
	return ext, nil
}

func quickJSBoolLike(v any, defaultValue bool) bool {
	if v == nil {
		return defaultValue
	}
	switch vv := v.(type) {
	case bool:
		return vv
	case string:
		return strings.TrimSpace(vv) != ""
	case int:
		return vv != 0
	case int8:
		return vv != 0
	case int16:
		return vv != 0
	case int32:
		return vv != 0
	case int64:
		return vv != 0
	case uint:
		return vv != 0
	case uint8:
		return vv != 0
	case uint16:
		return vv != 0
	case uint32:
		return vv != 0
	case uint64:
		return vv != 0
	case float32:
		return vv != 0
	case float64:
		return vv != 0
	default:
		return true
	}
}

func invokeCmdItemWithJSEngine(d *Dice, item *CmdItemInfo, ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) (result CmdExecuteResult, err error) {
	if item == nil {
		return CmdExecuteResult{}, fmt.Errorf("nil command item")
	}
	if item.Solve == nil {
		return CmdExecuteResult{}, fmt.Errorf("command solve is nil: %s", item.Name)
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	result = item.Solve(ctx, msg, cmdArgs)
	return result, nil
}

func cmdExecuteResultToMap(ret CmdExecuteResult) map[string]any {
	return map[string]any{
		"matched":  ret.Matched,
		"solved":   ret.Solved,
		"showHelp": ret.ShowHelp,
	}
}

func buildQuickJSCmdInfo(d *Dice, extName string, cmdName string, rawCmd map[string]any) *CmdItemInfo {
	cmdInfo := &CmdItemInfo{
		Name:          cmdName,
		IsJsSolveFunc: true,
	}
	if rawCmd != nil {
		if shortHelp, ok := rawCmd["shortHelp"].(string); ok {
			cmdInfo.ShortHelp = shortHelp
		}
		if help, ok := rawCmd["help"].(string); ok {
			cmdInfo.Help = help
		}
		if allowDelegate, ok := rawCmd["allowDelegate"].(bool); ok {
			cmdInfo.AllowDelegate = allowDelegate
		}
		if disabledInPrivate, ok := rawCmd["disabledInPrivate"].(bool); ok {
			cmdInfo.DisabledInPrivate = disabledInPrivate
		}
		if enableExecuteTimesParse, ok := rawCmd["enableExecuteTimesParse"].(bool); ok {
			cmdInfo.EnableExecuteTimesParse = enableExecuteTimesParse
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
		if hasHelpFunc, ok := rawCmd["__sdHasHelpFunc"].(bool); ok && hasHelpFunc {
			cmdInfo.HelpFunc = func(isShort bool) string {
				invoker, ok := d.ScriptEngine.(interface {
					InvokeStoredCmdHelp(extName string, cmdName string, isShort bool) (string, error)
				})
				if !ok {
					d.Logger.Errorf("QuickJS 命令帮助执行器不可用: %s.%s", extName, cmdName)
					return ""
				}
				ret, err := invoker.InvokeStoredCmdHelp(extName, cmdName, isShort)
				if err != nil {
					d.Logger.Errorf("QuickJS 命令帮助执行失败 %s.%s: %v", extName, cmdName, err)
					return ""
				}
				return ret
			}
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
			"ctx":         ctx,
			"ctxData":     quickJSCtxSnapshot(ctx),
			"msg":         msg,
			"msgData":     quickJSMessageSnapshot(msg),
			"cmdArgs":     cmdArgs,
			"cmdArgsData": quickJSCmdArgsSnapshot(cmdArgs),
			"getArgN": func(n int64) string {
				if cmdArgs == nil {
					return ""
				}
				return cmdArgs.GetArgN(int(n))
			},
			"isArgEqual": func(n int64, ss []string) bool {
				if cmdArgs == nil {
					return false
				}
				return cmdArgs.IsArgEqual(int(n), ss...)
			},
			"getKwargJSON": func(name string) string {
				if cmdArgs == nil {
					return "null"
				}
				raw, _ := json.Marshal(cmdArgs.GetKwarg(name))
				return string(raw)
			},
			"getRestArgsFrom": func(index int64) string {
				if cmdArgs == nil {
					return ""
				}
				return cmdArgs.GetRestArgsFrom(int(index))
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
			if matched, ok := ret["matched"]; ok {
				result.Matched = quickJSBoolLike(matched, false)
			}
			if solved, ok := ret["solved"]; ok {
				result.Solved = quickJSBoolLike(solved, false)
			}
			if showHelp, ok := ret["showHelp"]; ok {
				result.ShowHelp = quickJSBoolLike(showHelp, false)
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
	cmdMap := map[string]any{}
	for cmdName, cmd := range ext.GetCmdMap() {
		if cmd == nil {
			continue
		}
		cmdObj := cmdItemInfoToJSMap(cmd)
		cmdObj["__sdHasSolve"] = cmd.Solve != nil
		cmdObj["__sdHasHelpFunc"] = cmd.HelpFunc != nil
		cmdMap[cmdName] = cmdObj
	}
	m := map[string]any{
		"name":       ext.Name,
		"aliases":    append([]string(nil), ext.Aliases...),
		"author":     ext.Author,
		"version":    ext.Version,
		"autoActive": ext.AutoActive,
		"isJsExt":    ext.IsJsExt,
		"brief":      ext.Brief,
		"official":   ext.Official,
		"activeWith": append([]string(nil), ext.ActiveWith...),
		"cmdMap":     cmdMap,
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

func cmdItemInfoToJSMap(ci *CmdItemInfo) map[string]any {
	if ci == nil {
		return nil
	}
	return map[string]any{
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
}

func cmdItemInfoToJSONString(ci *CmdItemInfo) string {
	if ci == nil {
		return "null"
	}
	m := cmdItemInfoToJSMap(ci)
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
	defer func() {
		if r := recover(); r != nil {
			d.ScriptEngine = nil
			d.Logger.Errorf("jsClear 发生panic: %v\n堆栈:\n%s", r, string(debug.Stack()))
			d.safeJSClearStateOnly("jsClear 清理")
		}
	}()
	d.disposeRetiredJSEngines("jsClear")
	if d.ScriptEngine != nil {
		if d.ScriptEngine.Name() == jsengine.EngineQuickJS {
			if quiescer, ok := d.ScriptEngine.(interface{ Quiesce() error }); ok {
				if err := quiescer.Quiesce(); err != nil {
					d.Logger.Warnf("QuickJS 引擎退役失败，尝试常规释放: %v", err)
					_ = d.ScriptEngine.Dispose()
				} else {
					// quickjs-go 在部分 teardown 路径上会直接导致进程退出。
					// 切换引擎时先静默退役并保留一个实例，延迟到下一次清理时再释放，
					// 避免在同一 teardown 路径上立即触发底层崩溃。
					d.RetiredJSEngines = []jsengine.Engine{d.ScriptEngine}
				}
			} else {
				_ = d.ScriptEngine.Dispose()
			}
		} else {
			_ = d.ScriptEngine.Dispose()
		}
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
}

func isScriptFile(filename string) bool {
	temp := strings.ToLower(filepath.Ext(filename))
	return temp == ".js" || temp == ".ts"
}

func jsCacheKey(path string) string {
	return filepath.ToSlash(path)
}

func loadJsMetaCache() *jsMetaCache {
	cachePath := filepath.Join(jsCacheDir, jsMetaCacheFile)
	var cache jsMetaCache
	if err := loadGobCacheFile(cachePath, &cache); err != nil {
		return nil
	}
	if cache.Version != jsMetaCacheVersion {
		return nil
	}
	if cache.Files == nil {
		cache.Files = map[string]jsMetaCacheEntry{}
	}
	return &cache
}

func saveJsMetaCache(cache *jsMetaCache) {
	if cache == nil {
		return
	}
	cachePath := filepath.Join(jsCacheDir, jsMetaCacheFile)
	_ = saveGobCacheFile(cachePath, cache)
}

func buildJsScriptInfoFromCache(d *Dice, path string, entry jsMetaCacheEntry) (*JsScriptInfo, error) {
	if entry.ParseErr != "" {
		return nil, errors.New(entry.ParseErr)
	}
	jsInfo := &JsScriptInfo{
		Name:         entry.Meta.Name,
		Filename:     path,
		InstallTime:  entry.InstallTime,
		Version:      entry.Meta.Version,
		Author:       entry.Meta.Author,
		License:      entry.Meta.License,
		HomePage:     entry.Meta.HomePage,
		Desc:         entry.Meta.Desc,
		UpdateTime:   entry.Meta.UpdateTime,
		UpdateUrls:   entry.Meta.UpdateUrls,
		Etag:         entry.Meta.Etag,
		Official:     entry.Meta.Official,
		signStatus:   entry.Meta.SignStatus,
		Builtin:      entry.Builtin,
		needCompiled: entry.Meta.NeedCompiled,
		StoreID:      entry.Meta.StoreID,
	}
	if jsInfo.Name == "" {
		jsInfo.Name = filepath.Base(path)
	}
	for _, dep := range entry.Meta.Depends {
		c, err := semver.NewConstraint(dep.Constraint)
		if err != nil {
			return nil, err
		}
		jsInfo.Depends = append(jsInfo.Depends, JsScriptDepends{
			Author:     dep.Author,
			Name:       dep.Name,
			Constraint: c,
			RawKey:     dep.RawKey,
		})
	}
	jsInfo.Enable = !(&d.Config).DisabledJsScripts[jsInfo.Name]
	d.JsScriptList = append(d.JsScriptList, jsInfo)
	return jsInfo, nil
}

func buildJsMetaCacheEntry(path string, info fs.FileInfo, jsInfo *JsScriptInfo, builtin bool, parseErr error) jsMetaCacheEntry {
	entry := jsMetaCacheEntry{
		Path:        filepath.ToSlash(path),
		Size:        info.Size(),
		ModTime:     info.ModTime().Unix(),
		Builtin:     builtin,
		InstallTime: info.ModTime().Unix(),
	}
	if parseErr != nil {
		entry.ParseErr = parseErr.Error()
		return entry
	}
	if jsInfo == nil {
		return entry
	}
	entry.Meta = jsMetaInfo{
		Name:         jsInfo.Name,
		Version:      jsInfo.Version,
		Author:       jsInfo.Author,
		License:      jsInfo.License,
		HomePage:     jsInfo.HomePage,
		Desc:         jsInfo.Desc,
		UpdateTime:   jsInfo.UpdateTime,
		UpdateUrls:   jsInfo.UpdateUrls,
		Etag:         jsInfo.Etag,
		Official:     jsInfo.Official,
		SignStatus:   jsInfo.signStatus,
		NeedCompiled: jsInfo.needCompiled,
		StoreID:      jsInfo.StoreID,
	}
	for _, dep := range jsInfo.Depends {
		entry.Meta.Depends = append(entry.Meta.Depends, jsMetaDepends{
			Author:     dep.Author,
			Name:       dep.Name,
			Constraint: dep.Constraint.String(),
			RawKey:     dep.RawKey,
		})
	}
	return entry
}

func (d *Dice) JsLoadScripts() {
	defer func() {
		if r := recover(); r != nil {
			d.Logger.Errorf("JsLoadScripts 发生panic: %v\n堆栈:\n%s", r, string(debug.Stack()))
			if d.JsLoadingScript != nil {
				d.JsLoadingScript.ErrText = fmt.Sprintf("panic: %v", r)
				d.JsLoadingScript.Enable = false
			}
			d.JsLoadingScript = nil
		}
	}()

	d.JsScriptList = []*JsScriptInfo{}

	path := filepath.Join(d.BaseConfig.DataDir, "scripts")
	builtinPath := filepath.Join(path, "_builtin")

	metaCache := loadJsMetaCache()
	newCache := &jsMetaCache{Version: jsMetaCacheVersion, Files: map[string]jsMetaCacheEntry{}}

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
					_ = os.WriteFile(target, scriptData, 0o644) //nolint:gosec
				}
			}
		}
	}

	var jsInfos []*JsScriptInfo
	// 解析内置脚本
	_ = filepath.Walk(builtinPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			d.Logger.Errorf("读取内置脚本目录失败(%s): %v", path, err)
			return nil
		}
		if info == nil {
			d.Logger.Warnf("读取内置脚本目录得到空文件信息: %s", path)
			return nil
		}
		if isScriptFile(path) {
			d.Logger.Info("正在读取内置脚本: ", path)
			key := jsCacheKey(path)
			if metaCache != nil {
				if entry, ok := metaCache.Files[key]; ok &&
					entry.Builtin && entry.Size == info.Size() && entry.ModTime == info.ModTime().Unix() {
					if entry.Meta.SignStatus != OfficialSign {
						d.Logger.Warnf("内置脚本「%s」校验未通过，拒绝加载", path)
						newCache.Files[key] = entry
						return nil
					}
					jsInfo, err := buildJsScriptInfoFromCache(d, "./"+path, entry)
					if err == nil {
						jsInfos = append(jsInfos, jsInfo)
						if len(jsInfo.StoreID) > 0 {
							d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
						}
						newCache.Files[key] = entry
						return nil
					}
					entry.ParseErr = err.Error()
					newCache.Files[key] = entry
					d.Logger.Error("读取内置脚本失败(错误依赖)", err.Error())
					return nil
				}
			}

			data, err := os.ReadFile(path) //nolint:gosec
			if err != nil {
				d.Logger.Error("读取内置脚本失败(无法访问): ", err.Error())
				return nil
			}
			ok, signStatus := CheckJsSign(data)
			if !ok {
				d.Logger.Warnf("内置脚本「%s」校验未通过，拒绝加载", path)
				entry := buildJsMetaCacheEntry(path, info, nil, true, errors.New("signature invalid"))
				entry.Meta.SignStatus = signStatus
				newCache.Files[key] = entry
				return nil
			}
			jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, true)
			newCache.Files[key] = buildJsMetaCacheEntry(path, info, jsInfo, true, err)
			if err != nil {
				d.Logger.Error("读取内置脚本失败(错误依赖)", err.Error())
				return nil
			}
			jsInfos = append(jsInfos, jsInfo)
			if len(jsInfo.StoreID) > 0 {
				d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
			}
		}
		return nil
	})

	// 解析第三方脚本
	_ = filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			d.Logger.Errorf("读取脚本目录失败(%s): %v", path, err)
			return nil
		}
		if info == nil {
			d.Logger.Warnf("读取脚本目录得到空文件信息: %s", path)
			return nil
		}
		if info.IsDir() && info.Name() == "_builtin" {
			return fs.SkipDir
		}
		if isScriptFile(path) {
			d.Logger.Info("正在读取脚本: ", path)
			key := jsCacheKey(path)
			if metaCache != nil {
				if entry, ok := metaCache.Files[key]; ok &&
					!entry.Builtin && entry.Size == info.Size() && entry.ModTime == info.ModTime().Unix() {
					jsInfo, err := buildJsScriptInfoFromCache(d, "./"+path, entry)
					if err == nil {
						jsInfos = append(jsInfos, jsInfo)
						if len(jsInfo.StoreID) > 0 {
							d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
						}
						newCache.Files[key] = entry
						return nil
					}
					entry.ParseErr = err.Error()
					newCache.Files[key] = entry
					d.Logger.Error("读取脚本失败(错误依赖)", err.Error())
					return nil
				}
			}

			data, err := os.ReadFile(path) //nolint:gosec
			if err != nil {
				d.Logger.Error("读取脚本失败(无法访问): ", err.Error())
				return nil
			}
			jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, false)
			newCache.Files[key] = buildJsMetaCacheEntry(path, info, jsInfo, false, err)
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

	saveJsMetaCache(newCache)

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

		func(info *JsScriptInfo) {
			defer func() {
				if r := recover(); r != nil {
					errText := fmt.Sprintf("panic: %v", r)
					if info != nil {
						info.ErrText = errText
						info.Enable = false
					}
					d.JsLoadingScript = nil
					d.Logger.Errorf("脚本加载异常(已隔离): %s\n堆栈:\n%s", errText, string(debug.Stack()))
				}
			}()
			d.JsLoadScriptRaw(info)
		}(jsInfo)
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

	// 仅在“配置与当前都为 quickjs 且已有引擎实例”时走软重置；
	// 其余情况走 JsInit 完整重建。
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
		desired = "quickjs"
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

type jsMetaDepends struct {
	Author     string `json:"author"`
	Name       string `json:"name"`
	Constraint string `json:"constraint"`
	RawKey     string `json:"rawKey"`
}

type jsMetaInfo struct {
	Name         string          `json:"name"`
	Version      string          `json:"version"`
	Author       string          `json:"author"`
	License      string          `json:"license"`
	HomePage     string          `json:"homepage"`
	Desc         string          `json:"desc"`
	UpdateTime   int64           `json:"updateTime"`
	UpdateUrls   []string        `json:"updateUrls"`
	Etag         string          `json:"etag"`
	Official     bool            `json:"official"`
	SignStatus   SignStatus      `json:"signStatus"`
	Depends      []jsMetaDepends `json:"depends"`
	NeedCompiled bool            `json:"needCompiled"`
	StoreID      string          `json:"storeId"`
}

type jsMetaCacheEntry struct {
	Path        string     `json:"path"`
	Size        int64      `json:"size"`
	ModTime     int64      `json:"modTime"`
	Builtin     bool       `json:"builtin"`
	InstallTime int64      `json:"installTime"`
	ParseErr    string     `json:"parseErr"`
	Meta        jsMetaInfo `json:"meta"`
}

type jsMetaCache struct {
	Version int                         `json:"version"`
	Files   map[string]jsMetaCacheEntry `json:"files"`
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
	defer func() {
		if r := recover(); r != nil {
			errText := fmt.Sprintf("panic: %v", r)
			scriptName := "<nil>"
			if jsInfo != nil {
				scriptName = jsInfo.Filename
				jsInfo.ErrText = errText
				jsInfo.Enable = false
			}
			d.JsLoadingScript = nil
			d.Logger.Errorf("读取脚本失败(运行崩溃): %s: %s\n堆栈:\n%s", scriptName, errText, string(debug.Stack()))
		}
	}()

	if jsInfo == nil {
		d.Logger.Error("读取脚本失败: jsInfo 为 nil")
		return
	}

	var err error
	if jsInfo.Enable {
		d.JsLoadingScript = jsInfo
		defer func() { d.JsLoadingScript = nil }()
		var targetPath string
		var cleanup bool
		if jsInfo.needCompiled {
			d.Logger.Infof("脚本<%s>正在经过编译处理……", jsInfo.Name)
			targetPath, cleanup, err = tsScriptCompile(jsInfo.Filename)
			if cleanup {
				defer func(name string) {
					_ = os.Remove(name)
				}(targetPath)
			}
		} else {
			targetPath = jsInfo.Filename
		}
		if err == nil {
			err = d.jsRequireModule(targetPath)
		}
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

func (d *Dice) jsRequireModule(targetPath string) (err error) {
	if d.ScriptEngine == nil {
		return errors.New("QuickJS 引擎未初始化")
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("QuickJS Require 执行panic(%s): %v", targetPath, r)
		}
	}()
	return d.ScriptEngine.Require(targetPath)
}

func tsScriptCompile(path string) (string, bool, error) {
	script, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	compiled := esbuild.Transform(string(script), esbuild.TransformOptions{
		Loader: esbuild.LoaderTS,
	})
	if len(compiled.Errors) > 0 {
		var msg strings.Builder
		for _, e := range compiled.Errors {
			msg.WriteString(e.Text) // FIXME 优化错误信息展示
		}
		return "", false, errors.New(msg.String())
	}
	sum := sha256.Sum256(append([]byte(fmt.Sprintf("ts-cache:%d;", tsCacheVersion)), script...))
	filename := hex.EncodeToString(sum[:]) + ".js"
	cachePath := filepath.Join(tsCacheDir, filename)
	if _, statErr := os.Stat(cachePath); statErr == nil {
		return cachePath, false, nil
	}
	if mkErr := os.MkdirAll(tsCacheDir, 0o755); mkErr != nil {
		return "", false, mkErr
	}
	tmpFile, err := os.CreateTemp(tsCacheDir, "compiled-*.js")
	if err != nil {
		return "", false, err
	}
	if _, err := tmpFile.Write(compiled.Code); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // temp file path is controlled
		return "", false, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name()) //nolint:gosec // temp file path is controlled
		return "", false, err
	}
	if err := os.Rename(tmpFile.Name(), cachePath); err != nil { //nolint:gosec // temp file path is controlled
		//nolint:nilerr // fallback to temp file path if rename fails
		return tmpFile.Name(), true, nil
	}
	return cachePath, false, nil
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
	// 更新插件，验证文件路径在脚本目录内以防止路径穿越
	scriptsDirAbs, err := filepath.Abs(filepath.Join(d.BaseConfig.DataDir, "scripts"))
	if err != nil {
		return fmt.Errorf("获取脚本目录绝对路径失败: %w", err)
	}
	filenameAbs, err := filepath.Abs(jsScriptInfo.Filename)
	if err != nil {
		return fmt.Errorf("获取脚本文件绝对路径失败: %w", err)
	}
	if !strings.HasPrefix(filenameAbs, scriptsDirAbs+string(filepath.Separator)) {
		return fmt.Errorf("script filename %q is outside scripts directory", jsScriptInfo.Filename)
	}
	err = os.WriteFile(filenameAbs, newData, 0o755) //nolint:gosec
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
	onceAt   time.Time
	timer    *time.Timer
	task     func(JsScriptTaskCtx)
	entryID  *cron.EntryID
	lock     *sync.Mutex

	stateLock sync.Mutex
	logger    *zap.SugaredLogger
}

type JsScriptTaskCtx struct {
	Now int64  `jsbind:"now"`
	Key string `jsbind:"key"`
}

type JsScriptTaskInfo struct {
	TaskType string `jsbind:"taskType"`
	Key      string `jsbind:"key"`
	Value    string `jsbind:"value"`
	Active   bool   `jsbind:"active"`
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
	t.stateLock.Lock()
	defer t.stateLock.Unlock()

	switch t.taskType {
	case "once":
		if t.timer != nil {
			return true
		}
		delay := time.Until(t.onceAt)
		if delay < 0 {
			delay = 0
		}
		var timer *time.Timer
		timer = time.AfterFunc(delay, func() {
			t.run()
			t.stateLock.Lock()
			if t.timer == timer {
				t.timer = nil
			}
			t.stateLock.Unlock()
		})
		t.timer = timer
		return true
	case "cron", "daily":
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
	default:
		return false
	}
}

func (t *JsScriptTask) Off() bool {
	t.stateLock.Lock()
	defer t.stateLock.Unlock()

	switch t.taskType {
	case "once":
		if t.timer == nil {
			return true
		}
		t.timer.Stop()
		t.timer = nil
		return true
	case "cron", "daily":
		if t.entryID == nil {
			return true
		}
		t.cron.Remove(*t.entryID)
		t.entryID = nil
		return true
	default:
		return false
	}
}

func (t *JsScriptTask) IsActive() bool {
	t.stateLock.Lock()
	defer t.stateLock.Unlock()

	switch t.taskType {
	case "once":
		return t.timer != nil
	case "cron", "daily":
		return t.entryID != nil
	default:
		return false
	}
}

func (t *JsScriptTask) reset(expr string) error {
	var wasScheduled bool
	t.stateLock.Lock()
	if t.taskType == "once" {
		wasScheduled = t.timer != nil
	} else {
		wasScheduled = t.entryID != nil
	}
	t.stateLock.Unlock()

	if wasScheduled {
		t.Off()
	}

	t.rawValue = expr
	shouldOn := wasScheduled
	switch t.taskType {
	case "cron":
		cronExpr, err := parseTaskCronExpr(expr)
		if err != nil {
			return err
		}
		t.cronExpr = cronExpr
	case "daily":
		cronExpr, err := parseTaskTime(expr)
		if err != nil {
			return err
		}
		t.cronExpr = cronExpr
	case "once":
		onceAt, normalizedExpr, err := parseTaskOnceExpr(expr)
		if err != nil {
			return err
		}
		t.onceAt = onceAt
		t.rawValue = normalizedExpr
		shouldOn = true // once 任务重置后应重新挂载一次执行
	default:
		return fmt.Errorf("unknown task type %s", t.taskType)
	}

	if shouldOn && !t.On() {
		return errors.New("重新注册任务失败")
	}
	return nil
}

func parseTaskCronExpr(expr string) (string, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", errors.New("cron 表达式不能为空")
	}

	if strings.HasPrefix(expr, "@") {
		lowerExpr := strings.ToLower(expr)
		switch lowerExpr {
		case "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly":
			if _, err := taskCronParser.Parse(lowerExpr); err != nil {
				return "", fmt.Errorf("cron 描述符解析失败: %w", err)
			}
			return lowerExpr, nil
		default:
			// 向后兼容 @every 语法
			fields := strings.Fields(lowerExpr)
			if len(fields) == 2 && fields[0] == "@every" {
				normalized := strings.Join(fields, " ")
				if _, err := taskCronParser.Parse(normalized); err != nil {
					return "", fmt.Errorf("cron 描述符解析失败: %w", err)
				}
				return normalized, nil
			}
			return "", errors.New("仅支持 @yearly/@annually/@monthly/@weekly/@daily/@midnight/@hourly（以及兼容 @every）")
		}
	}

	fields := strings.Fields(expr)
	if len(fields) != 5 && len(fields) != 6 {
		return "", fmt.Errorf("cron 表达式仅支持 5 位或 6 位(含秒)，当前为 %d 位", len(fields))
	}

	normalized := strings.Join(fields, " ")
	if _, err := taskCronParser.Parse(normalized); err != nil {
		return "", fmt.Errorf("cron 表达式解析失败: %w", err)
	}

	return normalized, nil
}

func parseTaskOnceExpr(expr string) (time.Time, string, error) {
	const maxDelayMs int64 = int64(365*24*time.Hour) / int64(time.Millisecond)
	const maxPastDuration = 365 * 24 * time.Hour

	expr = strings.TrimSpace(expr)
	if expr == "" {
		return time.Time{}, "", errors.New("once 表达式不能为空")
	}

	delayOrTs, err := strconv.ParseInt(expr, 10, 64)
	if err != nil {
		return time.Time{}, "", errors.New("once 仅支持毫秒延迟或 13 位毫秒时间戳")
	}
	if delayOrTs < 0 {
		return time.Time{}, "", errors.New("once 不支持负数")
	}

	now := time.Now()
	digitLen := len(strings.TrimLeft(expr, "+-"))
	isTimestamp := digitLen == 13

	// 智能判断：非13位但超过1年延迟时，优先尝试按时间戳解释。
	if !isTimestamp && delayOrTs > maxDelayMs {
		ts := time.UnixMilli(delayOrTs)
		if ts.After(now.Add(-maxPastDuration)) {
			isTimestamp = true
		} else {
			return time.Time{}, "", errors.New("once 延迟超过1年，请使用13位毫秒时间戳")
		}
	}

	var executeAt time.Time
	if isTimestamp {
		executeAt = time.UnixMilli(delayOrTs)
	} else {
		executeAt = now.Add(time.Duration(delayOrTs) * time.Millisecond)
	}
	return executeAt, strconv.FormatInt(executeAt.UnixMilli(), 10), nil
}

func normalizeTaskSelector(taskType string, key string) (string, string) {
	taskType = strings.ToLower(strings.TrimSpace(taskType))
	if taskType == "" {
		taskType = "*"
	}
	key = strings.TrimSpace(key)
	if key == "" {
		key = "*"
	}
	return taskType, key
}

func taskTypeMatched(selector string, taskType string) bool {
	return selector == "*" || selector == strings.ToLower(taskType)
}

func keyMatched(selector string, key string) bool {
	return selector == "*" || selector == key
}

func matchTaskSelector(task *JsScriptTask, taskType string, key string) bool {
	if task == nil {
		return false
	}
	return taskTypeMatched(taskType, task.taskType) && keyMatched(key, task.key)
}

func configTypeToTaskType(configType string) (string, bool) {
	switch configType {
	case "task:cron":
		return "cron", true
	case "task:daily":
		return "daily", true
	case "task:once":
		return "once", true
	default:
		return "", false
	}
}

func removeTaskFromList(taskList []*JsScriptTask, target *JsScriptTask) []*JsScriptTask {
	if len(taskList) == 0 || target == nil {
		return taskList
	}
	filtered := make([]*JsScriptTask, 0, len(taskList))
	for _, task := range taskList {
		if task != target {
			filtered = append(filtered, task)
		}
	}
	return filtered
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
