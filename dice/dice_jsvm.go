package dice

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
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

	"Scardice-core/static"
	"Scardice-core/utils/crypto"

	sealcrypto "Scardice-core/utils/plugin/crypto"
	sealws "Scardice-core/utils/plugin/websocket"
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

type JsDangerousAPIUsage struct {
	ID                string                     `json:"id"`
	Name              string                     `json:"name"`
	Description       string                     `json:"description"`
	Risk              string                     `json:"risk"`
	Occurrences       []JsDangerousAPIOccurrence `json:"occurrences"`
	ReferencedMembers []string                   `json:"referencedMembers"`
}

type JsDangerousAPIOccurrence struct {
	Line              int    `json:"line"`
	Column            int    `json:"column"`
	Kind              string `json:"kind"`
	Member            string `json:"member"`
	Access            string `json:"access"`
	MemberDescription string `json:"memberDescription"`
}

type jsDangerousAPIRule struct {
	ID          string
	Name        string
	Description string
	Risk        string
	Pattern     *regexp.Regexp
}

func normalizeDangerousAPIOccurrences(items []JsDangerousAPIOccurrence) []JsDangerousAPIOccurrence {
	if len(items) == 0 {
		return []JsDangerousAPIOccurrence{}
	}
	out := make([]JsDangerousAPIOccurrence, 0, len(items))
	for _, item := range items {
		out = append(out, JsDangerousAPIOccurrence{
			Line:              item.Line,
			Column:            item.Column,
			Kind:              item.Kind,
			Member:            item.Member,
			Access:            item.Access,
			MemberDescription: item.MemberDescription,
		})
	}
	return out
}

func normalizeDangerousAPIUsages(items []JsDangerousAPIUsage) []JsDangerousAPIUsage {
	if len(items) == 0 {
		return []JsDangerousAPIUsage{}
	}
	out := make([]JsDangerousAPIUsage, 0, len(items))
	for _, item := range items {
		usage := JsDangerousAPIUsage{
			ID:                item.ID,
			Name:              item.Name,
			Description:       item.Description,
			Risk:              item.Risk,
			Occurrences:       normalizeDangerousAPIOccurrences(item.Occurrences),
			ReferencedMembers: []string{},
		}
		if len(item.ReferencedMembers) > 0 {
			usage.ReferencedMembers = append(usage.ReferencedMembers, item.ReferencedMembers...)
		}
		out = append(out, usage)
	}
	return out
}

var jsDangerousAPIRules = []jsDangerousAPIRule{
	{
		ID:          "seal.inst",
		Name:        "seal.inst",
		Description: "向脚本暴露核心 Dice 实例。",
		Risk:        "可直接访问核心导出方法，可能修改配置、增删骰主、重载或关闭 JS 环境，并读写运行时状态。",
		Pattern:     regexp.MustCompile(`\bseal(?:\s*\?\s*\.\s*|\s*\.\s*)inst\b|\bseal(?:\s*\?\s*\.\s*|\s*)\[\s*["']inst["']\s*\]`),
	},
}

var sealInstMemberDescriptions = map[string]string{
	"ImSession":                      "当前 IM 会话对象，包含端点、群组会话和消息处理运行态。",
	"imSession":                      "当前 IM 会话对象，包含端点、群组会话和消息处理运行态。",
	"CmdMap":                         "核心命令映射表，包含已注册的命令项。",
	"ExtList":                        "当前扩展列表，包含已注册扩展对象。",
	"ExtRegistry":                    "扩展注册表，用于按名称或别名索引扩展。",
	"ActiveWithGraph":                "扩展开关联动图，用于处理 ActiveWith 依赖关系。",
	"ActiveWithGraphMu":              "保护扩展开关联动图的读写锁。",
	"ExtRegistryVersion":             "扩展注册表版本号，扩展变更时递增。",
	"RollParser":                     "骰点表达式解析器实例。",
	"LastUpdatedTime":                "最近一次标记为已修改的时间戳。",
	"TextMap":                        "当前文本模板映射表。",
	"BaseConfig":                     "基础配置对象，包含实例名和数据目录等基础信息。",
	"DBOperator":                     "数据库操作器，用于访问底层数据库。",
	"Logger":                         "核心日志记录器。",
	"LogWriter":                      "供 UI 使用的日志写入器。",
	"IsDeckLoading":                  "当前是否正在加载牌堆。",
	"DeckList":                       "当前牌堆列表。",
	"deckList":                       "当前牌堆列表。",
	"CommandPrefix":                  "当前命令前缀列表，例如 .、。等，会影响命令解析入口。",
	"commandPrefix":                  "当前命令前缀列表，例如 .、。等，会影响命令解析入口。",
	"DiceMasters":                    "当前骰主列表。改写后可直接影响管理权限。",
	"diceMasters":                    "当前骰主列表。改写后可直接影响管理权限。",
	"MasterUnlockCode":               "当前骰主解锁码。",
	"MasterUnlockCodeTime":           "当前骰主解锁码的更新时间。",
	"CustomReplyConfig":              "自定义回复配置列表。",
	"TextMapRaw":                     "原始文本模板配置。",
	"TextMapHelpInfo":                "文本模板帮助信息映射。",
	"TextMapCompatible":              "文本模板兼容层映射。",
	"ConfigManager":                  "插件配置管理器。",
	"Parent":                         "所属 DiceManager 实例。",
	"CocExtraRules":                  "COC 额外规则映射。",
	"Cron":                           "核心 cron 调度器。",
	"AliveNoticeEntry":               "存活通知任务的 cron 条目 ID。",
	"JsPrinter":                      "JS 控制台输出记录器。",
	"ExtLoopManager":                 "JS 事件循环管理器。",
	"JsScriptList":                   "当前加载的 JS 脚本元数据列表。",
	"JsScriptCron":                   "JS 脚本专用 cron 调度器。",
	"JsScriptCronLock":               "JS 脚本 cron 调度器的互斥锁。",
	"JsReloadLock":                   "JS 重载锁，用于避免并发重载。",
	"JsBuiltinDigestSet":             "内置脚本摘要表，用于判断内置脚本是否被更新。",
	"JsLoadingScript":                "当前正在加载的脚本元数据。",
	"GameSystemMap":                  "游戏系统模板映射。",
	"RunAfterLoaded":                 "核心加载完成后待执行的回调列表。",
	"UIEndpoint":                     "UI 使用的端点信息。",
	"CensorManager":                  "敏感词审查管理器。",
	"AttrsManager":                   "属性管理器。",
	"Config":                         "核心配置对象，包含 JS 开关、邮件、日志、风控等大量运行配置。",
	"AdvancedConfig":                 "高级配置对象，包含危险开关和跑团日志后端等高级设置。",
	"PublicDice":                     "公骰客户端对象，用于与公骰服务端通信。",
	"PublicDiceTimerId":              "公骰心跳任务的 cron 条目 ID。",
	"ContainerMode":                  "当前是否处于容器模式。",
	"IsAlreadyLoadConfig":            "核心配置是否已完成加载。",
	"SaveDatabaseInsertCheckMapFlag": "数据库插入检查表的初始化标记。",
	"SaveDatabaseInsertCheckMap":     "数据库插入检查映射。",
	"StoreManager":                   "扩展商店管理器。",
	"JsExtRegistry":                  "JS 扩展真实注册表。",
	"ExtUpdateTime":                  "扩展变更时间戳，用于触发延迟更新。",
	"JsReloading":                    "当前是否正在重载 JS 扩展。",
	"DirtyGroups":                    "脏群组列表，用于保存优化。",

	"MarkModified":                  "标记核心状态已修改，更新时间戳以触发后续保存。",
	"StartStartupJsLoad":            "在启动阶段异步开始加载 JS 脚本。",
	"WaitStartupJsLoaded":           "等待启动阶段的 JS 脚本加载完成。",
	"CocExtraRulesAdd":              "添加一条 COC 额外规则。",
	"Init":                          "初始化核心实例，包括配置、扩展、调度器和各类管理器。",
	"ExtFind":                       "按名称或别名查找扩展。",
	"ExtAliasToName":                "将扩展别名转换成主扩展名。",
	"ExtRemove":                     "移除一个扩展。",
	"MasterRefresh":                 "整理骰主列表并去重。",
	"MasterAdd":                     "向骰主列表中新增一项，可能直接提升管理权限。",
	"MasterCheck":                   "检查某个群组 ID 或用户 ID 是否拥有骰主权限。",
	"MasterRemove":                  "从骰主列表中移除一项。",
	"UnlockCodeUpdate":              "刷新或生成骰主解锁码。",
	"UnlockCodeVerify":              "校验给定解锁码是否有效。",
	"IsMaster":                      "检查某个统一 ID 是否属于骰主。",
	"ApplyAliveNotice":              "重建并应用存活通知定时任务。",
	"GameSystemTemplateAddEx":       "添加或覆盖一个游戏系统模板。",
	"GameSystemTemplateAdd":         "添加一个游戏系统模板，已存在时不会覆盖。",
	"ResetQuitInactiveCron":         "重建退群判定的定时任务。",
	"PublicDiceEndpointRefresh":     "向公骰服务刷新端点在线信息。",
	"PublicDiceInfoRegister":        "向公骰服务注册或更新公骰信息。",
	"PublicDiceSetupTick":           "重建公骰心跳定时更新。",
	"PublicDiceSetup":               "初始化公骰客户端并完成注册、端点刷新与心跳配置。",
	"StoreSetup":                    "初始化扩展商店管理器。",
	"NoticeForEveryEndpoint":        "向各端点发送通知消息。",
	"RegisterBuiltinExt":            "注册内置扩展。",
	"RegisterBuiltinSystemTemplate": "注册内置游戏系统模板。",
	"RegisterExtension":             "向核心注册新的扩展对象，直接影响扩展系统。",
	"GetExtDataDir":                 "返回指定扩展的数据目录路径，并在必要时创建目录。",
	"GetDiceDataPath":               "返回核心数据目录下指定名称对应的路径。",
	"GetExtConfigFilePath":          "返回指定扩展配置文件的完整路径。",
	"JsInit":                        "初始化并重建整个 JS 运行环境。",
	"JsShutdown":                    "关闭 JS 环境。",
	"JsLoadScripts":                 "扫描脚本目录并加载脚本元数据与脚本内容。",
	"JsReload":                      "重建并重载整个 JS 环境。",
	"JsExtSettingVacuum":            "清理已删除脚本对应的插件配置。该方法已标记为弃用且存在已知问题。",
	"JsParseMeta":                   "解析脚本文件的元数据头和签名信息。",
	"JsLoadScriptRaw":               "加载并执行单个脚本文件。",
	"JsCheckUpdate":                 "检查某个 JS 脚本是否存在更新。",
	"JsUpdate":                      "应用某个 JS 脚本的更新文件。",
	"JsDownload":                    "下载 JS 脚本或其更新文件。",
	"GenerateTextMap":               "根据原始配置重建文本模板映射。",
	"SaveText":                      "将文本模板配置落盘保存。",
	"ApplyExtDefaultSettings":       "应用扩展默认设置。",
	"Save":                          "将当前配置和高级配置落盘保存。",
	"CanSendMail":                   "检查邮件配置是否完整可用。",
	"SendMail":                      "按当前邮件配置发送通知邮件。",
	"SendMailRow":                   "直接发送邮件，可指定主题、收件人、正文和附件。",
	"GetBanList":                    "获取当前黑名单/信任列表。",
	"NewCensorManager":              "初始化敏感词审查管理器。",
	"CensorMsg":                     "执行一条消息的敏感词审查。",
	"DeckCheckUpdate":               "检查某个牌堆是否存在更新。",
	"DeckUpdate":                    "应用某个牌堆更新文件。",
	"DeckDownload":                  "下载牌堆或其更新文件。",
}

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

func (p *PrinterFunc) Error(s string) { p.doRecord("error", s); p.d.Logger.Error(s) }

func (d *Dice) JsInit() {
	// 读取官方 Mod 公钥
	if pub, err := static.Scripts.ReadFile("scripts/seal_mod.public.pem"); err == nil && len(pub) > 0 {
		OfficialModPublicKey = string(pub)
	}
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

	d.JsScriptCron = cron.New(cron.WithParser(taskCronParser))
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

			task := JsScriptTask{cron: scriptCron, key: key, task: fn, lock: ei.dice.JsScriptCronLock, logger: ei.dice.Logger}
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

		// 暴露 Dice 实例会让脚本直接访问大量核心导出方法，因此必须由显式危险开关控制。
		if d.AdvancedConfig.ExposeDangerousSealInst {
			_ = seal.Set("inst", exposeDangerousJSValue(vm, d))
			d.JsSealInstExposed = true
		}
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
	d.Logger.Info("已加载JS环境")
	d.MarkModified()
	d.Save(false)
}

func (d *Dice) JsShutdown() {
	(&d.Config).JsEnable = false
	d.jsClear()
	d.Logger.Info("已关闭JS环境")
	d.MarkModified()
	d.Save(false)
}

func (d *Dice) jsClear() {
	// Wrapper 架构：不再调用 ExtRemove，只清空 JsExtRegistry
	// 注意：不标记 wrapper 为 IsDeleted，否则重载期间消息到达会导致 wrapper 被移除
	// IsDeleted 只在 JsDelete/ExtRemove（永久删除脚本）时设置
	d.JsSealInstExposed = false

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

func sanitizeSourceForDangerousAPIAnalysis(source string) string {
	buf := make([]byte, len(source))
	for i := range buf {
		buf[i] = ' '
	}

	inLineComment := false
	inBlockComment := false
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	templateExprDepth := 0
	templateResumeDepths := []int{}
	escaped := false

	for i := 0; i < len(source); i++ {
		ch := source[i]

		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				buf[i] = ch
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(source) && source[i+1] == '/' {
				buf[i] = ' '
				buf[i+1] = ' '
				inBlockComment = false
				i++
				continue
			}
			if ch == '\n' || ch == '\r' {
				buf[i] = ch
			}
			continue
		}

		if inSingleQuote || inDoubleQuote || inBacktick {
			if ch == '\n' || ch == '\r' {
				buf[i] = ch
			}
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if inSingleQuote && ch == '\'' {
				inSingleQuote = false
			} else if inDoubleQuote && ch == '"' {
				inDoubleQuote = false
			} else if inBacktick {
				if ch == '`' {
					inBacktick = false
				} else if ch == '$' && i+1 < len(source) && source[i+1] == '{' {
					buf[i] = ch
					buf[i+1] = '{'
					templateExprDepth++
					templateResumeDepths = append(templateResumeDepths, templateExprDepth)
					inBacktick = false
					i++
				}
			}
			continue
		}

		if ch == '/' && i+1 < len(source) {
			next := source[i+1]
			if next == '/' {
				inLineComment = true
				i++
				continue
			}
			if next == '*' {
				inBlockComment = true
				i++
				continue
			}
		}

		if templateExprDepth > 0 {
			switch ch {
			case '{':
				templateExprDepth++
			case '}':
				templateExprDepth--
				if n := len(templateResumeDepths); n > 0 && templateExprDepth == templateResumeDepths[n-1]-1 {
					templateResumeDepths = templateResumeDepths[:n-1]
					inBacktick = true
				}
			}
			buf[i] = ch
			continue
		}

		switch ch {
		case '\'':
			inSingleQuote = true
		case '"':
			inDoubleQuote = true
		case '`':
			inBacktick = true
		}

		buf[i] = ch
	}

	return string(buf)
}

func jsIdentifierLength(source string, offset int) int {
	if offset >= len(source) {
		return 0
	}
	isIdentStart := func(ch byte) bool {
		return ch == '_' || ch == '$' || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
	}
	isIdentChar := func(ch byte) bool {
		return isIdentStart(ch) || (ch >= '0' && ch <= '9')
	}
	if !isIdentStart(source[offset]) {
		return 0
	}
	length := 1
	for i := offset + 1; i < len(source); i++ {
		if !isIdentChar(source[i]) {
			break
		}
		length++
	}
	return length
}

func lineColumnFromOffset(source string, offset int) (int, int) {
	line := 1
	column := 1
	for i := 0; i < offset && i < len(source); i++ {
		if source[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return line, column
}

func describeDangerousAPIMember(apiID string, member string, kind string) string {
	if apiID != "seal.inst" {
		return ""
	}

	if member == "" {
		return "直接获取高权限 API 本体。后续可继续读取字段、调用方法或转存到其它变量。"
	}

	if desc, ok := sealInstMemberDescriptions[member]; ok {
		return desc
	}
	if len(member) > 0 {
		lowerFirst := strings.ToLower(member[:1]) + member[1:]
		if desc, ok := sealInstMemberDescriptions[lowerFirst]; ok {
			return desc
		}
		upperFirst := strings.ToUpper(member[:1]) + member[1:]
		if desc, ok := sealInstMemberDescriptions[upperFirst]; ok {
			return desc
		}
	}

	if kind == "method" {
		return "检测到对核心实例方法的直接调用，但当前没有预置说明。"
	}
	return "检测到对核心实例字段或属性的直接访问，但当前没有预置说明。"
}

func buildDangerousAPIOccurrence(source string, rule jsDangerousAPIRule, start int, end int) JsDangerousAPIOccurrence {
	line, column := lineColumnFromOffset(source, start)
	occurrence := JsDangerousAPIOccurrence{
		Line:   line,
		Column: column,
		Kind:   "direct",
		Access: rule.Name,
	}

	index := end
	for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r') {
		index++
	}

	member, kind, accessSuffix, nextIndex, ok := parseDangerousAPIMemberAccess(source, index)
	if !ok {
		occurrence.MemberDescription = describeDangerousAPIMember(rule.ID, occurrence.Member, occurrence.Kind)
		return occurrence
	}
	occurrence.Member = member
	occurrence.Kind = kind
	occurrence.Access = rule.Name + accessSuffix
	_ = nextIndex
	occurrence.MemberDescription = describeDangerousAPIMember(rule.ID, occurrence.Member, occurrence.Kind)

	return occurrence
}

func parseDangerousAPIMemberAccess(source string, index int) (member string, kind string, accessSuffix string, nextIndex int, ok bool) {
	for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r') {
		index++
	}

	originalIndex := index
	bracketSyntax := false
	if index < len(source)-1 && source[index] == '?' && source[index+1] == '.' {
		index += 2
	} else if index < len(source) && source[index] == '.' {
		index++
	} else if index < len(source) && source[index] == '[' {
		bracketSyntax = true
	} else {
		return "", "", "", originalIndex, false
	}

	for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r') {
		index++
	}

	if bracketSyntax || (index < len(source) && source[index] == '[') {
		bracketSyntax = true
		if source[index] == '[' {
			index++
		}
		for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r') {
			index++
		}
		if index >= len(source) || (source[index] != '"' && source[index] != '\'') {
			return "", "", "", originalIndex, false
		}
		quote := source[index]
		index++
		start := index
		for index < len(source) && source[index] != quote {
			index++
		}
		if index >= len(source) {
			return "", "", "", originalIndex, false
		}
		member = source[start:index]
		index++
		for index < len(source) && (source[index] == ' ' || source[index] == '\t' || source[index] == '\n' || source[index] == '\r') {
			index++
		}
		if index >= len(source) || source[index] != ']' {
			return "", "", "", originalIndex, false
		}
		index++
	} else {
		length := jsIdentifierLength(source, index)
		if length == 0 {
			return "", "", "", originalIndex, false
		}
		member = source[index : index+length]
		index += length
	}

	kind = "property"
	if bracketSyntax {
		accessSuffix = `["` + member + `"]`
	} else {
		accessSuffix = "." + member
	}

	nextIndex = index
	for nextIndex < len(source) && (source[nextIndex] == ' ' || source[nextIndex] == '\t' || source[nextIndex] == '\n' || source[nextIndex] == '\r') {
		nextIndex++
	}
	if nextIndex < len(source) && source[nextIndex] == '(' {
		kind = "method"
		accessSuffix += "()"
	}
	return member, kind, accessSuffix, nextIndex, true
}

func detectDangerousAPIUsages(rawSource []byte) []JsDangerousAPIUsage {
	source := string(rawSource)
	sanitized := sanitizeSourceForDangerousAPIAnalysis(source)
	usages := make([]JsDangerousAPIUsage, 0, len(jsDangerousAPIRules))
	for _, rule := range jsDangerousAPIRules {
		rawMatches := rule.Pattern.FindAllStringIndex(source, -1)
		matches := make([][]int, 0, len(rawMatches))
		for _, match := range rawMatches {
			if len(match) < 2 {
				continue
			}
			start := match[0]
			if start < 0 || start >= len(sanitized) || sanitized[start] != source[start] {
				continue
			}
			matches = append(matches, match)
		}
		if len(matches) == 0 {
			continue
		}

		usage := JsDangerousAPIUsage{
			ID:                rule.ID,
			Name:              rule.Name,
			Description:       rule.Description,
			Risk:              rule.Risk,
			Occurrences:       make([]JsDangerousAPIOccurrence, 0, len(matches)),
			ReferencedMembers: []string{},
		}
		memberSet := map[string]bool{}

		for _, match := range matches {
			occurrence := buildDangerousAPIOccurrence(source, rule, match[0], match[1])
			usage.Occurrences = append(usage.Occurrences, occurrence)
			if occurrence.Member != "" && !memberSet[occurrence.Member] {
				memberSet[occurrence.Member] = true
				usage.ReferencedMembers = append(usage.ReferencedMembers, occurrence.Member)
			}
		}

		usages = append(usages, usage)
	}
	return normalizeDangerousAPIUsages(usages)
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

func isCompatibleJsMetaCacheEntry(entry jsMetaCacheEntry) bool {
	return entry.Meta.DangerousAPIUsages != nil
}

func buildJsScriptInfoFromCache(d *Dice, path string, entry jsMetaCacheEntry) (*JsScriptInfo, error) {
	if entry.ParseErr != "" {
		return nil, errors.New(entry.ParseErr)
	}
	jsInfo := &JsScriptInfo{
		Name:               entry.Meta.Name,
		Filename:           path,
		InstallTime:        entry.InstallTime,
		Version:            entry.Meta.Version,
		Author:             entry.Meta.Author,
		License:            entry.Meta.License,
		HomePage:           entry.Meta.HomePage,
		Desc:               entry.Meta.Desc,
		UpdateTime:         entry.Meta.UpdateTime,
		UpdateUrls:         entry.Meta.UpdateUrls,
		Etag:               entry.Meta.Etag,
		Official:           entry.Meta.Official,
		signStatus:         entry.Meta.SignStatus,
		Builtin:            entry.Builtin,
		needCompiled:       entry.Meta.NeedCompiled,
		StoreID:            entry.Meta.StoreID,
		DangerousAPIUsages: normalizeDangerousAPIUsages(entry.Meta.DangerousAPIUsages),
	}
	if jsInfo.Name == "" {
		jsInfo.Name = filepath.Base(path)
	}
	jsInfo.HasDangerousAPIUsage = len(jsInfo.DangerousAPIUsages) > 0
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
		Name:               jsInfo.Name,
		Version:            jsInfo.Version,
		Author:             jsInfo.Author,
		License:            jsInfo.License,
		HomePage:           jsInfo.HomePage,
		Desc:               jsInfo.Desc,
		UpdateTime:         jsInfo.UpdateTime,
		UpdateUrls:         jsInfo.UpdateUrls,
		Etag:               jsInfo.Etag,
		Official:           jsInfo.Official,
		SignStatus:         jsInfo.signStatus,
		NeedCompiled:       jsInfo.needCompiled,
		StoreID:            jsInfo.StoreID,
		DangerousAPIUsages: normalizeDangerousAPIUsages(jsInfo.DangerousAPIUsages),
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

func collectJsScriptPaths(root string, skipBuiltin bool) []string {
	files := make([]string, 0)
	_ = filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info == nil {
			return nil
		}
		if info.IsDir() && skipBuiltin && info.Name() == "_builtin" {
			return fs.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		if isScriptFile(path) {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files
}

func (d *Dice) JsLoadScripts() {
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
	builtinFiles := collectJsScriptPaths(builtinPath, false)
	userFiles := collectJsScriptPaths(path, true)
	totalFiles := len(builtinFiles) + len(userFiles)
	scannedFiles := 0
	cacheHits := 0
	failedFiles := 0
	d.Logger.Infof("JS 脚本开始扫描，共计 %d 个", totalFiles)
	recordScanned := func() {
		scannedFiles++
	}
	recordCacheHit := func() {
		cacheHits++
	}
	recordFailure := func() {
		failedFiles++
	}

	// 解析内置脚本
	for _, path := range builtinFiles {
		recordScanned()
		info, err := os.Stat(path)
		if err != nil {
			recordFailure()
			continue
		}
		key := jsCacheKey(path)
		if metaCache != nil {
			if entry, ok := metaCache.Files[key]; ok &&
				entry.Builtin && entry.Size == info.Size() && entry.ModTime == info.ModTime().Unix() &&
				isCompatibleJsMetaCacheEntry(entry) {
				if entry.Meta.SignStatus != OfficialSign {
					recordFailure()
					d.Logger.Warnf("内置脚本「%s」校验未通过，拒绝加载", path)
					newCache.Files[key] = entry
					continue
				}
				jsInfo, buildErr := buildJsScriptInfoFromCache(d, "./"+path, entry)
				if buildErr == nil {
					recordCacheHit()
					jsInfos = append(jsInfos, jsInfo)
					if len(jsInfo.StoreID) > 0 {
						d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
					}
					newCache.Files[key] = entry
					continue
				}
				recordFailure()
				entry.ParseErr = buildErr.Error()
				newCache.Files[key] = entry
				d.Logger.Error("读取内置脚本失败(错误依赖)", buildErr.Error())
				continue
			}
		}

		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			recordFailure()
			d.Logger.Error("读取内置脚本失败(无法访问): ", err.Error())
			continue
		}
		ok, signStatus := CheckJsSign(data)
		if !ok {
			recordFailure()
			d.Logger.Warnf("内置脚本「%s」校验未通过，拒绝加载", path)
			entry := buildJsMetaCacheEntry(path, info, nil, true, errors.New("signature invalid"))
			entry.Meta.SignStatus = signStatus
			newCache.Files[key] = entry
			continue
		}
		jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, true)
		newCache.Files[key] = buildJsMetaCacheEntry(path, info, jsInfo, true, err)
		if err != nil {
			recordFailure()
			d.Logger.Error("读取内置脚本失败(错误依赖)", err.Error())
			continue
		}
		jsInfos = append(jsInfos, jsInfo)
		if len(jsInfo.StoreID) > 0 {
			d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
		}
	}

	// 解析第三方脚本
	for _, path := range userFiles {
		recordScanned()
		info, err := os.Stat(path)
		if err != nil {
			recordFailure()
			continue
		}
		key := jsCacheKey(path)
		if metaCache != nil {
			if entry, ok := metaCache.Files[key]; ok &&
				!entry.Builtin && entry.Size == info.Size() && entry.ModTime == info.ModTime().Unix() &&
				isCompatibleJsMetaCacheEntry(entry) {
				jsInfo, buildErr := buildJsScriptInfoFromCache(d, "./"+path, entry)
				if buildErr == nil {
					recordCacheHit()
					jsInfos = append(jsInfos, jsInfo)
					if len(jsInfo.StoreID) > 0 {
						d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
					}
					newCache.Files[key] = entry
					continue
				}
				recordFailure()
				entry.ParseErr = buildErr.Error()
				newCache.Files[key] = entry
				d.Logger.Error("读取脚本失败(错误依赖)", buildErr.Error())
				continue
			}
		}

		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			recordFailure()
			d.Logger.Error("读取脚本失败(无法访问): ", err.Error())
			continue
		}
		jsInfo, err := d.JsParseMeta("./"+path, info.ModTime(), data, false)
		newCache.Files[key] = buildJsMetaCacheEntry(path, info, jsInfo, false, err)
		if err != nil {
			recordFailure()
			d.Logger.Error("读取脚本失败(错误依赖)", err.Error())
			continue
		}
		jsInfos = append(jsInfos, jsInfo)
		if len(jsInfo.StoreID) > 0 {
			d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
		}
	}

	saveJsMetaCache(newCache)
	d.Logger.Infof("JS 脚本扫描结束，扫描 %d 个，命中 %d 个，失败 %d 个", scannedFiles, cacheHits, failedFiles)
	if metaCache != nil {
		removed := 0
		for key := range metaCache.Files {
			if _, ok := newCache.Files[key]; !ok {
				removed++
			}
		}
		if removed > 0 {
			d.Logger.Infof("JS 元数据缓存已移除 %d 个已删除脚本条目", removed)
		}
	}

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
}

func (d *Dice) JsReload() {
	startTime := time.Now()
	d.Logger.Infof("JsReload: 开始重载")

	if d.JsScriptCron != nil {
		d.JsScriptCron.Stop()
		d.JsScriptCron = nil
	}

	// Wrapper 架构：设置重载标志，避免重载期间访问无效的 CmdMap
	d.JsReloading = true

	// Wrapper 架构：不再需要记录快照，wrapper 保留在群组中
	// jsClear 清空 JsExtRegistry，seal.ext.register 会复用 wrapper 并注册新的真实扩展

	d.JsInit()
	_ = d.ConfigManager.Load()
	d.JsLoadScripts()

	// ApplyExtDefaultSettings 会遍历扩展的 GetCmdMap() 来重建 disabledCommand。
	// JS 扩展在重载期间通过 wrapper 暴露，而 wrapper 的 GetCmdMap() 在 JsReloading=true 时会主动返回空映射，
	// 以避免半重载状态下读取到失效 CmdMap。原先在 JsLoadScripts() 末尾应用默认设置，会导致第三方 JS 扩展
	// 的指令列表被错误置空，WebUI 综合设置 - 基本设置 - 扩展及扩展指令 里只能看到官方扩展命令。
	// 因此这里改为先结束重载状态，再统一应用默认设置，让 JS wrapper 能解析到命令表。
	d.JsReloading = false
	d.ApplyExtDefaultSettings()

	// 更新扩展变更时间戳，触发延迟更新
	d.ExtUpdateTime = time.Now().Unix()

	d.MarkModified()
	d.Save(false)

	d.Logger.Infof("JsReload: 重载完成，耗时 %dms", time.Since(startTime).Milliseconds())
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
	/** 是否包含危险 API 调用 */
	HasDangerousAPIUsage bool `json:"hasDangerousApiUsage"`
	/** 命中的危险 API 列表 */
	DangerousAPIUsages []JsDangerousAPIUsage `json:"dangerousApiUsages"`
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
	Name               string                `json:"name"`
	Version            string                `json:"version"`
	Author             string                `json:"author"`
	License            string                `json:"license"`
	HomePage           string                `json:"homepage"`
	Desc               string                `json:"desc"`
	UpdateTime         int64                 `json:"updateTime"`
	UpdateUrls         []string              `json:"updateUrls"`
	Etag               string                `json:"etag"`
	Official           bool                  `json:"official"`
	SignStatus         SignStatus            `json:"signStatus"`
	Depends            []jsMetaDepends       `json:"depends"`
	NeedCompiled       bool                  `json:"needCompiled"`
	StoreID            string                `json:"storeId"`
	DangerousAPIUsages []JsDangerousAPIUsage `json:"dangerousApiUsages"`
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
	jsInfo.DangerousAPIUsages = normalizeDangerousAPIUsages(detectDangerousAPIUsages(rawData))
	jsInfo.HasDangerousAPIUsage = len(jsInfo.DangerousAPIUsages) > 0

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
			_, err = d.ExtLoopManager.GetWebLoop().RequireModule(targetPath)
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
	}
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
