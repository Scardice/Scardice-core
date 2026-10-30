package dice

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// 局部重载（增量加载）
//
// 目前只实现“新增”：上传一个全新的插件文件时，直接把它加载进正在运行的 runtime，
// 不重建 VM、不屏蔽其他插件，并顺带补载此前因缺少依赖而被阻塞的依赖方。
// 其余变更（更新、禁用、删除）仍然需要手动全量重载（JsReload）。
//
// TODO(局部重载/禁用与删除): 禁用、删除已加载插件时不再全量重载，而是卸载该插件及其
// 反向依赖闭包（逆拓扑序）；依赖方标记为 depsBlocked，插件回来后由 JsAddScript 自动补载。
// 入口见 JsDisable / JsEnable / JsDelete。
//   subTODO(局部重载): 脚本资源归属表：脚本 -> 扩展名、任务、JS 模板、CoC 规则、模块 ID、定时器、连接。
//   subTODO(局部重载): 脚本级生命周期上下文：无消息的 jsExecutionContext 的 ExecutionContext() 目前返回
//     context.Background()，脚本顶层注册的 setTimeout/setInterval/Promise 回调无法撤销。
//   subTODO(局部重载): 定时器句柄登记与撤销：回调被短路后 setInterval 仍会空转。
//   subTODO(局部重载): WebSocket / fetch 按脚本归属关闭（WebSocketManager 只有 CloseAll）。
//   subTODO(局部重载): JS 规则模板、CoC 规则按脚本摘除（clearJSTemplates / clearCocExtraRules 只能整体清空）。
//   subTODO(局部重载): 反向依赖闭包：在 checkJsScriptsDeps / sortJsScripts 之上提供 dependentsOf(script)。
//
// TODO(局部重载/更新同名插件): 更新已加载插件时驱逐旧模块并整链重载依赖方。入口见 JsUpdate 与上传覆盖。
//   subTODO(局部重载): 模块缓存驱逐原语：CommonJSProgram 按文件名缓存，同名再次加载不会执行，且加载失败的
//     半成品也会留在缓存里；QuickJS 原生 provider 能否卸载模块尚未验证。
//   subTODO(局部重载): 依赖闭包整链重载：依赖方可能持有旧 exports / ExtInfo 引用；seal.ext.find 与 require
//     观察到的“未声明依赖边”需要在运行时记录。
//   subTODO(局部重载): 加载失败时回滚注册与模块缓存，保证失败原子性。
//
// TODO(局部重载/通用):
//   subTODO(局部重载): 按插件的门控，取代全局 JsReloading（wrapper.GetCmdMap 与 jsCallbacksGated 目前是全局的）。
//   subTODO(局部重载): 把 JsLoadScripts 拆成 扫描 / 计划 / 应用，并提供“重载计划”预览接口与 UI。
//   subTODO(局部重载): 统一重载互斥：JsReload 本身不持有 JsReloadLock；JsScriptList 目前没有并发读写保护。
//   subTODO(局部重载): 局部加载期间长耗时脚本会阻塞共享事件循环，需要按插件超时或隔离。

// JsIncrementalUnavailableError 表示该变更不能局部加载，调用方应退回手动全量重载。
type JsIncrementalUnavailableError struct{ Reason string }

func (e *JsIncrementalUnavailableError) Error() string { return "无法局部加载：" + e.Reason }

func newJsIncrementalUnavailable(format string, args ...any) *JsIncrementalUnavailableError {
	return &JsIncrementalUnavailableError{Reason: fmt.Sprintf(format, args...)}
}

// JsAddIssue 描述局部加载中未能加载的脚本及原因。
type JsAddIssue struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// JsAddResult 是一次局部新增的结果。
type JsAddResult struct {
	// Loaded 按加载顺序列出实际加载的脚本，包括被解除阻塞的依赖方。
	Loaded []string `json:"loaded"`
	// Disabled 表示新脚本已被用户禁用，只登记、未加载。
	Disabled bool         `json:"disabled"`
	Rejected []JsAddIssue `json:"rejected"`
	Warnings []string     `json:"warnings"`
}

// JsAddScript 把一个新上传的插件文件加载进正在运行的 runtime，而不重建 VM。
// 只处理“全新”的脚本；已加载过的文件、同名插件等属于更新，返回 *JsIncrementalUnavailableError，
// 调用方需要退回手动全量重载。
func (d *Dice) JsAddScript(filename string) (*JsAddResult, error) {
	if d == nil || !d.Config.JsEnable || d.ExtLoopManager == nil {
		return nil, newJsIncrementalUnavailable("JS 环境未运行")
	}
	if !d.JsReloadLock.TryLock() {
		return nil, newJsIncrementalUnavailable("JS 正在重载")
	}
	defer d.JsReloadLock.Unlock()
	if !d.beginStartupJsLoad() {
		return nil, newJsIncrementalUnavailable("JS 环境正在停止")
	}
	defer d.finishStartupJsLoad()
	if d.JsReloading {
		return nil, newJsIncrementalUnavailable("JS 正在重载")
	}

	target, err := d.jsIncrementalScriptPath(filename)
	if err != nil {
		return nil, err
	}
	// 相对路径沿用全量重载的 "./" 前缀约定；绝对路径不能再加前缀，否则会被当成相对路径读取。
	jsFilename := target
	if !filepath.IsAbs(target) {
		jsFilename = "./" + target
	}
	for _, existing := range d.JsScriptList {
		if existing != nil && filepath.Clean(existing.Filename) == filepath.Clean(jsFilename) {
			return nil, newJsIncrementalUnavailable("该文件已经加载过，属于更新")
		}
	}

	info, err := os.Stat(target)
	if err != nil {
		return nil, fmt.Errorf("读取脚本失败: %w", err)
	}
	data, err := os.ReadFile(target) //nolint:gosec // 路径已校验位于插件目录内
	if err != nil {
		return nil, fmt.Errorf("读取脚本失败: %w", err)
	}

	result := &JsAddResult{}
	jsInfo, parseErr := d.JsParseMeta(jsFilename, info.ModTime(), data, false)
	if parseErr != nil {
		// JsParseMeta 已把带错误信息的条目登记进脚本列表，与全量重载的表现一致。
		result.Rejected = append(result.Rejected, JsAddIssue{Name: filepath.Base(target), Reason: parseErr.Error()})
		return result, nil
	}
	for _, other := range d.JsScriptList {
		if other != nil && other != jsInfo && other.Name == jsInfo.Name {
			d.removeJsScriptInfo(jsInfo)
			return nil, newJsIncrementalUnavailable("已存在同名插件「%s」，属于更新或重名冲突", jsInfo.Name)
		}
	}
	if d.StoreManager != nil && jsInfo.StoreID != "" && d.StoreManager.InstalledPlugins != nil {
		d.StoreManager.InstalledPlugins[jsInfo.StoreID] = true
	}

	if jsInfo.Enable {
		if prepared := d.prepareJSScriptRuntimes([]*JsScriptInfo{jsInfo}); len(prepared) == 0 {
			result.Rejected = append(result.Rejected, JsAddIssue{Name: jsInfo.Name, Reason: jsInfo.ErrText})
			return result, nil
		}
	}
	// 与全量重载一致：被用户禁用的脚本也参与依赖存在性检查。
	scope := append(slices.Clone(d.jsDependencyScope), jsInfo)
	d.jsDependencyScope = scope
	if !jsInfo.Enable {
		result.Disabled = true
		return result, nil
	}

	// 此前因依赖不满足被阻塞的脚本重新参与检查；仍不满足的会被再次标记。
	want := map[*JsScriptInfo]bool{jsInfo: true}
	for _, script := range scope {
		if script != jsInfo && script.depsBlocked {
			want[script] = true
			script.depsBlocked = false
			script.Enable = !d.Config.DisabledJsScripts[script.Name]
			script.ErrText = ""
		}
	}
	canLoad, _ := checkJsScriptsDeps(scope)
	sorted, _ := sortJsScripts(canLoad)

	var toLoad []*JsScriptInfo
	for _, script := range sorted {
		if want[script] && script.Enable && script.ErrText == "" {
			toLoad = append(toLoad, script)
		}
	}
	if !slices.Contains(toLoad, jsInfo) {
		reason := jsInfo.ErrText
		if reason == "" {
			reason = "插件未能满足加载条件"
		}
		result.Rejected = append(result.Rejected, JsAddIssue{Name: jsInfo.Name, Reason: reason})
		d.Logger.Warnf("插件「%s」拒绝加载：\n%s", jsInfo.Name, reason)
	}

	before := map[string]*ExtInfo{}
	if d.JsExtRegistry != nil {
		d.JsExtRegistry.Range(func(name string, ext *ExtInfo) bool {
			before[name] = ext
			return true
		})
	}
	loaded := map[*JsScriptInfo]bool{}
	for _, script := range toLoad {
		d.Logger.Infof("局部加载脚本「%s:%s:%s」", script.Author, script.Name, script.Version)
		if strings.EqualFold(filepath.Ext(script.Filename), ".ts") {
			script.needCompiled = true
		}
		d.JsLoadScriptRaw(script)
		if script.Enable && script.ErrText == "" {
			loaded[script] = true
			result.Loaded = append(result.Loaded, script.Name)
			continue
		}
		result.Rejected = append(result.Rejected, JsAddIssue{Name: script.Name, Reason: script.ErrText})
	}
	if len(loaded) == 0 {
		return result, nil
	}

	registered := map[string]struct{}{}
	if d.JsExtRegistry != nil {
		d.JsExtRegistry.Range(func(name string, ext *ExtInfo) bool {
			if ext == nil || !loaded[ext.Source] {
				return true
			}
			registered[name] = struct{}{}
			if previous := before[name]; previous != nil && previous != ext {
				// TODO(局部重载/更新同名插件): 被替换扩展的任务、存储需要一并清理；目前只能提示全量重载。
				warning := fmt.Sprintf("扩展「%s」替换了已加载的同名扩展，建议执行一次全量重载", name)
				result.Warnings = append(result.Warnings, warning)
				d.Logger.Warn(warning)
			}
			return true
		})
	}
	if len(registered) > 0 {
		// 只处理新扩展，不重置各群的手动关闭记录；各群随 ExtRegistryVersion 在下一条消息时懒同步。
		d.applyExtDefaultSettings(registered, false)
	}
	d.ExtUpdateTime = time.Now().Unix()
	d.MarkModified()
	d.Save(false)
	return result, nil
}

// jsIncrementalScriptPath 校验文件位于插件目录内（且不是内置目录）并返回规范化路径。
func (d *Dice) jsIncrementalScriptPath(filename string) (string, error) {
	scriptsDir := filepath.Join(d.BaseConfig.DataDir, "scripts")
	target := filepath.Clean(filename)
	relative, err := filepath.Rel(scriptsDir, target)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", newJsIncrementalUnavailable("脚本不在插件目录内")
	}
	if strings.SplitN(filepath.ToSlash(relative), "/", 2)[0] == "_builtin" {
		return "", newJsIncrementalUnavailable("内置脚本目录不支持局部加载")
	}
	if !d.isJSScriptFile(target) {
		return "", newJsIncrementalUnavailable("不是受支持的脚本类型")
	}
	return target, nil
}

func (d *Dice) removeJsScriptInfo(target *JsScriptInfo) {
	kept := make([]*JsScriptInfo, 0, len(d.JsScriptList))
	for _, script := range d.JsScriptList {
		if script != target {
			kept = append(kept, script)
		}
	}
	d.JsScriptList = kept
}
