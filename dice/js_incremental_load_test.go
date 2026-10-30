package dice

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"Scardice-core/utils/jsengine"
)

func newIncrementalFixture(t *testing.T) (*Dice, string) {
	t.Helper()
	d, _, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(func() {
		if d.ExtLoopManager != nil {
			d.ExtLoopManager.SetLoop(nil)
		}
		cleanup()
	})
	d.jsRuntimeManager = newJSRuntimeManagerForDice(d, false)
	d.Config.JsEngine = string(jsengine.EngineGoja)
	d.JsInit()
	if !d.Config.JsEnable {
		t.Fatalf("JS initialization failed: %+v", d.jsRuntimeManagerInstance().Statuses())
	}
	return d, filepath.Join(d.BaseConfig.DataDir, "scripts")
}

func writeIncrementalScript(t *testing.T, dir, file, name, extraHeader, body string) string {
	t.Helper()
	source := "// ==UserScript==\n// @name " + name + "\n// @author Tester\n// @version 1.0.0\n" + extraHeader +
		"// ==/UserScript==\n" + body
	path := filepath.Join(dir, file)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func evalIncrementalGlobal(t *testing.T, d *Dice, expression string) any {
	t.Helper()
	loop, _ := d.ExtLoopManager.CurrentLoop()
	var out any
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString("probe.js", expression)
		if err != nil {
			return err
		}
		out = value.Export()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func registrySnapshot(d *Dice) []string {
	var names []string
	d.JsExtRegistry.Range(func(name string, _ *ExtInfo) bool {
		names = append(names, name)
		return true
	})
	slices.Sort(names)
	return names
}

const incrementalPlugin = `globalThis.__runs = (globalThis.__runs || {});
globalThis.__runs[%q] = (globalThis.__runs[%q] || 0) + 1;
const ext = seal.ext.new(%q, "Tester", "1.0.0");
seal.ext.register(ext);
`

func pluginBody(name string) string {
	return strings.NewReplacer("%q", `"`+name+`"`).Replace(incrementalPlugin)
}

func TestJsAddScriptLoadsNewPluginWithoutRebuildingTheRuntime(t *testing.T) {
	d, dir := newIncrementalFixture(t)
	generation := d.ExtLoopManager.version

	first, err := d.JsAddScript(writeIncrementalScript(t, dir, "a.js", "AddBase", "", pluginBody("AddBase")))
	if err != nil || !slices.Equal(first.Loaded, []string{"AddBase"}) {
		t.Fatalf("first add = %+v, err = %v", first, err)
	}
	baseExt, _ := d.JsExtRegistry.Load("AddBase")

	// 另一个群曾手动关闭过 AddBase；局部新增不能把它重新打开，也不能重置群同步版本。
	group := &GroupInfo{GroupID: "QQ-Group:manual-off", InactivatedExtSet: StringSet{"AddBase": {}}, ExtAppliedVersion: 7}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)

	second, err := d.JsAddScript(writeIncrementalScript(t, dir, "c.js", "AddIndependent", "", pluginBody("AddIndependent")))
	if err != nil || !slices.Equal(second.Loaded, []string{"AddIndependent"}) {
		t.Fatalf("second add = %+v, err = %v", second, err)
	}

	if got := d.ExtLoopManager.version; got != generation {
		t.Fatalf("runtime generation changed from %d to %d: the VM was rebuilt", generation, got)
	}
	if stillThere, _ := d.JsExtRegistry.Load("AddBase"); stillThere != baseExt {
		t.Fatal("an already loaded plugin was replaced")
	}
	if runs := evalIncrementalGlobal(t, d, `globalThis.__runs.AddBase`); runs != int64(1) {
		t.Fatalf("AddBase top-level ran %v times, want 1", runs)
	}
	if d.JsReloading || d.jsCallbacksGated.Load() {
		t.Fatal("a partial load must not put the whole JS environment into reload state")
	}
	wrapper := d.ExtFind("AddIndependent", false)
	if wrapper == nil || !wrapper.IsWrapper || wrapper.GetRealExt() == nil || wrapper.DefaultSetting == nil {
		t.Fatalf("new plugin wrapper = %#v", wrapper)
	}
	if _, kept := group.InactivatedExtSet["AddBase"]; !kept || group.ExtAppliedVersion != 7 {
		t.Fatalf("group state was disturbed: inactivated=%v applied=%d", group.InactivatedExtSet, group.ExtAppliedVersion)
	}
	var listed []string
	for _, script := range d.JsScriptList {
		listed = append(listed, script.Name)
	}
	slices.Sort(listed)
	if !slices.Equal(listed, []string{"AddBase", "AddIndependent"}) {
		t.Fatalf("script list = %v", listed)
	}
}

func TestJsAddScriptUnblocksDependentsInDependencyOrder(t *testing.T) {
	d, dir := newIncrementalFixture(t)
	dependent := writeIncrementalScript(t, dir, "b.js", "AddDependent", "// @depends Tester:AddDependency\n",
		`globalThis.__order = (globalThis.__order || []); globalThis.__order.push("dependent:" + (seal.ext.find("AddDependency") !== null));`+"\n"+
			`seal.ext.register(seal.ext.new("AddDependent", "Tester", "1.0.0"));`)

	blocked, err := d.JsAddScript(dependent)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked.Loaded) != 0 || len(blocked.Rejected) != 1 || !strings.Contains(blocked.Rejected[0].Reason, "依赖") {
		t.Fatalf("dependent without its dependency = %+v", blocked)
	}
	if _, loaded := d.JsExtRegistry.Load("AddDependent"); loaded {
		t.Fatal("a plugin with a missing dependency was loaded")
	}

	dependency := writeIncrementalScript(t, dir, "a.js", "AddDependency", "",
		`globalThis.__order = (globalThis.__order || []); globalThis.__order.push("dependency");`+"\n"+
			`seal.ext.register(seal.ext.new("AddDependency", "Tester", "1.0.0"));`)
	result, err := d.JsAddScript(dependency)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.Loaded, []string{"AddDependency", "AddDependent"}) {
		t.Fatalf("loaded = %v, want dependency before its dependent", result.Loaded)
	}
	order := evalIncrementalGlobal(t, d, `globalThis.__order.join(",")`)
	if order != "dependency,dependent:true" {
		t.Fatalf("execution order = %v", order)
	}
	for _, script := range d.JsScriptList {
		if script.Name == "AddDependent" && (!script.Enable || script.ErrText != "") {
			t.Fatalf("unblocked dependent state: enable=%v err=%q", script.Enable, script.ErrText)
		}
	}
}

func TestJsAddScriptLeavesUpdatesAndConflictsToFullReload(t *testing.T) {
	d, dir := newIncrementalFixture(t)
	path := writeIncrementalScript(t, dir, "a.js", "AddBase", "", pluginBody("AddBase"))
	if _, err := d.JsAddScript(path); err != nil {
		t.Fatal(err)
	}
	listed := len(d.JsScriptList)

	var unavailable *JsIncrementalUnavailableError
	if _, err := d.JsAddScript(path); !errors.As(err, &unavailable) {
		t.Fatalf("re-adding an already loaded file err = %v, want unavailable", err)
	}
	renamed := writeIncrementalScript(t, dir, "a-copy.js", "AddBase", "", pluginBody("AddBase"))
	if _, err := d.JsAddScript(renamed); !errors.As(err, &unavailable) {
		t.Fatalf("same-name plugin in another file err = %v, want unavailable", err)
	}
	if len(d.JsScriptList) != listed {
		t.Fatalf("a refused add left %d entries in the script list, want %d", len(d.JsScriptList), listed)
	}
	if runs := evalIncrementalGlobal(t, d, `globalThis.__runs.AddBase`); runs != int64(1) {
		t.Fatalf("refused adds re-ran the plugin: %v", runs)
	}
}

func TestJsAddScriptRegistersUserDisabledPluginWithoutRunningIt(t *testing.T) {
	d, dir := newIncrementalFixture(t)
	d.Config.DisabledJsScripts = map[string]bool{"AddOff": true}

	result, err := d.JsAddScript(writeIncrementalScript(t, dir, "off.js", "AddOff", "", pluginBody("AddOff")))
	if err != nil || !result.Disabled || len(result.Loaded) != 0 {
		t.Fatalf("disabled add = %+v, err = %v", result, err)
	}
	if _, loaded := d.JsExtRegistry.Load("AddOff"); loaded {
		t.Fatal("a user-disabled plugin was loaded")
	}
	if len(d.JsScriptList) != 1 || d.JsScriptList[0].Enable {
		t.Fatalf("script list = %+v", d.JsScriptList)
	}
}

func TestJsAddScriptRefusesWhileTheEnvironmentIsBusy(t *testing.T) {
	d, dir := newIncrementalFixture(t)
	var unavailable *JsIncrementalUnavailableError

	d.setJsReloading(true)
	if _, err := d.JsAddScript(writeIncrementalScript(t, dir, "a.js", "AddBase", "", pluginBody("AddBase"))); !errors.As(err, &unavailable) {
		t.Fatalf("add during reload err = %v", err)
	}
	d.setJsReloading(false)

	d.JsReloadLock.Lock()
	_, err := d.JsAddScript(writeIncrementalScript(t, dir, "b.js", "AddOther", "", pluginBody("AddOther")))
	d.JsReloadLock.Unlock()
	if !errors.As(err, &unavailable) {
		t.Fatalf("add while another reload holds the lock err = %v", err)
	}

	d.Config.JsEnable = false
	if _, err := d.JsAddScript(writeIncrementalScript(t, dir, "c.js", "AddThird", "", pluginBody("AddThird"))); !errors.As(err, &unavailable) {
		t.Fatalf("add with JS disabled err = %v", err)
	}
	if len(d.JsScriptList) != 0 {
		t.Fatalf("refused adds registered scripts: %+v", d.JsScriptList)
	}
}

// 局部加载的最终状态必须与全量重载一致。
func TestJsAddScriptMatchesFullReload(t *testing.T) {
	t.Chdir(t.TempDir()) // JS 元数据缓存与相对数据目录都落在这里
	d, _ := newIncrementalFixture(t)
	// 生产环境的 DataDir 是相对路径，脚本文件名带 "./" 前缀；差分对比必须走同一约定。
	d.BaseConfig.DataDir = filepath.Join("data", "default")
	dir := filepath.Join(d.BaseConfig.DataDir, "scripts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	d.JsBuiltinDigestSet = map[string]bool{}
	for _, script := range []struct{ file, name, header, body string }{
		{"b.js", "DiffDependent", "// @depends Tester:DiffBase\n", `seal.ext.register(seal.ext.new("DiffDependent", "Tester", "1.0.0"));`},
		{"a.js", "DiffBase", "", pluginBody("DiffBase")},
		{"c.js", "DiffIndependent", "", pluginBody("DiffIndependent")},
	} {
		if _, err := d.JsAddScript(writeIncrementalScript(t, dir, script.file, script.name, script.header, script.body)); err != nil {
			t.Fatal(err)
		}
	}
	incremental := registrySnapshot(d)
	var incrementalScripts []string
	for _, script := range d.JsScriptList {
		incrementalScripts = append(incrementalScripts, script.Name+":"+boolText(script.Enable)+":"+script.ErrText)
	}
	slices.Sort(incrementalScripts)

	d.JsReload()
	var reloadedScripts []string
	for _, script := range d.JsScriptList {
		reloadedScripts = append(reloadedScripts, script.Name+":"+boolText(script.Enable)+":"+script.ErrText)
	}
	slices.Sort(reloadedScripts)
	if reloaded := registrySnapshot(d); !slices.Equal(incremental, reloaded) {
		t.Fatalf("registry differs: incremental=%v full reload=%v", incremental, reloaded)
	}
	if !slices.Equal(incrementalScripts, reloadedScripts) {
		t.Fatalf("script states differ: incremental=%v full reload=%v", incrementalScripts, reloadedScripts)
	}
}

func boolText(value bool) string {
	if value {
		return "on"
	}
	return "off"
}

func TestApplyExtDefaultSettingsCanBeLimitedToNewExtensions(t *testing.T) {
	oldExt := &ExtInfo{Name: "old", AutoActive: true}
	newExt := &ExtInfo{Name: "new", AutoActive: true}
	d := newTestDice([]*ExtInfo{oldExt, newExt})
	d.ImSession = &IMSession{ServiceAtNew: new(SyncMap[string, *GroupInfo])}
	group := &GroupInfo{GroupID: "QQ-Group:1", InactivatedExtSet: StringSet{"old": {}}, ExtAppliedVersion: 5}
	atomic.StoreInt64(&group.ExtAppliedTime, 9)
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)

	d.applyExtDefaultSettings(map[string]struct{}{"new": {}}, false)

	if newExt.DefaultSetting == nil {
		t.Fatal("the new extension did not receive its default setting")
	}
	if oldExt.DefaultSetting != nil {
		t.Fatal("an extension outside the requested set was touched")
	}
	if _, kept := group.InactivatedExtSet["old"]; !kept || group.ExtAppliedVersion != 5 || atomic.LoadInt64(&group.ExtAppliedTime) != 9 {
		t.Fatalf("group state changed: %v version=%d time=%d", group.InactivatedExtSet, group.ExtAppliedVersion, atomic.LoadInt64(&group.ExtAppliedTime))
	}
}
