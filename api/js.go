package api

import (
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/utils"
	"Scardice-core/utils/jsengine"
)

func exportJSAPIValue(value jsengine.Value) (interface{}, error) {
	if value == nil {
		return nil, jsengine.ErrPrimitiveExportUnsupported
	}
	primitive, err := value.ExportPrimitive()
	if errors.Is(err, jsengine.ErrNoPrimitiveValue) {
		return primitive, nil
	}
	return primitive, err
}

func jsExec(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	if !myDice.Config.JsEnable {
		resp := c.JSON(200, map[string]interface{}{
			"result": false,
			"err":    "js扩展支持已关闭",
		})
		return resp
	}

	v := struct {
		Value string `json:"value"`
	}{}
	err := c.Bind(&v)
	if err != nil {
		return c.String(430, err.Error())
	}

	source := "(function(exports, require, module) {" + v.Value + "\n})({}, globalThis.require, {exports: {}})"
	engine := jsengine.NormalizeEngineID(myDice.Config.JsEngine)
	if engine == "" {
		engine = jsengine.EngineGoja
	}
	if myDice.ExtLoopManager == nil || myDice.JsPrinter == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result": false,
			"err":    "JS运行时不可用",
		})
	}

	myDice.JsPrinter.RecordStart()
	var retFinal interface{}
	loop, _ := myDice.ExtLoopManager.CurrentLoop()
	if loop == nil {
		err = fmt.Errorf("JS运行时不可用: %s", engine)
	} else if loop.Engine() != engine {
		err = fmt.Errorf("JS运行时与配置不匹配: configured=%s active=%s", engine, loop.Engine())
	} else {
		err = loop.Run(func(runtime jsengine.Runtime) error {
			ret, runErr := runtime.RunString("api-js-exec.js", source)
			if runErr != nil {
				return runErr
			}
			retFinal, runErr = exportJSAPIValue(ret)
			return runErr
		})
	}
	outputs := myDice.JsPrinter.RecordEnd()

	var errText interface{}
	if err != nil {
		errText = err.Error()
	}

	resp := c.JSON(200, map[string]interface{}{
		"result":  true,
		"ret":     retFinal,
		"outputs": outputs,
		"err":     errText,
	})

	return resp
}

func jsGetRecord(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if !myDice.Config.JsEnable {
		resp := c.JSON(200, map[string]interface{}{
			"outputs": []string{},
		})
		return resp
	}

	outputs := myDice.JsPrinter.RecordEnd()
	resp := c.JSON(200, map[string]interface{}{
		"outputs": outputs,
	})
	return resp
}

func jsDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	if !myDice.Config.JsEnable {
		resp := c.JSON(200, map[string]interface{}{
			"result": false,
			"err":    "js扩展支持已关闭",
		})
		return resp
	}

	v := struct {
		Filename string `json:"filename"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, js := range myDice.JsScriptList {
			if js.Filename == v.Filename {
				dice.JsDelete(myDice, js)
				break
			}
		}
	}

	return c.JSON(http.StatusOK, nil)
}

func jsReload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	// 尝试取锁，如果取不到，说明正在后台重载中
	// TODO:用户提示模式？
	locked := myDice.JsReloadLock.TryLock()
	if !locked {
		return c.NoContent(400)
	}
	defer myDice.JsReloadLock.Unlock()
	myDice.JsReload()
	return c.NoContent(200)
}

func jsReloadStatus(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	progress := myDice.JsReloadProgressSnapshot()
	return c.JSON(http.StatusOK, progress)
}
func jsRuntimeStatus(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"testMode": true,
		})
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"runtimes":       myDice.JSRuntimeStatuses(),
		"discoveryError": myDice.JSRuntimeDiscoveryError(),
	})
}

func jsUpload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	// -----------
	// Read file
	// -----------

	// Source
	file, err := c.FormFile("file")
	if err != nil {
		return err
	}
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer func(src multipart.File) {
		_ = src.Close()
	}(src)

	// Destination
	// fmt.Println("????", filepath.Join("./data/decks", file.Filename))
	file.Filename = strings.ReplaceAll(file.Filename, "/", "_")
	file.Filename = strings.ReplaceAll(file.Filename, "\\", "_")
	destination := filepath.Join(myDice.BaseConfig.DataDir, "scripts", file.Filename)
	_, statErr := os.Stat(destination)
	overwritten := statErr == nil
	if err = utils.AtomicWriteReader(destination, src, 0o644); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, applyUploadedJs(destination, overwritten))
}

// jsUploadResponse 描述上传后的生效情况：全新的插件会被局部加载；其余情况仍需手动重载。
type jsUploadResponse struct {
	Result      bool   `json:"result"`
	Incremental bool   `json:"incremental"`
	NeedReload  bool   `json:"needReload"`
	Reason      string `json:"reason,omitempty"`
	*dice.JsAddResult
}

func applyUploadedJs(destination string, overwritten bool) jsUploadResponse {
	response := jsUploadResponse{Result: true, NeedReload: true}
	if overwritten {
		// TODO(局部重载/更新同名插件): 覆盖已有文件属于更新，目前仍需手动全量重载。
		response.Reason = "覆盖了已有文件，需要手动重载插件"
		return response
	}
	if !myDice.Config.JsEnable {
		response.Reason = "JS 支持未开启"
		return response
	}
	added, err := myDice.JsAddScript(destination)
	var unavailable *dice.JsIncrementalUnavailableError
	switch {
	case errors.As(err, &unavailable):
		response.Reason = unavailable.Error()
	case err != nil:
		myDice.Logger.Errorf("局部加载上传的插件失败: %v", err)
		response.Reason = err.Error()
	default:
		response.Incremental = true
		response.NeedReload = false
		response.JsAddResult = added
	}
	return response
}

func jsExtensionNamesForScript(d *dice.Dice, script *dice.JsScriptInfo) []string {
	names := make([]string, 0, 1)
	if d == nil || d.JsExtRegistry == nil || script == nil || script.Filename == "" {
		return names
	}
	d.JsExtRegistry.Range(func(name string, ext *dice.ExtInfo) bool {
		if ext != nil && ext.Source != nil && ext.Source.Filename == script.Filename {
			names = append(names, name)
		}
		return true
	})
	sort.Strings(names)
	return names
}

func jsList(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if !myDice.Config.JsEnable {
		resp := c.JSON(200, []*dice.JsScriptInfo{})
		return resp
	}

	type script struct {
		*dice.JsScriptInfo
		BuiltinUpdated bool          `json:"builtinUpdated"`
		ExtensionNames []string      `json:"extensionNames"`
		Memory         *jsMemoryView `json:"memory"`
	}
	heap, sweptAt := myDice.JSHeapTracker().Snapshot()
	heapByScript := make(map[string]dice.JSHeapStat, len(heap))
	for _, stat := range heap {
		heapByScript[stat.Script] = stat
	}
	scripts := make([]*script, 0, len(myDice.JsScriptList))
	for _, info := range myDice.JsScriptList {
		temp := script{
			JsScriptInfo:   info,
			BuiltinUpdated: info.Builtin && !myDice.JsBuiltinDigestSet[info.Digest],
			ExtensionNames: jsExtensionNamesForScript(myDice, info),
			Memory:         jsMemoryFor(info, heapByScript, sweptAt),
		}
		scripts = append(scripts, &temp)
	}

	return c.JSON(http.StatusOK, scripts)
}

type jsMemoryAmount struct {
	Objects uint64 `json:"objects"`
	Bytes   uint64 `json:"bytes"`
}

// jsMemoryView is a plugin's estimated live JS heap. Status is "ok", "pending"
// before the first sweep of its runtime, or "unsupported" for runtimes
// without allocation tracking.
type jsMemoryView struct {
	Status      string         `json:"status"`
	Objects     uint64         `json:"objects"`
	Bytes       uint64         `json:"bytes"`
	Object      jsMemoryAmount `json:"object"`
	Array       jsMemoryAmount `json:"array"`
	ArrayBuffer jsMemoryAmount `json:"arrayBuffer"`
	Large       jsMemoryAmount `json:"large"`
	Samples     uint64         `json:"samples"`
	// SweptAt is the Unix time of the sweep in milliseconds.
	SweptAt int64 `json:"sweptAt"`
}

// jsMemoryFor reports nothing for scripts that are not running.
func jsMemoryFor(info *dice.JsScriptInfo, heap map[string]dice.JSHeapStat, sweptAt time.Time) *jsMemoryView {
	switch {
	case !info.Enable || info.RuntimeID == "":
		return nil
	case info.RuntimeID != string(jsengine.EngineGoja):
		return &jsMemoryView{Status: "unsupported"}
	case sweptAt.IsZero():
		return &jsMemoryView{Status: "pending"}
	}
	stat := heap[info.Filename]
	amount := func(a dice.JSHeapAmount) jsMemoryAmount { return jsMemoryAmount{Objects: a.Objects, Bytes: a.Bytes} }
	return &jsMemoryView{
		Status:      "ok",
		Objects:     stat.Total.Objects,
		Bytes:       stat.Total.Bytes,
		Object:      amount(stat.Object),
		Array:       amount(stat.Array),
		ArrayBuffer: amount(stat.ArrayBuffer),
		Large:       amount(stat.Large),
		Samples:     stat.Samples,
		SweptAt:     sweptAt.UnixMilli(),
	}
}

func jsShutdown(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"testMode": true,
		})
	}

	if myDice.Config.JsEnable {
		myDice.JsShutdown()
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"result": true,
	})
}

func jsStatus(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]interface{}{
		"result": true,
		"status": myDice.Config.JsEnable,
	})
}

func jsEnable(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	v := struct {
		Name string `form:"name" json:"name"`
	}{}
	err := c.Bind(&v)

	if err == nil {
		dice.JsEnable(myDice, v.Name)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result": true,
			"name":   v.Name,
		})
	}
	return c.JSON(http.StatusBadRequest, nil)
}

func jsDisable(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	v := struct {
		Name string `form:"name" json:"name"`
	}{}
	err := c.Bind(&v)

	if err == nil {
		dice.JsDisable(myDice, v.Name)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result": true,
			"name":   v.Name,
		})
	}

	return c.JSON(http.StatusBadRequest, nil)
}

func jsCheckUpdate(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	v := struct {
		Filename string `json:"filename"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, jsScript := range myDice.JsScriptList {
			if jsScript.Filename == v.Filename {
				oldJs, newJs, tempFileName, errUpdate := myDice.JsCheckUpdate(jsScript)
				if errUpdate != nil {
					return Error(&c, errUpdate.Error(), Response{})
				}
				return Success(&c, Response{
					"old":          oldJs,
					"new":          newJs,
					"format":       "javascript",
					"filename":     jsScript.Filename,
					"tempFileName": tempFileName,
				})
			}
		}
		return Error(&c, "未找到脚本", Response{})
	}
	return Success(&c, Response{})
}

func jsUpdate(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	if !myDice.Config.JsEnable {
		return Error(&c, "js扩展支持已关闭", Response{})
	}

	v := struct {
		Filename     string `json:"filename"`
		TempFileName string `json:"tempFileName"`
	}{}
	err := c.Bind(&v)

	if err == nil && v.Filename != "" {
		for _, jsScript := range myDice.JsScriptList {
			if jsScript.Filename == v.Filename {
				err = myDice.JsUpdate(jsScript, v.TempFileName)
				if err != nil {
					return Error(&c, err.Error(), Response{})
				}
				myDice.MarkModified()
				break
			}
		}
	}
	return Success(&c, Response{})
}
