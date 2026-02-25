package api

import (
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dop251/goja"
	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func normalizeJsEngineName(name string) string {
	engine := strings.ToLower(strings.TrimSpace(name))
	switch engine {
	case "goja", "quickjs":
		return engine
	default:
		return ""
	}
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

	var retFinal interface{}
	var errText interface{}
	source := "(function(exports, require, module) {" + v.Value + "\n})()"
	codeJSON, _ := json.Marshal(v.Value)
	// QuickJS 使用局部作用域注入 CommonJS 变量，避免污染共享 VM 的全局对象。
	// 先用 direct eval 保留脚本 completion value（如 async IIFE Promise），
	// 若命中“顶层 return”语法错误，再回退到 Function 包装兼容旧控制台写法。
	quickJSSource := `(function(){
	const exports = {};
	const module = { exports: exports };
	const require = function(_name){ throw new Error("require is not available in js/exec sandbox"); };
	const __sd_code = ` + string(codeJSON) + `;
	try {
		return eval(__sd_code);
	} catch (e) {
		const isReturnSyntaxError = e && e.name === "SyntaxError" && /return/i.test(String(e.message || ""));
		if (!isReturnSyntaxError) {
			throw e;
		}
		const fn = new Function("exports", "require", "module", __sd_code);
		return fn(exports, require, module);
	}
	})()`
	if myDice.JsPrinter != nil {
		myDice.JsPrinter.RecordStart()
	}

	if myDice.JsEngineEffective == "quickjs" {
		// QuickJS 走统一脚本引擎接口，避免依赖 Goja 的 eventloop。
		if myDice.ScriptEngine == nil {
			errText = "QuickJS引擎未初始化"
		} else if evalWithRet, ok := myDice.ScriptEngine.(interface {
			EvalWithResult(code string) (any, error)
		}); ok {
			retFinal, err = evalWithRet.EvalWithResult(quickJSSource)
			if err != nil {
				errText = err.Error()
			}
		} else if err = myDice.ScriptEngine.Eval(quickJSSource); err != nil {
			errText = err.Error()
		}
	} else {
		if myDice.ExtLoopManager == nil || myDice.ExtLoopManager.GetWebLoop() == nil {
			errText = "Goja事件循环未初始化"
		} else {
			loop := myDice.ExtLoopManager.GetWebLoop()
			waitRun := make(chan int, 1)
			var ret goja.Value
			loop.RunOnLoop(func(vm *goja.Runtime) {
				defer func() {
					// 防止崩掉进程
					if r := recover(); r != nil {
						if myDice.JsPrinter != nil {
							myDice.JsPrinter.InternalError(fmt.Sprintf("JS脚本报错: %v", r))
						}
					}
					waitRun <- 1
				}()
				ret, err = vm.RunString(source)
			})
			<-waitRun
			if ret != nil {
				retFinal = ret.Export()
			}
			if err != nil {
				errText = err.Error()
			}
		}
	}

	outputs := []string{}
	if myDice.JsPrinter != nil {
		outputs = myDice.JsPrinter.RecordEnd()
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
	dst, err := os.Create(filepath.Join(myDice.BaseConfig.DataDir, "scripts", file.Filename))
	if err != nil {
		return err
	}
	defer func(dst *os.File) {
		_ = dst.Close()
	}(dst)

	// Copy
	if _, err = io.Copy(dst, src); err != nil {
		return err
	}

	return c.JSON(http.StatusOK, nil)
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
		dice.JsScriptInfo
		BuiltinUpdated bool `json:"builtinUpdated"`
	}
	scripts := make([]*script, 0, len(myDice.JsScriptList))
	for _, info := range myDice.JsScriptList {
		temp := script{
			JsScriptInfo:   *info,
			BuiltinUpdated: info.Builtin && !myDice.JsBuiltinDigestSet[info.Digest],
		}
		scripts = append(scripts, &temp)
	}

	return c.JSON(http.StatusOK, scripts)
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

func jsEngineGet(c echo.Context) error {
	current := normalizeJsEngineName(myDice.Config.JsEngine)
	if current == "" {
		current = "goja"
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"result":          true,
		"engine":          current,
		"effectiveEngine": myDice.JsEngineEffective,
		"fallbackReason":  myDice.JsEngineFallback,
		"options":         []string{"goja", "quickjs"},
	})
}

func jsEngineSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	req := struct {
		Engine string `json:"engine"`
	}{}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"result": false,
			"err":    err.Error(),
		})
	}

	engine := normalizeJsEngineName(req.Engine)
	if engine == "" {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"result": false,
			"err":    "engine仅支持 goja 或 quickjs",
		})
	}

	currentCfgEngine := normalizeJsEngineName(myDice.Config.JsEngine)
	currentEffective := normalizeJsEngineName(myDice.JsEngineEffective)
	if currentCfgEngine == engine && currentEffective == engine {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result":  true,
			"engine":  engine,
			"changed": false,
		})
	}

	reloaded := false
	if myDice.Config.JsEnable {
		locked := myDice.JsReloadLock.TryLock()
		if !locked {
			return c.JSON(http.StatusConflict, map[string]interface{}{
				"result": false,
				"err":    "当前有其他JS重载任务正在执行，请稍后重试",
			})
		}
		defer myDice.JsReloadLock.Unlock()
	}

	myDice.Config.JsEngine = engine
	myDice.MarkModified()
	myDice.Save(false)

	if myDice.Config.JsEnable {
		myDice.JsReload()
		reloaded = true
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"result":   true,
		"engine":   engine,
		"changed":  true,
		"reloaded": reloaded,
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
