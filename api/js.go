package api

import (
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/dop251/goja"
	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/utils"
	"Scardice-core/utils/jsengine"
)

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
	engine, configErr := jsengine.ParseEngineID(myDice.Config.JsEngine)
	if configErr != nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result": false,
			"err":    fmt.Sprintf("JS引擎配置无效: %v", configErr),
		})
	}
	if myDice.ExtLoopManager == nil || myDice.JsPrinter == nil {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"result": false,
			"err":    "JS运行时不可用",
		})
	}

	myDice.JsPrinter.RecordStart()
	var retFinal interface{}
	switch engine {
	case jsengine.EngineQuickJS:
		loop := myDice.ExtLoopManager.GetActiveEngineLoop()
		if loop == nil {
			err = errors.New("QuickJS运行时不可用")
			break
		}
		if loop.Engine() != engine {
			err = errors.New("JS运行时与配置不匹配")
			break
		}
		err = loop.Run(func(runtime jsengine.Runtime) error {
			ret, runErr := runtime.RunString("api-js-exec.js", source)
			if runErr != nil {
				return runErr
			}
			retFinal = ret.Export()
			return nil
		})
	case jsengine.EngineGoja:
		loop := myDice.ExtLoopManager.GetWebLoop()
		if loop == nil {
			err = errors.New("Goja运行时不可用")
			break
		}
		waitRun := make(chan int, 1)
		var ret goja.Value
		if !loop.RunOnLoop(func(vm *goja.Runtime) {
			defer func() {
				// 防止崩掉进程
				if r := recover(); r != nil {
					// fmt.Println("xx", r.(goja.Exception))
					myDice.JsPrinter.Error(fmt.Sprintf("JS脚本报错: %v", r))
				}
				waitRun <- 1
			}()
			ret, err = vm.RunString(source)
		}) {
			err = errors.New("Goja运行时已停止")
			break
		}
		<-waitRun
		if ret != nil {
			retFinal = ret.Export()
		}
	default:
		err = fmt.Errorf("不支持的JS引擎: %s", engine)
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
	if err = utils.AtomicWriteReader(filepath.Join(myDice.BaseConfig.DataDir, "scripts", file.Filename), src, 0o644); err != nil {
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
