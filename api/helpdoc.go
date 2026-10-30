package api

import (
	"mime/multipart"
	"net/http"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func helpDocStatus(c echo.Context) error {
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	return Success(&c, Response{
		"loading": dm.IsHelpDocLoading(),
	})
}

func helpDocTree(c echo.Context) error {
	if !doAuth(c) {
		return c.NoContent(http.StatusForbidden)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}

	if err := waitForHelpDocStartup(c, Response{}); err != nil {
		return err
	}
	return dm.WithHelpDocManagerRead(func(help *dice.HelpManager) error {
		if help == nil {
			return helpDocUnavailable(c)
		}
		return Success(&c, Response{
			"data": help.HelpDocTree,
		})
	})
}

func helpDocUnavailable(c echo.Context) error {
	return Error(&c, "帮助文档不可用，请重载或重启", Response{})
}

func waitForHelpDocStartup(c echo.Context, data Response) error {
	if err := dm.WaitForHelpDocStartup(c.Request().Context()); err != nil {
		return Error(&c, err.Error(), data)
	}
	return nil
}

func helpDocReload(c echo.Context) error {
	if !doAuth(c) {
		return c.NoContent(http.StatusForbidden)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}

	if !dm.IsHelpReloading.Load() {
		if err := dm.ReloadHelp(); err != nil {
			return Error(&c, err.Error(), Response{})
		}
		return Success(&c, Response{})
	}
	return Error(&c, "帮助文档正在重新装载", Response{})
}

func helpDocUpload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Success(&c, Response{
			"testMode": true,
		})
	}
	if err := waitForHelpDocStartup(c, Response{}); err != nil {
		return err
	}
	available := false
	if err := dm.WithHelpDocManagerRead(func(help *dice.HelpManager) error {
		available = help != nil
		return nil
	}); err != nil {
		return err
	}
	if !available {
		return helpDocUnavailable(c)
	}

	group := c.FormValue("group")
	form, err := c.MultipartForm()
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	if group == "builtin" {
		return Error(&c, "不能为内置分组", Response{})
	}
	files := form.File["files"]
	return dm.WithHelpDocManagerWrite(func(help *dice.HelpManager) error {
		if help == nil {
			return helpDocUnavailable(c)
		}
		for _, file := range files {
			src, err := file.Open()
			if err != nil {
				return Error(&c, err.Error(), Response{})
			}
			defer func(src multipart.File) {
				_ = src.Close()
			}(src)

			if err := help.UploadHelpDoc(src, group, file.Filename); err != nil {
				return Error(&c, "上传文件 "+file.Filename+" 失败："+err.Error(), Response{})
			}
		}
		return Success(&c, Response{"result": true})
	})
}

func helpDocDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Success(&c, Response{
			"testMode": true,
		})
	}

	if err := waitForHelpDocStartup(c, Response{}); err != nil {
		return err
	}
	return dm.WithHelpDocManagerWrite(func(help *dice.HelpManager) error {
		if help == nil {
			return helpDocUnavailable(c)
		}
		v := struct {
			Keys []string `json:"keys"`
		}{}
		if err := c.Bind(&v); err == nil {
			if err := help.DeleteHelpDoc(v.Keys); err != nil {
				return Error(&c, err.Error(), Response{})
			}
		}
		return Success(&c, Response{})
	})
}

func helpGetTextItemPage(c echo.Context) error {
	v := struct {
		PageNum  int    `json:"pageNum"`
		PageSize int    `json:"pageSize"`
		ID       string `json:"id"`
		Group    string `json:"group"`
		From     string `json:"from"`
		Title    string `json:"title"`
	}{}
	err := c.Bind(&v)
	if err == nil {
		if err := waitForHelpDocStartup(c, Response{"total": 0, "data": dice.HelpTextVos{}}); err != nil {
			return err
		}
		return dm.WithHelpDocManagerRead(func(help *dice.HelpManager) error {
			if help == nil || !help.IsAvailable() {
				return Error(&c, "帮助文档不可用，请重载或重启", Response{"total": 0, "data": dice.HelpTextVos{}})
			}
			total, data := help.GetHelpItemPage(v.PageNum, v.PageSize, v.ID, v.Group, v.From, v.Title)
			return Success(&c, Response{"total": total, "data": data})
		})
	}
	return Success(&c, Response{"total": 0, "data": dice.HelpTextVos{}})
}

func helpGetConfig(c echo.Context) error {
	if err := waitForHelpDocStartup(c, Response{}); err != nil {
		return err
	}
	return dm.WithHelpDocManagerRead(func(help *dice.HelpManager) error {
		if help == nil || help.Config == nil {
			return c.JSON(http.StatusOK, dice.HelpConfig{Aliases: make(map[string][]string)})
		}
		return c.JSON(http.StatusOK, help.Config)
	})
}

func helpSetConfig(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Success(&c, Response{
			"testMode": true,
		})
	}
	if dm.IsHelpReloading.Load() {
		return Error(&c, "帮助文档正在重新装载", Response{})
	}
	if err := waitForHelpDocStartup(c, Response{}); err != nil {
		return err
	}
	return dm.WithHelpDocManagerWrite(func(help *dice.HelpManager) error {
		if help == nil {
			return helpDocUnavailable(c)
		}
		var v dice.HelpConfig
		if err := c.Bind(&v); err != nil {
			return c.NoContent(http.StatusBadRequest)
		}
		if err := help.SaveHelpConfig(&v); err != nil {
			return Error(&c, err.Error(), Response{})
		}
		return Success(&c, Response{})
	})
}
