package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/service"
	"Scardice-core/dice/storylog"
	"Scardice-core/model"
)

func storyGetInfo(c echo.Context) error {
	info, err := service.LogGetInfo(myDice.DBOperator)
	if err != nil {
		myDice.Logger.Error("storyGetInfo", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, info)
}

// Deprecated: replaced by page
func storyGetLogs(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	logs, err := service.LogGetLogs(myDice.DBOperator)
	if err != nil {
		myDice.Logger.Error("storyGetLogs", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, logs)
}

func storyGetLogPage(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	v := service.QueryLogPage{}
	err := c.Bind(&v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}

	if v.PageNum < 1 {
		v.PageNum = 1
	}
	if v.PageSize <= 0 {
		v.PageSize = 20
	}

	total, page, err := service.LogGetLogPage(myDice.DBOperator, &v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}

	return Success(&c, Response{
		"data":     page,
		"total":    total,
		"pageNum":  v.PageNum,
		"pageSize": len(page),
	})
}

// Deprecated: replaced by page
func storyGetItems(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	lines, err := service.LogGetAllLines(myDice.DBOperator, c.QueryParam("groupId"), c.QueryParam("name"))
	if err != nil {
		myDice.Logger.Error("storyGetItems", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, lines)
}

func storyGetItemPage(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := service.QueryLogLinePage{}
	err := c.Bind(&v)
	if err != nil {
		myDice.Logger.Error("storyGetItemPage", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	if v.PageNum < 1 {
		v.PageNum = 1
	}
	if v.PageSize <= 0 {
		v.PageSize = 10
	}

	lines, err := service.LogGetLinePage(myDice.DBOperator, &v)
	if err != nil {
		myDice.Logger.Error("storyGetItemPage", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, lines)
}

func storyDelLog(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	v := &model.LogInfo{}
	err := c.Bind(&v)
	if err != nil {
		myDice.Logger.Error("storyDelLog", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	err = service.LogDelete(myDice.DBOperator, v.GroupID, v.Name)
	if err != nil {
		if errors.Is(err, service.ErrLogNotFound) {
			return c.JSON(http.StatusNotFound, false)
		}
		myDice.Logger.Error("storyDelLog", "failed to delete", err)
		return c.JSON(http.StatusInternalServerError, false)
	}
	return c.JSON(http.StatusOK, true)
}

func storyDownloadLog(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	groupID := strings.TrimSpace(c.QueryParam("groupId"))
	name := strings.TrimSpace(c.QueryParam("name"))
	if groupID == "" || name == "" {
		return Error(&c, "groupId 和 name 不能为空", Response{})
	}

	path, filename, err := storylog.ExportLocalZip(storylog.UploadEnv{
		Db:      myDice.DBOperator,
		Log:     myDice.Logger,
		GroupID: groupID,
		LogName: name,
	})
	if err != nil {
		myDice.Logger.Warn("storyDownloadLog", err)
		return Error(&c, "导出日志失败："+err.Error(), Response{})
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(path)) }()
	return c.Attachment(path, filename)
}

func storyUploadLog(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	v := &model.LogInfo{}
	_ = c.Bind(&v)
	url, notice, err := logSendToBackend(v.GroupID, v.Name)
	if err != nil {
		myDice.Logger.Error("storyUploadLog", err)
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	ret := fmt.Sprintf("跑团日志已上传服务器，链接如下：<br/>%s", url)
	if notice != "" {
		ret += "<br/>" + notice
	}
	return c.JSON(http.StatusOK, ret)
}

func storyGetLogBackupList(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	list, err := dice.StoryLogBackupList(myDice)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	return Success(&c, Response{
		"data": list,
	})
}

func storyDownloadLogBackup(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	name := c.QueryParam("name")
	path, err := dice.StoryLogBackupDownloadPath(myDice, name)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	return c.Attachment(path, name)
}

func storyBatchDeleteLogBackup(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := struct {
		Names []string `json:"names"`
	}{}
	err := c.Bind(&v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	fails := dice.StoryLogBackupBatchDelete(myDice, v.Names)
	if len(fails) > 0 {
		return Error(&c, fmt.Sprintf("部分备份删除失败：%s", strings.Join(fails, "，")), Response{})
	}
	return Success(&c, Response{})
}

func logSendToBackend(groupID string, logName string) (string, string, error) {
	ctx := &dice.MsgContext{
		Dice:     myDice,
		EndPoint: myDice.UIEndpoint,
	}

	return dice.LogSendToBackend(ctx, groupID, logName)
}
