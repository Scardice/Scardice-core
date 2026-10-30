package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/service"
	"Scardice-core/model"
)

func requireStoryLogRepository() (service.LogRepository, error) {
	if myDice == nil || myDice.LogRepository == nil {
		return nil, service.ErrLogRepositoryUnavailable
	}
	return myDice.LogRepository, nil
}

func storyCheckLog(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if _, err := requireStoryLogRepository(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	var request struct {
		EndpointID string `json:"endpointId"`
		GroupID    string `json:"groupId"`
		AfterSeq   int64  `json:"afterSeq"`
		BeforeSeq  int64  `json:"beforeSeq"`
	}
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	if err := myDice.StartLogGapCheck(request.EndpointID, request.GroupID, request.AfterSeq, request.BeforeSeq); err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}
	return c.JSON(http.StatusAccepted, map[string]bool{"accepted": true})
}

func storyGetInfo(c echo.Context) error {
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	info, err := repo.StorageInfo()
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
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	logs, err := repo.AllLogs()
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
	if err := c.Bind(&v); err != nil {
		return Error(&c, err.Error(), Response{})
	}
	if v.PageNum < 1 {
		v.PageNum = 1
	}
	if v.PageSize <= 0 {
		v.PageSize = 20
	}
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	total, page, err := repo.LogsPage(&v)
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
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	lines, err := repo.Entries(c.QueryParam("groupId"), c.QueryParam("name"))
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
	if err := c.Bind(&v); err != nil {
		myDice.Logger.Error("storyGetItemPage", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	if v.PageNum < 1 {
		v.PageNum = 1
	}
	if v.PageSize <= 0 {
		v.PageSize = 10
	}
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	lines, err := repo.ItemsPage(v.GroupID, v.LogName, v.PageNum, v.PageSize)
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
	v := struct {
		GroupID string `json:"groupId" query:"groupId"`
		Name    string `json:"name"    query:"name"`
	}{}
	if err := c.Bind(&v); err != nil {
		myDice.Logger.Error("storyDelLog", err)
		return c.JSON(http.StatusInternalServerError, err)
	}
	repo, err := requireStoryLogRepository()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	if err = repo.Delete(v.GroupID, v.Name); err != nil {
		if errors.Is(err, service.ErrLogNotFound) {
			return c.JSON(http.StatusNotFound, false)
		}
		myDice.Logger.Error("storyDelLog", "failed to delete", err)
		return c.JSON(http.StatusInternalServerError, false)
	}
	return c.JSON(http.StatusOK, true)
}

func storyUploadLog(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if _, err := requireStoryLogRepository(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, err.Error())
	}
	v := &model.LogInfo{}
	_ = c.Bind(&v)
	unofficial, url, notice, err := logSendToBackend(v.GroupID, v.Name)
	if err != nil {
		myDice.Logger.Error("storyUploadLog", err)
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	ret := fmt.Sprintf("跑团日志已上传服务器，链接如下：<br/>%s", url)
	if unofficial {
		ret += "<br/>[注意：该链接非余烬官方染色器]"
	}
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

func logSendToBackend(groupID string, logName string) (bool, string, string, error) {
	ctx := &dice.MsgContext{
		Dice:     myDice,
		EndPoint: myDice.UIEndpoint,
	}

	return dice.LogSendToBackend(ctx, groupID, logName)
}
