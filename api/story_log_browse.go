package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice/service"
)

// storyBrowseItemPage 群消息 log 浏览器：按群聊日志分页检索消息。
// 与 /story/items/page 的区别是支持关键词、发送者、时间范围和排序，并返回总数。
func storyBrowseItemPage(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := service.QueryLogLineBrowse{}
	if err := c.Bind(&v); err != nil {
		return Error(&c, err.Error(), Response{})
	}
	if v.GroupID == "" || v.LogName == "" {
		return Error(&c, "groupId 和 logName 不能为空", Response{})
	}

	total, items, err := service.LogBrowseLinePage(myDice.DBOperator, &v)
	if err != nil {
		myDice.Logger.Error("storyBrowseItemPage", err)
		return Error(&c, "查询群消息失败", Response{})
	}

	return Success(&c, Response{
		"data":     items,
		"total":    total,
		"pageNum":  v.PageNum,
		"pageSize": v.PageSize,
	})
}
