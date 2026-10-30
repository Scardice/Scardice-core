package api

import (
	"bufio"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func banConfigGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	return c.JSON(http.StatusOK, myDice.Config.BanList)
}

func banConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := dice.BanListInfo{}
	err := c.Bind(&v)
	if err != nil {
		return c.String(430, err.Error())
	}

	if v.ThresholdWarn == 0 {
		v.ThresholdWarn = 100
	}

	if v.ThresholdBan == 0 {
		v.ThresholdBan = 200
	}

	config := &myDice.Config
	config.BanList.BanBehaviorRefuseReply = v.BanBehaviorRefuseReply
	config.BanList.BanBehaviorRefuseInvite = v.BanBehaviorRefuseInvite
	config.BanList.BanBehaviorQuitLastPlace = v.BanBehaviorQuitLastPlace
	config.BanList.BanBehaviorQuitPlaceImmediately = v.BanBehaviorQuitPlaceImmediately
	config.BanList.BanBehaviorQuitIfAdmin = v.BanBehaviorQuitIfAdmin
	config.BanList.BanBehaviorQuitIfAdminSilentIfNotAdmin = v.BanBehaviorQuitIfAdminSilentIfNotAdmin
	config.BanList.ScoreReducePerMinute = v.ScoreReducePerMinute
	config.BanList.ThresholdWarn = v.ThresholdWarn
	config.BanList.ThresholdBan = v.ThresholdBan
	config.BanList.ScoreGroupMuted = v.ScoreGroupMuted
	config.BanList.ScoreGroupKicked = v.ScoreGroupKicked
	config.BanList.ScoreTooManyCommand = v.ScoreTooManyCommand

	config.BanList.JointScorePercentOfGroup = v.JointScorePercentOfGroup
	config.BanList.JointScorePercentOfInviter = v.JointScorePercentOfInviter
	config.BanList.BanNotifyIntervalMinutes = v.BanNotifyIntervalMinutes
	myDice.MarkModified()

	return c.JSON(http.StatusOK, myDice.Config.BanList)
}

func banMapList(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil || myDice.Config.BanList == nil {
		return c.JSON(http.StatusServiceUnavailable, Response{
			"code":    "ban_storage_unavailable",
			"message": "黑白名单存储不可用",
		})
	}
	if err := myDice.Config.BanList.PersistenceError(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, Response{
			"code":    "ban_storage_unavailable",
			"message": err.Error(),
		})
	}
	return c.JSON(http.StatusOK, myDice.GetBanList())
}

func banMapDeleteOne(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm != nil && dm.JustForTest {
		return c.JSON(http.StatusOK, map[string]interface{}{"testMode": true})
	}
	v := dice.BanListInfoItem{}
	if err := c.Bind(&v); err != nil {
		return c.String(430, err.Error())
	}
	if v.ID == "" {
		return c.JSON(http.StatusBadRequest, Response{"code": "invalid_ban_id", "message": "ID 不能为空"})
	}
	if myDice == nil || myDice.Config.BanList == nil {
		return c.JSON(http.StatusServiceUnavailable, Response{"code": "ban_storage_unavailable", "message": "黑白名单存储不可用"})
	}
	if err := myDice.Config.BanList.PersistenceError(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, Response{"code": "ban_storage_unavailable", "message": err.Error()})
	}
	if err := myDice.Config.BanList.DeleteByIDWithError(myDice, v.ID); err != nil {
		return c.JSON(http.StatusInternalServerError, Response{"code": "ban_storage_failed", "message": err.Error()})
	}
	return c.JSON(http.StatusOK, nil)
}

func banMapAddOne(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm != nil && dm.JustForTest {
		return c.JSON(http.StatusOK, map[string]interface{}{"testMode": true})
	}
	v := dice.BanListInfoItem{}
	if err := c.Bind(&v); err != nil {
		return c.String(430, err.Error())
	}
	if v.ID == "" {
		return c.JSON(http.StatusBadRequest, Response{"code": "invalid_ban_id", "message": "ID 不能为空"})
	}
	if myDice == nil || myDice.Config.BanList == nil {
		return c.JSON(http.StatusServiceUnavailable, Response{"code": "ban_storage_unavailable", "message": "黑白名单存储不可用"})
	}
	banList := myDice.Config.BanList
	if err := banList.PersistenceError(); err != nil {
		return c.JSON(http.StatusServiceUnavailable, Response{"code": "ban_storage_unavailable", "message": err.Error()})
	}
	reason := "骰主后台设置"
	if len(v.Reasons) > 0 && v.Reasons[0] != "" {
		reason = v.Reasons[0]
	}
	switch v.Rank {
	case dice.BanRankBanned, dice.BanRankWarn, dice.BanRankTrusted, dice.BanRankNormal:
	default:
		return c.JSON(http.StatusBadRequest, Response{"code": "invalid_ban_rank", "message": "身份必须为禁止、警告、信任或常规"})
	}
	if err := banList.SetRankByID(myDice, v.ID, v.Rank, v.Name, "余烬后台", reason); err != nil {
		return c.JSON(http.StatusInternalServerError, Response{"code": "ban_storage_failed", "message": err.Error()})
	}
	return c.JSON(http.StatusOK, nil)
}

//
// func banMapSet(c echo.Context) error {
//	if !doAuth(c) {
//		return c.JSON(http.StatusForbidden, nil)
//	}
//
//	v := struct {
//		data []byte
//	}{}
//	err := c.Bind(&v)
//	if err != nil {
//		return c.String(430, err.Error())
//	}
//
//	(&myDice.Config).BanList.LoadMapFromJSON(v.data)
//	return c.JSON(http.StatusOK, nil)
//}

func banExport(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm != nil && dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	if myDice == nil || myDice.Config.BanList == nil {
		return Error(&c, "黑白名单存储不可用", Response{"code": "ban_storage_unavailable"})
	}
	if err := myDice.Config.BanList.PersistenceError(); err != nil {
		return Error(&c, err.Error(), Response{"code": "ban_storage_unavailable"})
	}
	lst := myDice.GetBanList()

	temp, err := os.CreateTemp("", "黑白名单-*.json")
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	defer func() {
		_ = temp.Close()
		_ = os.Remove(temp.Name()) //nolint:gosec
	}()
	writer := bufio.NewWriter(temp)
	if err = json.NewEncoder(writer).Encode(&lst); err != nil {
		return Error(&c, err.Error(), Response{})
	}
	if err = writer.Flush(); err != nil {
		return Error(&c, err.Error(), Response{})
	}
	if err = temp.Close(); err != nil {
		return Error(&c, err.Error(), Response{})
	}

	c.Response().Header().Add("Cache-Control", "no-store")
	return c.Attachment(temp.Name(), "黑白名单.json")
}

func banImport(c echo.Context) error {
	if !doAuth(c) {
		return c.NoContent(http.StatusForbidden)
	}
	if dm != nil && dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}
	if myDice == nil || myDice.Config.BanList == nil {
		return Error(&c, "黑白名单存储不可用", Response{"code": "ban_storage_unavailable"})
	}
	if err := myDice.Config.BanList.PersistenceError(); err != nil {
		return Error(&c, err.Error(), Response{"code": "ban_storage_unavailable"})
	}

	file, err := c.FormFile("file")
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	src, err := file.Open()
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	defer func(src multipart.File) {
		_ = src.Close()
	}(src)

	var lst []*dice.BanListInfoItem
	data, err := io.ReadAll(src)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	err = json.Unmarshal(data, &lst)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}

	for _, item := range lst {
		if item == nil || item.ID == "" {
			return Error(&c, "名单文件包含空身份 ID", Response{"code": "invalid_ban_id"})
		}
	}

	for _, item := range lst {
		var newReasons []string
		for _, reason := range item.Reasons {
			if !strings.HasSuffix(reason, "（来自导入）") {
				newReasons = append(newReasons, reason+"（来自导入）")
			}
		}
		item.Reasons = newReasons
	}
	if err = myDice.Config.BanList.ImportItems(myDice, lst); err != nil {
		return Error(&c, err.Error(), Response{"code": "ban_storage_failed"})
	}

	return Success(&c, Response{})
}
