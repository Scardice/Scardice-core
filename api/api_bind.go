package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humaecho"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/monaco-io/request"
	"github.com/robfig/cron/v3"
	"github.com/samber/lo"

	"Scardice-core/dice"
)

const CodeAlreadyExists = 602

var startTime = time.Now().Unix()

type VersionDetail struct {
	Major         uint64 `json:"major"`
	Minor         uint64 `json:"minor"`
	Patch         uint64 `json:"patch"`
	Prerelease    string `json:"prerelease"`
	BuildMetaData string `json:"buildMetaData"`
}

func preInfo(c echo.Context) error {
	return c.JSON(200, map[string]interface{}{
		"testMode":                       dm.JustForTest,
		"testWebUIAuthBypass":            testWebUIAuthBypassEnabled(),
		"testWebUIOriginRateLimitBypass": WebUIOriginRateLimitBypassEnabled(),
	})
}

func baseInfo(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var versionNew string
	var versionNewNote string
	var versionNewCode int64
	if dm.AppVersionOnline != nil {
		versionNew = dm.AppVersionOnline.VersionLatestDetail
		versionNewNote = dm.AppVersionOnline.VersionLatestNote
		versionNewCode = dm.AppVersionOnline.VersionLatestCode
	}

	getName := func() string {
		defer func() {
			// 防止报错
			_ = recover()
		}()

		ctx := &dice.MsgContext{Dice: myDice, EndPoint: nil, Session: myDice.ImSession}
		return dice.DiceFormatTmpl(ctx, "核心:骰子名字")
	}
	extraTitle := getName()

	versionDetail := VersionDetail{
		Major:         dice.VERSION.Major(),
		Minor:         dice.VERSION.Minor(),
		Patch:         dice.VERSION.Patch(),
		Prerelease:    dice.VERSION.Prerelease(),
		BuildMetaData: dice.VERSION.Metadata(),
	}

	return c.JSON(http.StatusOK, struct {
		AppName        string        `json:"appName"`
		AppChannel     string        `json:"appChannel"`
		Version        string        `json:"version"`
		VersionSimple  string        `json:"versionSimple"`
		VersionDetail  VersionDetail `json:"versionDetail"`
		VersionNew     string        `json:"versionNew"`
		VersionNewNote string        `json:"versionNewNote"`
		VersionCode    int64         `json:"versionCode"`
		VersionNewCode int64         `json:"versionNewCode"`
		MemoryAlloc    uint64        `json:"memoryAlloc"`
		Uptime         int64         `json:"uptime"`
		MemoryUsedSys  uint64        `json:"memoryUsedSys"`
		ExtraTitle     string        `json:"extraTitle"`
		OS             string        `json:"OS"`
		Arch           string        `json:"arch"`
		JustForTest    bool          `json:"justForTest"`
		ContainerMode  bool          `json:"containerMode"`
	}{
		AppName:        dice.APPNAME,
		AppChannel:     dice.APP_CHANNEL,
		Version:        dice.VERSION.String(),
		VersionSimple:  dice.VERSION_MAIN + dice.VERSION_PRERELEASE,
		VersionDetail:  versionDetail,
		VersionNew:     versionNew,
		VersionNewNote: versionNewNote,
		VersionCode:    dice.VERSION_CODE,
		VersionNewCode: versionNewCode,
		MemoryAlloc:    m.Alloc,
		MemoryUsedSys:  m.Sys - m.HeapReleased,
		Uptime:         time.Now().Unix() - startTime,
		ExtraTitle:     extraTitle,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		JustForTest:    dm.JustForTest,
		ContainerMode:  dm.ContainerMode,
	})
}

func hello2(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	return c.JSON(http.StatusOK, nil)
}

var (
	myDice *dice.Dice
	dm     *dice.DiceManager
)

type fStopEcho struct {
	Key string `json:"key"`
}

// 这个函数是用来强制停止程序的，只有在Android上才能使用，其他平台会返回403
func forceStop(c echo.Context) error {
	if runtime.GOOS != "android" {
		return c.JSON(http.StatusForbidden, nil)
	}
	// this is a dangerous api, so we need to check the key
	haskey := false
	for _, s := range os.Environ() {
		if strings.HasPrefix(s, "FSTOP_KEY=") {
			key := strings.TrimPrefix(s, "FSTOP_KEY=")
			v := fStopEcho{}
			err := c.Bind(&v)
			if err != nil {
				return c.JSON(http.StatusBadRequest, nil)
			}
			if v.Key == key {
				haskey = true
				break
			} else {
				return c.JSON(http.StatusForbidden, nil)
			}
		}
	}
	if !haskey {
		return c.JSON(http.StatusForbidden, nil)
	}
	defer func() {
		log := myDice.Logger
		log.Info("程序即将退出，进行清理……")
		if err := recover(); err != nil {
			log.Errorf("异常: %v\n堆栈: %v", err, string(debug.Stack()))
		}
		diceManager := dm
		for _, instance := range diceManager.Dice {
			if instance != nil && instance.Cron != nil {
				instance.Cron.Stop()
			}
		}
		if diceManager.Cron != nil {
			diceManager.Cron.Stop()
		}
		log.Info("事件源 Core 清理完成，程序即将退出")
		os.Exit(0)
	}()
	return c.JSON(http.StatusOK, nil)
}

func doSignInGetSalt(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{
		"salt": myDice.Parent.UIPasswordSalt,
	})
}

func checkSecurity(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	isPublicService := strings.HasPrefix(myDice.Parent.ServeAddress, "0.0.0.0") || myDice.Parent.ServeAddress == ":3211"
	isEmptyPassword := myDice.Parent.UIPasswordHash == ""
	return c.JSON(200, map[string]bool{
		"isOk": !isEmptyPassword || !isPublicService,
	})
}

func doSignIn(c echo.Context) error {
	v := struct {
		Password string `json:"password"` //nolint:gosec
	}{}

	err := c.Bind(&v)
	if err != nil {
		return c.JSON(400, nil)
	}

	generateToken := func() error {
		now := time.Now().Unix()
		head := hex.EncodeToString(Int64ToBytes(now))
		randomPart, err := dice.GenerateCryptoToken(32)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error": "failed to generate authentication token",
			})
		}
		token := randomPart + ":" + head

		if myDice.Parent.EventSourcedMode {
			authenticated, err := myDice.Parent.AuthenticateAndStoreAccessToken(v.Password, token)
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to persist authentication token"})
			}
			if !authenticated {
				return c.JSON(http.StatusBadRequest, nil)
			}
		} else {
			myDice.Parent.AccessTokens.Store(token, true)
			myDice.Parent.Save()
		}
		myDice.LastUpdatedTime = time.Now().Unix()
		return c.JSON(http.StatusOK, map[string]string{
			"token": token,
		})
	}

	if myDice.Parent.EventSourcedMode {
		return generateToken()
	}

	if myDice.Parent.UIPasswordHash == "" || myDice.Parent.UIPasswordHash == v.Password {
		return generateToken()
	}

	return c.JSON(400, nil)
}

func logFetchAndClear(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	return c.JSON(http.StatusOK, myDice.LogWriter.Snapshot())
}

func logStream(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	flusher, ok := c.Response().Writer.(http.Flusher)
	if !ok {
		return c.String(http.StatusInternalServerError, "streaming unsupported")
	}

	header := c.Response().Header()
	header.Set(echo.HeaderContentType, "text/event-stream; charset=utf-8")
	header.Set(echo.HeaderCacheControl, "no-cache")
	header.Set(echo.HeaderConnection, "keep-alive")
	header.Set("X-Accel-Buffering", "no")
	c.Response().WriteHeader(http.StatusOK)

	writeEvent := func(event string, payload interface{}) error {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if _, err = fmt.Fprintf(c.Response(), "event: %s\n", event); err != nil {
			return err
		}
		if _, err = fmt.Fprintf(c.Response(), "data: %s\n\n", data); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}

	if _, err := fmt.Fprint(c.Response(), "retry: 3000\n\n"); err != nil {
		return nil
	}
	flusher.Flush()

	subID, logCh, snapshot := myDice.LogWriter.Subscribe(256)
	defer myDice.LogWriter.Unsubscribe(subID)

	if err := writeEvent("snapshot", snapshot); err != nil {
		return nil
	}

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	ctx := c.Request().Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-heartbeat.C:
			if _, err := fmt.Fprint(c.Response(), ": ping\n\n"); err != nil {
				return nil
			}
			flusher.Flush()
		case item, ok := <-logCh:
			if !ok {
				return nil
			}
			if err := writeEvent("log", item); err != nil {
				return nil
			}
		}
	}
}

// uiExecLastAt 记录每个 UI 测试会话最近一次执行的时间，按会话独立限流，
// 多个测试用户或测试群并行发言时互不阻塞。
var uiExecLastAt = struct {
	sync.Mutex
	byConversation map[string]int64
}{byConversation: map[string]int64{}}

type diceExecSplitOption struct {
	Key             string `json:"key"`
	Label           string `json:"label"`
	MessageSplitLen int    `json:"messageSplitLen"`
}

var diceExecSplitOptionsResponse = struct {
	DefaultKey string                `json:"defaultKey"`
	Options    []diceExecSplitOption `json:"options"`
}{
	DefaultKey: "qq",
	Options: []diceExecSplitOption{
		{Key: "short", Label: "短分段 300", MessageSplitLen: 300},
		{Key: "qq", Label: "QQ 分段 2000", MessageSplitLen: 2000},
		{Key: "unlimited", Label: "无限", MessageSplitLen: 0},
	},
}

func diceExecSplitOptions(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	return c.JSON(http.StatusOK, diceExecSplitOptionsResponse)
}

type diceExecRequest struct {
	ID              string `form:"id"              json:"id"`
	Message         string `form:"message"         json:"message"`
	MessageType     string `form:"messageType"     json:"messageType"`
	MessageSplitLen *int   `form:"messageSplitLen" json:"messageSplitLen"`
	UserID          string `form:"userId"          json:"userId"`
	Nickname        string `form:"nickname"        json:"nickname"`
	GroupID         string `form:"groupId"         json:"groupId"`
	GroupName       string `form:"groupName"       json:"groupName"`
	GroupRole       string `form:"groupRole"       json:"groupRole"`
}

type diceExecIdentity struct {
	messageType string
	userID      string
	nickname    string
	groupID     string
	groupName   string
	groupRole   string
}

const (
	uiUserIDPrefix  = "UI:"
	uiGroupIDPrefix = "UI-Group:"
	uiExecNameLimit = 32
)

// uiSandboxIDSuffix 只允许字母、数字、下划线与连字符，长度 1–32，
// 防止测试界面伪造其他平台的身份或注入分隔符。
func validUISandboxIDSuffix(suffix string) bool {
	if suffix == "" || len(suffix) > 32 {
		return false
	}
	for _, r := range suffix {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func trimUIExecName(name, fallback string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return fallback
	}
	if runes := []rune(name); len(runes) > uiExecNameLimit {
		return string(runes[:uiExecNameLimit])
	}
	return name
}

// resolveDiceExecIdentity 把测试请求映射为虚拟发送者。未提供身份字段时保持旧行为：
// 私聊为 UI:1001，群聊为 UI-Group:2001 中的群主 UI:1002。
func resolveDiceExecIdentity(v diceExecRequest) (diceExecIdentity, error) {
	id := diceExecIdentity{messageType: "private", userID: "UI:1001", nickname: "User"}
	if v.MessageType == "group" {
		id = diceExecIdentity{
			messageType: "group", userID: "UI:1002", nickname: "User",
			groupID: "UI-Group:2001", groupName: "UI-Group 2001", groupRole: "owner",
		}
	}
	if v.UserID != "" {
		if !strings.HasPrefix(v.UserID, uiUserIDPrefix) || !validUISandboxIDSuffix(strings.TrimPrefix(v.UserID, uiUserIDPrefix)) {
			return id, errors.New("userId 必须形如 UI:1001")
		}
		id.userID = v.UserID
	}
	id.nickname = trimUIExecName(v.Nickname, id.nickname)
	if id.messageType != "group" {
		return id, nil
	}
	if v.GroupID != "" {
		if !strings.HasPrefix(v.GroupID, uiGroupIDPrefix) || !validUISandboxIDSuffix(strings.TrimPrefix(v.GroupID, uiGroupIDPrefix)) {
			return id, errors.New("groupId 必须形如 UI-Group:2001")
		}
		id.groupID = v.GroupID
		id.groupName = strings.ReplaceAll(strings.TrimPrefix(v.GroupID, "UI-"), ":", " ")
	}
	id.groupName = trimUIExecName(v.GroupName, id.groupName)
	switch v.GroupRole {
	case "":
	case "owner", "admin", "member":
		id.groupRole = v.GroupRole
	default:
		return id, errors.New("groupRole 只能是 owner、admin 或 member")
	}
	return id, nil
}

// DiceExec assigns every accepted request a server-generated `UI:exec:<uuid>`
// RawID, not a provider ID or request-controlled idempotency key. Inbound
// group-log consumers can therefore archive repeated synthetic UI messages.
func DiceExec(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := diceExecRequest{}
	err := c.Bind(&v)
	if err != nil {
		return c.JSON(400, "格式错误")
	}
	if v.Message == "" {
		return c.JSON(400, "格式错误")
	}
	identity, err := resolveDiceExecIdentity(v)
	if err != nil {
		return c.JSON(400, err.Error())
	}
	timeNeed := int64(500)
	if dm.JustForTest {
		timeNeed = 80
	}

	conversation := identity.messageType + ":" + identity.userID
	if identity.messageType == "group" {
		conversation = identity.messageType + ":" + identity.groupID
	}
	now := time.Now().UnixMilli()
	uiExecLastAt.Lock()
	if now-uiExecLastAt.byConversation[conversation] < timeNeed {
		uiExecLastAt.Unlock()
		return c.JSON(400, "过于频繁")
	}
	uiExecLastAt.byConversation[conversation] = now
	uiExecLastAt.Unlock()

	msg := &dice.Message{
		MessageType: identity.messageType,
		Message:     v.Message,
		RawID:       "UI:exec:" + uuid.NewString(),
		Platform:    "UI",
		Sender: dice.SenderBase{
			Nickname:  identity.nickname,
			UserID:    identity.userID,
			GroupRole: identity.groupRole,
		},
		GroupID:   identity.groupID,
		GroupName: identity.groupName,
	}
	if v.MessageSplitLen != nil {
		msg.TestUIOutputSplitLength = *v.MessageSplitLen
		msg.TestUIOutputSplitLengthSet = true
	}
	myDice.ImSession.Execute(myDice.UIEndpoint, msg, false)
	return c.JSON(200, "ok")
}

func DiceRecentMessage(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	reader, ok := myDice.UIEndpoint.Adapter.(interface {
		RecentMessagesSince(string) dice.HTTPMessageBatch
	})
	if !ok {
		return c.JSON(http.StatusServiceUnavailable, nil)
	}
	return c.JSON(http.StatusOK, reader.RecentMessagesSince(c.QueryParam("cursor")))
}

func DiceAllCommand(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	var cmdLst []string
	for k := range myDice.CmdMap {
		cmdLst = append(cmdLst, k)
	}

	for _, i := range myDice.ExtList {
		for k := range i.GetCmdMap() {
			cmdLst = append(cmdLst, k)
		}
	}
	sort.Sort(dice.ByLength(cmdLst))
	return c.JSON(200, cmdLst)
}

func onebotTool(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	v := struct {
		Port int64 `form:"port" json:"port"`
	}{}
	_ = c.Bind(&v)

	port := int64(13325)
	if v.Port != 0 {
		port = v.Port
	}

	errText := ""
	ip, err := socksOpen(myDice, port)
	if err != nil {
		errText = err.Error()
	}

	resp := c.JSON(200, map[string]interface{}{
		"ok":      err == nil,
		"ip":      ip,
		"errText": errText,
	})
	return resp
}

type apiPluginConfig struct {
	PluginName string             `json:"pluginName"`
	Configs    []*dice.ConfigItem `jsbind:"configs"  json:"configs"`
}

type getConfigResp map[string]*apiPluginConfig

type setConfigReq map[string]*apiPluginConfig

type setConfigSingleReq struct {
	PluginName string      `json:"pluginName"`
	Key        string      `json:"key"`
	Value      interface{} `json:"value"`
}

func handleGetConfigs(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	pluginName := c.QueryParam("pluginName")
	resp := getConfigResp{}
	if myDice.DurableStoreAttached() {
		state, itemsErr := myDice.DurableExtensionState(c.Request().Context())
		if itemsErr != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, itemsErr.Error())
		}
		for _, id := range state.ExtensionOrder {
			if pluginName != "" && id != pluginName {
				continue
			}
			configs, err := myDice.DurableExtensionConfigItems(c.Request().Context(), id)
			if err != nil {
				return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
			}
			resp[id] = &apiPluginConfig{PluginName: id, Configs: configs}
		}
		data, itemsErr := json.Marshal(resp)
		if itemsErr != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to marshal data")
		}
		return c.JSONBlob(http.StatusOK, data)
	}
	for k, v := range myDice.ConfigManager.Plugins {
		if pluginName != "" && k != pluginName {
			continue
		}
		configs := make([]*dice.ConfigItem, 0, len(v.OrderedConfigKeys))
		for _, key := range v.OrderedConfigKeys {
			configs = append(configs, v.Configs[key])
		}
		resp[k] = &apiPluginConfig{
			PluginName: v.PluginName,
			Configs:    configs,
		}
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to marshal data")
	}

	return c.JSONBlob(http.StatusOK, data)
}

func handleSetConfigs(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	var data setConfigReq
	err := c.Bind(&data)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse data")
	}
	var errors []error
	for k, v := range data {
		for _, i := range v.Configs {
			err := myDice.ConfigManager.SetConfig(k, i.Key, i.Value)
			if err != nil {
				errors = append(errors, err)
			}
		}
	}
	if len(errors) > 0 {
		errMsg := strings.Join(lo.Map(errors, func(e error, _ int) string {
			return e.Error()
		}), "\n")
		return c.JSON(http.StatusInternalServerError, errMsg)
	}
	return c.JSON(http.StatusOK, nil)
}

func handleSetConfig(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	var data setConfigSingleReq
	err := c.Bind(&data)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse data")
	}
	err = myDice.ConfigManager.SetConfig(data.PluginName, data.Key, data.Value)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, nil)
}

func handleDeleteUnusedConfigs(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	type handleDeleteUnusedConfigsReq struct {
		PluginName string   `json:"pluginName"`
		Keys       []string `json:"keys"`
	}
	var data handleDeleteUnusedConfigsReq
	err := c.Bind(&data)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse data")
	}
	for _, key := range data.Keys {
		myDice.ConfigManager.UnregisterConfig(data.PluginName, key)
	}
	return c.JSON(http.StatusOK, nil)
}

func handleResetConfig(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	var data map[string]string
	err := c.Bind(&data)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse data")
	}
	myDice.ConfigManager.ResetConfigToDefault(data["pluginName"], data["key"])
	return c.JSON(http.StatusOK, nil)
}

func getToken(c echo.Context) error {
	if dm.JustForTest {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"testMode": true,
		})
	}

	key := c.QueryParam("key")
	req := request.Client{
		URL:    fmt.Sprintf("https://gocqhelper.sealdice.com/code_query?key=%s", key),
		Method: "GET",
	}

	resp := req.Send()
	if resp.OK() {
		text := resp.String()
		return c.String(http.StatusOK, text)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{})
}

func checkCronExpr(c echo.Context) error {
	req := make(map[string]string)
	err := c.Bind(&req)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to parse data")
	}
	if _, exist := req["expr"]; !exist {
		return echo.NewHTTPError(http.StatusBadRequest, "No expression")
	}
	_, err = cron.ParseStandard(req["expr"])
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid expression")
	}
	return c.JSON(http.StatusOK, nil)
}

func Bind(e *echo.Echo, _myDice *dice.DiceManager) {
	dm = _myDice
	myDice = _myDice.Dice[0]

	prefix := "/sd-api"

	// 挂载 humaecho 到 echo 实例
	_ = humaecho.New(e, huma.DefaultConfig("Sealdiciapi", "1.0.0"))
	installActivityJSONSerializer(e)
	e.Use(activityMiddleware)

	e.GET(prefix+"/preInfo", preInfo)
	e.GET(prefix+"/baseInfo", baseInfo)
	e.GET(prefix+"/hello", hello2)
	e.GET(prefix+"/log/fetchAndClear", logFetchAndClear)
	e.GET(prefix+"/log/stream", logStream)
	e.GET(prefix+"/endpoints", endpointList)
	e.GET(prefix+"/activity/recent", activityRecent)

	e.POST(prefix+"/endpoints", endpointCreate)
	e.GET(prefix+"/endpoints/:id", endpointGet)
	e.PATCH(prefix+"/endpoints/:id/config", endpointConfigPatch)
	e.POST(prefix+"/endpoints/:id/enable", endpointEnable)
	e.POST(prefix+"/endpoints/:id/disable", endpointDisable)
	e.POST(prefix+"/endpoints/:id/relogin", endpointRelogin)
	e.POST(prefix+"/endpoints/:id/actions/:action", endpointAction)
	e.GET(prefix+"/endpoints/:id/diagnostics", endpointDiagnostics)
	e.DELETE(prefix+"/endpoints/:id", endpointDelete)
	e.GET(prefix+"/operations/:id", operationGet)
	e.POST(prefix+"/operations/:id/resolve", operationResolve)
	e.GET(prefix+"/operations/:id/artifact", operationArtifact)

	e.GET(prefix+"/configs/customText", customText)
	e.POST(prefix+"/configs/customText/save", customTextSave)
	e.POST(prefix+"/configs/customText/preview-refresh", customTextPreviewRefresh)

	e.GET(prefix+"/configs/custom_reply", customReplyGet)
	e.POST(prefix+"/configs/custom_reply/save", customReplySave)
	e.GET(prefix+"/configs/custom_reply/file_list", customReplyFileList)
	e.POST(prefix+"/configs/custom_reply/file_new", customReplyFileNew)
	e.POST(prefix+"/configs/custom_reply/file_delete", customReplyFileDelete)
	e.GET(prefix+"/configs/custom_reply/file_download", customReplyFileDownload)
	e.POST(prefix+"/configs/custom_reply/file_upload", customReplyFileUpload)
	e.GET(prefix+"/configs/custom_reply/debug_mode", customReplyDebugModeGet)
	e.POST(prefix+"/configs/custom_reply/debug_mode", customReplyDebugModeSet)

	e.GET(prefix+"/dice/config/get", DiceConfig)
	e.POST(prefix+"/dice/config/set", DiceConfigSet)
	e.GET(prefix+"/dice/config/advanced/get", DiceAdvancedConfigGet)
	e.POST(prefix+"/dice/config/advanced/set", DiceAdvancedConfigSet)
	e.POST(prefix+"/dice/config/mail_test", DiceMailTest)
	e.POST(prefix+"/dice/exec", DiceExec)
	e.GET(prefix+"/dice/exec/split_options", diceExecSplitOptions)
	e.GET(prefix+"/dice/recentMessage", DiceRecentMessage)
	e.GET(prefix+"/dice/cmdList", DiceAllCommand)
	e.POST(prefix+"/dice/upload_to_upgrade", DiceNewVersionUpload)

	e.GET(prefix+"/dice/public/info", dicePublicInfo)
	e.POST(prefix+"/dice/public/set", dicePublicSet)

	e.POST(prefix+"/dice/config/vm-version-set", vmVersionSet)

	e.POST(prefix+"/signin", doSignIn)
	e.GET(prefix+"/signin/salt", doSignInGetSalt)
	e.GET(prefix+"/checkSecurity", checkSecurity)

	e.GET(prefix+"/backup/list", backupGetList)
	e.POST(prefix+"/backup/do_backup", backupExec)
	e.GET(prefix+"/backup/status", backupStatus)
	e.GET(prefix+"/backup/config_get", backupConfigGet)
	e.POST(prefix+"/backup/config_set", backupConfigSave)
	e.GET(prefix+"/backup/download", backupDownload)
	e.POST(prefix+"/backup/delete", backupDelete)
	e.POST(prefix+"/backup/batch_delete", backupBatchDelete)

	e.GET(prefix+"/group/list", groupList)
	e.POST(prefix+"/group/set_one", groupSetOne)
	e.POST(prefix+"/group/quit_one", groupQuit)
	e.POST(prefix+"/group/local_data/delete", groupLocalDataDelete)

	e.GET(prefix+"/banconfig/list", banMapList)
	e.GET(prefix+"/banconfig/get", banConfigGet)
	e.POST(prefix+"/banconfig/set", banConfigSet)
	// e.GET(prefix+"/banconfig/map_get", banMapGet)
	e.POST(prefix+"/banconfig/map_delete_one", banMapDeleteOne)
	e.POST(prefix+"/banconfig/map_add_one", banMapAddOne)
	// e.POST(prefix+"/banconfig/map_set", banMapSet)
	e.GET(prefix+"/banconfig/export", banExport)
	e.POST(prefix+"/banconfig/import", banImport)

	e.GET(prefix+"/deck/list", deckList)
	e.POST(prefix+"/deck/reload", deckReload)
	e.POST(prefix+"/deck/upload", deckUpload)
	e.POST(prefix+"/deck/enable", deckEnable)
	e.POST(prefix+"/deck/delete", deckDelete)
	e.POST(prefix+"/deck/check_update", deckCheckUpdate)
	e.POST(prefix+"/deck/update", deckUpdate)

	e.POST(prefix+"/dice/upgrade", upgrade)

	e.POST(prefix+"/force_stop", forceStop)

	e.POST(prefix+"/js/reload", jsReload)
	e.GET(prefix+"/js/reload/status", jsReloadStatus)
	e.GET(prefix+"/js/runtime/status", jsRuntimeStatus)
	e.GET(prefix+"/js/runtime/management", jsRuntimeManagementGet)
	e.POST(prefix+"/js/runtime/config", jsRuntimeConfigSet)
	e.POST(prefix+"/js/runtime/install", jsRuntimeInstall)
	e.POST(prefix+"/js/runtime/uninstall", jsRuntimeUninstall)
	e.POST(prefix+"/js/execute", jsExec)
	e.POST(prefix+"/js/upload", jsUpload)
	e.GET(prefix+"/js/list", jsList)
	e.POST(prefix+"/js/delete", jsDelete)
	e.GET(prefix+"/js/get_record", jsGetRecord)
	e.POST(prefix+"/js/shutdown", jsShutdown)
	e.GET(prefix+"/js/status", jsStatus)
	e.POST(prefix+"/js/enable", jsEnable)
	e.POST(prefix+"/js/disable", jsDisable)
	e.POST(prefix+"/js/check_update", jsCheckUpdate)
	e.POST(prefix+"/js/update", jsUpdate)
	e.GET(prefix+"/js/get_configs", handleGetConfigs)
	e.POST(prefix+"/js/set_configs", handleSetConfigs)
	e.POST(prefix+"/js/set_config", handleSetConfig)
	e.POST(prefix+"/js/delete_unused_configs", handleDeleteUnusedConfigs)
	e.POST(prefix+"/js/reset_config", handleResetConfig)

	e.GET(prefix+"/helpdoc/status", helpDocStatus)
	e.GET(prefix+"/helpdoc/tree", helpDocTree)
	e.POST(prefix+"/helpdoc/reload", helpDocReload)
	e.POST(prefix+"/helpdoc/upload", helpDocUpload)
	e.POST(prefix+"/helpdoc/delete", helpDocDelete)
	e.POST(prefix+"/helpdoc/textitem/get_page", helpGetTextItemPage)
	e.GET(prefix+"/helpdoc/config", helpGetConfig)
	e.POST(prefix+"/helpdoc/config", helpSetConfig)

	e.GET(prefix+"/story/info", storyGetInfo)
	e.GET(prefix+"/story/logs", storyGetLogs)
	e.GET(prefix+"/story/logs/page", storyGetLogPage)
	e.GET(prefix+"/story/items", storyGetItems)
	e.GET(prefix+"/story/items/page", storyGetItemPage)
	e.DELETE(prefix+"/story/log", storyDelLog)
	e.POST(prefix+"/story/uploadLog", storyUploadLog)
	e.POST(prefix+"/story/check", storyCheckLog)
	e.GET(prefix+"/story/backup/list", storyGetLogBackupList)
	e.GET(prefix+"/story/backup/download", storyDownloadLogBackup)
	e.POST(prefix+"/story/backup/batch_delete", storyBatchDeleteLogBackup)

	e.POST(prefix+"/tool/onebot", onebotTool)
	e.GET(prefix+"/utils/ga/:uid", getGithubAvatar)
	e.GET(prefix+"/utils/news", getNews)
	e.POST(prefix+"/utils/check_news", checkNews)
	e.GET(prefix+"/utils/get_token", getToken)
	e.POST(prefix+"/utils/check_cron_expr", checkCronExpr)
	e.GET(prefix+"/utils/check_network_health", checkNetworkHealth)

	e.POST(prefix+"/censor/restart", censorRestart)
	e.POST(prefix+"/censor/stop", censorStop)
	e.GET(prefix+"/censor/status", censorGetStatus)
	e.GET(prefix+"/censor/config", censorGetConfig)
	e.POST(prefix+"/censor/config", censorSetConfig)
	e.GET(prefix+"/censor/words", censorGetWords)
	e.GET(prefix+"/censor/files", censorGetWordFiles)
	e.POST(prefix+"/censor/files/upload", censorUploadWordFiles)
	e.DELETE(prefix+"/censor/files", censorDeleteWordFiles)
	e.GET(prefix+"/censor/files/template/toml", censorGetTomlFileTemplate)
	e.GET(prefix+"/censor/files/template/txt", censorGetTxtFileTemplate)
	e.GET(prefix+"/censor/logs/page", censorGetLogPage)

	e.GET(prefix+"/resource/page", resourceGetList)
	e.GET(prefix+"/resource/download", resourceDownload)
	e.POST(prefix+"/resource", resourceUpload)
	e.DELETE(prefix+"/resource", resourceDelete)
	e.GET(prefix+"/resource/data", resourceGetData)

	e.GET(prefix+"/store/backend/list", storeBackendList)
	e.POST(prefix+"/store/backend/add", storeAddBackend)
	e.POST(prefix+"/store/backend/enable", storeEnableBackend)
	e.POST(prefix+"/store/backend/disable", storeDisableBackend)
	e.DELETE(prefix+"/store/backend/remove", storeRemoveBackend)
	e.GET(prefix+"/store/recommend", storeRecommend)
	e.GET(prefix+"/store/page", storeGetPage)
	e.GET(prefix+"/store/files/:namespace/:package/:version", storePackageFiles)
	e.GET(prefix+"/store/file/:namespace/:package/:version", storePackageFilePreview)
	e.GET("/dice/api/store/files/:namespace/:package/:version", storePackageFiles)
	e.GET("/dice/api/store/file/:namespace/:package/:version", storePackageFilePreview)
	e.POST(prefix+"/store/preview-download", storePreviewDownload)
	e.POST(prefix+"/store/download", storeDownload)
	e.POST(prefix+"/store/package-info-list", storePackageInfoList)
	e.POST(prefix+"/store/install-list", storeInstallList)
	e.POST(prefix+"/store/rating", storeRating)

	// 扩展包管理
	e.GET(prefix+"/package/list", packageList)
	e.POST(prefix+"/package/refresh", packageRefresh)
	e.GET(prefix+"/package/asset", packageAsset)
	e.GET(prefix+"/package/:id", packageGet)
	e.POST(prefix+"/package/preview-upload", packagePreviewFromUpload)
	e.POST(prefix+"/package/upload-preview", packagePreviewFromUpload)
	e.POST(prefix+"/package/install-upload", packageInstallFromUpload)
	e.POST(prefix+"/package/upload-install", packageInstallFromUpload)
	e.POST(prefix+"/package/install-url", packageInstallFromURL)
	e.POST(prefix+"/package/install-from-url", packageInstallFromURL)
	e.POST(prefix+"/package/uninstall", packageUninstall)
	e.POST(prefix+"/package/enable", packageEnable)
	e.POST(prefix+"/package/disable", packageDisable)
	e.POST(prefix+"/package/reload", packageReload)
	e.POST(prefix+"/package/reload-content", packageReloadContent)
	e.POST(prefix+"/package/reload-all", packageReloadAll)
	e.GET(prefix+"/package/:id/config", packageGetConfig)
	e.POST(prefix+"/package/:id/config", packageSetConfig)
	e.GET(prefix+"/package/:id/config-schema", packageGetConfigSchema)

	bindPProfAPIs(e, prefix)
}
