package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/eventstore"
)

const activityResponseMetadataKey = "scardice-management-activity-response"

const (
	defaultActivityLimit = eventstore.DefaultManagementActivityLimit
	maxActivityLimit     = eventstore.MaxManagementActivityLimit
)

type activityRoute struct {
	method string
	path   string
}

type activityAction struct {
	id        string
	label     string
	adminAuth bool
}

// activityActions is deliberately route-specific. POST requests that search,
// preview, poll, authenticate, or test connectivity do not enter this list.
var activityActions = map[activityRoute]activityAction{
	{http.MethodPost, "/sd-api/endpoints"}:                        {id: "endpoint_create", label: "新增连接端点", adminAuth: true},
	{http.MethodPatch, "/sd-api/endpoints/:id/config"}:            {id: "endpoint_config", label: "修改连接端点配置", adminAuth: true},
	{http.MethodPost, "/sd-api/endpoints/:id/enable"}:             {id: "endpoint_enable", label: "启用连接端点", adminAuth: true},
	{http.MethodPost, "/sd-api/endpoints/:id/disable"}:            {id: "endpoint_disable", label: "停用连接端点", adminAuth: true},
	{http.MethodPost, "/sd-api/endpoints/:id/relogin"}:            {id: "endpoint_relogin", label: "重新登录连接端点", adminAuth: true},
	{http.MethodPost, "/sd-api/endpoints/:id/actions/:action"}:    {id: "endpoint_action", label: "提交连接端点操作", adminAuth: true},
	{http.MethodDelete, "/sd-api/endpoints/:id"}:                  {id: "endpoint_delete", label: "删除连接端点", adminAuth: true},
	{http.MethodPost, "/sd-api/operations/:id/resolve"}:           {id: "endpoint_operation_resolve", label: "处理连接端点操作", adminAuth: true},
	{http.MethodPost, "/sd-api/configs/customText/save"}:          {id: "text_template_save", label: "保存自定义文本", adminAuth: false},
	{http.MethodPost, "/sd-api/configs/custom_reply/save"}:        {id: "custom_reply_save", label: "保存自定义回复", adminAuth: false},
	{http.MethodPost, "/sd-api/configs/custom_reply/file_new"}:    {id: "custom_reply_file_create", label: "新建自定义回复文件", adminAuth: false},
	{http.MethodPost, "/sd-api/configs/custom_reply/file_delete"}: {id: "custom_reply_file_delete", label: "删除自定义回复文件", adminAuth: false},
	{http.MethodPost, "/sd-api/configs/custom_reply/file_upload"}: {id: "custom_reply_file_upload", label: "上传自定义回复文件", adminAuth: false},
	{http.MethodPost, "/sd-api/configs/custom_reply/debug_mode"}:  {id: "custom_reply_debug_mode", label: "修改自定义回复调试设置", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/config/set"}:                  {id: "dice_config_save", label: "保存骰子设置", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/config/advanced/set"}:         {id: "dice_advanced_config_save", label: "保存高级设置", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/public/set"}:                  {id: "dice_public_config_save", label: "保存公骰设置", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/config/vm-version-set"}:       {id: "dice_vm_version_set", label: "修改骰子版本", adminAuth: false},
	{http.MethodPost, "/sd-api/backup/do_backup"}:                 {id: "backup_create", label: "创建备份", adminAuth: false},
	{http.MethodPost, "/sd-api/backup/config_set"}:                {id: "backup_config_save", label: "保存备份设置", adminAuth: false},
	{http.MethodPost, "/sd-api/backup/delete"}:                    {id: "backup_delete", label: "删除备份", adminAuth: false},
	{http.MethodPost, "/sd-api/backup/batch_delete"}:              {id: "backup_batch_delete", label: "批量删除备份", adminAuth: false},
	{http.MethodPost, "/sd-api/group/set_one"}:                    {id: "group_settings_save", label: "保存群组设置", adminAuth: false},
	{http.MethodPost, "/sd-api/group/quit_one"}:                   {id: "group_quit", label: "退出群组", adminAuth: false},
	{http.MethodPost, "/sd-api/group/local_data/delete"}:          {id: "group_local_data_delete", label: "删除群组本地数据", adminAuth: false},
	{http.MethodPost, "/sd-api/banconfig/set"}:                    {id: "ban_config_save", label: "保存封禁设置", adminAuth: false},
	{http.MethodPost, "/sd-api/banconfig/map_delete_one"}:         {id: "ban_record_delete", label: "删除封禁记录", adminAuth: false},
	{http.MethodPost, "/sd-api/banconfig/map_add_one"}:            {id: "ban_record_add", label: "添加封禁记录", adminAuth: false},
	{http.MethodPost, "/sd-api/banconfig/import"}:                 {id: "ban_records_import", label: "导入封禁记录", adminAuth: false},
	{http.MethodPost, "/sd-api/deck/reload"}:                      {id: "deck_reload", label: "重载牌堆", adminAuth: false},
	{http.MethodPost, "/sd-api/deck/upload"}:                      {id: "deck_upload", label: "上传牌堆", adminAuth: false},
	{http.MethodPost, "/sd-api/deck/enable"}:                      {id: "deck_enable", label: "启用牌堆", adminAuth: false},
	{http.MethodPost, "/sd-api/deck/delete"}:                      {id: "deck_delete", label: "删除牌堆", adminAuth: false},
	{http.MethodPost, "/sd-api/deck/update"}:                      {id: "deck_update", label: "更新牌堆", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/upload_to_upgrade"}:           {id: "dice_upgrade_upload", label: "上传骰子升级包", adminAuth: false},
	{http.MethodPost, "/sd-api/dice/upgrade"}:                     {id: "dice_upgrade", label: "升级骰子", adminAuth: false},
	{http.MethodPost, "/sd-api/js/reload"}:                        {id: "js_reload", label: "重载扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/execute"}:                       {id: "js_execute", label: "执行扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/upload"}:                        {id: "js_upload", label: "上传扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/delete"}:                        {id: "js_delete", label: "删除扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/shutdown"}:                      {id: "js_shutdown", label: "关闭扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/enable"}:                        {id: "js_enable", label: "启用扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/disable"}:                       {id: "js_disable", label: "停用扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/update"}:                        {id: "js_update", label: "更新扩展脚本", adminAuth: false},
	{http.MethodPost, "/sd-api/js/runtime/config"}:                {id: "js_runtime_config_save", label: "保存 JavaScript 运行时设置", adminAuth: false},
	{http.MethodPost, "/sd-api/js/runtime/install"}:               {id: "js_runtime_install", label: "安装 JavaScript 运行时", adminAuth: false},
	{http.MethodPost, "/sd-api/js/runtime/uninstall"}:             {id: "js_runtime_uninstall", label: "卸载 JavaScript 运行时", adminAuth: false},
	{http.MethodPost, "/sd-api/js/set_configs"}:                   {id: "plugin_configs_save", label: "保存扩展配置", adminAuth: false},
	{http.MethodPost, "/sd-api/js/set_config"}:                    {id: "plugin_config_save", label: "保存扩展配置项", adminAuth: false},
	{http.MethodPost, "/sd-api/js/delete_unused_configs"}:         {id: "plugin_unused_configs_delete", label: "清理无用扩展配置", adminAuth: false},
	{http.MethodPost, "/sd-api/js/reset_config"}:                  {id: "plugin_config_reset", label: "重置扩展配置", adminAuth: false},
	{http.MethodPost, "/sd-api/helpdoc/reload"}:                   {id: "helpdoc_reload", label: "重载帮助文档", adminAuth: false},
	{http.MethodPost, "/sd-api/helpdoc/upload"}:                   {id: "helpdoc_upload", label: "上传帮助文档", adminAuth: false},
	{http.MethodPost, "/sd-api/helpdoc/delete"}:                   {id: "helpdoc_delete", label: "删除帮助文档", adminAuth: false},
	{http.MethodPost, "/sd-api/helpdoc/config"}:                   {id: "helpdoc_config_save", label: "保存帮助文档设置", adminAuth: false},
	{http.MethodDelete, "/sd-api/story/log"}:                      {id: "story_log_delete", label: "删除跑团记录", adminAuth: false},
	{http.MethodPost, "/sd-api/story/backup/batch_delete"}:        {id: "story_backup_delete", label: "批量删除跑团备份", adminAuth: false},
	{http.MethodPost, "/sd-api/store/backend/add"}:                {id: "store_backend_add", label: "添加扩展商店", adminAuth: false},
	{http.MethodPost, "/sd-api/store/backend/enable"}:             {id: "store_backend_enable", label: "启用扩展商店", adminAuth: false},
	{http.MethodPost, "/sd-api/store/backend/disable"}:            {id: "store_backend_disable", label: "停用扩展商店", adminAuth: false},
	{http.MethodDelete, "/sd-api/store/backend/remove"}:           {id: "store_backend_remove", label: "移除扩展商店", adminAuth: false},
	{http.MethodPost, "/sd-api/store/download"}:                   {id: "store_package_download", label: "安装商店扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/store/install-list"}:               {id: "store_packages_install", label: "批量安装商店扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/install-upload"}:           {id: "package_install_upload", label: "安装上传的扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/upload-install"}:           {id: "package_install_upload", label: "安装上传的扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/install-url"}:              {id: "package_install_url", label: "安装远程扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/install-from-url"}:         {id: "package_install_url", label: "安装远程扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/uninstall"}:                {id: "package_uninstall", label: "卸载扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/enable"}:                   {id: "package_enable", label: "启用扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/disable"}:                  {id: "package_disable", label: "停用扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/reload"}:                   {id: "package_reload", label: "重载扩展包", adminAuth: false},
	{http.MethodPost, "/sd-api/package/reload-content"}:           {id: "package_reload_content", label: "重载扩展包内容", adminAuth: false},
	{http.MethodPost, "/sd-api/package/reload-all"}:               {id: "package_reload_all", label: "重载所有扩展包内容", adminAuth: false},
	{http.MethodPost, "/sd-api/package/:id/config"}:               {id: "package_config_save", label: "保存扩展包设置", adminAuth: false},
	{http.MethodPost, "/sd-api/resource"}:                         {id: "resource_upload", label: "上传资源文件", adminAuth: false},
	{http.MethodDelete, "/sd-api/resource"}:                       {id: "resource_delete", label: "删除资源文件", adminAuth: false},
	{http.MethodPost, "/sd-api/censor/restart"}:                   {id: "censor_restart", label: "重启内容审查", adminAuth: false},
	{http.MethodPost, "/sd-api/censor/stop"}:                      {id: "censor_stop", label: "停止内容审查", adminAuth: false},
	{http.MethodPost, "/sd-api/censor/config"}:                    {id: "censor_config_save", label: "保存内容审查设置", adminAuth: false},
	{http.MethodPost, "/sd-api/censor/files/upload"}:              {id: "censor_words_upload", label: "上传审查词库", adminAuth: false},
	{http.MethodDelete, "/sd-api/censor/files"}:                   {id: "censor_words_delete", label: "删除审查词库", adminAuth: false},
}

type activityResponseMetadata struct {
	businessFailure bool
}

type activityJSONSerializer struct {
	delegate echo.JSONSerializer
}

func (s activityJSONSerializer) Serialize(c echo.Context, value interface{}, indent string) error {
	if metadata, ok := c.Get(activityResponseMetadataKey).(*activityResponseMetadata); ok && reportedBusinessFailure(value, c.Path()) {
		metadata.businessFailure = true
	}
	return s.delegate.Serialize(c, value, indent)
}

func (s activityJSONSerializer) Deserialize(c echo.Context, value interface{}) error {
	return s.delegate.Deserialize(c, value)
}

func installActivityJSONSerializer(e *echo.Echo) {
	if e == nil {
		return
	}
	if _, wrapped := e.JSONSerializer.(activityJSONSerializer); wrapped {
		return
	}
	delegate := e.JSONSerializer
	if delegate == nil {
		delegate = &echo.DefaultJSONSerializer{}
	}
	e.JSONSerializer = activityJSONSerializer{delegate: delegate}
}

func reportedBusinessFailure(value interface{}, resource string) bool {
	unwrap := func(candidate reflect.Value) reflect.Value {
		for candidate.IsValid() && (candidate.Kind() == reflect.Interface || candidate.Kind() == reflect.Pointer) {
			if candidate.IsNil() {
				return reflect.Value{}
			}
			candidate = candidate.Elem()
		}
		return candidate
	}
	candidate := unwrap(reflect.ValueOf(value))
	field := func(name string) reflect.Value {
		if candidate.Kind() == reflect.Map {
			if candidate.Type().Key().Kind() == reflect.String {
				return unwrap(candidate.MapIndex(reflect.ValueOf(name).Convert(candidate.Type().Key())))
			}
		} else if candidate.Kind() == reflect.Struct {
			for index := range candidate.NumField() {
				structField := candidate.Type().Field(index)
				tag, _, _ := strings.Cut(structField.Tag.Get("json"), ",")
				if tag == name {
					return unwrap(candidate.Field(index))
				}
			}
		}
		return reflect.Value{}
	}
	result := field("result")
	success := field("success")
	if result.Kind() == reflect.Bool && !result.Bool() || success.Kind() == reflect.Bool && !success.Bool() {
		return true
	}
	testMode := field("testMode")
	if testMode.Kind() == reflect.Bool && testMode.Bool() {
		return true
	}
	errorText := field("err")
	if errorText.Kind() == reflect.String && errorText.Len() > 0 {
		return true
	}
	switch resource {
	case "/sd-api/dice/config/vm-version-set":
		failedTypes := field("failTypes")
		return failedTypes.Kind() == reflect.Slice && failedTypes.Len() > 0
	case "/sd-api/store/install-list":
		data := field("data")
		if data.Kind() == reflect.Map && data.Type().Key().Kind() == reflect.String {
			failed := unwrap(data.MapIndex(reflect.ValueOf("failed").Convert(data.Type().Key())))
			return failed.CanInt() && failed.Int() > 0
		}
	}
	return false
}

func activityMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if c == nil || c.Request() == nil {
			return next(c)
		}
		action, recognized := activityActions[activityRoute{method: c.Request().Method, path: c.Path()}]
		if !recognized {
			return next(c)
		}

		legacyAuthorized := false
		if !action.adminAuth && myDice != nil && myDice.Parent != nil {
			legacyAuthorized = doAuth(c)
		}
		metadata := &activityResponseMetadata{}
		previousMetadata := c.Get(activityResponseMetadataKey)
		c.Set(activityResponseMetadataKey, metadata)
		defer c.Set(activityResponseMetadataKey, previousMetadata)

		err := next(c)
		authorized := legacyAuthorized
		actor := "WebUI 管理员"
		if action.adminAuth {
			actor = adminPrincipalFromContext(c)
			authorized = actor != ""
		}
		if !authorized {
			return err
		}

		status := c.Response().Status
		if err != nil {
			var httpError *echo.HTTPError
			if errors.As(err, &httpError) && httpError.Code >= 100 && httpError.Code <= 599 {
				status = httpError.Code
			} else {
				status = http.StatusInternalServerError
			}
		}
		if status == 0 {
			status = http.StatusOK
		}
		resultStatus := "succeeded"
		if status < 200 || status >= 300 || metadata.businessFailure {
			resultStatus = "failed"
		} else if status == http.StatusAccepted {
			resultStatus = "accepted"
		}

		if err := recordManagementActivity(action, c.Path(), resultStatus, status, actor, c.Request().RemoteAddr); err != nil {
			log.Printf("management activity capture failed for %s: %v", action.id, err)
		}
		return err
	}
}

func recordManagementActivity(action activityAction, resource, resultStatus string, status int, actor, remoteAddr string) error {
	if myDice == nil || myDice.DurableStore == nil {
		return errors.New("event store is unavailable")
	}
	repository, ok := myDice.DurableStore.(eventstore.ManagementActivityRepository)
	if !ok {
		return errors.New("event store does not support management activity")
	}
	sourceIP := activityPeerIP(remoteAddr)
	if sourceIP == "" {
		return errors.New("transport peer address is not an IP address")
	}
	id, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	return repository.AppendManagementActivity(context.Background(), eventstore.ManagementActivity{
		ID: id, OccurredAt: time.Now().UTC(), Action: action.id, Label: action.label,
		Resource: resource, Status: resultStatus, HTTPStatus: status, Actor: actor, SourceIP: sourceIP,
	})
}

func activityPeerIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	if address, err := netip.ParseAddr(remoteAddr); err == nil {
		return address.String()
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ""
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return ""
	}
	return host
}

type activityRecentItem struct {
	ID         string `json:"id"`
	OccurredAt int64  `json:"occurredAt"`
	Action     string `json:"action"`
	Label      string `json:"label"`
	Resource   string `json:"resource"`
	Status     string `json:"status"`
	HTTPStatus int    `json:"httpStatus"`
	Actor      string `json:"actor"`
	SourceIP   string `json:"sourceIP"`
}

type activityRecentResponse struct {
	Result    bool                 `json:"result"`
	Items     []activityRecentItem `json:"items"`
	Timestamp int64                `json:"timestamp"`
}

type activityErrorResponse struct {
	Result  bool   `json:"result"`
	Message string `json:"message"`
}

func activityRecent(c echo.Context) error {
	if myDice == nil || myDice.Parent == nil || !doAuth(c) {
		return c.JSON(http.StatusForbidden, activityErrorResponse{Result: false, Message: "forbidden"})
	}
	repository, ok := myDice.DurableStore.(eventstore.ManagementActivityRepository)
	if !ok {
		return c.JSON(http.StatusServiceUnavailable, activityErrorResponse{Result: false, Message: "activity history is unavailable"})
	}
	limit := defaultActivityLimit
	if requested, err := strconv.Atoi(c.QueryParam("limit")); err == nil && requested > 0 {
		limit = requested
	}
	if limit > maxActivityLimit {
		limit = maxActivityLimit
	}
	activities, err := repository.RecentManagementActivities(c.Request().Context(), limit)
	if err != nil {
		log.Printf("management activity read failed: %v", err)
		return c.JSON(http.StatusServiceUnavailable, activityErrorResponse{Result: false, Message: "activity history is unavailable"})
	}
	items := make([]activityRecentItem, 0, len(activities))
	for _, activity := range activities {
		items = append(items, activityRecentItem{
			ID: activity.ID, OccurredAt: activity.OccurredAt.UnixMilli(), Action: activity.Action,
			Label: activity.Label, Resource: activity.Resource, Status: activity.Status,
			HTTPStatus: activity.HTTPStatus, Actor: activity.Actor, SourceIP: activity.SourceIP,
		})
	}
	return c.JSON(http.StatusOK, activityRecentResponse{Result: true, Items: items, Timestamp: time.Now().UTC().UnixMilli()})
}
