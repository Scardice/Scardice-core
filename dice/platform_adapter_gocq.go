package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"Scardice-core/message"
	"Scardice-core/utils"
	"Scardice-core/utils/procs"

	"github.com/sacOO7/gowebsocket"
	"github.com/samber/lo"
)

// 0 默认 1登录中 2登录中-二维码 3登录中-滑条 4登录中-手机验证码 10登录成功 11登录失败

const (
	StateCodeInit                      = 0
	StateCodeInLogin                   = 1
	StateCodeInLoginQrCode             = 2
	GoCqhttpStateCodeInLoginBar        = 3
	GoCqhttpStateCodeInLoginVerifyCode = 6
	StateCodeInLoginDeviceLock         = 7
	StateCodeLoginSuccessed            = 10
	StateCodeLoginFailed               = 11
	GoCqhttpStateCodeClosed            = 20
)

type echoMapInfo struct {
	ch            chan string
	echoOverwrite any
}

type PlatformAdapterGocq struct {
	EndPoint *EndPointInfo `json:"-" yaml:"-"`

	IsReverse   bool   `json:"isReverse"   yaml:"isReverse"`
	ReverseAddr string `json:"reverseAddr" yaml:"reverseAddr"`

	Socket     *gowebsocket.Socket `json:"-"           yaml:"-"`
	ConnectURL string              `json:"connectUrl"  yaml:"connectUrl"` // 连接地址
	//nolint:gosec
	AccessToken string `json:"accessToken" yaml:"accessToken"` // 访问令牌

	UseInPackClient bool   `json:"useInPackGoCqhttp" yaml:"useInPackGoCqhttp"` // 是否使用内置的gocqhttp
	BuiltinMode     string `json:"builtinMode"       yaml:"builtinMode"`       // 分为 lagrange 和 gocq
	GoCqhttpState   int    `json:"loginState"        yaml:"-"`                 // 当前状态
	CurLoginIndex   int    `json:"curLoginIndex"     yaml:"-"`                 // 当前登录序号，如果正在进行的登录不是该Index，证明过时

	GoCqhttpProcess           *procs.Process `json:"-"                    yaml:"-"`
	GocqhttpLoginFailedReason string         `json:"curLoginFailedReason" yaml:"-"` // 当前登录失败原因

	GoCqhttpLoginCaptcha       string `json:"goCqHttpLoginCaptcha"       yaml:"-"`
	GoCqhttpLoginVerifyCode    string `json:"goCqHttpLoginVerifyCode"    yaml:"-"`
	GoCqhttpLoginDeviceLockURL string `json:"goCqHttpLoginDeviceLockUrl" yaml:"-"`
	GoCqhttpQrcodeData         []byte `json:"-"                          yaml:"-"` // 二维码数据
	GoCqhttpSmsNumberTip       string `json:"goCqHttpSmsNumberTip"       yaml:"-"`

	GoCqLastAutoLoginTime      int64 `json:"-"                            yaml:"inPackGoCqLastAutoLoginTime"`  // 上次自动重新登录的时间
	GoCqhttpLoginSucceeded     bool  `json:"-"                            yaml:"inPackGoCqHttpLoginSucceeded"` // 是否登录成功过
	GoCqhttpLastRestrictedTime int64 `json:"inPackGoCqHttpLastRestricted" yaml:"inPackGoCqHttpLastRestricted"` // 上次风控时间
	ForcePrintLog              bool  `json:"forcePrintLog"                yaml:"forcePrintLog"`                // 是否一定输出日志，隐藏配置项

	InPackGoCqhttpProtocol       int      `json:"inPackGoCqHttpProtocol"   yaml:"inPackGoCqHttpProtocol"`
	InPackGoCqhttpAppVersion     string   `json:"inPackGoCqHttpAppVersion" yaml:"inPackGoCqHttpAppVersion"`
	InPackGoCqhttpPassword       string   `json:"-"                        yaml:"inPackGoCqHttpPassword"`
	InPackGoCqhttpDisconnectedCH chan int `json:"-"                        yaml:"-"`                   // 信号量，用于关闭连接
	IgnoreFriendRequest          bool     `json:"ignoreFriendRequest"      yaml:"ignoreFriendRequest"` // 忽略好友请求处理开关

	customEcho     int64                          `yaml:"-"` // 自定义返回标记
	echoMap        *SyncMap[any, chan *MessageQQ] `yaml:"-"`
	echoMap2       *SyncMap[any, *echoMapInfo]    `yaml:"-"`
	Implementation string                         `json:"implementation" yaml:"implementation"`

	UseSignServer    bool              `json:"useSignServer"    yaml:"useSignServer"`
	SignServerConfig *SignServerConfig `json:"signServerConfig" yaml:"signServerConfig"`
	ExtraArgs        string            `json:"extraArgs"        yaml:"extraArgs"`

	useArrayMessage bool   `yaml:"-"`                                    // 使用分段消息
	SignServerVer   string `json:"signServerVer"  yaml:"signServerVer"`  // 用于前端显示
	SignServerName  string `json:"signServerName" yaml:"signServerName"` // 用于前端显示
}

type Sender struct {
	Age      int32           `json:"age"`
	Card     string          `json:"card"`
	IsRobot  bool            `json:"is_robot"`
	Nickname string          `json:"nickname"`
	Role     string          `json:"role"` // owner 群主
	UserID   json.RawMessage `json:"user_id"`
}

type OnebotUserInfo struct {
	// 个人信息
	Nickname string `json:"nickname"`
	UserID   string `json:"user_id"`

	// 群信息
	GroupID         string `json:"group_id"`          // 群号
	GroupCreateTime uint32 `json:"group_create_time"` // 群号
	MemberCount     int64  `json:"member_count"`
	GroupName       string `json:"group_name"`
	MaxMemberCount  int32  `json:"max_member_count"`
	Card            string `json:"card"`
	Role            string `json:"role"`
}

type MessageQQBase struct {
	MessageID     int64           `json:"message_id"`   // QQ信息此类型为int64，频道中为string
	MessageType   string          `json:"message_type"` // Group
	Sender        *Sender         `json:"sender"`       // 发送者
	RawMessage    string          `json:"raw_message"`
	Time          int64           `json:"time"` // 发送时间
	MetaEventType string          `json:"meta_event_type"`
	OperatorID    json.RawMessage `json:"operator_id"`  // 操作者帐号
	GroupID       json.RawMessage `json:"group_id"`     // 群号
	PostType      string          `json:"post_type"`    // 上报类型，如group、notice
	RequestType   string          `json:"request_type"` // 请求类型，如group
	SubType       string          `json:"sub_type"`     // 子类型，如add invite
	Flag          string          `json:"flag"`         // 请求 flag, 在调用处理请求的 API 时需要传入
	NoticeType    string          `json:"notice_type"`
	UserID        json.RawMessage `json:"user_id"`
	SelfID        json.RawMessage `json:"self_id"`
	Duration      int64           `json:"duration"`
	Comment       string          `json:"comment"`
	TargetID      json.RawMessage `json:"target_id"`

	Data *struct {
		// 个人信息
		Nickname string          `json:"nickname"`
		UserID   json.RawMessage `json:"user_id"`

		// 群信息
		GroupID         json.RawMessage `json:"group_id"`          // 群号
		GroupCreateTime uint32          `json:"group_create_time"` // 群号
		MemberCount     int64           `json:"member_count"`
		GroupName       string          `json:"group_name"`
		MaxMemberCount  int32           `json:"max_member_count"`

		// 群成员信息
		Card string `json:"card"`
		Role string `json:"role"`
	} `json:"data"`
	Retcode int64 `json:"retcode"`
	// Status string `json:"status"`
	Echo json.RawMessage `json:"echo"` // 声明类型而不是interface的原因是interface下数字不能正确转换

	Msg string `json:"msg"`
	// Status  interface{} `json:"status"`
	Wording string `json:"wording"`
}

type MessageQQ struct {
	MessageQQBase
	Message string `json:"message"` // 消息内容
}

// 注: 这部分对应了 onebot v11 的另一种消息格式
// https://github.com/botuniverse/onebot-11/blob/master/message/array.md

type OneBotV11MsgItemTextType struct {
	Text string `json:"text"`
}

type OneBotV11MsgItemImageType struct {
	File string `json:"file"`
}

type OneBotV11MsgItemFaceType struct {
	Id string `json:"id"`
}

type OneBotV11MsgItemRecordType struct {
	File string `json:"file"`
}

type OneBotV11MsgItemAtType struct {
	QQ string `json:"qq"`
}

type OneBotV11MsgItemPokeType struct {
	Type string `json:"type"`
	Id   string `json:"id"`
}

type OneBotV11MsgItemReplyType struct {
	Id string `json:"id"`
}

type OneBotV11MsgItem struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

type OneBotV11ArrMsgItem[T any] struct {
	Type string `json:"type"`
	Data T      `json:"data"`
}

type MessageQQArray struct {
	MessageQQBase
	Message []*OneBotV11MsgItem `json:"message"` // 消息内容
}

type LastWelcomeInfo struct {
	UserID  string
	GroupID string
	Time    int64
}

func (msgQQ *MessageQQ) toStdMessage() *Message {
	msg := new(Message)
	msg.Time = msgQQ.Time
	msg.MessageType = msgQQ.MessageType
	msg.Message = msgQQ.Message
	msg.Message = strings.ReplaceAll(msg.Message, "&#91;", "[")
	msg.Message = strings.ReplaceAll(msg.Message, "&#93;", "]")
	msg.Message = strings.ReplaceAll(msg.Message, "&amp;", "&")
	msg.RawID = msgQQ.MessageID
	msg.Platform = "QQ"

	if msg.MessageType == "" {
		msg.MessageType = "private"
	}

	if msgQQ.Data != nil && len(msgQQ.Data.GroupID) > 0 {
		msg.GroupID = FormatDiceIDQQGroup(string(msgQQ.Data.GroupID))
	}
	if string(msgQQ.GroupID) != "" {
		if msg.MessageType == "private" {
			msg.MessageType = "group"
		}
		msg.GroupID = FormatDiceIDQQGroup(string(msgQQ.GroupID))
	}
	if msgQQ.Sender != nil {
		msg.Sender.Nickname = msgQQ.Sender.Nickname
		if msgQQ.Sender.Card != "" {
			msg.Sender.Nickname = msgQQ.Sender.Card
		}
		msg.Sender.GroupRole = msgQQ.Sender.Role
		msg.Sender.UserID = FormatDiceIDQQ(string(msgQQ.Sender.UserID))
		msg.Sender.IsRobot = msgQQ.Sender.IsRobot || isQQBotUserID(msg.Sender.UserID)
	}
	return msg
}

func FormatDiceIDQQ(diceQQ string) string {
	return fmt.Sprintf("QQ:%s", diceQQ)
}

func FormatDiceIDQQGroup(diceQQ string) string {
	return fmt.Sprintf("QQ-Group:%s", diceQQ)
}

func FormatDiceIDQQCh(userID string) string {
	return fmt.Sprintf("QQ-CH:%s", userID)
}

func FormatDiceIDQQChGroup(guildID, channelID string) string {
	return fmt.Sprintf("QQ-CH-Group:%s-%s", guildID, channelID)
}

// urlSchemeRegexp 匹配 URI scheme 前缀（如 http://、file://、base64://、HTTP://）
// 大小写不敏感（RFC 3986 scheme 生产式: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )）
var urlSchemeRegexp = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+\-.]*://`)

func hasURLScheme(text string) bool {
	return urlSchemeRegexp.MatchString(text)
}

func tryParseOneBot11ArrayMessage(log *zap.SugaredLogger, message string, writeTo *MessageQQ) error {
	// 不合法的信息体
	if !gjson.Valid(message) {
		log.Warn("无法解析 onebot11 字段:", message)
		return errors.New("解析失败")
	}
	// 原版本转换为gjson对象
	parseContent := gjson.Parse(message)
	arrayContent := parseContent.Get("message").Array()
	cqMessage := strings.Builder{}

	for _, i := range arrayContent {
		// 使用String()方法，如果为空，会自动产生空字符串
		typeStr := i.Get("type").String()
		dataObj := i.Get("data")
		switch typeStr {
		case "text":
			cqMessage.WriteString(dataObj.Get("text").String())
		case "image":
			// 兼容NC情况, 此时file字段只有文件名, 完整URL在url字段
			if !hasURLScheme(dataObj.Get("file").String()) && hasURLScheme(dataObj.Get("url").String()) {
				_, _ = fmt.Fprintf(&cqMessage, "[CQ:image,file=%v]", dataObj.Get("url").String())
			} else {
				_, _ = fmt.Fprintf(&cqMessage, "[CQ:image,file=%v]", dataObj.Get("file").String())
			}
		case "face":
			// 兼容四叶草，移除 .(string)。自动获取的信息表示此类型为 float64，这是go解析的问题
			_, _ = fmt.Fprintf(&cqMessage, "[CQ:face,id=%v]", dataObj.Get("id").String())
		case "record":
			// 兼容NC情况, 此时file字段只有文件名, 完整路径在path字段
			if !hasURLScheme(dataObj.Get("file").String()) && dataObj.Get("path").String() != "" {
				_, _ = fmt.Fprintf(&cqMessage, "[CQ:record,file=%v]", dataObj.Get("path").String())
			} else {
				_, _ = fmt.Fprintf(&cqMessage, "[CQ:record,file=%v]", dataObj.Get("file").String())
			}
		case "at":
			_, _ = fmt.Fprintf(&cqMessage, "[CQ:at,qq=%v]", dataObj.Get("qq").String())
		case "poke":
			cqMessage.WriteString("[CQ:poke]")
		case "reply":
			_, _ = fmt.Fprintf(&cqMessage, "[CQ:reply,id=%v]", dataObj.Get("id").String())
		case "forward":
			_, _ = fmt.Fprintf(&cqMessage, "[CQ:forward,id=%v]", dataObj.Get("id").String())
		}
	}
	// 赋值对应的Message
	tempStr, err := sjson.Set(parseContent.String(), "message", cqMessage.String())
	if err != nil {
		return err
	}
	// 返回被转换成结构体的结果
	err = json.Unmarshal([]byte(tempStr), &writeTo)
	if err != nil {
		return err
	}
	return nil
}

func OneBot11CqMessageToArrayMessage(longText string) []interface{} {
	re := regexp.MustCompile(`\[CQ:.+?]`)
	m := re.FindAllStringIndex(longText, -1)

	newText := longText
	var arr []interface{}

	for i := len(m) - 1; i >= 0; i-- {
		p := m[i]
		cq := CQParse(longText[p[0]:p[1]])

		// 如果尾部有文本，将其拼入数组
		endText := newText[p[1]:]
		if len(endText) > 0 {
			i := OneBotV11ArrMsgItem[OneBotV11MsgItemTextType]{Type: "text", Data: OneBotV11MsgItemTextType{Text: endText}}
			arr = append(arr, i)
		}

		// 将 CQ 拼入数组
		switch cq.Type {
		case "image":
			// 兼容NC情况, 此时file字段只有文件名, 完整URL在url字段
			if !hasURLScheme(cq.Args["file"]) && hasURLScheme(cq.Args["url"]) {
				i := OneBotV11ArrMsgItem[OneBotV11MsgItemImageType]{Type: "image", Data: OneBotV11MsgItemImageType{File: cq.Args["url"]}}
				arr = append(arr, i)
			} else {
				i := OneBotV11ArrMsgItem[OneBotV11MsgItemImageType]{Type: "image", Data: OneBotV11MsgItemImageType{File: cq.Args["file"]}}
				arr = append(arr, i)
			}
		case "record":
			// 兼容NC情况, 此时file字段只有文件名, 完整路径在path字段
			if !hasURLScheme(cq.Args["file"]) && cq.Args["path"] != "" {
				i := OneBotV11ArrMsgItem[OneBotV11MsgItemImageType]{Type: "record", Data: OneBotV11MsgItemImageType{File: cq.Args["path"]}}
				arr = append(arr, i)
			} else {
				i := OneBotV11ArrMsgItem[OneBotV11MsgItemRecordType]{Type: "record", Data: OneBotV11MsgItemRecordType{File: cq.Args["file"]}}
				arr = append(arr, i)
			}
		case "at":
			// [CQ:at,qq=10001000]
			i := OneBotV11ArrMsgItem[OneBotV11MsgItemAtType]{Type: "at", Data: OneBotV11MsgItemAtType{QQ: cq.Args["qq"]}}
			arr = append(arr, i)
		default:
			data := make(map[string]interface{})
			for k, v := range cq.Args {
				data[k] = v
			}
			i := OneBotV11MsgItem{Type: cq.Type, Data: data}
			arr = append(arr, i)
		}

		newText = newText[:p[0]]
	}

	// 如果剩余有文本，将其拼入数组
	if len(newText) > 0 {
		i := OneBotV11ArrMsgItem[OneBotV11MsgItemTextType]{Type: "text", Data: OneBotV11MsgItemTextType{Text: newText}}
		arr = append(arr, i)
	}

	return lo.Reverse(arr) //nolint:staticcheck // old code
}

func (pa *PlatformAdapterGocq) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterGocq) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterGocq) SetQQProtocol(protocol int) bool {
	// oldProtocol := pa.InPackGoCqHttpProtocol
	pa.InPackGoCqhttpProtocol = protocol

	// ep.Session.Parent.GetDiceDataPath(ep.RelWorkDir)
	workDir := filepath.Join(pa.EndPoint.Session.Parent.BaseConfig.DataDir, pa.EndPoint.RelWorkDir)
	deviceFilePath := filepath.Join(workDir, "device.json")
	if _, err := os.Stat(deviceFilePath); err == nil {
		configFile, _ := os.ReadFile(deviceFilePath)
		info := map[string]interface{}{}
		err = json.Unmarshal(configFile, &info)

		if err == nil {
			info["protocol"] = protocol
			data, err := json.Marshal(info)
			if err == nil {
				_ = utils.AtomicWriteFile(deviceFilePath, data, 0644)
				return true
			}
		}
	}
	return false
}

func (pa *PlatformAdapterGocq) SetSignServer(signServerConfig *SignServerConfig) bool {
	workDir := filepath.Join(pa.EndPoint.Session.Parent.BaseConfig.DataDir, pa.EndPoint.RelWorkDir)
	configFilePath := filepath.Join(workDir, "config.yml")
	if _, err := os.Stat(configFilePath); err == nil {
		configFile, _ := os.ReadFile(configFilePath)
		info := map[string]interface{}{}
		err = yaml.Unmarshal(configFile, &info)

		if err == nil {
			if signServerConfig.SignServers != nil {
				mainServer := signServerConfig.SignServers[0]
				(info["account"]).(map[string]interface{})["sign-server"] = mainServer.URL
				(info["account"]).(map[string]interface{})["key"] = mainServer.Key
				(info["account"]).(map[string]interface{})["sign-servers"] = signServerConfig.SignServers
				(info["account"]).(map[string]interface{})["ruleChangeSignServer"] = signServerConfig.RuleChangeSignServer
				(info["account"]).(map[string]interface{})["maxCheckCount"] = signServerConfig.MaxCheckCount
				(info["account"]).(map[string]interface{})["signServerTimeout"] = signServerConfig.SignServerTimeout
				(info["account"]).(map[string]interface{})["autoRegister"] = signServerConfig.AutoRegister
				(info["account"]).(map[string]interface{})["autoRefreshToken"] = signServerConfig.AutoRefreshToken
				(info["account"]).(map[string]interface{})["refreshInterval"] = signServerConfig.RefreshInterval
			}
			data, err := yaml.Marshal(info)
			if err == nil {
				_ = utils.AtomicWriteFile(configFilePath, data, 0644)
				return true
			}
		}
	}
	return false
}

func (pa *PlatformAdapterGocq) IsInLogin() bool {
	return pa.GoCqhttpState < StateCodeLoginSuccessed
}

func (pa *PlatformAdapterGocq) IsLoginSuccessed() bool {
	return pa.GoCqhttpState == StateCodeLoginSuccessed
}
