package kook

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// RolePermission is the type for the permission of a user in guilds or channels.
type RolePermission int64

// HasPermission checks if having the provided permission.
func (r RolePermission) HasPermission(p RolePermission) bool {
	return r&(p|RolePermissionAdmin) != 0
}

// These are the permission defined in system.
const (
	RolePermissionAdmin RolePermission = 1 << iota
	RolePermissionManageGuild
	RolePermissionViewAuditLog
	RolePermissionCreateInvite
	RolePermissionManageInvite
	RolePermissionManageChannel
	RolePermissionKickUser
	RolePermissionBanUser
	RolePermissionManageGuildEmoji
	RolePermissionChangeNickname
	RolePermissionManageRolePermission
	RolePermissionViewChannel
	RolePermissionSendMessage
	RolePermissionManageMessage
	RolePermissionUploadFile
	RolePermissionConnectVoice
	RolePermissionManageVoice
	RolePermissionMentionEveryone
	RolePermissionCreateReaction
	RolePermissionFollowReaction
	RolePermissionInvitedToVoice
	RolePermissionForceManualVoice
	RolePermissionFreeVoice
	RolePermissionVoice
	RolePermissionManageUserVoiceReceive
	RolePermissionManageUserVoiceCreate
	RolePermissionManageNickname
	RolePermissionPlayMusic
)

// UserStatus is the type for user status(banned or not).
type UserStatus int8

// IsBanned checks if the user is banned.
func (r UserStatus) IsBanned() bool {
	return r == UserStatusBanned
}

// These are all the status of a user.
const (
	UserStatusNormal UserStatus = 1
	UserStatusBanned UserStatus = 10
)

// GuildNotifyType is the type of the notify type of a guild.
type GuildNotifyType int8

// These are all notify types.
const (
	GuildNotifyTypeDefault GuildNotifyType = iota
	GuildNotifyTypeAll
	GuildNotifyTypeMention
	GuildNotifyTypeDisable
)

// ChannelType is the type of a channel.
type ChannelType int8

// These are all channel types.
const (
	ChannelTypeText ChannelType = 1 + iota
	ChannelTypeVoice
)

// User is the struct for a user. Some property may missing.
type User struct {
	ID             string         `json:"id"`
	Username       string         `json:"username"`
	IdentifyNum    string         `json:"identify_num"`
	Online         bool           `json:"online"`
	Status         UserStatus     `json:"status"`
	Avatar         string         `json:"avatar"`
	VipAvatar      string         `json:"vip_avatar"`
	Bot            bool           `json:"bot"`
	MobileVerified bool           `json:"mobile_verified"`
	System         bool           `json:"system"`
	MobilePrefix   string         `json:"mobile_prefix"`
	Mobile         string         `json:"mobile"`
	InviteCount    int64          `json:"invite_count"`
	Nickname       string         `json:"nickname"`
	Roles          []int64        `json:"roles"`
	FullName       string         `json:"full_name"`
	IsVip          bool           `json:"is_vip"`
	JoinedAt       MilliTimeStamp `json:"joined_at"`
	ActiveTime     MilliTimeStamp `json:"active_time"`
}

// Guild is the struct for a server/guild(服务器).
type Guild struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Topic    string `json:"topic"`
	MasterID string `json:"master_id"`
	// For compatibility reason
	UserID           string          `json:"user_id"`
	Icon             string          `json:"icon"`
	NotifyType       GuildNotifyType `json:"notify_type"`
	Region           string          `json:"region"`
	EnableOpen       IntBool         `json:"enable_open"`
	OpenID           string          `json:"open_id"`
	DefaultChannelID string          `json:"default_channel_id"`
	WelcomeChannelID string          `json:"welcome_channel_id"`
	Roles            []Role          `json:"roles"`
	Channels         []Channel       `json:"channels"`
}

// GetMasterID returns the master id of the guild, not sure if it is necessary as may doc is wrong.
func (g Guild) GetMasterID() string {
	if g.MasterID != "" {
		return g.MasterID
	}
	return g.UserID
}

// IntBool is the type for some int value in response which only has two valid values.
type IntBool bool

// MarshalJSON is used to marshal IntBool for reqeust.
func (i *IntBool) MarshalJSON() ([]byte, error) {
	switch *i {
	case true:
		return []byte("1"), nil
	case false:
		return []byte("0"), nil
	default:
		return []byte(""), nil
	}
}

// UnmarshalJSON is used to unmarshal IntBool from response.
func (i *IntBool) UnmarshalJSON(bytes []byte) error {
	switch bytes[0] {
	case '0', 'f':
		*i = false
	case '1', 't':
		*i = true
	default:
		return errors.New("unable to unmarshal int-bool")
	}
	return nil
}

// Role is the struct for a role in the guild.
type Role struct {
	RoleID      int64          `json:"role_id"`
	Name        string         `json:"name,omitempty"`
	Color       int            `json:"color,omitempty"`
	Position    int            `json:"position"`
	Hoist       IntBool        `json:"hoist,omitempty"`
	Mentionable IntBool        `json:"mentionable,omitempty"`
	Permissions RolePermission `json:"permissions,omitempty"`
}

// Channel is the struct for a channel in guild. For different channels, some fields may be empty.
type Channel struct {
	ID                   string                    `json:"id"`
	Name                 string                    `json:"name"`
	UserID               string                    `json:"user_id"`
	MasterID             string                    `json:"master_id"`
	GuildID              string                    `json:"guild_id"`
	Topic                string                    `json:"topic"`
	IsCategory           IntBool                   `json:"is_category"`
	ParentID             string                    `json:"parent_id"`
	Level                int                       `json:"level"`
	SlowMode             int                       `json:"slow_mode"`
	Type                 ChannelType               `json:"type"`
	LimitAmount          int                       `json:"limit_amount"`
	PermissionOverwrites []PermissionOverwrite     `json:"permission_overwrites"`
	PermissionUsers      []UserPermissionOverwrite `json:"permission_users"`
	PermissionSync       IntBool                   `json:"permission_sync"`
	ServerURL            string                    `json:"server_url"`
}

// PermissionOverwrite is the struct for where needs to customize permission for a role in a channel.
type PermissionOverwrite struct {
	RoleID int64          `json:"role_id"`
	Allow  RolePermission `json:"allow"`
	Deny   RolePermission `json:"deny"`
}

// UserPermissionOverwrite is the struct for where needs to customize permission for a user in a channel.
type UserPermissionOverwrite struct {
	User  *User          `json:"user"`
	Allow RolePermission `json:"allow"`
	Deny  RolePermission `json:"deny"`
}

// Event is the struct for every received event.
type Event struct {
	Signal         EventSignal     `json:"s"`
	Data           json.RawMessage `json:"d"`
	SequenceNumber int64           `json:"sn"`
}

// EventSignal is the type for event types.
type EventSignal int8

// All event signal consts.
const (
	EventSignalEvent     EventSignal = 0
	EventSignalHello     EventSignal = 1
	EventSignalPing      EventSignal = 2
	EventSignalPong      EventSignal = 3
	EventSignalResume    EventSignal = 4
	EventSignalReconnect EventSignal = 5
	EventSignalResumeAck EventSignal = 6
)

// EventStatusCode is the type for various event status code.
type EventStatusCode int

// EventStatusCode consts for event status.
// Keep these values in sync with the KOOK WebSocket documentation.
const (
	EventStatusOk                    EventStatusCode = 0
	EventStatusMissingArgument       EventStatusCode = 40100
	EventStatusInvalidToken          EventStatusCode = 40101
	EventStatusTokenAuthFailed       EventStatusCode = 40102
	EventStatusTokenExpired          EventStatusCode = 40103
	EventStatusResumeFailed          EventStatusCode = 40106
	EventStatusSessionExpired        EventStatusCode = 40107
	EventStatusInvalidSequenceNumber EventStatusCode = 40108
)

// EventDataHello is the struct for the data of event hello
type EventDataHello struct {
	Code      EventStatusCode `json:"code"`
	SessionID string          `json:"session_id"`
}

// EventDataResumeAck is the struct for the data of event resume ack.
type EventDataResumeAck struct {
	SessionID string `json:"session_id"`
}

// Identify is the struct for the initial settings sent to kookapp.
type Identify struct {
	Token        string
	Compress     bool
	WebsocketKey []byte
	ClientID     string
	ClientSecret string
	VerifyToken  string
}

// Session is the struct for a bot session.
type Session struct {
	sync.RWMutex

	Identify          Identify
	LastHeartbeatAck  time.Time
	LastHeartbeatSent time.Time
	Client            *http.Client
	MaxRetry          int
	RetryTimeout      time.Duration
	ContentType       string
	Logger            Logger
	Sync              bool
	// FatalHandler 在后台重连遇到不可恢复的认证/会话错误时回调。
	// 由上层适配器回置端点在线状态；必须通过 SetFatalHandler 设置。
	FatalHandler func(error)
	// ReconnectHandler 在后台 resume/重连成功后回调，用于把端点从
	// “连接中”恢复为“已连接”。必须通过 SetReconnectHandler 设置。
	ReconnectHandler func()

	wsConn  *websocket.Conn
	wsMutex sync.Mutex
	// openMu 串行化 Open/reconnect 的建连过程，避免两个并发建连互相重置 sn 状态。
	openMu    sync.Mutex
	gateway   string
	sessionID string
	sequence  *int64
	listening chan interface{}

	// lastConnectAt 用于限制“握手成功后立刻断开”的重连频率。
	lastConnectAt time.Time

	// sessionEpoch 在每次非 resume 建连、resume 状态被丢弃或 Close 时递增。
	// 事件处理协程用它丢弃旧会话的迟到回调。
	// 使用 atomic.Uint64 而不是裸 uint64：32 位平台（386/arm）也能保证 8 字节对齐。
	sessionEpoch atomic.Uint64
	dispatcher   *eventDispatcher

	// eventMu 保护 inFlight。
	eventMu  sync.Mutex
	inFlight map[int64]struct{}

	// handlerMu 跨 dispatcher 串行化 handler。
	// 重连/Close 时旧 dispatcher 可能还有 handler 未结束，新 dispatcher 不能与它并发执行。
	handlerMu sync.Mutex
	// externalHandlerMu 由适配器注入，跨 Session 串行化 handler。
	// 禁用后立即启用会创建新 Session，仅靠 Session 内的 handlerMu 无法阻止
	// 旧 Session 的迟到 handler 与新 Session 并发修改同一份骰子数据。
	externalHandlerMu *sync.Mutex

	// snPersist 在 sn 前进后回调，用于把 resume 快照刷到磁盘。
	snPersistMu sync.RWMutex
	snPersist   func()

	closed       bool
	closedCh     chan struct{}
	reconnecting bool
	reconnectSeq uint64

	// resyncMu 保护强制重同步节流，避免 handler 卡死时形成连接风暴。
	resyncMu         sync.Mutex
	lastForcedResync time.Time

	handlersMu sync.RWMutex
	handlers   map[string][]*eventHandlerInstance
}

// EventDataGeneral is the struct passed to all event handler.
type EventDataGeneral struct {
	ChannelType  string      `json:"channel_type"`
	Type         MessageType `json:"type"`
	TargetID     string      `json:"target_id"`
	AuthorID     string      `json:"author_id"`
	Content      string      `json:"content"`
	MsgID        string      `json:"msg_id"`
	MsgTimestamp int64       `json:"msg_timestamp"`
	Nonce        string      `json:"nonce"`
}

// EventData is the struct for initial parsing event's data payload.
type EventData struct {
	*EventDataGeneral
	Extra json.RawMessage `json:"extra"`
}

// MessageType is the type for messages from events.
type MessageType uint8

// MessageType consts for event message type
const (
	MessageTypeText MessageType = 1 + iota
	MessageTypeImage
	MessageTypeVideo
	MessageTypeFile
	MessageTypeAudio MessageType = 4 + iota
	MessageTypeKMarkdown
	MessageTypeCard
	MessageTypeSystem MessageType = 255
)

// EndpointGeneralResponse is the struct for initial parsing REST requests.
type EndpointGeneralResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

const heartbeatInterval = time.Second * 30

const (
	// minStableConnection 内的连接被视为短命连接，重连前会补足等待时间，
	// 避免网关“接受握手后立即断开”时形成无退避的重连风暴。
	minStableConnection = 5 * time.Second
	// heartbeatJitter 是 KOOK 文档要求的 30s + rand(-5,5) 抖动。
	heartbeatJitter = 5 * time.Second
)

// MessageReaction is the struct for reactions embedded to a message.
type MessageReaction struct {
	MsgID     string    `json:"msg_id"`
	UserID    string    `json:"user_id"`
	ChannelID string    `json:"channel_id"`
	ChatCode  string    `json:"chat_code"`
	Emoji     EmojiItem `json:"emoji"`
}

// EmojiItem is the type for an emoji.
type EmojiItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// IsEqual compares standard emoji string with kook's emoji representation.
func (e *EmojiItem) IsEqual(s string) bool {
	return e.Convert() == s
}

// Convert converts kook's emoji to standard emoji.
func (e *EmojiItem) Convert() string {
	if !strings.HasPrefix(e.ID, "[#") {
		return e.ID
	}
	t := strings.TrimLeft(e.ID, "[#")
	t = strings.TrimRight(t, ";]")
	i, err := strconv.Atoi(t)
	if err != nil {
		return ""
	}
	return string([]rune{int32(i)})
}

// ChannelMessage is the struct for a message in a channel.
type ChannelMessage struct {
	MsgID       string   `json:"msg_id"`
	Content     string   `json:"content"`
	ContentID   string   `json:"content_id"`
	Mention     []string `json:"mention"`
	MentionAll  bool     `json:"mention_all"`
	MentionHere bool     `json:"mention_here"`
	MentionRole []string `json:"mention_role"`
	UpdatedAt   int64    `json:"updated_at"`
}

// DetailedChannelMessage is the struct for a detailed message in a channel.
type DetailedChannelMessage struct {
	ID          string                  `json:"id"`
	Type        MessageType             `json:"type"`
	Author      User                    `json:"author"`
	Content     string                  `json:"content"`
	Mention     []string                `json:"mention"`
	MentionAll  bool                    `json:"mention_all"`
	MentionHere bool                    `json:"mention_here"`
	MentionRole []string                `json:"mention_role"`
	Embeds      []map[string]string     `json:"embeds"`
	Attachments *Attachment             `json:"attachments"`
	Reactions   []ReactionItem          `json:"reactions"`
	Quote       *DetailedChannelMessage `json:"quote"`
	MentionInfo struct {
		MentionPart     []*User `json:"mention_part"`
		MentionRolePart []*Role `json:"mention_role_part"`
	} `json:"mention_info"`
}

// ReactionItem is the reactions for a emoji to a message.
type ReactionItem struct {
	Emoji EmojiItem `json:"emoji"`
	Count int       `json:"count"`
	Me    bool      `json:"me"`
}

// MilliTimeStamp is the timestamp used in kookapp API.
type MilliTimeStamp int64

// ToTime converts the timestamp to golang's time.Time.
func (t *MilliTimeStamp) ToTime() time.Time {
	return time.Unix(int64(*t)/1000, int64(*t)%1000*1000*1000)
}

// MilliTimeStampOfTime converts the time.Time to MillTimeStamp
func MilliTimeStampOfTime(t time.Time) MilliTimeStamp {
	return MilliTimeStamp(t.UnixNano() / 1000000)
}

// PrivateMessage is the struct for messages in direct chat.
type PrivateMessage struct {
	MsgID     string         `json:"msg_id"`
	AuthorID  string         `json:"author_id"`
	TargetID  string         `json:"target_id"`
	Content   string         `json:"content"`
	ChatCode  string         `json:"chat_code"`
	UpdatedAt MilliTimeStamp `json:"updated_at"`
	DeletedAt MilliTimeStamp `json:"deleted_at"`
}

// Attachment is the struct for various attachments, so that according to type, some fields may be empty.
type Attachment struct {
	Type     string  `json:"type"`
	URL      string  `json:"url"`
	Name     string  `json:"name"`
	FileType string  `json:"file_type"`
	Size     int64   `json:"size"`
	Duration float64 `json:"duration"`
	Width    int     `json:"width"`
	Height   int     `json:"height"`
}

// MessageWithAttachment is a message with attachment.
type MessageWithAttachment struct {
	Type        MessageType `json:"type"`
	Code        string      `json:"code"`
	GuildID     string      `json:"guild_id"`
	Attachments Attachment  `json:"attachments"`
	Author      User        `json:"author"`
}

// EventDataSystem is the struct for initial parsing system events.
// TODO: Implement a marshaller.
type EventDataSystem struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

//type RestChannelMessage struct {
//	ID string `json:"id"`
//	Type MessageType `json:"type"`
//	Author User `json:"author"`
//	Content string `json:"content"`
//	Mention []string `json:"mention"`
//	MentionAll bool `json:"mention_all"`
//	MentionRoles []string `json:"mention_roles"`
//	MentionHere bool `json:"mention_here"`
//	Embeds []map[string]string `json:"embeds"`
//	Attachments Attachment `json:"attachments"`
//}

// UserChat is the struct for DirectMessage or UserChat
type UserChat struct {
	Code            string         `json:"code"`
	LastReadTime    MilliTimeStamp `json:"last_read_time"`
	LatestMsgTime   MilliTimeStamp `json:"latest_msg_time"`
	UnreadCount     int            `json:"unread_count"`
	IsFriend        bool           `json:"is_friend"`
	IsBlocked       bool           `json:"is_blocked"`
	IsTargetBlocked bool           `json:"is_target_blocked"`
	TargetInfo      User           `json:"target_info"`
}

// GeneralListData is the struct for list GET responses.
type GeneralListData struct {
	Items json.RawMessage `json:"items"`
	Meta  PageInfo        `json:"meta"`
	Sort  map[string]int  `json:"sort"`
}

// PageInfo is the struct for page info in list GET responses.
type PageInfo struct {
	Page      int `json:"page"`
	PageTotal int `json:"page_total"`
	PageSize  int `json:"page_size"`
	Total     int `json:"total"`
}

// PageSetting is the type for page setting in list GET request arguments.
type PageSetting struct {
	Page     *int    `json:"page"`
	PageSize *int    `json:"page_size"`
	Sort     *string `json:"sort"`
}

// EventHandlerCommonContext is the common context for event handlers.
type EventHandlerCommonContext struct {
	Session *Session
	Common  *EventDataGeneral
}

// Quote is the struct for quotes in message events.
type Quote struct {
	ID       string         `json:"id"`
	Type     MessageType    `json:"type"`
	Content  string         `json:"content"`
	CreateAt MilliTimeStamp `json:"create_at"`
	Author   *User          `json:"author"`
	RongID   string         `json:"rong_id"`
}
