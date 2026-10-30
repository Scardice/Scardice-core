package dice

import "fmt"

type RedPack[T any] struct {
	Type    string `json:"type"`
	Payload *T     `json:"payload"`
}

type RedConnectReq struct {
	Token string `json:"token"`
}

type RedConnectResp struct {
	Version  string       `json:"version"`
	Name     string       `json:"name"`
	AuthData *RedAuthData `json:"authData"`
}

type RedAuthData struct {
	Uin      string `json:"uin"`
	NickName string `json:"nickName"`
}

type RedMessageRecv []*RedMessage

type RedChatType int

const (
	PersonChat RedChatType = 1
	GroupChat  RedChatType = 2
)

type RedPeer struct {
	ChatType RedChatType `json:"chatType"`
	PeerUin  string      `json:"peerUin"`
	GuildID  string      `json:"guildId,omitempty"`
}

type RedMessageSend struct {
	Peer     *RedPeer      `json:"peer"`
	Elements []*RedElement `json:"elements"`
}

type RedMessage struct {
	MsgID          string        `json:"msgId"`
	MsgTime        string        `json:"msgTime"`
	ChatType       int           `json:"chatType"`
	SenderUid      string        `json:"senderUid"`
	PeerUid        string        `json:"peerUid"`
	SenderUin      string        `json:"senderUin"`
	PeerUin        string        `json:"peerUin"`
	SendMemberName string        `json:"sendMemberName"`
	SendNickName   string        `json:"sendNickName"`
	Elements       []*RedElement `json:"elements"`
}

type RedElement struct {
	ElementType int             `json:"elementType,omitempty"`
	ElementId   string          `json:"elementId,omitempty"`
	PicElement  *RedPicElement  `json:"picElement,omitempty"`
	TextElement *RedTextElement `json:"textElement,omitempty"`
}

// RedGroupMember is one entry of the provider's group/getMemberList response,
// carried under the response's "detail" key. Role encodes the member's group
// permission: 2-普通成员 3-管理 4-群主. It is the only place the Red protocol
// exposes a member's permission level; message events do not carry it.
type RedGroupMember struct {
	Uin      string `json:"uin"`
	Uid      string `json:"uid"`
	Nick     string `json:"nick"`
	CardName string `json:"cardName"`
	Role     int    `json:"role"`
}

type RedPicElement struct {
	OriginImageUrl string `json:"originImageUrl,omitempty"`
}

type RedTextElement struct {
	Content string `json:"content,omitempty"`
	AtType  int    `json:"atType,omitempty"`
	AtUid   string `json:"atUid,omitempty"`
	AtNtUin string `json:"atNtUin,omitempty"`
}

func formatDiceIDRed(id string) string {
	return fmt.Sprintf("QQ:%s", id)
}

func formatDiceIDRedGroup(id string) string {
	return fmt.Sprintf("QQ-Group:%s", id)
}
