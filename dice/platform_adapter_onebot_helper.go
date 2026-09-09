package dice

import (
	"github.com/google/uuid"
)

type AddOnebotEcho struct {
	Token             string
	ConnectURL        string
	ReverseURL        string
	ReverseSuffix     string
	Mode              string
	ImageAssetBaseURL string
}

func NewOnebotConnItem(v AddOnebotEcho) *EndPointInfo {
	conn := new(EndPointInfo)
	conn.ID = uuid.New().String()
	conn.Platform = "QQ"
	conn.ProtocolType = "pureonebot"
	conn.Enable = false
	conn.RelWorkDir = "extra/pureonebot-" + conn.ID // 也不知道干啥的
	if v.ReverseSuffix == "" {
		v.ReverseSuffix = "/ws"
	}
	conn.Adapter = &PlatformAdapterOnebot{
		EndPoint:          conn,
		Token:             v.Token,
		ConnectURL:        v.ConnectURL,
		ReverseSuffix:     v.ReverseSuffix,
		ReverseUrl:        v.ReverseURL,
		Mode:              v.Mode,
		ImageAssetBaseURL: v.ImageAssetBaseURL,
	}
	return conn
}
