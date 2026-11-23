package dice

import (
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"Scardice-core/logger"
)

func NewKookConnItem(token string) *EndPointInfo {
	conn := new(EndPointInfo)
	conn.ID = uuid.New().String()
	conn.Platform = "KOOK"
	conn.ProtocolType = ""
	conn.Enable = false
	conn.RelWorkDir = "extra/kook-" + conn.ID
	conn.Adapter = &PlatformAdapterKook{
		EndPoint: conn,
		Token:    token,
	}
	return conn
}

func ServeKook(d *Dice, ep *EndPointInfo) {
	log := zap.S().Named(logger.LogKeyAdapter)
	defer CrashLog()
	if ep.Platform == "KOOK" {
		conn := ep.Adapter.(*PlatformAdapterKook)
		ep.BindRuntime(d.ImSession)
		log.Infof("KOOK 尝试连接")
		if conn.Serve() != 0 {
			log.Errorf("连接KOOK服务失败")
			// Serve 已写入精确状态（失败/禁用/被重登接管）；这里只在端点仍空闲时兜底，
			// 不能覆盖并发启动的新会话状态。
			conn.setEndpointStateIfIdle(false, StateConnectionFailed)
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
		}
	}
}
