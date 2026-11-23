package dice

import (
	"sync"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	"go.uber.org/zap"

	"Scardice-core/logger"
)

// botgo calls event.DefaultHandlers.Ready for every connection's READY frame
// (it does not consult the per-AppID handler map for READY). Keep one global
// dispatcher that forwards the event to the adapter currently responsible for
// that AppID.
var (
	officialQQReadyMu    sync.Mutex
	officialQQReadySinks = map[string]func(*dto.WSReadyData){}
)

func init() {
	qqevent.DefaultHandlers.Ready = func(payload *dto.WSPayload, data *dto.WSReadyData) {
		if payload == nil || payload.Session == nil {
			return
		}
		officialQQReadyMu.Lock()
		sink := officialQQReadySinks[payload.Session.AppID]
		officialQQReadyMu.Unlock()
		if sink == nil {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					// READY 回调来自 botgo 的读循环；panic 必须留在本地，
					// 但不能再静默吞掉，否则端点会一直停在“连接中”且没有日志。
					zap.S().Named(logger.LogKeyAdapter).Errorf("official qq READY 回调异常: %v", r)
				}
			}()
			sink(data)
		}()
	}
}

func registerOfficialQQReadySink(appID string, sink func(*dto.WSReadyData)) {
	if appID == "" || sink == nil {
		return
	}
	officialQQReadyMu.Lock()
	officialQQReadySinks[appID] = sink
	officialQQReadyMu.Unlock()
}
