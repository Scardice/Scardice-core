package dice

import (
	"sync"

	"github.com/sealdice/botgo/dto"
	qqevent "github.com/sealdice/botgo/event"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"Scardice-core/logger"
)

// botgo calls event.DefaultHandlers.Ready for every connection's READY frame
// (it does not consult the per-AppID handler map for READY). Keep one global
// dispatcher that forwards the event to the adapter currently responsible for
// that AppID.
var (
	officialQQReadyMu    sync.Mutex
	officialQQReadySinks = map[string]officialQQReadySink{}
)

type officialQQReadySink struct {
	// tokenSource 是该次连接传给 botgo 的 token source。1118: READY 全局
	// 回调只带 AppID，同一 AppID 新旧连接短时并存时，旧连接的迟到 READY
	// 会命中新注册的 sink。比较 token source 指针可以精确忽略旧连接。
	tokenSource oauth2.TokenSource
	sink        func(*dto.WSReadyData)
}

//nolint:gochecknoinits // botgo 的全局 READY 分发器必须在包初始化时注册
func init() {
	qqevent.DefaultHandlers.Ready = func(payload *dto.WSPayload, data *dto.WSReadyData) {
		if payload == nil || payload.Session == nil {
			return
		}
		officialQQReadyMu.Lock()
		entry, ok := officialQQReadySinks[payload.Session.AppID]
		officialQQReadyMu.Unlock()
		if !ok || entry.sink == nil {
			return
		}
		if entry.tokenSource != nil && payload.Session.TokenSource != nil &&
			entry.tokenSource != payload.Session.TokenSource {
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
			entry.sink(data)
		}()
	}
}

func registerOfficialQQReadySink(appID string, tokenSource oauth2.TokenSource, sink func(*dto.WSReadyData)) {
	if appID == "" || sink == nil {
		return
	}
	officialQQReadyMu.Lock()
	officialQQReadySinks[appID] = officialQQReadySink{
		tokenSource: tokenSource,
		sink:        sink,
	}
	officialQQReadyMu.Unlock()
}
