package dice

import (
	"context"
	"errors"
	"fmt"

	"github.com/sealdice/botgo/dto"
)

var (
	ErrOfficialQQZeroShards = errors.New("official QQ websocket returned zero shards")
	ErrOfficialQQReconnect  = errors.New("official QQ websocket reconnect requested")
)

func validateOfficialQQWebsocketAP(ws *dto.WebsocketAP) error {
	if ws == nil {
		return errors.New("official QQ websocket access point is nil")
	}
	if ws.Shards == 0 {
		return ErrOfficialQQZeroShards
	}
	if ws.Shards > ws.SessionStartLimit.Remaining {
		return fmt.Errorf("official QQ session limited: shards=%d remaining=%d", ws.Shards, ws.SessionStartLimit.Remaining)
	}
	return nil
}

func runOfficialQQSession(ctx context.Context, start func(context.Context) error) error {
	for {
		err := start(ctx)
		if !errors.Is(err, ErrOfficialQQReconnect) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}
