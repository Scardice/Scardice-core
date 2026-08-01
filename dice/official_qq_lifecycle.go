package dice

import (
	"context"
	"errors"
	"fmt"

	"github.com/sealdice/botgo/dto"
)

var (
	ErrOfficialQQDuplicateAccount = errors.New("official QQ account already exists")
	ErrOfficialQQZeroShards       = errors.New("official QQ websocket returned zero shards")
	ErrOfficialQQReconnect        = errors.New("official QQ websocket reconnect requested")
)

func (pa *PlatformAdapterOfficialQQ) acceptVerifiedAccount(ctx context.Context, d *Dice, identity *dto.User) error {
	if identity == nil || identity.ID == "" {
		_, err := pa.migrateVerifiedIdentityAfterMe(ctx, d, &dto.User{})
		return err
	}
	userID := formatDiceIDOfficialQQ(identity.ID)
	for _, endpoint := range d.ImSession.EndPoints {
		if endpoint == nil || endpoint == pa.EndPoint || endpoint.ID == pa.EndPoint.ID {
			continue
		}
		if endpoint.Platform == "QQ" && endpoint.ProtocolType == "official" && endpoint.UserID == userID {
			return fmt.Errorf("%s: %w", userID, ErrOfficialQQDuplicateAccount)
		}
	}
	pa.EndPoint.UserID = userID
	pa.EndPoint.Nickname = identity.Username
	_, err := pa.migrateVerifiedIdentityAfterMe(ctx, d, identity)
	return err
}

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
