package dice

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/adapterapi"
)

type officialQQBlockingCore struct {
	started chan struct{}
}

func (core *officialQQBlockingCore) HandleInbound(ctx context.Context, _ adapterapi.InboundMessage) (adapterapi.IngressReceipt, error) {
	close(core.started)
	<-ctx.Done()
	return adapterapi.IngressReceipt{}, ctx.Err()
}

func (*officialQQBlockingCore) ReportObservation(context.Context, adapterapi.LifecycleObservation) error {
	return nil
}

func TestOfficialQQDirectHandlerUsesRunContext(t *testing.T) {
	runtime := &officialQQRuntime{queue: newOfficialQQEventQueue()}
	core := &officialQQBlockingCore{started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	direct := dto.WSDirectMessageData(dto.Message{
		ID: "message-context", GuildID: "guild-1", ChannelID: "channel-1",
		Timestamp: dto.Timestamp(time.Now().UTC().Format(time.RFC3339Nano)), Author: &dto.User{ID: "user-1"},
	})
	result := make(chan error, 1)
	go func() { result <- runtime.directMessageHandler(ctx, core)(nil, &direct) }()

	select {
	case <-core.started:
	case <-time.After(time.Second):
		t.Fatal("Core ingress did not start")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("handler returned %v after Run context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Official QQ handler remained blocked after Run context cancellation")
	}
}
