package privacypurge

import (
	"context"
	"errors"
	"testing"
)

func TestPrivacyServiceRejectsUnavailableRepository(t *testing.T) {
	service := NewService(nil)
	if _, err := service.DryRun(context.Background(), Request{GroupID: "g", DiceIDs: []string{"dice"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("dry run=%v", err)
	}
	if _, err := service.Confirm(context.Background(), Request{GroupID: "g", DiceIDs: []string{"dice"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("confirm=%v", err)
	}
}
