//go:build cgo

package native

import (
	"reflect"
	"testing"

	"Scardice-core/utils/jsengine/hostbridge"
)

func TestNativeCodecRejectsNilCallbackTarget(t *testing.T) {
	var target reflect.Type
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Decode panicked for nil callback target: %v", recovered)
		}
	}()
	_, err := (nativeCodec{}).Decode(hostbridge.CallbackValue(1), target)
	if err == nil || err.Error() != "native codec callback target is nil" {
		t.Fatalf("Decode error = %v, want deterministic nil-target error", err)
	}
}
