//nolint:testpackage
package dice

import (
	"testing"

	"github.com/dop251/goja"
)

func TestParseMessagePreprocessValue(t *testing.T) {
	vm := goja.New()

	tests := []struct {
		name        string
		src         string
		wantAction  messagePreprocessAction
		wantMessage string
	}{
		{
			name:       "undefined result is noop",
			src:        "undefined",
			wantAction: messagePreprocessNoop,
		},
		{
			name:       "null result is noop",
			src:        "null",
			wantAction: messagePreprocessNoop,
		},
		{
			name:        "string result rewrites",
			src:         `"rewritten"`,
			wantAction:  messagePreprocessRewrite,
			wantMessage: "rewritten",
		},
		{
			name:       "empty string result intercepts",
			src:        `""`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:        "object string message rewrites",
			src:         `({ message: ".r 1d6" })`,
			wantAction:  messagePreprocessRewrite,
			wantMessage: ".r 1d6",
		},
		{
			name:       "object empty string message intercepts",
			src:        `({ message: "" })`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:       "object false message intercepts",
			src:        `({ message: false })`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:       "object zero message intercepts",
			src:        `({ message: 0 })`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:       "object null message intercepts",
			src:        `({ message: null })`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:       "object undefined message intercepts",
			src:        `({ message: undefined })`,
			wantAction: messagePreprocessIntercept,
		},
		{
			name:       "object true message is noop",
			src:        `({ message: true })`,
			wantAction: messagePreprocessNoop,
		},
		{
			name:       "object nonzero message is noop",
			src:        `({ message: 1 })`,
			wantAction: messagePreprocessNoop,
		},
		{
			name:       "object truthy object message is noop",
			src:        `({ message: {} })`,
			wantAction: messagePreprocessNoop,
		},
		{
			name:       "missing message is noop",
			src:        `({ reason: "ignored" })`,
			wantAction: messagePreprocessNoop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := vm.RunString(tt.src)
			if err != nil {
				t.Fatalf("RunString(%s): %v", tt.src, err)
			}
			got := parseMessagePreprocessValue(vm, value)
			if got.action != tt.wantAction {
				t.Fatalf("action = %v, want %v", got.action, tt.wantAction)
			}
			if got.message != tt.wantMessage {
				t.Fatalf("message = %q, want %q", got.message, tt.wantMessage)
			}
		})
	}
}
