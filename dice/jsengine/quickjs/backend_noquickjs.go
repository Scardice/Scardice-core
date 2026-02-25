//go:build !quickjs

package quickjs

import (
	"fmt"

	"Scardice-core/dice/jsengine"
)

type unavailableBackend struct{}

func (b *unavailableBackend) Dispose() error { return nil }

func (b *unavailableBackend) Eval(_ string) error { return fmt.Errorf("QuickJS backend 不可用") }
func (b *unavailableBackend) EvalWithResult(_ string) (any, error) {
	return nil, fmt.Errorf("QuickJS backend 不可用")
}

func (b *unavailableBackend) Require(_ string) error { return fmt.Errorf("QuickJS backend 不可用") }

func (b *unavailableBackend) RegisterHostAPI(_ jsengine.HostAPI) error {
	return fmt.Errorf("QuickJS backend 不可用")
}

func (b *unavailableBackend) Reset() error { return fmt.Errorf("QuickJS backend 不可用") }

func (b *unavailableBackend) InvokeStoredSolve(_ string, _ string, _ map[string]any) (map[string]any, error) {
	return nil, fmt.Errorf("QuickJS backend 不可用")
}
func (b *unavailableBackend) InvokeStoredOnNotCommand(_ string, _ map[string]any) error {
	return fmt.Errorf("QuickJS backend 不可用")
}

func (b *unavailableBackend) InvokeStoredTask(_ string, _ map[string]any) error {
	return fmt.Errorf("QuickJS backend 不可用")
}

func init() {
	// 未启用 quickjs 标签时，使用降级后端，明确返回错误。
	newRuntimeBackend = func(_ jsengine.Config, _ Options) (runtimeBackend, error) {
		return &unavailableBackend{}, fmt.Errorf("QuickJS backend 不可用：需要 -tags quickjs")
	}
}
