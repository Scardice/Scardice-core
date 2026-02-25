package jsengine

import (
	"fmt"
	"sync"
)

// Constructor 是引擎构造器函数签名。
type Constructor func() Engine

var (
	registryMu sync.RWMutex
	registry   = map[EngineName]Constructor{}
)

// Register 注册引擎构造器。
func Register(name EngineName, ctor Constructor) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = ctor
}

// New 根据配置创建引擎实例。
func New(cfg Config) (Engine, error) {
	registryMu.RLock()
	ctor, ok := registry[cfg.Name]
	registryMu.RUnlock()
	if !ok || ctor == nil {
		return nil, &EngineError{
			Kind:    ErrInit,
			Message: fmt.Sprintf("不支持的引擎类型: %s", cfg.Name),
		}
	}
	return ctor(), nil
}
