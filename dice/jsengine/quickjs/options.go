package quickjs

// Options 定义 QuickJS 运行时专用参数。
// 当前仅保留字段，后续按真实需求扩展。
type Options struct {
	// MemoryLimitBytes 运行时内存上限（字节）。
	MemoryLimitBytes int64
	// TODO: 目前该字段尚未接入到底层 quickjs runtime（当前不会生效）。
	// 后续在 backend_quickjs 初始化/重置路径补齐 stack limit 设置后再启用。
	// MaxStackBytes JS 栈上限（字节）。
	MaxStackBytes int64
}
