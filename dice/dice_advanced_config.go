package dice

import "errors"

const DefaultCustomReplyCooldown = 5.0

var ErrDangerousSealInstUnsupported = errors.New("dice: seal.inst is no longer supported")

type AdvancedConfig struct {
	source configViewSource
	Show   bool `json:"show"   yaml:"show"`   // 显示高级设置页
	Enable bool `json:"enable" yaml:"enable"` // 启用高级设置

	// 跑团日志相关

	StoryLogBackendUrl   string `json:"storyLogBackendUrl"   yaml:"storyLogBackendUrl"`   // 自定义后端地址
	StoryLogApiVersion   string `json:"storyLogApiVersion"   yaml:"storyLogApiVersion"`   // 后端 api 版本
	StoryLogBackendToken string `json:"storyLogBackendToken" yaml:"storyLogBackendToken"` // 自定义后端 token

	// 自定义回复属于内建能力而非 ext 配置项，因此统一冷却时间放在高级设置中集中管理。
	CustomReplyCooldown               float64 `json:"customReplyCooldown"        yaml:"customReplyCooldown"`                      // 自定义回复全局统一冷却时间（秒）
	ExposeDangerousSealInst           bool    `json:"exposeDangerousSealInst"    yaml:"exposeDangerousSealInst"`                  // 历史请求值，仅用于解码和明确报告；运行时不再暴露 seal.inst
	DangerousSealInstSupported        bool    `json:"dangerousSealInstSupported" yaml:"-"`                                        // 固定为 false，明确报告该能力已移除
	AllowFilesystemUnrestrictedAccess bool    `json:"allowFilesystemUnrestrictedAccess" yaml:"allowFilesystemUnrestrictedAccess"` // 允许 JS fs 模块访问绝对路径与核心可执行文件相对路径（危险）
}
