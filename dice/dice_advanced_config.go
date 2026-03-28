package dice

const DefaultCustomReplyCooldown = 5.0

type AdvancedConfig struct {
	Show   bool `json:"show"   yaml:"show"`   // 显示高级设置页
	Enable bool `json:"enable" yaml:"enable"` // 启用高级设置

	// 跑团日志相关

	StoryLogBackendUrl   string `json:"storyLogBackendUrl"   yaml:"storyLogBackendUrl"`   // 自定义后端地址
	StoryLogApiVersion   string `json:"storyLogApiVersion"   yaml:"storyLogApiVersion"`   // 后端 api 版本
	StoryLogBackendToken string `json:"storyLogBackendToken" yaml:"storyLogBackendToken"` // 自定义后端 token

	// 自定义回复属于内建能力而非 ext 配置项，因此统一冷却时间放在高级设置中集中管理。
	CustomReplyCooldown     float64 `json:"customReplyCooldown"   yaml:"customReplyCooldown"`       // 自定义回复全局统一冷却时间（秒）
	ExposeDangerousSealInst bool    `json:"exposeDangerousSealInst" yaml:"exposeDangerousSealInst"` // 向 JS 暴露 seal.inst 危险接口
}
