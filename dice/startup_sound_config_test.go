package dice

import "testing"

func TestStartupSoundConfigDefaultAndOverride(t *testing.T) {
	c := NewConfig(nil)
	if c.StartupSoundEnable {
		t.Fatal("StartupSoundEnable 默认应为关闭")
	}

	// 旧版 serve.yaml 没有该字段，升级后应保持默认关闭。
	if err := c.LoadYamlConfig([]byte("configVersion: 1\n")); err != nil {
		t.Fatalf("解析旧配置失败: %v", err)
	}
	if c.StartupSoundEnable {
		t.Fatal("旧配置缺少 startupSoundEnable 时应保持默认关闭")
	}

	// 显式开启后必须保持开启。
	c = NewConfig(nil)
	if err := c.LoadYamlConfig([]byte("configVersion: 1\nstartupSoundEnable: true\n")); err != nil {
		t.Fatalf("解析开启配置失败: %v", err)
	}
	if !c.StartupSoundEnable {
		t.Fatal("显式 startupSoundEnable: true 应保持开启")
	}
}
