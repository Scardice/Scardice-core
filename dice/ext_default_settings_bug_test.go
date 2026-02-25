//lint:file-ignore testpackage Tests need access to internal helpers and types
package dice //nolint:testpackage // tests rely on unexported helpers

import (
	"testing"

	"go.uber.org/zap"
)

// 复现问题：
// 1) 扩展曾被记录到 InactivatedExtSet（历史关闭）
// 2) WebUI 将该扩展默认设置改为 AutoActive=true，并调用 ApplyExtDefaultSettings
// 3) 群内同步时仍因 InactivatedExtSet 阻断，扩展不会自动开启
func TestApplyExtDefaultSettings_AutoActiveStillBlockedByInactivatedSet(t *testing.T) {
	ext := &ExtInfo{
		Name:       "js-demo",
		AutoActive: true,
		CmdMap:     CmdMapCls{},
	}

	d := &Dice{
		Logger:      zap.NewNop().Sugar(),
		ExtList:     []*ExtInfo{ext},
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
		Config:      Config{},
	}
	d.Config.ExtDefaultSettings = []*ExtDefaultSettingItem{
		{
			Name:            ext.Name,
			AutoActive:      true,
			DisabledCommand: map[string]bool{},
		},
	}
	ext.dice = d
	d.ExtRegistry.Store(ext.Name, ext)
	d.ExtRegistryVersion = 1

	group := &GroupInfo{
		GroupID:           "QQ-Group:123",
		InactivatedExtSet: StringSet{ext.Name: {}}, // 历史关闭记录
	}
	group.SetActivatedExtList([]*ExtInfo{}, d)
	group.ExtAppliedVersion = d.ExtRegistryVersion // 模拟“已同步”状态（线上常态）
	d.ImSession = &IMSession{
		ServiceAtNew: new(SyncMap[string, *GroupInfo]),
	}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)

	// 模拟 WebUI 配置保存后逻辑：仅应用默认设置，不清理群级关闭集合
	d.ApplyExtDefaultSettings()
	group.SyncExtensionsOnMessage(d)

	if group.ExtGetActive(ext.Name) == nil {
		t.Fatalf("expected ext %q to be auto-activated after enabling AutoActive in default settings, but it stays inactive", ext.Name)
	}
}

// 回归测试：
// 默认设置从 AutoActive=true 改为 false 时，不应强制关闭已开启扩展；
// 仅影响后续自动激活决策。
func TestApplyExtDefaultSettings_DisableAutoActiveDoesNotForceDeactivate(t *testing.T) {
	ext := &ExtInfo{
		Name:       "js-demo",
		AutoActive: true,
		CmdMap:     CmdMapCls{},
	}

	d := &Dice{
		Logger:      zap.NewNop().Sugar(),
		ExtList:     []*ExtInfo{ext},
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
		Config:      Config{},
	}
	d.Config.ExtDefaultSettings = []*ExtDefaultSettingItem{
		{
			Name:            ext.Name,
			AutoActive:      false,
			DisabledCommand: map[string]bool{},
		},
	}
	ext.dice = d
	d.ExtRegistry.Store(ext.Name, ext)
	d.ExtRegistryVersion = 1

	group := &GroupInfo{
		GroupID:           "QQ-Group:456",
		InactivatedExtSet: StringSet{},
	}
	// 模拟：该扩展已经处于开启状态（用户手动开过/历史状态）
	group.SetActivatedExtList([]*ExtInfo{ext}, d)
	group.ExtAppliedVersion = d.ExtRegistryVersion
	d.ImSession = &IMSession{
		ServiceAtNew: new(SyncMap[string, *GroupInfo]),
	}
	d.ImSession.ServiceAtNew.Store(group.GroupID, group)

	d.ApplyExtDefaultSettings()
	group.SyncExtensionsOnMessage(d)

	if group.ExtGetActive(ext.Name) == nil {
		t.Fatalf("expected ext %q to remain active after disabling AutoActive default setting", ext.Name)
	}
	if group.IsExtInactivated(ext.Name) {
		t.Fatalf("expected ext %q not to be marked inactivated while it is already active", ext.Name)
	}
}
