package dice

import (
	"path/filepath"
	"testing"

	ds "github.com/sealdice/dicescript"

	sealdiceLogger "Scardice-core/logger"
)

// newVarTestContext 构造一个读库会失败的变量上下文。
// mockDatabaseOperator 指向一个没有建表的 SQLite 文件，
// LoadByCtx 的角色绑定查询会返回错误，正好覆盖过去 lo.Must 的崩溃路径。
func newVarTestContext(t *testing.T) (*MsgContext, func()) {
	t.Helper()

	mockDB, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "attrs.db"))
	if err != nil {
		t.Fatalf("newMockDatabaseOperator: %v", err)
	}
	d := &Dice{
		Logger:       sealdiceLogger.M(),
		AttrsManager: &AttrsManager{db: mockDB, logger: sealdiceLogger.M()},
	}
	ctx := &MsgContext{
		Dice:    d,
		Session: &IMSession{},
		Group:   &GroupInfo{GroupID: "QQ-Group:10001"},
		Player:  &GroupPlayerInfo{UserID: "QQ:10002"},
	}
	return ctx, mockDB.Close
}

func TestVarGetValueDoesNotPanicOnAttrsLoadError(t *testing.T) {
	ctx, cleanup := newVarTestContext(t)
	defer cleanup()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VarGetValue 不应 panic: %v", r)
		}
	}()

	// 个人属性走 LoadByCtx，读库失败时应返回 (nil, false)，而不是抛 panic。
	if v, ok := VarGetValue(ctx, "hp"); ok || v != nil {
		t.Fatalf("VarGetValue(hp) = (%v, %v), want (nil, false)", v, ok)
	}
	if v, ok := VarGetValueStr(ctx, "hp"); ok || v != "" {
		t.Fatalf("VarGetValueStr(hp) = (%q, %v), want (\"\", false)", v, ok)
	}
	if v, ok := VarGetValueInt64(ctx, "hp"); ok || v != 0 {
		t.Fatalf("VarGetValueInt64(hp) = (%d, %v), want (0, false)", v, ok)
	}

	// $m/$g 走 LoadById；这里即使查不到也只会得到空值，不能 panic。
	_, _ = VarGetValue(ctx, "$mhp")
	_, _ = VarGetValue(ctx, "$ghp")
}

func TestVarSetAndDelValueDoNotPanicOnAttrsLoadError(t *testing.T) {
	ctx, cleanup := newVarTestContext(t)
	defer cleanup()

	// 预置 vm，跳过 CreateVmIfNotExists 的完整模板初始化。
	ctx.vm = ds.NewVM()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VarSetValue/VarDelValue 不应 panic: %v", r)
		}
	}()

	VarSetValue(ctx, "$mhp", ds.NewIntVal(1))
	VarSetValue(ctx, "$ghp", ds.NewIntVal(1))
	VarSetValue(ctx, "hp", ds.NewIntVal(1))

	VarDelValue(ctx, "$mhp")
	VarDelValue(ctx, "$ghp")
	VarDelValue(ctx, "hp")
}

func TestVarGetValueTempVarWithNilPlayerDoesNotPanic(t *testing.T) {
	ctx, cleanup := newVarTestContext(t)
	defer cleanup()
	ctx.Group = nil
	ctx.Player = nil

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("$t 变量在 Player 为空时不应 panic: %v", r)
		}
	}()

	if v, ok := VarGetValue(ctx, "$t测试"); ok || v != nil {
		t.Fatalf("VarGetValue($t测试) = (%v, %v), want (nil, false)", v, ok)
	}
}
