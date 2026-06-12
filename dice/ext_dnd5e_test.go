//nolint:testpackage
package dice

import (
	"testing"

	"Scardice-core/model"
)

func TestDnd5eSpellSlotStatusReturnsSolved(t *testing.T) {
	d, ep, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	mockDB, ok := d.DBOperator.(*mockDatabaseOperator)
	if !ok {
		t.Fatalf("expected mock database operator, got %T", d.DBOperator)
	}
	if err := mockDB.db.AutoMigrate(&model.AttributesItemModel{}); err != nil {
		t.Fatalf("migrate attrs table: %v", err)
	}

	var dndExt *ExtInfo
	for _, ext := range d.ExtList {
		if ext != nil && ext.Name == "dnd5e" {
			dndExt = ext
			break
		}
	}
	if dndExt == nil {
		t.Fatal("dnd5e extension not registered")
	}

	cmd := dndExt.GetCmdMap()["ss"]
	if cmd == nil {
		t.Fatal("ss command not registered")
	}

	ctx, msg := newQuitCommandTestContext(t, d, ep, "QQ:9100", "QQ-Group:2100", "DNDGroup")
	result := cmd.Solve(ctx, msg, &CmdArgs{Command: "ss"})
	if !result.Matched || !result.Solved {
		t.Fatalf("expected ss command to be solved after replying, got %#v", result)
	}
}
