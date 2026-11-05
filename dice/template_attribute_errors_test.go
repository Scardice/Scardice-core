package dice

import (
	"errors"
	"testing"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/execution"
)

func TestTemplateSyncRecordsRejectedAttributeMutation(t *testing.T) {
	for _, migrateAlias := range []bool{false, true} {
		name := "version-only"
		if migrateAlias {
			name = "alias-migration"
		}
		t.Run(name, func(t *testing.T) {
			d, _ := newCanonicalTestDice(t)
			endpoint := newCanonicalTestEndpoint(d, "QQ:10001")
			ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:10002", "QQ:10003", ""), "template-write-failure")
			attrs, err := d.AttrsManager.LoadByCtx(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err = attrs.SetSheetType("template-write-failure"); err != nil {
				t.Fatal(err)
			}
			if err = attrs.Store("legacy", ds.NewIntVal(17)); err != nil {
				t.Fatal(err)
			}
			tmpl := &GameSystemTemplateV2{Name: "template-write-failure", Version: "2.0.0"}
			if migrateAlias {
				tmpl.Alias = Alias{"canonical": {"legacy"}}
			}
			tmpl.Init()
			if err = ctx.callbackTransaction.Finalize(ctx.domainContext()); err != nil {
				t.Fatal(err)
			}

			ctx.syncAttrsForTemplate(attrs, tmpl)

			if err = ctx.getExecutionError(); !errors.Is(err, execution.ErrDomainTxClosed) {
				t.Errorf("rejected template mutation was not recorded: %v", err)
			}
			if _, exists := attrs.LoadX(attrsTemplateVersionKey); exists {
				t.Error("rejected migration advanced the card version")
			}
			if value, exists := attrs.LoadX("legacy"); !exists || value.ToString() != "17" {
				t.Errorf("rejected migration lost the original attribute: %v, %t", value, exists)
			}
			if _, exists := attrs.LoadX("canonical"); exists {
				t.Error("rejected migration added the canonical attribute")
			}
		})
	}
}

func TestRollVMAttributeAssignmentRecordsUnavailableExecution(t *testing.T) {
	for _, name := range []string{"$m持久变量", "$g持久变量"} {
		t.Run(name, func(t *testing.T) {
			d, _ := newCanonicalTestDice(t)
			endpoint := newCanonicalTestEndpoint(d, "QQ:10001")
			ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:10002", "QQ:10003", ""), "vm-write-failure")
			ctx.callbackTransaction = nil
			vm := ds.NewVM()
			config := ctx.GenDefaultRollVmConfig()
			defer func() {
				if failure := recover(); failure != nil {
					t.Errorf("attribute assignment escaped as a panic: %v", failure)
				}
			}()

			config.HookValueStore(vm, name, ds.NewIntVal(17))

			if !errors.Is(vm.Error, ErrAttributeExecutionUnavailable) {
				t.Errorf("VM did not report unavailable attribute execution: %v", vm.Error)
			}
			if err := ctx.getExecutionError(); !errors.Is(err, ErrAttributeExecutionUnavailable) {
				t.Errorf("callback did not record unavailable attribute execution: %v", err)
			}
		})
	}
}

func TestExecutionErrorFromShallowCopyReachesCallbackRoot(t *testing.T) {
	root := &MsgContext{}
	child := root.ShallowCopy().ShallowCopy()
	failure := errors.New("attribute write rejected")

	child.setExecutionError(failure)
	child.setExecutionError(errors.New("later execution failure"))

	if err := root.getExecutionError(); !errors.Is(err, failure) {
		t.Fatalf("callback root did not retain the first child failure: %v", err)
	}
}
