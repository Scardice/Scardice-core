package dice

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/eventstore"
)

const stFormatTransactionChildEnv = "SCARDICE_ST_FORMAT_TRANSACTION_CHILD"

// A deadlocked DomainTx cannot be aborted by test cleanup. Keep the real
// formatting path in a bounded child so a regression cannot stall the suite.
func runStFormatTransactionChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv(stFormatTransactionChildEnv) == t.Name() {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1")
	command.Env = append(os.Environ(), stFormatTransactionChildEnv+"="+t.Name())
	output, err := command.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("character formatting did not finish on its canonical DomainTx within 10s; blocked child terminated:\n%s", output)
	}
	if err != nil {
		t.Fatalf("isolated character formatting failed: %v\n%s", err, output)
	}
	return true
}

func newStFormatTransactionFixture(t *testing.T, dodge int64) (*Dice, *EndPointInfo, *Message, *GameSystemTemplate) {
	t.Helper()
	d, _ := newCanonicalTestDice(t)
	tmpl, err := loadBuiltinTemplate("coc7.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d.GameSystemMap.Store(tmpl.Name, tmpl)
	setupBaseTextTemplate(d)
	d.GenerateTextMap()
	endpoint := newCanonicalTestEndpoint(d, "QQ:st-format-bot")
	message := newGroupMsg("QQ-Group:st-format", "QQ:st-format-user", "")
	withCanonicalTestMessageContext(t, d, endpoint, message, "seed-st-format", func(ctx *MsgContext) error {
		if err := ctx.Group.SetSystem("coc7"); err != nil {
			return err
		}
		attrs, err := d.AttrsManager.LoadByCtx(ctx)
		if err != nil {
			return err
		}
		nested := &ds.ValueMap{}
		nested.Store("kept", ds.NewIntVal(9))
		for key, value := range map[string]*ds.VMValue{
			"敏捷":          ds.NewIntVal(70),
			"闪避":          ds.NewIntVal(ds.IntType(dodge)),
			"聆听":          ds.NewIntVal(20),
			"语言":          ds.NewIntVal(37),
			"custom-int":  ds.NewIntVal(99),
			"custom-text": ds.NewStrVal("unchanged"),
			"custom-dict": ds.NewDictVal(nested).V(),
		} {
			if err = attrs.Store(key, value); err != nil {
				return err
			}
		}
		return nil
	})
	return d, endpoint, message, tmpl
}

func assertStFormatTransactionResult(t *testing.T, ctx *MsgContext, dodge int64, setStrength bool) {
	t.Helper()
	attrs, err := ctx.Dice.AttrsManager.LoadByCtx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"敏捷": "70", "外语": "37", "custom-int": "99", "custom-text": "unchanged", attrsTemplateVersionKey: "1.1.0",
	} {
		value, found := attrs.LoadX(key)
		if !found || value.ToString() != want {
			t.Errorf("formatted attribute %q = %v, present=%t; want %q", key, value, found, want)
		}
	}
	for _, key := range []string{"语言", "聆听"} {
		if _, found := attrs.LoadX(key); found {
			t.Errorf("formatting retained alias/default attribute %q", key)
		}
	}
	storedDodge, found := attrs.LoadX("闪避")
	if dodge == 35 {
		if found {
			t.Errorf("computed default dodge was not removed: %v", storedDodge)
		}
	} else if !found || storedDodge.ToString() != "36" {
		t.Errorf("non-default dodge = %v, present=%t; want 36", storedDodge, found)
	}
	if attrs.SheetType() != "coc7" {
		t.Errorf("formatted sheet type = %q, want coc7", attrs.SheetType())
	}
	nested := attrs.Load("custom-dict")
	if nested == nil {
		t.Fatal("formatting lost the unknown dictionary attribute")
	}
	dict, ok := nested.ReadDictData()
	if !ok {
		t.Fatalf("unknown dictionary attribute changed type: %v", nested)
	}
	value, found := dict.Dict.Load("kept")
	if !found || value.ToString() != "9" {
		t.Errorf("unknown dictionary value = %v, present=%t; want 9", value, found)
	}

	ctx.SystemTemplate = ctx.Group.GetCharTemplate(ctx.Dice)
	result := ctx.Eval("闪避 + 敏捷", nil)
	want := "105"
	if dodge == 36 {
		want = "106"
	}
	if result == nil || result.vm.Error != nil || result.ToString() != want {
		t.Fatalf("COC template consumer returned %v; want %s", result, want)
	}
	_, names, err := cmdStSortNamesByTmpl(ctx, ctx.SystemTemplate, map[string]int{}, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"$ver", "custom-dict", "custom-int", "custom-text"}
	if setStrength {
		wantNames = append(wantNames, "力量")
		if value := attrs.Load("力量"); value == nil || value.ToString() != "61" {
			t.Errorf("st attribute command did not retain its update: %v", value)
		}
	}
	wantNames = append(wantNames, "外语", "敏捷")
	if dodge == 36 {
		wantNames = append(wantNames, "闪避")
	}
	if !reflect.DeepEqual(names, wantNames) {
		t.Errorf("formatted export attribute order = %v, want %v", names, wantNames)
	}
}

func TestStCharFormatComputedDefaultCanonicalTransaction(t *testing.T) {
	for _, test := range []struct {
		name    string
		dodge   int64
		command string
	}{
		{name: "formatter-default", dodge: 35},
		{name: "formatter-override", dodge: 36},
		{name: "fmt-command", dodge: 35, command: "fmt"},
		{name: "attribute-command", dodge: 35, command: "力量61"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if runStFormatTransactionChild(t) {
				return
			}
			d, endpoint, message, tmpl := newStFormatTransactionFixture(t, test.dodge)
			id := message.GroupID + "-" + message.Sender.UserID
			before, err := d.AttrsManager.durable.LoadForExecution(context.Background(), d.BaseConfig.Name, id)
			if err != nil {
				t.Fatal(err)
			}
			withCanonicalTestMessageContext(t, d, endpoint, message, "format-st-card", func(ctx *MsgContext) error {
				ctx.SystemTemplate = tmpl
				if test.command == "" {
					if err := cmdStCharFormat(ctx, tmpl); err != nil {
						return err
					}
				} else {
					result := getCmdStBase(CmdStOverrideInfo{}).Solve(ctx, message, &CmdArgs{
						Args: []string{test.command}, CleanArgs: test.command,
					})
					if !result.Matched || !result.Solved || result.ShowHelp {
						t.Fatalf("st command result = %#v", result)
					}
				}
				if err := ctx.getExecutionError(); err != nil {
					return err
				}
				assertStFormatTransactionResult(t, ctx, test.dodge, test.command == "力量61")
				uncommitted, err := d.AttrsManager.durable.LoadForExecution(context.Background(), d.BaseConfig.Name, id)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(uncommitted.State, before.State) || !bytes.Equal(uncommitted.Plaintext, before.Plaintext) {
					t.Fatal("formatting persisted card changes before its root committed")
				}
				return ctx.getExecutionError()
			})
			persisted, err := d.AttrsManager.durable.LoadForExecution(context.Background(), d.BaseConfig.Name, id)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.StreamVersion != before.StreamVersion+1 || persisted.State.SecretVersion != before.State.SecretVersion+1 {
				t.Fatalf("formatting did not persist one atomic card snapshot: before=%#v after=%#v", before.State, persisted.State)
			}
			fresh := newCanonicalTestMessageContext(t, d, endpoint, message, "read-formatted-st-card")
			assertStFormatTransactionResult(t, fresh, test.dodge, test.command == "力量61")
		})
	}
}

func TestStCharFormatConflictDoesNotPartiallyPersist(t *testing.T) {
	if runStFormatTransactionChild(t) {
		return
	}
	d, endpoint, message, tmpl := newStFormatTransactionFixture(t, 35)
	id := message.GroupID + "-" + message.Sender.UserID
	before, err := d.AttrsManager.durable.LoadForExecution(context.Background(), d.BaseConfig.Name, id)
	if err != nil {
		t.Fatal(err)
	}
	identity := canonicalFixtureLabel(t, "st-format-conflict")
	err = d.WithDomainExecution(context.Background(), identity, []byte(identity), func(transaction *DurableCallbackTransaction) error {
		ctx, err := NewDomainMsgContext(transaction, d, d.ImSession, endpoint, message)
		if err != nil {
			return err
		}
		defer ctx.releaseExecutionState()
		ctx.SystemTemplate = tmpl
		if err = cmdStCharFormat(ctx, tmpl); err != nil {
			return err
		}
		assertStFormatTransactionResult(t, ctx, 35, false)
		withCanonicalTestMessageContext(t, d, endpoint, message, "concurrent-st-write", func(concurrent *MsgContext) error {
			attrs, err := d.AttrsManager.LoadByCtx(concurrent)
			if err != nil {
				return err
			}
			return attrs.Store("concurrent", ds.NewIntVal(1))
		})
		return ctx.getExecutionError()
	})
	if !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("stale format root error = %v, want stream conflict", err)
	}
	persisted, err := d.AttrsManager.durable.LoadForExecution(context.Background(), d.BaseConfig.Name, id)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.StreamVersion != before.StreamVersion+1 || persisted.State.SecretVersion != before.State.SecretVersion+1 {
		t.Fatalf("rejected formatting persisted another card snapshot: before=%#v after=%#v", before.State, persisted.State)
	}
	fresh := newCanonicalTestMessageContext(t, d, endpoint, message, "read-rejected-st-format")
	attrs, err := d.AttrsManager.LoadByCtx(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if attrs.SheetType() != "" {
		t.Errorf("rejected format persisted sheet type %q", attrs.SheetType())
	}
	for key, want := range map[string]string{"语言": "37", "聆听": "20", "闪避": "35", "敏捷": "70", "concurrent": "1"} {
		value := attrs.Load(key)
		if value == nil || value.ToString() != want {
			t.Errorf("attribute %q after rejected format = %v, want %s", key, value, want)
		}
	}
	for _, key := range []string{"外语", attrsTemplateVersionKey} {
		if _, found := attrs.LoadX(key); found {
			t.Errorf("rejected format partially persisted %q", key)
		}
	}
}
