//nolint:testpackage
package dice

import (
	"strings"
	"testing"
	"time"

	"Scardice-core/eventstore"
)

func executeLogBoundaryCommandWithoutDatabaseOperator(t *testing.T, command string) string {
	t.Helper()

	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	const groupID = "UI-Group:9002"
	_, _ = newQuitCommandTestContext(t, d, ep, "QQ:9002", groupID, "EventSourceGroup")
	d.DBOperator = nil

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupID, "QQ:9002", command))

	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatalf("timeout: expected a reply to %q", command)
	}
	return reply
}

func TestStatLogWithoutStorageCompletesAndRepliesToGroup(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()
	ctx, msg := newQuitCommandTestContext(t, d, ep, "QQ:9002", "UI-Group:9002", "EventSourceGroup")
	d.DBOperator = nil
	msg.Message = ".stat log"
	extension, ok := d.ExtRegistry.Load("log")
	if !ok || extension.CmdMap["stat"] == nil {
		t.Fatal("registered .stat command is unavailable")
	}

	result := extension.CmdMap["stat"].Solve(ctx, msg, &CmdArgs{Args: []string{"log"}, RawArgs: "log"})
	if !result.Matched || !result.Solved || result.ShowHelp {
		t.Fatalf("unavailable-storage command result = %#v, want consumed without usage fallback", result)
	}
	if _, ok := adapter.waitForMsg(2 * time.Second); !ok {
		t.Fatal("unavailable-storage command did not deliver its reply")
	}
	adapter.mu.Lock()
	groupReplies, privateReplies := len(adapter.groupMsgs), len(adapter.personMsgs)
	adapter.mu.Unlock()
	if groupReplies != 1 || privateReplies != 0 {
		t.Fatalf("reply routing: group=%d private=%d, want one group reply", groupReplies, privateReplies)
	}
}

func TestLogUsageWithoutDatabaseOperator(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
	}{
		{name: "help", command: ".log help"},
		{name: "unknown subcommand", command: ".log unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := executeLogBoundaryCommandWithoutDatabaseOperator(t, tc.command)
			if !strings.Contains(reply, ".log list") {
				t.Fatalf("reply = %q, want log command usage", reply)
			}
		})
	}
}

func TestBuiltinLogCallbacksSkipWhenDatabaseOperatorIsNil(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	RegisterBuiltinExtLog(d)

	var logExt *ExtInfo
	for _, ext := range d.ExtList {
		if ext.Name == "log" {
			logExt = ext
			break
		}
	}
	if logExt == nil {
		t.Fatal("built-in log extension was not registered")
	}

	tests := []struct {
		name string
		run  func(*MsgContext, *Message)
	}{
		{
			name: "received",
			run:  logExt.OnMessageReceived,
		},
		{
			name: "sent",
			run: func(ctx *MsgContext, msg *Message) {
				logExt.OnMessageSend(ctx, msg, "")
			},
		},
		{
			name: "edited",
			run:  logExt.OnMessageEdit,
		},
		{
			name: "deleted",
			run:  logExt.OnMessageDeleted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const groupID = "QQ-Group:nil-log-operator"
			endpoint := newCanonicalTestEndpoint(d, "QQ:bot")
			msg := newGroupMsg(groupID, "QQ:tester", "fixture message")
			msg.RawID = "raw-" + tt.name
			msg.Seq = 1
			ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "nil-log-operator:"+tt.name)
			if err := ctx.callbackTransaction.SetStoryLogState(ctx.domainContext(), eventstore.StoryLogState{
				DiceID: d.BaseConfig.Name, GroupID: groupID, Name: "fixture", On: true,
			}); err != nil {
				t.Fatal(err)
			}
			if tt.name == "sent" {
				if err := ctx.Group.SetActivation(endpoint.UserID, true, true); err != nil {
					t.Fatal(err)
				}
			}

			if d.DBOperator != nil {
				t.Fatal("test requires an in-memory Dice with a nil database operator")
			}
			// Each hook's production SQL path dereferences DBOperator, so this fixture
			// also detects any attempt to call the SQL log service.
			tt.run(ctx, msg)

			state, err := ctx.Group.GetLogState()
			if err != nil {
				t.Fatal(err)
			}
			if !state.On || state.Name != "fixture" || state.ID != 0 {
				t.Fatalf("log state after callback = %#v, want the unchanged enabled fixture", state)
			}
		})
	}
}
