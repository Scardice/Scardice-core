package emitter

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"Scardice-core/dice/imsdk/onebot/schema"
)

type observedAction struct {
	action   string
	frame    []byte
	response []byte
	finished int
}

type recordingObserver struct {
	mu      sync.Mutex
	actions []*observedAction
}

func (o *recordingObserver) BeginAction(action string, frame []byte) func([]byte) {
	record := &observedAction{action: action, frame: append([]byte(nil), frame...)}
	o.mu.Lock()
	o.actions = append(o.actions, record)
	o.mu.Unlock()
	return func(response []byte) {
		o.mu.Lock()
		record.response = append([]byte(nil), response...)
		record.finished++
		o.mu.Unlock()
	}
}

// answeringEmitter stands in for the protocol end: every frame is answered
// with the same send response, echoing the frame's correlation id.
func answeringEmitter(observer ActionObserver, respond bool) *emitterSocket {
	e := &emitterSocket{observer: observer}
	e.emit = func(frame []byte) {
		if !respond {
			return
		}
		var request struct {
			Echo string `json:"echo"`
		}
		_ = json.Unmarshal(frame, &request)
		e.HandleEcho(request.Echo, []byte(`{"status":"ok","retcode":0,"data":{"message_id":321},"echo":"`+request.Echo+`"}`))
	}
	return e
}

// Core's sends leave through the typed helpers, Raw (outbound effects) and
// RawJSON (plugin callApi/callApiRaw); the observer must see all of them.
func TestEmitterObserverSeesTypedRawAndRawJSONActions(t *testing.T) {
	observer := &recordingObserver{}
	e := answeringEmitter(observer, true)

	if _, err := e.SendGrMsg(t.Context(), 2002, schema.MessageChain{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SendPvtMsg(t.Context(), 1001, schema.MessageChain{}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Raw(t.Context(), "send_group_forward_msg", map[string]any{"group_id": 2002}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.RawJSON(t.Context(), []byte(`{"action":"send_msg","params":{"message_type":"group","group_id":2002,"message":"hi"}}`)); err != nil {
		t.Fatal(err)
	}

	want := []string{ACTION_SEND_GROUP_MSG, ACTION_SEND_PRIVATE_MSG, "send_group_forward_msg", "send_msg"}
	if len(observer.actions) != len(want) {
		t.Fatalf("observed %d actions, want %d", len(observer.actions), len(want))
	}
	for i, action := range observer.actions {
		var frame struct {
			Action string `json:"action"`
			Echo   string `json:"echo"`
		}
		if err := json.Unmarshal(action.frame, &frame); err != nil || frame.Action != want[i] || frame.Echo == "" {
			t.Fatalf("action %d frame = %s (err %v), want %s with an echo", i, action.frame, err, want[i])
		}
		if action.action != want[i] || action.finished != 1 {
			t.Fatalf("action %d = %q finished %d times, want %q once", i, action.action, action.finished, want[i])
		}
		var response struct {
			Data struct {
				MessageID int64 `json:"message_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(action.response, &response); err != nil || response.Data.MessageID != 321 {
			t.Fatalf("action %d response = %s, want the provider's whole response frame", i, action.response)
		}
	}
}

func TestEmitterObserverFinishesWithoutResponseWhenTheActionTimesOut(t *testing.T) {
	old := EchoTimeOut
	EchoTimeOut = 20 * time.Millisecond
	defer func() { EchoTimeOut = old }()

	observer := &recordingObserver{}
	e := answeringEmitter(observer, false)
	if _, err := e.SendGrMsg(t.Context(), 2002, schema.MessageChain{}); err == nil {
		t.Fatal("unanswered send reported success")
	}
	if _, err := e.RawJSON(t.Context(), []byte(`{"action":"send_msg","params":{}}`)); err == nil {
		t.Fatal("unanswered raw send reported success")
	}
	if len(observer.actions) != 2 {
		t.Fatalf("observed %d actions, want 2", len(observer.actions))
	}
	for i, action := range observer.actions {
		if action.finished != 1 || len(action.response) != 0 {
			t.Fatalf("action %d finished %d times with response %q, want once and none", i, action.finished, action.response)
		}
	}
}
