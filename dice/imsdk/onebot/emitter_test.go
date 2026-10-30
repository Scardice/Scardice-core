//nolint:testpackage // Tests intentionally cover internal error-wrapping helpers.
package emitter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bytedance/sonic"
)

func TestResponseUnmarshalReadsStandardRetcode(t *testing.T) {
	var resp Response[sonic.NoCopyRawMessage]
	if err := sonic.Unmarshal([]byte(`{"status":"failed","retcode":100,"data":{"message":"boom"},"echo":"echo-1"}`), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if resp.Status != "failed" {
		t.Fatalf("status = %q, want failed", resp.Status)
	}
	if resp.RetCode != 100 {
		t.Fatalf("retcode = %d, want 100", resp.RetCode)
	}
	if string(resp.Data) != `{"message":"boom"}` {
		t.Fatalf("data = %s, want payload preserved", resp.Data)
	}
	if resp.Echo != "echo-1" {
		t.Fatalf("echo = %q, want echo-1", resp.Echo)
	}
}

func TestWrapActionErrorTimeoutIncludesChineseContext(t *testing.T) {
	err := wrapActionError(context.DeadlineExceeded, ACTION_SET_FRIEND_ADD_REQUEST, "echo-timeout", map[string]any{
		"flag":    "friend-flag",
		"approve": true,
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "等待 OneBot Echo 超时") {
		t.Fatalf("expected timeout message in %q", msg)
	}
	if !strings.Contains(msg, "set_friend_add_request") {
		t.Fatalf("expected action in %q", msg)
	}
	if !strings.Contains(msg, "echo-timeout") {
		t.Fatalf("expected echo id in %q", msg)
	}
	if !strings.Contains(msg, `"flag":"friend-flag"`) {
		t.Fatalf("expected params in %q", msg)
	}
}

func TestDecodeResponseFailedStatusIncludesRequestAndResponse(t *testing.T) {
	resp := Response[sonic.NoCopyRawMessage]{
		Status:  "failed",
		RetCode: 1401,
		Data:    sonic.NoCopyRawMessage(`{"message":"denied"}`),
		Echo:    "echo-failed",
	}

	_, err := decodeResponse[map[string]any](ACTION_SET_GROUP_ADD_REQUEST, "echo-failed", map[string]any{
		"flag":     "group-flag",
		"sub_type": "invite",
		"approve":  false,
	}, resp)
	if err == nil {
		t.Fatal("expected failed-status error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "OneBot 动作执行失败") {
		t.Fatalf("expected failed-status message in %q", msg)
	}
	if !strings.Contains(msg, `"sub_type":"invite"`) {
		t.Fatalf("expected request params in %q", msg)
	}
	if !strings.Contains(msg, `"retcode":1401`) {
		t.Fatalf("expected response retcode in %q", msg)
	}
	if !strings.Contains(msg, `"message":"denied"`) {
		t.Fatalf("expected response data in %q", msg)
	}
}

func TestDecodeResponseDecodeFailureIncludesRawResponse(t *testing.T) {
	resp := Response[sonic.NoCopyRawMessage]{
		Status:  "ok",
		RetCode: 0,
		Data:    sonic.NoCopyRawMessage(`{"group_id":"bad-int"}`),
		Echo:    "echo-decode",
	}

	_, err := decodeResponse[struct {
		GroupID int64 `json:"group_id"`
	}](ACTION_GET_GROUP_INFO, "echo-decode", map[string]any{
		"group_id": 12345,
		"no_cache": true,
	}, resp)
	if err == nil {
		t.Fatal("expected decode error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "解析 OneBot 响应失败") {
		t.Fatalf("expected decode message in %q", msg)
	}
	if !strings.Contains(msg, `"group_id":"bad-int"`) {
		t.Fatalf("expected raw response in %q", msg)
	}
	if !strings.Contains(msg, `"group_id":12345`) {
		t.Fatalf("expected request params in %q", msg)
	}
}
func TestDecodeResponseRejectsUnknownOrEmptyStatus(t *testing.T) {
	for _, status := range []string{"", "pending", "unknown"} {
		t.Run(status, func(t *testing.T) {
			resp := Response[sonic.NoCopyRawMessage]{Status: status, RetCode: 0, Data: sonic.NoCopyRawMessage(`{}`)}
			if _, err := decodeResponse[map[string]any](ACTION_GET_STATUS, "echo-status", nil, resp); err == nil {
				t.Fatalf("status %q was accepted", status)
			}
		})
	}
}

func TestWaitEchoAfterSendTimeoutWrapsActionContext(t *testing.T) {
	oldTimeout := EchoTimeOut
	EchoTimeOut = 10 * time.Millisecond
	defer func() {
		EchoTimeOut = oldTimeout
	}()

	e := &emitterSocket{}
	_, err := e.waitEchoAfterSend(t.Context(), ACTION_GET_GROUP_INFO, "echo-timeout-2", map[string]any{
		"group_id": 12345,
	}, func() error {
		return nil
	})
	if err == nil {
		t.Fatal("expected timeout")
	}

	msg := err.Error()
	if !strings.Contains(msg, "等待 OneBot Echo 超时") {
		t.Fatalf("expected timeout message in %q", msg)
	}
	if !strings.Contains(msg, "get_group_info") {
		t.Fatalf("expected action in %q", msg)
	}
}

func TestWrapActionErrorIncludesOriginalFailure(t *testing.T) {
	err := wrapActionError(errors.New("write failed"), ACTION_SET_GROUP_ADD_REQUEST, "echo-send", map[string]any{
		"flag":     "group-flag",
		"sub_type": "invite",
	})
	if err == nil {
		t.Fatal("expected wrapped error")
	}

	msg := err.Error()
	if !strings.Contains(msg, "write failed") {
		t.Fatalf("expected original error in %q", msg)
	}
	if !strings.Contains(msg, `"sub_type":"invite"`) {
		t.Fatalf("expected params in %q", msg)
	}
}
func TestDecodeResponseMarksRejectedAction(t *testing.T) {
	resp := Response[sonic.NoCopyRawMessage]{
		Status:  "failed",
		RetCode: 1401,
		Data:    sonic.NoCopyRawMessage(`{"message":"denied"}`),
		Echo:    "echo-rejected",
	}
	_, err := decodeResponse[map[string]any](ACTION_SEND_PRIVATE_MSG, "echo-rejected", nil, resp)
	if err == nil {
		t.Fatal("expected failed action response")
	}
	var rejected interface{ IsActionRejected() }
	if !errors.As(err, &rejected) {
		t.Fatalf("failed action error %T lacks action-rejected classification", err)
	}
}
func TestDecodeResponseOnlyMarksExplicitActionRejections(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		retcode      int
		wantRejected bool
	}{
		{name: "failed status", status: "failed", wantRejected: true},
		{name: "nonzero retcode", status: "ok", retcode: 1401, wantRejected: true},
		{name: "empty status", wantRejected: false},
		{name: "pending status", status: "pending", wantRejected: false},
		{name: "unknown status", status: "unknown", wantRejected: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := Response[sonic.NoCopyRawMessage]{
				Status:  test.status,
				RetCode: test.retcode,
				Data:    sonic.NoCopyRawMessage(`{}`),
				Echo:    "echo-classification",
			}
			_, err := decodeResponse[map[string]any](ACTION_SEND_PRIVATE_MSG, "echo-classification", nil, resp)
			if err == nil {
				t.Fatal("expected non-success response error")
			}
			var rejected interface{ IsActionRejected() }
			gotRejected := errors.As(err, &rejected)
			if gotRejected != test.wantRejected {
				t.Fatalf("action-rejected classification = %v, want %v; error=%v", gotRejected, test.wantRejected, err)
			}
		})
	}
}

func TestDecodeResponseLeavesSuccessfulMissingMessageIDForAdapterClassification(t *testing.T) {
	resp := Response[sonic.NoCopyRawMessage]{
		Status:  "ok",
		RetCode: 0,
		Data:    sonic.NoCopyRawMessage(`{}`),
		Echo:    "echo-missing-id",
	}
	result, err := decodeResponse[struct {
		MessageID int64 `json:"message_id"`
	}](ACTION_SEND_PRIVATE_MSG, "echo-missing-id", nil, resp)
	if err != nil {
		t.Fatalf("decode successful response without message ID: %v", err)
	}
	if result == nil || result.MessageID != 0 {
		t.Fatalf("decoded result = %#v, want a decoded response with no message ID", result)
	}
}
