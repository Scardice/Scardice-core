package dice

import (
	"errors"
	"os"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/model"

	"gopkg.in/gomail.v2"
)

// runLogExport runs `.log export` inside a canonical durable root. A durable
// root never hands an unpersisted file path to a platform adapter, so the
// adapter must see no file-send dispatch.
func runLogExport(t *testing.T, groupID string) (files []string, replies []string, fileDir string) {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	fileDir = t.TempDir()
	t.Setenv("TMPDIR", fileDir)
	accepted := adapterapi.SucceededResult("synthetic-upload-id")
	adapter.fileResult = &accepted
	useCanonicalTestStoryLogRepository(t, d)
	seedCanonicalTestStoryLog(t, d, groupID, "local-story", &model.LogOneItem{
		Nickname: "Tester",
		IMUserID: "QQ:tester",
		Message:  "local log fixture",
	})

	msg := newGroupMsg(groupID, "QQ:tester", ".log export local-story")
	ctx := newCanonicalTestMessageContext(t, d, ep, msg, "log-export")
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok || logExt.CmdMap["log"] == nil {
		t.Fatal("registered .log command is unavailable")
	}
	result := logExt.CmdMap["log"].Solve(ctx, msg, &CmdArgs{Args: []string{"export", "local-story"}, RawArgs: "export local-story"})
	if !result.Matched || !result.Solved {
		t.Fatalf(".log export result = %#v, want matched and solved", result)
	}

	adapter.mu.Lock()
	files = append([]string(nil), adapter.files...)
	replies = append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	return files, replies, fileDir
}

func TestLogExportDoesNotReportSuccessWhenDurableRootRefusesFileSend(t *testing.T) {
	files, replies, fileDir := runLogExport(t, "QQ-Group:log-export-durable-refusal")
	if len(files) != 0 {
		t.Fatalf("file-send dispatches = %v, want none: a durable root must not send unpersisted file paths", files)
	}
	var reportedFailure, reportedSuccess bool
	for _, reply := range replies {
		reportedFailure = reportedFailure || strings.Contains(reply, "文件发送不可用") || strings.Contains(reply, "导出失败")
		reportedSuccess = reportedSuccess || strings.Contains(reply, "成功") || strings.Contains(reply, "已导出") || strings.Contains(reply, "已上传")
	}
	if reportedSuccess || !reportedFailure {
		t.Fatalf(".log export replies = %q, want an explicit failure and no success claim", replies)
	}

	entries, err := os.ReadDir(fileDir)
	if err != nil {
		t.Fatalf("ReadDir local file fixture: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary export fixture was not cleaned up: %v", entries)
	}
}

func TestLogExportDoesNotReportEmailSuccessWhenDeliveryFails(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	fileDir := t.TempDir()
	t.Setenv("TMPDIR", fileDir)

	groupID := "QQ-Group:log-export-mail-failure"
	useCanonicalTestStoryLogRepository(t, d)
	seedCanonicalTestStoryLog(t, d, groupID, "local-story", &model.LogOneItem{
		Nickname: "Tester",
		IMUserID: "QQ:tester",
		Message:  "local log fixture",
	})

	configureCanonicalTestMail(t, d, nil)
	deliveryErr := errors.New("synthetic delivery failure")
	mailCalls := 0
	d.mailSend = func(_ *gomail.Dialer, _ *gomail.Message) error {
		mailCalls++
		return deliveryErr
	}

	msg := newGroupMsg(groupID, "QQ:tester", ".log export local-story recipient@example.com")
	ctx := newCanonicalTestMessageContext(t, d, ep, msg, "log-export-mail")
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok || logExt.CmdMap["log"] == nil {
		t.Fatal("registered .log command is unavailable")
	}
	result := logExt.CmdMap["log"].Solve(ctx, msg, &CmdArgs{
		Args:    []string{"export", "local-story", "recipient@example.com"},
		RawArgs: "export local-story recipient@example.com",
	})
	if !result.Matched || !result.Solved {
		t.Fatalf(".log export result = %#v, want matched and solved", result)
	}
	if mailCalls != 1 {
		t.Fatalf("mail sender calls = %d, want one synthetic failed delivery", mailCalls)
	}

	adapter.mu.Lock()
	replies := append([]string(nil), adapter.groupMsgs...)
	adapter.mu.Unlock()
	var reportedSuccess, reportedFailure bool
	for _, reply := range replies {
		reportedSuccess = reportedSuccess || strings.Contains(reply, "已向以下邮箱发送记录邮件")
		reportedFailure = reportedFailure || strings.Contains(reply, deliveryErr.Error())
	}
	if reportedSuccess || !reportedFailure {
		t.Fatalf(".log export replies = %q, want delivery failure and no email success claim", replies)
	}
}

func TestSendMailPropagatesDeliveryFailure(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	configureCanonicalTestMail(t, d, func(config *Config) {
		config.NoticeIDs = []string{"Mail:recipient@example.com"}
	})
	deliveryErr := errors.New("synthetic delivery failure")
	d.mailSend = func(_ *gomail.Dialer, _ *gomail.Message) error {
		return deliveryErr
	}

	if err := d.SendMail("synthetic body", MailTest); !errors.Is(err, deliveryErr) {
		t.Fatalf("SendMail error = %v, want delivery error %v", err, deliveryErr)
	}
}
