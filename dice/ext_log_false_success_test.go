package dice

import (
	"errors"
	"os"
	"strings"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/logger"
	"Scardice-core/model"
	"Scardice-core/utils/constant"

	"gopkg.in/gomail.v2"
)

func runLogExportWithMockFileResult(t *testing.T, groupID string, fileResult *adapterapi.EffectResult) (files []string, replies []string, fileDir string) {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	fileDir = t.TempDir()
	t.Setenv("TMPDIR", fileDir)
	adapter.fileResult = fileResult
	if err := d.DBOperator.GetLogDB(constant.WRITE).AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatalf("AutoMigrate log fixtures: %v", err)
	}
	if !LogAppend(&MsgContext{Dice: d}, groupID, 0, "local-story", &model.LogOneItem{
		Nickname: "Tester",
		IMUserID: "QQ:tester",
		Message:  "local log fixture",
	}) {
		t.Fatal("LogAppend failed for local fixture")
	}

	ctx := &MsgContext{
		Dice:        d,
		EndPoint:    ep,
		Session:     d.ImSession,
		MessageType: "group",
		Group:       &GroupInfo{GroupID: groupID},
		Player:      &GroupPlayerInfo{Name: "Tester"},
	}
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok || logExt.CmdMap["log"] == nil {
		t.Fatal("registered .log command is unavailable")
	}
	msg := newGroupMsg(groupID, "QQ:tester", ".log export local-story")
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

func TestLogExportReportsSuccessAfterAdapterAcceptance(t *testing.T) {
	accepted := adapterapi.SucceededResult("synthetic-upload-id")
	files, replies, fileDir := runLogExportWithMockFileResult(t, "QQ-Group:log-export-accepted", &accepted)
	if len(files) != 1 || !strings.HasPrefix(files[0], "file://") {
		t.Fatalf("legacy file-send dispatches = %v, want one synthetic file:// export", files)
	}

	var reportedFailure, reportedSuccess bool
	for _, reply := range replies {
		reportedFailure = reportedFailure || strings.Contains(reply, "文件发送不可用") || strings.Contains(reply, "导出失败") || strings.Contains(reply, "未确认")
		reportedSuccess = reportedSuccess || strings.Contains(reply, "成功") || strings.Contains(reply, "已导出") || strings.Contains(reply, "已上传")
	}
	if reportedFailure || !reportedSuccess {
		t.Fatalf(".log export replies = %q, want success only after adapter acceptance", replies)
	}

	entries, err := os.ReadDir(fileDir)
	if err != nil {
		t.Fatalf("ReadDir local file fixture: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary export fixture was not cleaned up: %v", entries)
	}
}

func TestLogExportDoesNotReportSuccessWithoutFileAcknowledgement(t *testing.T) {
	files, replies, _ := runLogExportWithMockFileResult(t, "QQ-Group:log-export-no-ack", nil)
	if len(files) != 1 {
		t.Fatalf("legacy file-send dispatches = %v, want exactly one synthetic adapter call", files)
	}
	var reportedFailure, reportedSuccess bool
	for _, reply := range replies {
		reportedFailure = reportedFailure || strings.Contains(reply, "未确认") || strings.Contains(reply, "导出失败")
		reportedSuccess = reportedSuccess || strings.Contains(reply, "成功") || strings.Contains(reply, "已导出") || strings.Contains(reply, "已上传")
	}
	if reportedSuccess || !reportedFailure {
		t.Fatalf(".log export replies = %q, want no success claim and an explicit unconfirmed/failure result", replies)
	}
}

func TestLogExportDoesNotReportSuccessWhenAdapterUnsupported(t *testing.T) {
	unsupported := adapterapi.UnsupportedResult("mock_file_send_unsupported")
	files, replies, _ := runLogExportWithMockFileResult(t, "QQ-Group:log-export-unsupported", &unsupported)
	if len(files) != 1 {
		t.Fatalf("legacy file-send dispatches = %v, want exactly one synthetic adapter call", files)
	}
	var reportedFailure, reportedSuccess bool
	for _, reply := range replies {
		reportedFailure = reportedFailure || strings.Contains(reply, "不支持") || strings.Contains(reply, "导出失败")
		reportedSuccess = reportedSuccess || strings.Contains(reply, "成功") || strings.Contains(reply, "已导出") || strings.Contains(reply, "已上传")
	}
	if reportedSuccess || !reportedFailure {
		t.Fatalf(".log export replies = %q, want no success claim and explicit unsupported result", replies)
	}
}

func TestLogExportDoesNotReportEmailSuccessWhenDeliveryFails(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	fileDir := t.TempDir()
	t.Setenv("TMPDIR", fileDir)

	groupID := "QQ-Group:log-export-mail-failure"
	if err := d.DBOperator.GetLogDB(constant.WRITE).AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatalf("AutoMigrate log fixtures: %v", err)
	}
	if !LogAppend(&MsgContext{Dice: d}, groupID, 0, "local-story", &model.LogOneItem{
		Nickname: "Tester",
		IMUserID: "QQ:tester",
		Message:  "local log fixture",
	}) {
		t.Fatal("LogAppend failed for local fixture")
	}

	d.Config.MailFrom = "sender@example.com"
	d.Config.MailPassword = "synthetic-password"
	d.Config.MailSMTP = "smtp.invalid"
	deliveryErr := errors.New("synthetic delivery failure")
	mailCalls := 0
	d.mailSend = func(_ *gomail.Dialer, _ *gomail.Message) error {
		mailCalls++
		return deliveryErr
	}

	ctx := &MsgContext{
		Dice:        d,
		EndPoint:    ep,
		Session:     d.ImSession,
		MessageType: "group",
		Group:       &GroupInfo{GroupID: groupID},
		Player:      &GroupPlayerInfo{Name: "Tester"},
	}
	logExt, ok := d.ExtRegistry.Load("log")
	if !ok || logExt.CmdMap["log"] == nil {
		t.Fatal("registered .log command is unavailable")
	}
	msg := newGroupMsg(groupID, "QQ:tester", ".log export local-story recipient@example.com")
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
	d := &Dice{
		Logger: logger.M(),
		Config: Config{
			BaseConfig: BaseConfig{NoticeIDs: []string{"Mail:recipient@example.com"}},
			MailConfig: MailConfig{
				MailFrom:     "sender@example.com",
				MailPassword: "synthetic-password",
				MailSMTP:     "smtp.invalid",
			},
		},
	}
	deliveryErr := errors.New("synthetic delivery failure")
	d.mailSend = func(_ *gomail.Dialer, _ *gomail.Message) error {
		return deliveryErr
	}

	if err := d.SendMail("synthetic body", MailTest); !errors.Is(err, deliveryErr) {
		t.Fatalf("SendMail error = %v, want delivery error %v", err, deliveryErr)
	}
}
