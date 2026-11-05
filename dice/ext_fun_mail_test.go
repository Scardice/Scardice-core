package dice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gopkg.in/gomail.v2"

	"Scardice-core/eventstore"
)

// configureCanonicalTestMail stores the SMTP password as a secret value
// and commits the mail config with its vault reference, as production does.
func configureCanonicalTestMail(t *testing.T, d *Dice, mutate func(*Config)) {
	t.Helper()
	const ref = "vault:test-mail-password"
	secrets, ok := d.DurableStore.(eventstore.SecretRepository)
	if !ok {
		t.Fatal("canonical fixture store does not provide secrets")
	}
	if _, err := secrets.PutSecret(context.Background(), eventstore.SecretPutRequest{
		SecretRef: ref, EndpointID: "mail", AdapterID: "smtp", Value: []byte("synthetic-password"),
	}); err != nil {
		t.Fatalf("store mail password secret: %v", err)
	}
	config, _ := d.ConfigEditSnapshot()
	config.MailEnable = true
	config.MailFrom = "sender@example.com"
	config.MailSMTP = "smtp.invalid"
	if mutate != nil {
		mutate(&config)
	}
	passwordRef := ref
	if err := d.DurableCommitConfigSnapshot(context.Background(), config, config.CommandPrefix, config.DiceMasters, &passwordRef); err != nil {
		t.Fatalf("commit mail config: %v", err)
	}
}

func runSendCommandWithMailResult(t *testing.T, deliveryErr error) []string {
	t.Helper()
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	configureCanonicalTestMail(t, d, func(config *Config) {
		config.NoticeIDs = []string{"Mail:owner@example.com"}
	})
	mailCalls := 0
	d.mailSend = func(_ *gomail.Dialer, _ *gomail.Message) error {
		mailCalls++
		return deliveryErr
	}

	funExt, ok := d.ExtRegistry.Load("fun")
	if !ok || funExt.CmdMap["send"] == nil {
		t.Fatal("registered .send command is unavailable")
	}
	msg := newPrivateMsg("QQ:tester", ".send test message")
	ctx := newCanonicalTestMessageContext(t, d, ep, msg, "send-command")
	result := funExt.CmdMap["send"].Solve(ctx, msg, &CmdArgs{
		Args:      []string{"test", "message"},
		CleanArgs: "test message",
	})
	if !result.Matched || !result.Solved {
		t.Fatalf(".send result = %#v, want matched and solved", result)
	}
	if mailCalls != 1 {
		t.Fatalf("mail sender calls = %d, want one synthetic delivery", mailCalls)
	}
	if _, ok := adapter.waitForMsg(time.Second); !ok {
		t.Fatal("timed out waiting for the .send response")
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return append([]string(nil), adapter.personMsgs...)
}

func TestSendCommandReportsMailFailureInsteadOfSuccess(t *testing.T) {
	deliveryErr := errors.New("synthetic send-note delivery failure")
	replies := runSendCommandWithMailResult(t, deliveryErr)
	var reportedSuccess, reportedFailure bool
	for _, reply := range replies {
		reportedSuccess = reportedSuccess || strings.Contains(reply, "您的留言已被记录")
		reportedFailure = reportedFailure || strings.Contains(reply, "留言邮件发送失败")
	}
	if reportedSuccess || !reportedFailure {
		t.Fatalf(".send replies = %q, want delivery failure feedback and no recorded-success confirmation", replies)
	}
}

func TestSendCommandConfirmsOnlySuccessfulMail(t *testing.T) {
	replies := runSendCommandWithMailResult(t, nil)
	var reportedSuccess, reportedFailure bool
	for _, reply := range replies {
		reportedSuccess = reportedSuccess || strings.Contains(reply, "您的留言已被记录")
		reportedFailure = reportedFailure || strings.Contains(reply, "留言邮件发送失败")
	}
	if !reportedSuccess || reportedFailure {
		t.Fatalf(".send replies = %q, want recorded confirmation only after successful delivery", replies)
	}
}
