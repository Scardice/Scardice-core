package dice

import (
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/model"
)

func TestOfficialQQLegacyFingerprintDetectsSameCountDifferentRows(t *testing.T) {
	dbOperator, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "fingerprint.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dbOperator.Close)
	if err = dbOperator.db.AutoMigrate(&model.GroupInfo{}); err != nil {
		t.Fatal(err)
	}

	m := &officialQQIdentityMigration{
		appID:  "app",
		uin:    "1",
		groups: map[string]string{},
		users:  map[string]string{},
	}
	oldA := "OpenQQ-Group-T:app-a"
	oldB := "OpenQQ-Group-T:app-b"
	updatedAt := int64(1)
	if err = dbOperator.db.Create(&model.GroupInfo{
		ID: oldA, CreatedAt: 1, UpdatedAt: &updatedAt, Data: []byte(`{"groupId":"` + oldA + `"}`),
	}).Error; err != nil {
		t.Fatal(err)
	}
	countA, fpA, err := m.legacyRowFingerprint(dbOperator)
	if err != nil {
		t.Fatal(err)
	}
	if countA != 1 {
		t.Fatalf("count = %d, want 1", countA)
	}
	if err = dbOperator.db.Delete(&model.GroupInfo{}, "id = ?", oldA).Error; err != nil {
		t.Fatal(err)
	}
	if err = dbOperator.db.Create(&model.GroupInfo{
		ID: oldB, CreatedAt: 2, UpdatedAt: &updatedAt, Data: []byte(`{"groupId":"` + oldB + `"}`),
	}).Error; err != nil {
		t.Fatal(err)
	}
	countB, fpB, err := m.legacyRowFingerprint(dbOperator)
	if err != nil {
		t.Fatal(err)
	}
	if countB != countA {
		t.Fatalf("count changed unexpectedly: %d -> %d", countA, countB)
	}
	if fpB == fpA {
		t.Fatal("fingerprint did not change when the row identity changed")
	}
}

func TestOfficialQQEventQueueCloseDrainsAcceptedEvents(t *testing.T) {
	q := newOfficialQQEventQueue()
	ran := make(chan struct{})
	if !q.Enqueue(func() { close(ran) }) {
		t.Fatal("Enqueue() rejected the event")
	}
	q.Close()
	if !q.WaitForIdle(2 * time.Second) {
		t.Fatal("queue did not become idle")
	}
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("accepted event was dropped on Close")
	}
}

func TestOfficialQQEventQueueAbandonReleasesWaiter(t *testing.T) {
	q := newOfficialQQEventQueue()
	block := make(chan struct{})
	started := make(chan struct{})
	q.Enqueue(func() {
		close(started)
		<-block
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first event did not start")
	}

	result := make(chan error, 1)
	go func() {
		result <- q.EnqueueWait(func() {})
	}()
	time.Sleep(20 * time.Millisecond)
	q.Abandon()
	close(block)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("EnqueueWait returned success for an abandoned event")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EnqueueWait did not return after Abandon")
	}
}

func TestOfficialQQDispatchWebhookWaitsForHandler(t *testing.T) {
	q := newOfficialQQEventQueue()
	pa := &PlatformAdapterOfficialQQ{
		UseWebhook:          true,
		eventQueue:          q,
		eventQueueAccepting: true,
	}
	block := make(chan struct{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pa.dispatchOfficialQQEvent(func() {
			close(started)
			<-block
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("webhook event did not start")
	}
	select {
	case err := <-done:
		t.Fatalf("webhook dispatch returned before handler completion: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("webhook dispatch error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("webhook dispatch did not finish")
	}
	q.Close()
	q.WaitForIdle(2 * time.Second)
}

func TestOfficialQQDispatchWSWaitsForHandler(t *testing.T) {
	q := newOfficialQQEventQueue()
	pa := &PlatformAdapterOfficialQQ{
		eventQueue:          q,
		eventQueueAccepting: true,
	}
	block := make(chan struct{})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pa.dispatchOfficialQQEvent(func() {
			close(started)
			<-block
		})
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("WS event did not start")
	}
	select {
	case <-done:
		t.Fatal("WS dispatch returned before handler completion")
	case <-time.After(50 * time.Millisecond):
	}
	close(block)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WS dispatch error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WS dispatch did not finish")
	}
	q.Close()
	q.WaitForIdle(2 * time.Second)
}
