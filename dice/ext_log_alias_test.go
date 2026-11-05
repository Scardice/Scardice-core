//nolint:testpackage
package dice

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
	"Scardice-core/model"
)

// useCanonicalTestStoryLogRepository binds d's log repository to the real
// EventStore story-log archive of its durable store.
func useCanonicalTestStoryLogRepository(t *testing.T, d *Dice) {
	t.Helper()
	archive, ok := d.DurableStore.(eventstore.LogRepository)
	if !ok {
		t.Fatal("canonical fixture store does not provide the story-log archive")
	}
	d.LogRepository = service.NewEventStoreLogRepository(archive, d.BaseConfig.Name)
}

// newCanonicalTestLogDice returns a canonical Dice whose log repository reads
// the real EventStore story-log archive.
func newCanonicalTestLogDice(t *testing.T) *Dice {
	t.Helper()
	d, _ := newCanonicalTestDice(t)
	useCanonicalTestStoryLogRepository(t, d)
	return d
}

// seedCanonicalTestStoryLog appends one entry to a story log through the same
// LogAppend path production uses, and commits it in its own root.
func seedCanonicalTestStoryLog(t *testing.T, d *Dice, groupID, logName string, item *model.LogOneItem) {
	t.Helper()
	endpoint := newCanonicalTestEndpoint(d, "UI:1000")
	label := fmt.Sprintf("seed-story-log-%d", canonicalTestMessageSequence.Add(1))
	withCanonicalTestMessageContext(t, d, endpoint, newPrivateMsg("UI:log-seed", ""), label, func(ctx *MsgContext) error {
		if !LogAppend(ctx, groupID, 0, logName, item) {
			return errors.New("LogAppend failed for " + strconv.Quote(logName))
		}
		return nil
	})
}

func appendTestLog(t *testing.T, d *Dice, groupID, logName string) {
	t.Helper()
	seedCanonicalTestStoryLog(t, d, groupID, logName, &model.LogOneItem{
		Nickname: "tester",
		IMUserID: "user",
		Message:  "line",
	})
}

func TestBuildLogNameAliasIndexUsesWrappedKeysAndResolvesInput(t *testing.T) {
	d := newCanonicalTestLogDice(t)
	groupID := "QQ-Group:1001"

	appendTestLog(t, d, groupID, "normal-log")
	appendTestLog(t, d, groupID, " spaced\nname ")

	index, err := buildLogNameAliasIndex(d.LogRepository, groupID)
	if err != nil {
		t.Fatalf("buildLogNameAliasIndex: %v", err)
	}
	if len(index.entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(index.entries))
	}

	for _, entry := range index.entries {
		if len(entry.Key) < 8 {
			t.Fatalf("key %q shorter than 8 chars", entry.Key)
		}
		if entry.Name == "normal-log" {
			if got, ok := index.Resolve(entry.Key); !ok || got != entry.Name {
				t.Fatalf("Resolve(%q) = (%q, %v), want (%q, true)", entry.Key, got, ok, entry.Name)
			}
		}
	}

	if got := formatLogNameForDisplay(" spaced\nname "); got != strconv.Quote(" spaced\nname ") {
		t.Fatalf("formatLogNameForDisplay() = %q", got)
	}
	if got := formatLogNameListLine(logNameAliasEntry{Key: "deadbeef", Name: "normal-log"}); got != "- 【deadbeef】: normal-log" {
		t.Fatalf("formatLogNameListLine() = %q", got)
	}
}

func TestBuildLogNameAliasEntriesExtendsConflictingPrefixes(t *testing.T) {
	buckets := map[byte][]string{}
	for i := range 4096 {
		name := fmt.Sprintf("log-%d", i)
		hash := logNameHashHex(name)
		prefix := hash[0]
		buckets[prefix] = append(buckets[prefix], name)
		if len(buckets[prefix]) >= 2 {
			break
		}
	}

	var names []string
	for _, candidates := range buckets {
		if len(candidates) >= 2 {
			names = candidates[:2]
			break
		}
	}
	if len(names) != 2 {
		t.Fatal("failed to generate colliding 1-char hash prefixes")
	}

	entries, err := buildLogNameAliasEntries(names, 1)
	if err != nil {
		t.Fatalf("buildLogNameAliasEntries: %v", err)
	}

	keys := map[string]struct{}{}
	grew := false
	for _, entry := range entries {
		if _, exists := keys[entry.Key]; exists {
			t.Fatalf("duplicate key %q", entry.Key)
		}
		keys[entry.Key] = struct{}{}
		if len(entry.Key) > 1 {
			grew = true
		}
	}
	if !grew {
		t.Fatal("expected at least one conflicting prefix to grow beyond min length")
	}
}

func TestResolveLogNameForGroupPrefersExactNameBeforeAlias(t *testing.T) {
	d := newCanonicalTestLogDice(t)
	groupID := "QQ-Group:1002"

	appendTestLog(t, d, groupID, "abcdef12")
	appendTestLog(t, d, groupID, "other-log")

	index, err := buildLogNameAliasIndex(d.LogRepository, groupID)
	if err != nil {
		t.Fatalf("buildLogNameAliasIndex: %v", err)
	}

	var alias string
	for _, entry := range index.entries {
		if entry.Name == "other-log" {
			alias = entry.Key
			break
		}
	}
	if alias == "" {
		t.Fatal("expected alias for other-log")
	}
	if strings.EqualFold(alias, "abcdef12") {
		t.Fatal("test setup produced ambiguous exact-name collision")
	}

	got, err := resolveLogNameForGroup(d.LogRepository, groupID, "abcdef12")
	if err != nil {
		t.Fatalf("resolveLogNameForGroup exact: %v", err)
	}
	if got != "abcdef12" {
		t.Fatalf("resolve exact = %q, want %q", got, "abcdef12")
	}
}

func TestLogSendToBackendAcceptsAliasKey(t *testing.T) {
	d := newCanonicalTestLogDice(t)
	groupID := "QQ-Group:1003"
	logName := "special name"
	appendTestLog(t, d, groupID, logName)

	index, err := buildLogNameAliasIndex(d.LogRepository, groupID)
	if err != nil {
		t.Fatalf("buildLogNameAliasIndex: %v", err)
	}
	var alias string
	for _, entry := range index.entries {
		if entry.Name == logName {
			alias = entry.Key
			break
		}
	}
	if alias == "" {
		t.Fatal("expected alias for special name")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dice/api/log" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if parseErr := r.ParseMultipartForm(1 << 20); parseErr != nil {
			t.Fatalf("ParseMultipartForm: %v", parseErr)
		}
		if got := r.FormValue("name"); got != logName {
			t.Fatalf("uploaded name = %q, want %q", got, logName)
		}
		_, _ = w.Write([]byte(`{"url":"https://example.com/log"}`))
	}))
	defer server.Close()

	oldBackends := BackendUrls
	BackendUrls = []string{server.URL}
	t.Cleanup(func() { BackendUrls = oldBackends })

	endpoint := newCanonicalTestEndpoint(d, "UI:1000")
	ctx := newCanonicalTestMessageContext(
		t, d, endpoint, newPrivateMsg("UI:log-alias-user", ""), "log-send-backend",
	)

	unofficial, url, notice, err := LogSendToBackend(ctx, groupID, alias)
	if err != nil {
		t.Fatalf("LogSendToBackend: %v", err)
	}
	if unofficial {
		t.Fatal("expected official backend path")
	}
	if notice != "" {
		t.Fatalf("unexpected notice %q", notice)
	}
	if url != "https://example.com/log" {
		t.Fatalf("url = %q", url)
	}
}

func TestLogListWithoutDatabaseOperatorReportsUnavailableStorage(t *testing.T) {
	d, ep, adapter, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	const groupID = "UI-Group:9001"
	_, _ = newQuitCommandTestContext(t, d, ep, "QQ:9001", groupID, "EventSourceGroup")
	d.DBOperator = nil

	executeNewAndWaitForCanonicalCommit(t, d, ep, newGroupMsg(groupID, "QQ:9001", ".log list"))

	reply, ok := adapter.waitForMsg(2 * time.Second)
	if !ok {
		t.Fatal("timeout: expected a reply to '.log list'")
	}
	if !strings.Contains(reply, "日志存储未初始化") || !strings.Contains(reply, "当前存储模式不可用") {
		t.Fatalf("reply = %q, want an explicit unavailable-log-storage explanation", reply)
	}
}
