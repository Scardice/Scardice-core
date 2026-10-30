package eventsourcing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	mysql "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	ds "github.com/sealdice/dicescript"
	"github.com/tidwall/buntdb"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type remoteBanQueryFailure struct {
	calls int
	err   error
}

func (q *remoteBanQueryFailure) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	q.calls++
	return nil, q.err
}

func TestRemoteBanRowsPropagatesColumnPermissionErrors(t *testing.T) {
	failures := []error{
		&mysql.MySQLError{Number: 1143, Message: "SELECT command denied for column ban_updated_at"},
		&pgconn.PgError{Code: "42501", Message: "permission denied for column ban_updated_at"},
	}
	for _, failure := range failures {
		queryer := &remoteBanQueryFailure{err: failure}
		rows, hasUpdatedAt, err := queryRemoteBanRows(context.Background(), queryer)
		if rows != nil {
			defer rows.Close()
			if rowsErr := rows.Err(); rowsErr != nil {
				t.Errorf("unexpected rows error: %v", rowsErr)
			}
		}
		if !errors.Is(err, failure) || rows != nil || hasUpdatedAt || queryer.calls != 1 {
			t.Fatalf("permission query result=%v,%v,%v calls=%d; want propagated error without fallback", rows, hasUpdatedAt, err, queryer.calls)
		}
	}
}

func TestRemoteBanRowsFallsBackWhenOptionalColumnIsAbsent(t *testing.T) {
	database, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = database.Exec("CREATE TABLE ban_info (id TEXT, data BLOB)"); err != nil {
		t.Fatal(err)
	}

	rows, hasUpdatedAt, err := queryRemoteBanRows(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if hasUpdatedAt || !slices.Equal(columns, []string{"id", "data"}) {
		t.Fatalf("legacy ban columns=%v hasUpdatedAt=%v; want id,data without timestamp", columns, hasUpdatedAt)
	}
}

func TestPendingLegacyMigrationsUsesLatestAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	writeLegacyFixtureFile(t, path, []byte(`[
		{"id":"failed-then-retried","success":false},
		{"id":"still-failed","success":true},
		{"id":"failed-then-retried","success":true},
		{"id":"still-failed","success":false}
	]`))
	pending, err := pendingLegacyMigrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0] != "still-failed" {
		t.Fatalf("pending migrations = %#v", pending)
	}
}

func TestLegacyBuiltinMilkyConfigCarriesAccountIdentity(t *testing.T) {
	key, raw, secrets, err := legacyEndpointConfig(
		"default",
		adapterapi.EndpointID("legacy-milky"),
		"QQ",
		"milky",
		"QQ:12345",
		map[string]any{"built_in_mode": "yogurt"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if key != dice.MilkyAdapterKey || len(secrets) != 0 {
		t.Fatalf("legacy built-in Milky conversion = key %q secrets=%d", key, len(secrets))
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["account"] != "QQ:12345" {
		t.Fatalf("legacy built-in Milky account = %#v", payload["account"])
	}
	config, err := dice.NewMilkyDescriptor().ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("legacy built-in Milky config rejected: %v", err)
	}
	if !strings.Contains(string(config.Canonical), `"account":"12345"`) {
		t.Fatalf("canonical built-in Milky config = %s", config.Canonical)
	}
}

func TestLegacySourceImportsStoppedYAMLSQLiteAndBuntDB(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	dataDir := filepath.Join(root, "default")
	if err := os.MkdirAll(filepath.Join(dataDir, "extensions", "test-ext"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte(`
diceConfigs:
  - name: default
    dataDir: default
serveAddress: 127.0.0.1:4321
trayTooltip: Legacy Dice
helpDocEngineType: 2
diceRandomMode: crypto
UIPasswordFrontendSalt: legacy-salt
uiPasswordHash: legacy-hash
accessTokens: [legacy-token]
autoBackupEnable: true
autoBackupTime: "@every 1h"
autoBackupSelection: 7
backupClean:
  strategy: 1
  keepCount: 3
  keepDur: 4
  trigger: 2
  cron: "@daily"
serviceName: legacy-service
configVersion: 9914
`))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "serve.yaml"), []byte(`
commandPrefix: [".", "!"]
diceMasters: ["QQ:master"]
mailEnable: true
mailFrom: bot@example.test
mailPassword: mail-secret
mailSmtp: smtp.example.test
extDefaultSettings:
  - name: coc7
    autoActive: true
    disabledCommand: {st: true}
imSession:
  endPoints:
    - baseInfo:
        id: legacy-onebot
        nickname: Legacy Bot
        platform: QQ
        protocolType: pureonebot
        enable: true
        isPublic: true
        userId: QQ:12345
        groupNum: 7
        cmdExecutedNum: 42
        cmdExecutedLastTime: 12345
        onlineTotalTime: 678
      adapter:
        mode: client
        connectUrl: ws://127.0.0.1:6700
        token: endpoint-secret
`))
	writeLegacyFixtureFile(t, filepath.Join(dataDir, "advanced.yaml"), []byte(`
show: true
enable: true
storyLogBackendUrl: https://story.example.test
storyLogApiVersion: v1
storyLogBackendToken: story-secret
customReplyCooldown: 3
`))
	createLegacySQLiteFixture(t, filepath.Join(dataDir, "data.db"))
	buntPath := filepath.Join(dataDir, "extensions", "test-ext", "storage.db")
	bunt, err := buntdb.Open(buntPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = bunt.Update(func(transaction *buntdb.Tx) error {
		if _, _, setErr := transaction.Set("campaign", `{"round":7}`, nil); setErr != nil {
			return setErr
		}
		_, _, setErr := transaction.Set("", "[object Object]", nil)
		return setErr
	}); err != nil {
		t.Fatal(err)
	}
	if err = bunt.Close(); err != nil {
		t.Fatal(err)
	}

	source := NewLegacySourceWithKeySource(root, sqliteTargetKeySource{})
	inventory, err := source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	streamed := 0
	if err = source.StreamRecords(ctx, func(batch []SourceRecord) error {
		streamed += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !inventory.LegacyOwnershipComplete || inventory.Kind != SourceKindLegacy || len(inventory.Records) != 0 || streamed < 8 {
		t.Fatalf("legacy inventory/stream = %#v/%d", inventory, streamed)
	}
	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "events.db"), sqliteTargetKeySource{})
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "old-index"}},
		Source:    source, Target: target, SnapshotRoot: filepath.Join(t.TempDir(), "snapshot"), TargetIdentity: "legacy-smoke",
	}).Run(ctx, Request{Mode: ModeImport})
	if err != nil {
		t.Fatal(err)
	}
	if result.Batches == 0 || len(result.ManifestDigest) != 32 {
		t.Fatalf("import result = %#v", result)
	}
	if err = target.Reopen(ctx); err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	endpointState, err := endpoint.NewRepository(target.store).Load(ctx, "legacy-onebot")
	if err != nil {
		t.Fatalf("load imported endpoint aggregate: %v", err)
	}
	if endpointState.DisplayName != "Legacy Bot" || endpointState.ProviderID != "QQ:12345" ||
		endpointState.Statistics != (endpoint.Statistics{GroupCount: 7, CommandCount: 84, LastCommandAt: 12345, OnlineSeconds: 789}) {
		t.Fatalf("imported endpoint identity and statistics = %#v", endpointState)
	}

	manager, err := managerstate.ReadProjected(ctx, target.store)
	if err != nil || manager.Public.ServeAddress != "127.0.0.1:4321" ||
		manager.Public.TrayTooltip != "Legacy Dice" || manager.Public.ServiceName != "legacy-service" ||
		manager.Public.DiceDataDirs["default"] != "default" {
		t.Fatalf("projected manager = %#v, err=%v", manager, err)
	}
	managerSecret, err := target.store.ResolveSecret(ctx, manager.AuthSecretRef, manager.AuthSecretVersion)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := managerstate.DecodeAuth(managerSecret.Plaintext)
	if err != nil || auth.UIPasswordSalt != "legacy-salt" || auth.UIPasswordHash != "legacy-hash" || len(auth.AccessTokens) != 1 || auth.AccessTokens[0] != "legacy-token" {
		t.Fatalf("manager auth = %#v, err=%v", auth, err)
	}
	config, err := configstate.ReadProjected(ctx, target.store, "default")
	if err != nil || config.Mail.MailPasswordRef != "vault:legacy-default-mail" ||
		config.Advanced.StoryLogBackendTokenRef != "vault:legacy-default-story-log" ||
		len(config.PublicDice.EndpointIDs) != 1 || config.PublicDice.EndpointIDs[0] != "legacy-onebot" {
		t.Fatalf("projected config = %#v, err=%v", config, err)
	}
	extensions, err := extensionstate.ReadProjected(ctx, target.store, "default")
	if err != nil || !extensions.EnabledExtensions["coc7"] || !extensions.DefaultCommands["coc7"].DisabledCommands["st"] {
		t.Fatalf("projected extensions = %#v, err=%v", extensions, err)
	}
	group, err := groupstate.ReadProjected(ctx, target.store, "default", "QQ-Group:100")
	if err != nil || group.GroupName != "Legacy Group" || !group.DiceIDActive["QQ:bot"] || group.System != "coc7" {
		t.Fatalf("projected group = %#v, err=%v", group, err)
	}
	player, err := playerstate.ReadProjectedPlayer(ctx, target.store, "default", "QQ-Group:100", "QQ:200")
	if err != nil || player.Name != "Alice" || player.AutoSetNameTemplate != "{$t玩家_RAW}" || player.DiceSideNum != 100 || player.LastCommandAt != 123 {
		t.Fatalf("projected player = %#v, err=%v", player, err)
	}
	attrs, err := attributestate.ReadProjected(ctx, target.store, "default", "QQ-Group:100-QQ:200")
	if err != nil || attrs.AttrsType != "group_user" || attrs.BindingSheetID != "character-1" {
		t.Fatalf("projected attrs = %#v, err=%v", attrs, err)
	}
	attrSecret, err := target.store.ResolveSecret(ctx, attrs.SecretRef, attrs.SecretVersion)
	if err != nil {
		t.Fatal(err)
	}
	attrValue, err := ds.VMValueFromJSON(attrSecret.Plaintext)
	if err != nil {
		t.Fatal(err)
	}
	attrDict, ok := attrValue.ReadDictData()
	if !ok {
		t.Fatalf("attrs secret=%q", attrSecret.Plaintext)
	}
	hp, hpExists := attrDict.Dict.Load("hp")
	san, sanExists := attrDict.Dict.Load("san")
	if !hpExists || !sanExists || hp.ToString() != "60" || san.ToString() != "45" {
		t.Fatalf("attrs secret=%q", attrSecret.Plaintext)
	}
	endpointRow, err := target.store.ReadProjectionRow(ctx, endpoint.EndpointProjectionName, "legacy-onebot")
	if err != nil {
		t.Fatal(err)
	}
	var endpointView endpoint.EndpointView
	if err = json.Unmarshal(endpointRow.Payload, &endpointView); err != nil ||
		endpointView.DesiredState != endpoint.DesiredStateEnabled ||
		endpointView.DisplayName != "Legacy Bot" ||
		endpointView.ProviderID != "QQ:12345" ||
		endpointView.Statistics != (endpoint.Statistics{GroupCount: 7, CommandCount: 84, LastCommandAt: 12345, OnlineSeconds: 789}) {
		t.Fatalf("projected endpoint = %#v, err=%v", endpointView, err)
	}
	var endpointConfig map[string]any
	if err = json.Unmarshal(endpointView.Config.Canonical, &endpointConfig); err != nil || endpointConfig["accountHint"] != "QQ:12345" {
		t.Fatalf("projected endpoint account hint = %#v, err=%v", endpointConfig, err)
	}
	endpointSecret, err := target.store.ResolveSecret(ctx, "vault:legacy-default-endpoint-legacy-onebot-token", 1)
	if err != nil || string(endpointSecret.Plaintext) != "endpoint-secret" {
		t.Fatalf("endpoint secret=%q err=%v", endpointSecret.Plaintext, err)
	}
	moderation, err := playerstate.ReadProjectedModeration(ctx, target.store, "default", "global", "QQ:bad")
	if err != nil || moderation.Score != 42 || moderation.Rank != int(dice.BanRankBanned) || moderation.ReasonDigest == "" {
		t.Fatalf("projected moderation = %#v, err=%v", moderation, err)
	}
	reason, err := json.Marshal(struct {
		Times   []int64  `json:"times"`
		Reasons []string `json:"reasons"`
		Places  []string `json:"places"`
	}{[]int64{100}, []string{"spam"}, []string{"QQ-Group:100"}})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("01234567890123456789012345678901"))
	_, _ = mac.Write([]byte("legacy-moderation-reason/v1\x00"))
	var reasonLength [8]byte
	binary.BigEndian.PutUint64(reasonLength[:], uint64(len(reason)))
	_, _ = mac.Write(reasonLength[:])
	_, _ = mac.Write(reason)
	if moderation.ReasonDigest != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("moderation reason digest = %q", moderation.ReasonDigest)
	}
	stream := playerstate.ModerationStream("default", "global", "QQ:bad")
	detailsDigest := sha256.Sum256([]byte(stream.AggregateID))
	detailsRef := "vault:moderation-details:" + hex.EncodeToString(detailsDigest[:16])
	detailsSecret, err := target.store.ResolveSecret(ctx, detailsRef, 1)
	if err != nil {
		t.Fatalf("resolve imported moderation history: %v", err)
	}
	var details struct {
		dice.BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}
	if err = json.Unmarshal(detailsSecret.Plaintext, &details); err != nil {
		t.Fatalf("decode imported moderation history: %v", err)
	}
	if details.ID != "QQ:bad" || details.Name != "Bad" || details.BanUpdatedAt != 100 ||
		!slices.Equal(details.Times, []int64{100}) || !slices.Equal(details.Reasons, []string{"spam"}) ||
		!slices.Equal(details.Places, []string{"QQ-Group:100"}) {
		t.Fatalf("imported moderation history = %#v", details)
	}
	mail, err := target.store.ResolveSecret(ctx, "vault:legacy-default-mail", 1)
	if err != nil || string(mail.Plaintext) != "mail-secret" {
		t.Fatalf("mail secret=%q err=%v", mail.Plaintext, err)
	}
	story, err := target.store.ResolveSecret(ctx, "vault:legacy-default-story-log", 1)
	if err != nil || string(story.Plaintext) != "story-secret" {
		t.Fatalf("story secret=%q err=%v", story.Plaintext, err)
	}
	plugin, err := target.store.GetPluginKV(ctx, "test-ext", "campaign")
	if err != nil || string(plugin.Value) != `{"round":7}` {
		t.Fatalf("plugin value=%q err=%v", plugin.Value, err)
	}
	emptyPluginKey, err := target.store.GetPluginKV(ctx, "test-ext", "")
	if err != nil || emptyPluginKey.Key != "" || string(emptyPluginKey.Value) != "[object Object]" {
		t.Fatalf("empty plugin key value=%q err=%v", emptyPluginKey.Value, err)
	}
	if err = source.Recheck(ctx, inventory.Metadata); err != nil {
		t.Fatalf("source mutated by import: %v", err)
	}
}

func TestLegacyImporterReadsInstallationRelativeDataDirFromSnapshot(t *testing.T) {
	ctx := context.Background()
	installationRoot := t.TempDir()
	root := filepath.Join(installationRoot, "data")
	instanceDir := filepath.Join(root, "default")
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: data/default\n"))
	writeLegacyFixtureFile(t, filepath.Join(instanceDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(instanceDir, "data.db"))

	target := NewSQLiteTarget(filepath.Join(t.TempDir(), "events.db"), sqliteTargetKeySource{})
	result, err := NewImporter(ImporterOptions{
		Readiness: &readinessFake{value: eventstore.Readiness{
			Mode: "fresh", SchemaVersion: 1, DatabaseIdentity: "old", IndexRootID: "old-index",
		}},
		Source:         NewLegacySourceWithKeySource(root, sqliteTargetKeySource{}),
		Target:         target,
		SnapshotRoot:   filepath.Join(t.TempDir(), "snapshot"),
		TargetIdentity: "installation-relative-data-dir",
	}).Run(ctx, Request{Mode: ModeImport})
	if err != nil {
		t.Fatalf("import installation-relative dataDir from snapshot: %v", err)
	}
	if result.Batches == 0 {
		t.Fatal("import completed without reading snapshot records")
	}
}

func TestLegacySnapshotRejectsMissingCapturedInstance(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	for _, name := range []string{"alpha", "beta"} {
		instanceDir := filepath.Join(root, name)
		if err := os.MkdirAll(instanceDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeLegacyFixtureFile(t, filepath.Join(instanceDir, "serve.yaml"), []byte("{}\n"))
		createLegacySQLiteFixture(t, filepath.Join(instanceDir, "data.db"))
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte(
		"diceConfigs:\n  - name: alpha\n    dataDir: alpha\n  - name: beta\n    dataDir: beta\n",
	))

	snapshot, err := NewLegacySource(root).Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(snapshot.Root, "dice.yaml"), []byte(
		"diceConfigs:\n  - name: alpha\n    dataDir: alpha\n",
	))
	if _, err = snapshot.Source.Inventory(ctx); !errors.Is(err, ErrSourceMutation) {
		t.Fatalf("snapshot missing a captured instance error = %v, want %v", err, ErrSourceMutation)
	}
}

func TestLegacySourceResolvesInstallationRelativeDataDirThroughRootSymlink(t *testing.T) {
	ctx := context.Background()
	installationRoot := t.TempDir()
	root := filepath.Join(installationRoot, "data")
	instanceDir := filepath.Join(root, "default")
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte(
		"diceConfigs:\n  - name: default\n    dataDir: data/default\n",
	))
	writeLegacyFixtureFile(t, filepath.Join(instanceDir, "serve.yaml"), []byte("{}\n"))
	createLegacySQLiteFixture(t, filepath.Join(instanceDir, "data.db"))
	rootAlias := filepath.Join(t.TempDir(), "renamed-source-root")
	if err := os.Symlink(root, rootAlias); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}

	source := NewLegacySource(rootAlias)
	if _, err := source.Inventory(ctx); err != nil {
		t.Fatalf("inventory through renamed data-root symlink: %v", err)
	}
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = snapshot.Source.Inventory(ctx); err != nil {
		t.Fatalf("inventory copied snapshot from renamed data-root symlink: %v", err)
	}
}

func TestRemoteSQLSourceSnapshotsIntoLocalReadOnlyImportSource(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "data")
	instanceDir := filepath.Join(root, "default")
	if err := os.MkdirAll(instanceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeLegacyFixtureFile(t, filepath.Join(root, "dice.yaml"), []byte("diceConfigs:\n  - name: default\n    dataDir: data/default\n"))
	writeLegacyFixtureFile(t, filepath.Join(instanceDir, "serve.yaml"), []byte("{}\n"))
	remotePath := filepath.Join(t.TempDir(), "remote.db")
	createLegacySQLiteFixture(t, remotePath)

	remoteDB, err := sql.Open("sqlite", remotePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remoteDB.Exec(`UPDATE group_info SET created_at = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err = remoteDB.Exec(`UPDATE group_player_info SET name = NULL, last_command_time = NULL, auto_set_name_template = NULL, dice_side_num = NULL`); err != nil {
		t.Fatal(err)
	}
	if err = remoteDB.Close(); err != nil {
		t.Fatal(err)
	}

	source := NewRemoteSQLSourceWithKeySource(root, eventstore.DatabaseConfig{Type: "mysql", DSN: "unused"}, sqliteTargetKeySource{})
	source.open = func(context.Context, eventstore.DatabaseConfig) (*sql.DB, error) {
		return sql.Open("sqlite", "file:"+filepath.ToSlash(remotePath)+"?mode=ro")
	}
	snapshot, err := source.Snapshot(ctx, filepath.Join(t.TempDir(), "snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Source == nil {
		t.Fatal("remote snapshot source is nil")
	}
	inventory, err := snapshot.Source.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	streamer, ok := snapshot.Source.(RecordStreamer)
	if !ok {
		t.Fatalf("snapshot source %T is not streaming", snapshot.Source)
	}
	records := 0
	if err = streamer.StreamRecords(ctx, func(batch []SourceRecord) error {
		records += len(batch)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if inventory.Kind != SourceKindLegacy || !inventory.LegacyOwnershipComplete || records == 0 {
		t.Fatalf("snapshot inventory/records = %#v/%d", inventory, records)
	}

	snapshotDB, err := sql.Open("sqlite", filepath.Join(snapshot.Root, "default", "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	var createdAt, lastCommandTime, diceSideNum int64
	var playerName, autoSetNameTemplate string
	if err = snapshotDB.QueryRow(`SELECT created_at FROM group_info WHERE id = 'QQ-Group:100'`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	if err = snapshotDB.QueryRow(`SELECT name, last_command_time, auto_set_name_template, dice_side_num FROM group_player_info WHERE user_id = 'QQ:200'`).
		Scan(&playerName, &lastCommandTime, &autoSetNameTemplate, &diceSideNum); err != nil {
		t.Fatal(err)
	}
	if err = snapshotDB.Close(); err != nil {
		t.Fatal(err)
	}
	if createdAt != 0 || playerName != "" || lastCommandTime != 0 || autoSetNameTemplate != "" || diceSideNum != 0 {
		t.Fatalf("normalized remote NULL values = %d/%q/%d/%q/%d", createdAt, playerName, lastCommandTime, autoSetNameTemplate, diceSideNum)
	}

	database, err := sql.Open("sqlite", remotePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO ban_info (id, data) VALUES ('QQ:later', '{"id":"QQ:later"}')`); err != nil {
		t.Fatal(err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}
	if err = source.Recheck(ctx, snapshot.Metadata); !errors.Is(err, ErrSourceDrift) {
		t.Fatalf("remote drift error = %v", err)
	}
}

func TestLegacyEndpointAdapterKeyFallsBackToNonQQPlatform(t *testing.T) {
	tests := map[string]adapterapi.AdapterKey{
		"DISCORD":   dice.DiscordAdapterKey,
		"KOOK":      dice.KookAdapterKey,
		"TG":        dice.TelegramAdapterKey,
		"TELEGRAM":  dice.TelegramAdapterKey,
		"SLACK":     dice.SlackAdapterKey,
		"DODO":      dice.DodoAdapterKey,
		"DINGTALK":  dice.DingTalkAdapterKey,
		"MC":        dice.MinecraftAdapterKey,
		"MINECRAFT": dice.MinecraftAdapterKey,
		"SEALCHAT":  dice.SealChatAdapterKey,
	}
	for platform, want := range tests {
		t.Run(platform, func(t *testing.T) {
			got, err := legacyEndpointAdapterKey(platform, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("adapter key = %q, want %q", got, want)
			}
		})
	}
}

func TestLegacyGoCQReverseConfigMigratesToListenerRuntime(t *testing.T) {
	key, raw, secrets, err := legacyEndpointConfig(
		"default",
		"legacy-gocq-reverse",
		"QQ",
		"onebot",
		"QQ:12345",
		map[string]any{"isReverse": true, "reverseAddr": "127.0.0.1:19001"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if key != dice.GocqAdapterKey || len(secrets) != 0 {
		t.Fatalf("adapter key/secrets = %q/%#v", key, secrets)
	}
	descriptor := dice.NewGocqDescriptor()
	config, err := descriptor.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatalf("validate migrated reverse config: %v", err)
	}
	runtime, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:     "legacy-gocq-reverse",
		Generation:     1,
		DesiredVersion: 1,
		Config:         config,
	})
	if err != nil {
		t.Fatalf("new migrated reverse runtime: %v", err)
	}
	if runtime == nil {
		t.Fatal("new migrated reverse runtime returned nil")
	}
}
