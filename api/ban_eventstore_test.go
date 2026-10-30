package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/core/playerstate"
	"Scardice-core/dice"
	"Scardice-core/eventstore"
)

const apiBanEventStoreTestDiceID = "api-ban-eventstore-test"

func openAPIBanEventStore(t *testing.T, dsn string, initialize bool) (*eventstore.Database, *eventstore.GORMStore) {
	t.Helper()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
		Type: "sqlite", DSN: dsn, DatabaseIdentity: apiBanEventStoreTestDiceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(endpointAPITestKeySource{}),
		eventstore.WithProjection(playerstate.ModerationProjection()),
	)
	if initialize {
		if err = store.SetReadiness(ctx, eventstore.Readiness{
			Mode: "import", SchemaVersion: 1, DatabaseIdentity: apiBanEventStoreTestDiceID,
			IndexRootID: "api-test-index-v1", EncryptionRootIDs: []string{"api-test-root-v1"},
			SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
			CompletedAt: time.Unix(1, 0).UTC(),
		}); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	if err = store.ValidateReadiness(ctx); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, store
}

func TestBanImportExportRoundTripsThroughEncryptedEventStore(t *testing.T) {
	previousDice, previousManager := myDice, dm
	t.Cleanup(func() { myDice, dm = previousDice, previousManager })

	manager := &dice.DiceManager{}
	manager.AccessTokens.Store("ban-list-token", true)
	dm = manager
	root := t.TempDir()
	dsn := filepath.Join(root, "events.db")
	db, store := openAPIBanEventStore(t, dsn, true)
	runtime := &dice.Dice{BaseConfig: dice.BaseConfig{Name: apiBanEventStoreTestDiceID}, Parent: manager, DurableStore: store}
	banList := &dice.BanListInfo{Parent: runtime}
	banList.Init()
	runtime.Config.BanList = banList
	myDice = runtime
	if err := banList.LoadsWithError(); err != nil {
		t.Fatalf("load empty EventStore list: %v", err)
	}

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "ban-list.json")
	if err != nil {
		t.Fatal(err)
	}
	const historyJSON = `[{"ID":"QQ:eventstore-member","name":"private member","score":200,"rank":-30,"times":[11,22],"reasons":["earlier reason","current reason"],"places":["QQ-Group:1","QQ-Group:2"],"banTime":10}]`
	if _, err = io.WriteString(part, historyJSON); err != nil {
		t.Fatal(err)
	}
	if err = form.Close(); err != nil {
		t.Fatal(err)
	}

	e := echo.New()
	importRequest := httptest.NewRequest(http.MethodPost, "/sd-api/banconfig/import", &body)
	importRequest.Header.Set(echo.HeaderContentType, form.FormDataContentType())
	importRequest.Header.Set("Token", "ban-list-token")
	importResponse := httptest.NewRecorder()
	if err = banImport(e.NewContext(importRequest, importResponse)); err != nil {
		t.Fatal(err)
	}
	if importResponse.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importResponse.Code, importResponse.Body.String())
	}

	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	_, reopenedStore := openAPIBanEventStore(t, dsn, false)
	runtime.DurableStore = reopenedStore
	if err = banList.LoadsWithError(); err != nil {
		t.Fatalf("reload EventStore list: %v", err)
	}
	item, ok := banList.GetByID("QQ:eventstore-member")
	if !ok || item.Name != "private member" || item.Rank != dice.BanRankBanned || item.Score != 200 ||
		!slices.Equal(item.Times, []int64{11, 22}) || !slices.Equal(item.Reasons, []string{"earlier reason（来自导入）", "current reason（来自导入）"}) ||
		!slices.Equal(item.Places, []string{"QQ-Group:1", "QQ-Group:2"}) || item.BanTime != 10 {
		t.Fatalf("reloaded imported history = %#v, exists=%v", item, ok)
	}

	exportRequest := httptest.NewRequest(http.MethodGet, "/sd-api/banconfig/export", nil)
	exportRequest.Header.Set("Token", "ban-list-token")
	exportResponse := httptest.NewRecorder()
	if err = banExport(e.NewContext(exportRequest, exportResponse)); err != nil {
		t.Fatal(err)
	}
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	var exported []dice.BanListInfoItem
	if err = json.Unmarshal(exportResponse.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 1 || exported[0].ID != item.ID || exported[0].Name != item.Name ||
		!slices.Equal(exported[0].Reasons, item.Reasons) || !slices.Equal(exported[0].Times, item.Times) || !slices.Equal(exported[0].Places, item.Places) {
		t.Fatalf("exported history = %#v", exported)
	}
}
