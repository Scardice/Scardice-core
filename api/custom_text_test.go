package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/dice"
)

func setupCustomTextHandlerTest(t *testing.T) {
	t.Helper()
	setupWebUIBypassAuthState(t)
	t.Setenv(adminAuthBypassEnv, "1")
	myDice.TextMapRaw = dice.TextTemplateWithWeightDict{
		"核心": {
			"用户文案": {{"用户配置", 1}},
		},
	}
	myDice.TextMapHelpInfo = dice.TextTemplateWithHelpDict{
		"核心": {
			"用户文案": {NotBuiltin: true},
			"内置文案": {Origin: []dice.TextTemplateItem{{"内置默认", 1}}},
		},
	}
}

func TestCustomTextDoesNotBackfillMissingBuiltinOnRead(t *testing.T) {
	setupCustomTextHandlerTest(t)
	ctx, _ := webUIBypassContext("/sd-api/configs/customText")

	if err := customText(ctx); err != nil {
		t.Fatalf("customText() error = %v", err)
	}
	if _, exists := myDice.TextMapRaw["核心"]["内置文案"]; exists {
		t.Fatal("reading user text configuration restored an omitted builtin entry")
	}
	if got := myDice.TextMapRaw["核心"]["用户文案"][0][0]; got != "用户配置" {
		t.Fatalf("user text = %v, want %q", got, "用户配置")
	}
}

func TestCustomTextSaveDoesNotBackfillMissingBuiltin(t *testing.T) {
	setupCustomTextHandlerTest(t)
	myDice.BaseConfig.DataDir = t.TempDir()
	myDice.Logger = zap.NewNop().Sugar()

	requestBody := `{"category":"核心","data":{}}`
	request := httptest.NewRequest(
		http.MethodPost,
		"/sd-api/configs/customText/save",
		strings.NewReader(requestBody),
	)
	request.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(request, recorder)

	if err := customTextSave(ctx); err != nil {
		t.Fatalf("customTextSave() error = %v", err)
	}
	if _, exists := myDice.TextMapRaw["核心"]["内置文案"]; exists {
		t.Fatal("saving user text configuration restored an omitted builtin entry")
	}
}

func TestCustomTextSavePreservesUnchangedSiblingWhitespace(t *testing.T) {
	const token = "custom-text-session"
	const category = "DND"

	dataDir := t.TempDir()
	testDice := &dice.Dice{
		BaseConfig: dice.BaseConfig{DataDir: dataDir},
		Logger:     zap.NewNop().Sugar(),
		TextMapRaw: dice.TextTemplateWithWeightDict{
			category: {
				"unchanged": {{"original text\n", 1}},
				"edited":    {{"before edit", 1}},
			},
		},
		TextMapHelpInfo: dice.TextTemplateWithHelpDict{
			category: {
				"unchanged": {},
				"edited":    {},
			},
		},
	}

	db, err := gorm.Open(gormsqlite.Open(filepath.Join(dataDir, "attrs.db")), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	testDice.DBOperator = &uiAPIContractLogOperator{db: db}
	testDice.Config = dice.NewConfig(testDice)
	session := &dice.IMSession{
		Parent:       testDice,
		ServiceAtNew: new(dice.SyncMap[string, *dice.GroupInfo]),
	}
	endpoint := &dice.EndPointInfo{}
	endpoint.Session = session
	testDice.ImSession = session
	testDice.UIEndpoint = endpoint
	testDice.AttrsManager = &dice.AttrsManager{}
	testDice.AttrsManager.Init(testDice)
	t.Cleanup(testDice.AttrsManager.Stop)
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	manager.AccessTokens.Store(token, true)
	testDice.Parent = manager

	previousDice, previousManager := myDice, dm
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})

	e := echo.New()
	Bind(e, manager)
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)

	request := func(method, path string, body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Token", token)
		if body != nil {
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		responseBody, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, responseBody
	}

	type customTextResponse struct {
		Texts dice.TextTemplateWithWeightDict `json:"texts"`
	}
	const customTextPath = "/sd-api/configs/customText"
	const savePath = "/sd-api/configs/customText/save"

	status, body := request(http.MethodGet, customTextPath, nil)
	if status != http.StatusOK {
		t.Fatalf("initial custom text GET status=%d body=%s", status, body)
	}
	t.Logf("initial GET HTTP %d body: %s", status, body)
	var initial customTextResponse
	if err := json.Unmarshal(body, &initial); err != nil {
		t.Fatalf("decode initial custom text GET: %v", err)
	}
	categoryData := initial.Texts[category]
	if got := categoryData["unchanged"][0][0]; got != "original text\n" {
		t.Fatalf("initial unchanged sibling = %q, want original value with trailing newline", got)
	}

	// The UI submits the entire category after editing one text item.
	categoryData["edited"][0][0] = "  edited text \n"
	saveBody, err := json.Marshal(struct {
		Category string                      `json:"category"`
		Data     dice.TextTemplateWithWeight `json:"data"`
	}{Category: category, Data: categoryData})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("save POST request body: %s", saveBody)
	status, body = request(http.MethodPost, savePath, saveBody)
	if status != http.StatusOK {
		t.Fatalf("custom text save status=%d body=%s", status, body)
	}
	t.Logf("save POST response HTTP %d body: %s", status, body)

	status, body = request(http.MethodGet, customTextPath, nil)
	if status != http.StatusOK {
		t.Fatalf("custom text readback status=%d body=%s", status, body)
	}
	t.Logf("readback GET HTTP %d body: %s", status, body)
	var readback customTextResponse
	if err := json.Unmarshal(body, &readback); err != nil {
		t.Fatalf("decode custom text readback: %v", err)
	}
	assertCategoryText := func(label string, texts dice.TextTemplateWithWeightDict, key, want string) {
		t.Helper()
		got, ok := texts[category][key][0][0].(string)
		if !ok || got != want {
			t.Fatalf("%s text = %q, want %q", label, got, want)
		}
	}
	assertCategoryText("API unchanged sibling", readback.Texts, "unchanged", "original text\n")
	assertCategoryText("API edited value", readback.Texts, "edited", "  edited text \n")

	savedFile, err := os.ReadFile(filepath.Join(dataDir, "configs/text-template.yaml"))
	if err != nil {
		t.Fatalf("read saved text template: %v", err)
	}
	var saved dice.TextTemplateWithWeightDict
	if err := yaml.Unmarshal(savedFile, &saved); err != nil {
		t.Fatalf("decode saved text template: %v", err)
	}
	assertCategoryText("persisted unchanged sibling", saved, "unchanged", "original text\n")
	assertCategoryText("persisted edited value", saved, "edited", "  edited text \n")
}
