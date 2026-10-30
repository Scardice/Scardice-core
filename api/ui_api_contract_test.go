package api

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/dice"
	"Scardice-core/dice/censor"
	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

const uiAPIContractToken = "ui-api-contract-token"

func setUpUIAPIContractDice(t *testing.T, testDice *dice.Dice) *dice.DiceManager {
	t.Helper()
	previousDice, previousManager := myDice, dm
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	manager.AccessTokens.Store(uiAPIContractToken, true)
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() { myDice, dm = previousDice, previousManager })
	return manager
}

func TestDiceExecSplitOptionsEndpointContract(t *testing.T) {
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/dice/exec/split_options", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("split options status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var got struct {
		DefaultKey string `json:"defaultKey"`
		Options    []struct {
			Key             string `json:"key"`
			Label           string `json:"label"`
			MessageSplitLen int    `json:"messageSplitLen"`
		} `json:"options"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode split options: %v", err)
	}
	wantKeys := []string{"short", "qq", "unlimited"}
	wantLengths := []int{300, 2000, 0}
	if got.DefaultKey != "qq" || len(got.Options) != len(wantKeys) {
		t.Fatalf("split options = %#v, want default qq and %d choices", got, len(wantKeys))
	}
	for i, option := range got.Options {
		if option.Key != wantKeys[i] || option.MessageSplitLen != wantLengths[i] || option.Label == "" {
			t.Fatalf("split option %d = %#v, want key %q and length %d", i, option, wantKeys[i], wantLengths[i])
		}
	}
}

func TestStoreRemoveBackendBindsAxiosDeleteQuery(t *testing.T) {
	const targetURL = "https://custom-store.example/dice/api/store"
	testDice := &dice.Dice{Config: dice.Config{StoreConfig: dice.StoreConfig{BackendUrls: []string{targetURL}}}}
	setUpUIAPIContractDice(t, testDice)
	testDice.StoreManager = dice.NewStoreManager(testDice)

	query := url.Values{"url": []string{targetURL}}
	req := httptest.NewRequest(http.MethodDelete, "/sd-api/store/backend/remove?"+query.Encode(), nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, recorder)
	if err := storeRemoveBackend(ctx); err != nil {
		t.Fatalf("storeRemoveBackend() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("storeRemoveBackend() status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if len(testDice.Config.BackendUrls) != 0 {
		t.Fatalf("backend URLs after removal = %#v, want target removed", testDice.Config.BackendUrls)
	}
}

func TestCensorDeleteWordFilesBindsAxiosBracketedArrayQuery(t *testing.T) {
	const fileKey = "contract-word-file"
	filePath := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(filePath, []byte("word"), 0o600); err != nil {
		t.Fatal(err)
	}
	testDice := &dice.Dice{
		Config: dice.Config{CensorConfig: dice.CensorConfig{EnableCensor: true}},
		CensorManager: &dice.CensorManager{
			SensitiveWordsFiles: map[string]*censor.WordFile{fileKey: {Key: fileKey, Path: filePath}},
		},
	}
	setUpUIAPIContractDice(t, testDice)

	query := url.Values{}
	query.Add("keys[]", fileKey)
	req := httptest.NewRequest(http.MethodDelete, "/sd-api/censor/files?"+query.Encode(), nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, recorder)
	if got := ctx.QueryParams().Get("keys[]"); got != fileKey {
		t.Fatalf("parsed DELETE keys[] = %q, want %q", got, fileKey)
	}
	if err := censorDeleteWordFiles(ctx); err != nil {
		t.Fatalf("censorDeleteWordFiles() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("censorDeleteWordFiles() status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("censor file still exists after DELETE: stat error = %v", err)
	}
	if _, exists := testDice.CensorManager.SensitiveWordsFiles[fileKey]; exists {
		t.Fatalf("censor file %q remains registered after DELETE", fileKey)
	}
}

type uiAPIContractLogOperator struct {
	db *gorm.DB
}

func (o *uiAPIContractLogOperator) Init(context.Context) error { return nil }
func (o *uiAPIContractLogOperator) Type() string               { return constant.SQLITE }
func (o *uiAPIContractLogOperator) DBCheck()                   {}
func (o *uiAPIContractLogOperator) GetDataDB(constant.DBMode) *gorm.DB {
	return o.db
}
func (o *uiAPIContractLogOperator) GetLogDB(constant.DBMode) *gorm.DB {
	return o.db
}
func (o *uiAPIContractLogOperator) GetCensorDB(constant.DBMode) *gorm.DB {
	return o.db
}
func (o *uiAPIContractLogOperator) Close() {}

func TestStoryDeleteLogBindsAxiosDeleteQuery(t *testing.T) {
	db, err := gorm.Open(gormsqlite.Open(filepath.Join(t.TempDir(), "story.db")), &gorm.Config{
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
	if err := db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatal(err)
	}
	const groupID, name = "QQ-Group:contract", "contract-story"
	if err := db.Create(&model.LogInfo{GroupID: groupID, Name: name}).Error; err != nil {
		t.Fatal(err)
	}
	testDice := &dice.Dice{DBOperator: &uiAPIContractLogOperator{db: db}}
	testDice.LogRepository = service.NewLegacyLogRepository(testDice.DBOperator, testDice.BaseConfig.Name)
	setUpUIAPIContractDice(t, testDice)

	query := url.Values{"groupId": []string{groupID}, "name": []string{name}}
	req := httptest.NewRequest(http.MethodDelete, "/sd-api/story/log?"+query.Encode(), nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, recorder)
	if err := storyDelLog(ctx); err != nil {
		t.Fatalf("storyDelLog() error = %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("storyDelLog() status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var remaining int64
	if err := db.Model(&model.LogInfo{}).Where("group_id = ? AND name = ?", groupID, name).Count(&remaining).Error; err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("matching story log rows remaining = %d, want 0", remaining)
	}
}

func TestDeckListReturnsEmptyArrayWhenNoDecksConfigured(t *testing.T) {
	testDice := &dice.Dice{}
	manager := setUpUIAPIContractDice(t, testDice)
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/deck/list", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("deck list status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var decks []*dice.DeckInfo
	if err := json.Unmarshal(recorder.Body.Bytes(), &decks); err != nil {
		t.Fatalf("decode deck list: %v", err)
	}
	if decks == nil {
		t.Fatalf("deck list must be an empty array when no decks are configured: %s", recorder.Body.String())
	}
	if len(decks) != 0 {
		t.Fatalf("deck list = %#v, want no decks", decks)
	}
}

func TestHelpDocTreeReportsUnavailableManagerWithoutPanicking(t *testing.T) {
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/helpdoc/tree", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()

	var panicValue any
	func() {
		defer func() {
			panicValue = recover()
		}()
		e.ServeHTTP(recorder, req)
	}()
	if panicValue != nil {
		t.Fatalf("helpdoc tree panicked without a manager: %v", panicValue)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("helpdoc tree status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Result bool   `json:"result"`
		Err    string `json:"err"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode helpdoc tree response: %v", err)
	}
	if response.Result || response.Err == "" {
		t.Fatalf("helpdoc tree without a manager should return a structured error: %s", recorder.Body.String())
	}
}

func TestBackupListReturnsEmptyArrayWhenBackupDirectoryDoesNotExist(t *testing.T) {
	t.Chdir(t.TempDir())
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/backup/list", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("backup list status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode backup list: %v", err)
	}
	if response.Items == nil || len(response.Items) != 0 {
		t.Fatalf("backup items = %#v, want an empty array", response.Items)
	}
}

func TestResourceListReturnsEmptyArrayWhenImageDirectoryDoesNotExist(t *testing.T) {
	t.Chdir(t.TempDir())
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/resource/page?type=image", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("resource list status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Result bool              `json:"result"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode resource list: %v", err)
	}
	if !response.Result {
		t.Fatalf("resource list result = false: %s", recorder.Body.String())
	}
	if response.Data == nil || len(response.Data) != 0 {
		t.Fatalf("resource data = %#v, want an empty array", response.Data)
	}
}

func TestHelpDocConfigReturnsEmptyAliasesWithoutManager(t *testing.T) {
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodGet, "/sd-api/helpdoc/config", nil)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("helpdoc config status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Aliases map[string][]string `json:"aliases"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode helpdoc config: %v", err)
	}
	if response.Aliases == nil || len(response.Aliases) != 0 {
		t.Fatalf("helpdoc aliases = %#v, want an empty object", response.Aliases)
	}
}

func TestHelpDocConfigSaveReportsUnavailableManager(t *testing.T) {
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	req := httptest.NewRequest(http.MethodPost, "/sd-api/helpdoc/config", nil)
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	e.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("helpdoc config save status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response struct {
		Result bool   `json:"result"`
		Err    string `json:"err"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode helpdoc config save: %v", err)
	}
	if response.Result || response.Err == "" {
		t.Fatalf("helpdoc config save without a manager should return a structured error: %s", recorder.Body.String())
	}
}

func TestHelpDocMutationsReportUnavailableManager(t *testing.T) {
	manager := setUpUIAPIContractDice(t, &dice.Dice{})
	e := echo.New()
	Bind(e, manager)

	deleteBody := bytes.NewBufferString(`{"keys":[]}`)
	deleteReq := httptest.NewRequest(http.MethodPost, "/sd-api/helpdoc/delete", deleteBody)
	deleteReq.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	deleteReq.Header.Set("Token", uiAPIContractToken)

	uploadBody := new(bytes.Buffer)
	uploadForm := multipart.NewWriter(uploadBody)
	part, err := uploadForm.CreateFormFile("files", "help.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("help")); err != nil {
		t.Fatal(err)
	}
	if err := uploadForm.WriteField("group", "custom"); err != nil {
		t.Fatal(err)
	}
	if err := uploadForm.Close(); err != nil {
		t.Fatal(err)
	}
	uploadReq := httptest.NewRequest(http.MethodPost, "/sd-api/helpdoc/upload", uploadBody)
	uploadReq.Header.Set(echo.HeaderContentType, uploadForm.FormDataContentType())
	uploadReq.Header.Set("Token", uiAPIContractToken)

	for _, req := range []*http.Request{uploadReq, deleteReq} {
		t.Run(req.URL.Path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			e.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Fatalf("%s %s status = %d, want %d: %s", req.Method, req.URL.Path, recorder.Code, http.StatusOK, recorder.Body.String())
			}
			var response struct {
				Result bool   `json:"result"`
				Err    string `json:"err"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("decode %s response: %v", req.URL.Path, err)
			}
			if response.Result || response.Err == "" {
				t.Fatalf("%s without a manager should return a structured error: %s", req.URL.Path, recorder.Body.String())
			}
		})
	}
}
