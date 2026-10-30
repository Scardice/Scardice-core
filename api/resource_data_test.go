package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"Scardice-core/dice"
)

const resourceDataTestToken = "resource-data-api-test-token"

const corruptResourcePNGHex = "89504e470d0a1a0a0000000d4948445200000001000000010804000000b51c0c020000000b4944415478da63fcff1f0003030200efbfa9640000000049454e44ae426082"

func newResourceDataTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()

	previousDice, previousManager := myDice, dm
	runtime := &dice.Dice{Logger: zap.NewNop().Sugar()}
	manager := &dice.DiceManager{Dice: []*dice.Dice{runtime}}
	manager.AccessTokens.Store(resourceDataTestToken, true)
	runtime.Parent = manager
	myDice, dm = runtime, manager
	t.Cleanup(func() {
		myDice, dm = previousDice, previousManager
	})

	e := echo.New()
	Bind(e, manager)
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	return server, resourceDataTestToken
}

func postResourceDataTestUpload(t *testing.T, server *httptest.Server, token, name string, content []byte) {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	file, err := writer.CreateFormFile("files", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/sd-api/resource", &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Token", token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("upload resource: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read resource upload response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("resource upload status = %d, want %d: %s", response.StatusCode, http.StatusOK, responseBody)
	}
	var result struct {
		Result bool   `json:"result"`
		Err    string `json:"err"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		t.Fatalf("decode resource upload response: %v", err)
	}
	if !result.Result {
		t.Fatalf("resource upload failed: %s", responseBody)
	}
}

func getResourceDataTestResponse(t *testing.T, server *httptest.Server, token, path string, thumbnail bool) (int, string, []byte) {
	t.Helper()

	query := url.Values{}
	query.Set("path", path)
	if thumbnail {
		query.Set("thumbnail", "true")
	}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/sd-api/resource/data?"+query.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Token", token)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatalf("GET resource/data (thumbnail=%t): %v", thumbnail, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read resource/data response: %v", err)
	}
	return response.StatusCode, response.Header.Get("Content-Type"), body
}

func TestResourceDataReturnsOriginalAndThumbnailForUploadedPNG(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Join("data", "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	server, token := newResourceDataTestServer(t)

	const filename = "resource-data-control.png"
	var source bytes.Buffer
	if err := png.Encode(&source, image.NewRGBA(image.Rect(0, 0, 128, 96))); err != nil {
		t.Fatal(err)
	}
	postResourceDataTestUpload(t, server, token, filename, source.Bytes())

	for _, test := range []struct {
		name       string
		thumbnail  bool
		wantBounds image.Rectangle
	}{
		{name: "original", wantBounds: image.Rect(0, 0, 128, 96)},
		{name: "thumbnail", thumbnail: true, wantBounds: image.Rect(0, 0, 64, 48)},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, contentType, body := getResourceDataTestResponse(t, server, token, "data/images/"+filename, test.thumbnail)
			if status != http.StatusOK {
				t.Fatalf("resource/data status = %d, want %d: %s", status, http.StatusOK, body)
			}
			if contentType != "image/png" {
				t.Fatalf("resource/data Content-Type = %q, want image/png", contentType)
			}
			decoded, err := png.Decode(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("decode resource/data PNG: %v", err)
			}
			if got := decoded.Bounds(); got != test.wantBounds {
				t.Fatalf("resource/data bounds = %v, want %v", got, test.wantBounds)
			}
		})
	}
}

func TestResourceDataReturnsClientErrorForUploadedUndecodablePNG(t *testing.T) {
	corruptPNG, err := hex.DecodeString(corruptResourcePNGHex)
	if err != nil {
		t.Fatalf("decode corrupt PNG fixture: %v", err)
	}
	if len(corruptPNG) != 68 {
		t.Fatalf("corrupt PNG fixture length = %d, want 68", len(corruptPNG))
	}
	if decoded, err := png.Decode(bytes.NewReader(corruptPNG)); err == nil || decoded != nil {
		t.Fatalf("corrupt PNG fixture decoded successfully: image=%v err=%v", decoded, err)
	}

	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Join("data", "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	server, token := newResourceDataTestServer(t)
	const filename = "UIE2E_fd9-live-actions-20261009-2310.png"
	postResourceDataTestUpload(t, server, token, filename, corruptPNG)

	status, contentType, body := getResourceDataTestResponse(t, server, token, "data/images/"+filename, true)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("resource/data status for undecodable uploaded PNG = %d, want %d: %s", status, http.StatusUnprocessableEntity, body)
	}
	if contentType != "application/json" {
		t.Fatalf("resource/data error Content-Type = %q, want application/json", contentType)
	}
	var result struct {
		Result bool   `json:"result"`
		Err    string `json:"err"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode resource/data error: %v", err)
	}
	if result.Result || result.Err == "" {
		t.Fatalf("resource/data error response = %#v, want a failed result with a useful error", result)
	}
}
