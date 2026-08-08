package dice

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type OfficialQQQRLoginState int

const (
	OfficialQQQRInitial OfficialQQQRLoginState = iota
	OfficialQQQRWaitingForScan
	OfficialQQQRFailed
)

type officialQQQREncoder func(string) ([]byte, error)

type officialQQQRClient interface {
	Create(ctx context.Context, key string) (string, error)
}

type officialQQQRHTTPClient struct {
	httpClient *http.Client
	baseURL    string
}

func newOfficialQQQRHTTPClient(httpClient *http.Client, baseURL string) *officialQQQRHTTPClient {
	return &officialQQQRHTTPClient{httpClient: httpClient, baseURL: strings.TrimRight(baseURL, "/")}
}

func (c *officialQQQRHTTPClient) Create(ctx context.Context, key string) (string, error) {
	body, err := json.Marshal(map[string]string{"key": key})
	if err != nil {
		return "", fmt.Errorf("encode official QQ QR request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/lite/create_bind_task", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create official QQ QR request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("create official QQ QR task: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create official QQ QR task: HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read official QQ QR response: %w", err)
	}
	var result struct {
		RetCode int `json:"retcode"`
		Data    struct {
			TaskID string `json:"task_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("decode official QQ QR response: %w", err)
	}
	if result.RetCode != 0 || result.Data.TaskID == "" {
		return "", errors.New("create official QQ QR task was rejected")
	}
	return result.Data.TaskID, nil
}

func (pa *PlatformAdapterOfficialQQ) beginQRLogin(ctx context.Context, source string) error {
	client := pa.qrClient
	if client == nil {
		client = newOfficialQQQRHTTPClient(http.DefaultClient, "https://q.qq.com")
	}
	keyBytes := make([]byte, 32)
	if _, err := crand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate official QQ QR key: %w", err)
	}
	taskID, err := client.Create(ctx, base64.StdEncoding.EncodeToString(keyBytes))
	if err != nil {
		pa.QRLoginState = OfficialQQQRFailed
		return err
	}
	baseURL := "https://q.qq.com"
	if httpClient, ok := client.(*officialQQQRHTTPClient); ok {
		baseURL = httpClient.baseURL
	}
	pa.QRURL = baseURL + "/qqbot/connect.html?task_id=" + url.QueryEscape(taskID) +
		"&source=" + url.QueryEscape(source) + "&_wv=2"
	if pa.qrEncoder != nil {
		pa.QRCodeData, err = pa.qrEncoder(pa.QRURL)
		if err != nil {
			pa.QRLoginState = OfficialQQQRFailed
			return fmt.Errorf("encode official QQ QR image: %w", err)
		}
	}
	pa.QRLoginState = OfficialQQQRWaitingForScan
	return nil
}
