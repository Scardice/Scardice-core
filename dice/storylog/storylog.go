package storylog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"Scardice-core/model"
	"Scardice-core/utils/dboperator/engine"
)

const (
	storylogHTTPTimeout    = 12 * time.Second
	maxBackendRespLogBytes = 512
)

var storylogHTTPClient = &http.Client{
	Timeout: storylogHTTPTimeout,
}

type UploadEnv struct {
	Dir      string
	Db       engine.DatabaseOperator
	Log      *zap.SugaredLogger
	Backends []string
	Version  StoryVersion

	LogName   string
	UniformID string
	GroupID   string
	Token     string

	lines []*model.LogOneItem
	data  *[]byte
}

func Upload(env UploadEnv) (string, error) {
	if env.Version == StoryVersionV1 {
		return uploadV1(env)
	}
	if env.Version == StoryVersionV105 {
		return uploadV105(env)
	}
	return "", errors.New("未指定日志版本")
}

func compactBackendRespForLog(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) <= maxBackendRespLogBytes {
		return s
	}
	return s[:maxBackendRespLogBytes] + "...(truncated)"
}

func uploadToBackend(env UploadEnv, backend string, data io.Reader) string {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	field, err := writer.CreateFormField("name")
	if err == nil {
		_, _ = field.Write([]byte(env.LogName))
	}

	field, err = writer.CreateFormField("uniform_id")
	if err == nil {
		_, _ = field.Write([]byte(env.UniformID))
	}

	field, err = writer.CreateFormField("client")
	if err == nil {
		// NOTE(lyjjl): 海豹染色器后端似乎只接受 client=SealDice 的请求。
		_, _ = field.Write([]byte("SealDice"))
	}

	field, err = writer.CreateFormField("version")
	if err == nil {
		_, _ = field.Write([]byte(strconv.Itoa(int(env.Version))))
	}

	part, _ := writer.CreateFormFile("file", "log-zlib-compressed")
	if _, err = io.Copy(part, data); err != nil {
		env.Log.Errorf("日志上传构造请求体失败: %v", err)
		return ""
	}
	_ = writer.Close()

	req, err := http.NewRequest(http.MethodPut, backend, body)
	if err != nil {
		env.Log.Errorf(err.Error())
		return ""
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	if len(env.Token) > 0 {
		req.Header.Set("Authorization", "Bearer "+env.Token)
	}

	resp, err := storylogHTTPClient.Do(req) //nolint:gosec
	if err != nil {
		env.Log.Errorf(err.Error())
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	bodyText, err := io.ReadAll(resp.Body)
	if err != nil {
		env.Log.Errorf(err.Error())
		return ""
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		env.Log.Errorf(
			"日志上传请求失败: backend=%s status=%d body=%s",
			backend,
			resp.StatusCode,
			compactBackendRespForLog(bodyText),
		)
		return ""
	}

	var ret struct {
		URL string `json:"url"`
	}
	if err = json.Unmarshal(bodyText, &ret); err != nil {
		env.Log.Errorf(
			"日志上传返回解析失败: backend=%s status=%d body=%s err=%v",
			backend,
			resp.StatusCode,
			compactBackendRespForLog(bodyText),
			err,
		)
		return ""
	}
	if ret.URL == "" {
		env.Log.Errorf(
			"日志上传的返回结果异常: backend=%s status=%d body=%s",
			backend,
			resp.StatusCode,
			compactBackendRespForLog(bodyText),
		)
	}
	return ret.URL
}
