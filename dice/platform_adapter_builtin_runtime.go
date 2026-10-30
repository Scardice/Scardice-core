package dice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/utils/procs"
)

const (
	builtinOnebotMode   = "builtin"
	builtinModeGoCQ     = "gocq"
	builtinModeLagrange = "lagrange"

	builtinModeMilkyLagrangeV2 = "lagrangeV2"
	builtinModeMilkyYogurt     = "yogurt"

	maxBuiltinQRCodeBytes = 32 * 1024 * 1024
)

var errBuiltinRuntimeStopped = errors.New("built-in runtime stopped")

type builtinSecretReference struct {
	SecretRef string `json:"secretRef"`
	Version   uint64 `json:"version"`
}

type builtinOnebotCanonicalConfig struct {
	Mode                string                  `json:"mode"`
	BuiltInMode         string                  `json:"builtinMode"`
	Account             string                  `json:"account"`
	Password            *builtinSecretReference `json:"password,omitempty"`
	Protocol            int                     `json:"protocol,omitempty"`
	AppVersion          string                  `json:"appVersion,omitempty"`
	UseSignServer       bool                    `json:"useSignServer,omitempty"`
	SignServerName      string                  `json:"signServerName,omitempty"`
	SignServerVersion   string                  `json:"signServerVersion,omitempty"`
	IgnoreFriendRequest bool                    `json:"ignoreFriendRequest,omitempty"`
	ImageAssetBaseURL   string                  `json:"imageAssetBaseUrl,omitempty"`
}
type builtinOnebotInput struct {
	Mode                string          `json:"mode"`
	ConnectURL          string          `json:"connectUrl"`
	URL                 string          `json:"url"`
	Token               json.RawMessage `json:"token"`
	AccessToken         json.RawMessage `json:"accessToken"`
	InsecureSkipVerify  bool            `json:"insecureSkipVerify"`
	FriendRequestPolicy string          `json:"friendRequestPolicy"`
	ReverseAddr         string          `json:"reverseAddr"`
	IsReverse           *bool           `json:"isReverse"`
	UseInPackGoCqhttp   *bool           `json:"useInPackGoCqhttp"`
	BuiltInMode         string          `json:"builtinMode"`
	Account             string          `json:"account"`
	AccountHint         string          `json:"accountHint"`
	Password            json.RawMessage `json:"password"`
	Protocol            int             `json:"protocol"`
	AppVersion          string          `json:"appVersion"`
	UseSignServer       bool            `json:"useSignServer"`
	SignServerConfig    json.RawMessage `json:"signServerConfig"`
	SignServerName      string          `json:"signServerName"`
	SignServerVersion   string          `json:"signServerVersion"`
	IgnoreFriendRequest *bool           `json:"ignoreFriendRequest"`
	IgnoreFriendLegacy  *bool           `json:"ignore_friend_request"`
	ImageAssetBaseURL   string          `json:"imageAssetBaseUrl"`
}

func decodeBuiltinOnebotInput(raw json.RawMessage) (builtinOnebotInput, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return builtinOnebotInput{}, errors.New("built-in configuration must be an object")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input builtinOnebotInput
	if err := decoder.Decode(&input); err != nil {
		return builtinOnebotInput{}, fmt.Errorf("invalid JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return builtinOnebotInput{}, errors.New("multiple JSON values")
		}
		return builtinOnebotInput{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return input, nil
}
func builtinOnebotRequested(raw json.RawMessage) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return false, errors.New("built-in configuration must be an object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return false, errors.New("built-in configuration has multiple JSON values")
		}
		return false, fmt.Errorf("built-in configuration has trailing JSON: %w", err)
	}
	useInPack, err := gocqBoolean(fields["useInPackGoCqhttp"])
	if err != nil {
		return false, err
	}
	if _, ok := fields["builtinMode"]; ok && bytes.Equal(bytes.TrimSpace(fields["builtinMode"]), []byte("null")) {
		return false, errors.New("builtinMode cannot be null")
	}
	mode := gocqString(fields["builtinMode"])
	if rawMode, ok := fields["builtinMode"]; ok && len(rawMode) > 0 {
		var value string
		if err := json.Unmarshal(rawMode, &value); err != nil {
			return false, errors.New("builtinMode must be a string")
		}
		mode = value
	}
	return useInPack || strings.TrimSpace(mode) != "", nil
}

func validateBuiltinOnebotConfig(ctx context.Context, raw json.RawMessage, defaultMode string) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	input, err := decodeBuiltinOnebotInput(raw)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("built-in OneBot configuration: %w", err)
	}
	if len(raw) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration must be an object")
		}
		if value, ok := fields["useInPackGoCqhttp"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: useInPackGoCqhttp cannot be null")
		}
		if value, ok := fields["builtinMode"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: builtinMode cannot be null")
		}
	}
	mode := strings.ToLower(strings.TrimSpace(input.BuiltInMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(defaultMode))
	}
	if mode != builtinModeGoCQ && mode != builtinModeLagrange {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("built-in OneBot configuration: unsupported mode %q", mode)
	}
	account := normalizeBuiltinAccount(input.Account)
	accountHint := normalizeBuiltinAccount(input.AccountHint)
	if account == "" {
		account = accountHint
	}
	if input.Account != "" && input.AccountHint != "" && account != accountHint {
		return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: account aliases conflict")
	}
	if err := validateBuiltinAccount(account); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if input.Protocol < 0 || input.Protocol > 6 {
		return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: protocol is invalid")
	}
	if err := validateBuiltinText(input.AppVersion, "appVersion", 128); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if err := validateBuiltinText(input.SignServerName, "signServerName", 1024); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if err := validateBuiltinText(input.SignServerVersion, "signServerVersion", 128); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	if input.IgnoreFriendRequest != nil &&
		input.IgnoreFriendLegacy != nil &&
		*input.IgnoreFriendRequest != *input.IgnoreFriendLegacy {
		return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: friend request aliases conflict")
	}
	policy := strings.ToLower(strings.TrimSpace(input.FriendRequestPolicy))
	if policy != "" &&
		policy != "accept" &&
		policy != "ignore" &&
		policy != "manual" &&
		policy != "deny" {
		return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: friend request policy is invalid")
	}
	if input.IgnoreFriendRequest != nil || input.IgnoreFriendLegacy != nil {
		ignore := input.IgnoreFriendRequest
		if ignore == nil {
			ignore = input.IgnoreFriendLegacy
		}
		boolPolicy := "accept"
		if *ignore {
			boolPolicy = "ignore"
		}
		if policy != "" && policy != boolPolicy {
			return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: friend request policy aliases conflict")
		}
		if policy == "" {
			policy = boolPolicy
		}
	}
	if policy == "" {
		policy = "accept"
	}
	ignoreFriendRequest := policy == "ignore"
	imageBase := strings.TrimRight(strings.TrimSpace(input.ImageAssetBaseURL), "/")
	if imageBase != "" {
		if err := validateOnebotHTTPURL(imageBase); err != nil {
			return adapterapi.ValidatedConfig{}, fmt.Errorf("built-in OneBot configuration: invalid image asset base URL: %w", err)
		}
	}
	if len(input.SignServerConfig) > 0 && !bytes.Equal(bytes.TrimSpace(input.SignServerConfig), []byte("null")) {
		return adapterapi.ValidatedConfig{}, errors.New("built-in OneBot configuration: signServerConfig is not supported; use signServerName and signServerVersion")
	}
	password, passwordRef, err := parseBuiltinSecret(input.Password, "password")
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	canonical := builtinOnebotCanonicalConfig{
		Mode:                builtinOnebotMode,
		BuiltInMode:         mode,
		Account:             account,
		Password:            password,
		Protocol:            input.Protocol,
		AppVersion:          strings.TrimSpace(input.AppVersion),
		UseSignServer:       input.UseSignServer,
		SignServerName:      strings.TrimSpace(input.SignServerName),
		SignServerVersion:   strings.TrimSpace(input.SignServerVersion),
		IgnoreFriendRequest: ignoreFriendRequest,
		ImageAssetBaseURL:   imageBase,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("built-in OneBot canonical config: %w", err)
	}
	canonicalJSON, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	refs := []adapterapi.SecretRef(nil)
	if passwordRef != nil {
		refs = []adapterapi.SecretRef{{Ref: passwordRef.SecretRef, Version: passwordRef.Version}}
	}
	validated := adapterapi.ValidatedConfig{Version: OnebotConfigVersion, Canonical: canonicalJSON, SecretRefs: refs}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}
func normalizeBuiltinAccount(raw string) string {
	value := strings.TrimSpace(raw)
	if len(value) >= 3 && strings.EqualFold(value[:3], "qq:") {
		value = strings.TrimSpace(value[3:])
	}
	return value
}

func validateBuiltinAccount(account string) error {
	if account == "" || strings.TrimSpace(account) != account {
		return errors.New("built-in QQ account is required")
	}
	value, err := strconv.ParseUint(account, 10, 64)
	if err != nil || value == 0 {
		return errors.New("built-in QQ account must be a positive integer")
	}
	return nil
}

func validateBuiltinText(value, name string, limit int) error {
	if strings.TrimSpace(value) != value || len(value) > limit {
		return fmt.Errorf("built-in OneBot configuration: %s is invalid", name)
	}
	return nil
}

func parseBuiltinSecret(raw json.RawMessage, name string) (*builtinSecretReference, *builtinSecretReference, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input struct {
		SecretRef string `json:"secretRef"`
		Ref       string `json:"ref"`
		Version   uint64 `json:"version"`
	}
	if err := decoder.Decode(&input); err != nil {
		return nil, nil, fmt.Errorf("built-in OneBot configuration: %s must be a secret reference", name)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("built-in OneBot configuration: %s must be a secret reference", name)
	}
	if input.SecretRef != "" && input.Ref != "" && input.SecretRef != input.Ref {
		return nil, nil, fmt.Errorf("built-in OneBot configuration: %s references conflict", name)
	}
	if input.SecretRef == "" {
		input.SecretRef = input.Ref
	}
	ref := adapterapi.SecretRef{Ref: strings.TrimSpace(input.SecretRef), Version: input.Version}
	if ref.Ref == "" || ref.Version == 0 {
		return nil, nil, fmt.Errorf("built-in OneBot configuration: %s reference is invalid", name)
	}
	if err := ref.Validate(); err != nil {
		return nil, nil, fmt.Errorf("built-in OneBot configuration: %s reference is invalid: %w", name, err)
	}
	canonical := &builtinSecretReference{SecretRef: ref.Ref, Version: ref.Version}
	return canonical, canonical, nil
}

func decodeBuiltinOnebotCanonical(config adapterapi.ValidatedConfig) (builtinOnebotCanonicalConfig, error) {
	var canonical builtinOnebotCanonicalConfig
	if err := json.Unmarshal(config.Canonical, &canonical); err != nil {
		return builtinOnebotCanonicalConfig{}, err
	}
	if canonical.Mode != builtinOnebotMode || canonical.BuiltInMode == "" {
		return builtinOnebotCanonicalConfig{}, errors.New("not a built-in OneBot config")
	}
	return canonical, nil
}

func isBuiltinOnebotConfig(config adapterapi.ValidatedConfig) bool {
	canonical, err := decodeBuiltinOnebotCanonical(config)
	return err == nil && canonical.Mode == builtinOnebotMode
}

type milkyBuiltinCanonicalConfig struct {
	Version             string `json:"version"`
	Account             string `json:"account"`
	BuiltInMode         string `json:"built_in_mode"`
	SignServerURL       string `json:"sign_server_url,omitempty"`
	IgnoreFriendRequest bool   `json:"ignore_friend_request"`
}

func validateBuiltinMilkyConfig(ctx context.Context, input milkyConfigInput) (adapterapi.ValidatedConfig, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	mode := strings.TrimSpace(input.BuiltInMode)
	if mode != builtinModeMilkyLagrangeV2 && mode != builtinModeMilkyYogurt {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: unsupported built-in mode %q", mode)
	}
	account := normalizeBuiltinAccount(input.Account)
	accountHint := normalizeBuiltinAccount(input.AccountHint)
	if account == "" {
		account = accountHint
	}
	if input.Account != "" && input.AccountHint != "" && account != accountHint {
		return adapterapi.ValidatedConfig{}, errors.New("milky: account aliases conflict")
	}
	if err := validateBuiltinAccount(account); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	signURL := strings.TrimSpace(input.SignServerURL)
	if signURL != "" {
		normalized, err := normalizeMilkyGateway(signURL, "http", "https")
		if err != nil {
			return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: invalid sign server URL: %w", err)
		}
		signURL = normalized
	}
	if len(input.WSGateway) > 0 || len(input.RESTGateway) > 0 || len(input.Token) > 0 {
		return adapterapi.ValidatedConfig{}, errors.New("milky: built-in mode cannot set external gateways or token")
	}
	canonical := milkyBuiltinCanonicalConfig{Version: "1.0", Account: account, BuiltInMode: mode, SignServerURL: signURL, IgnoreFriendRequest: input.IgnoreFriendRequest}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return adapterapi.ValidatedConfig{}, fmt.Errorf("milky: canonical built-in config: %w", err)
	}
	canonicalJSON, err := adapterapi.CanonicalizeJSON(encoded)
	if err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	validated := adapterapi.ValidatedConfig{Version: 1, Canonical: canonicalJSON}
	if err := validated.Validate(); err != nil {
		return adapterapi.ValidatedConfig{}, err
	}
	return validated, nil
}

func decodeBuiltinMilkyCanonical(config adapterapi.ValidatedConfig) (milkyBuiltinCanonicalConfig, error) {
	var canonical milkyBuiltinCanonicalConfig
	if err := json.Unmarshal(config.Canonical, &canonical); err != nil {
		return milkyBuiltinCanonicalConfig{}, err
	}
	if canonical.BuiltInMode == "" {
		return milkyBuiltinCanonicalConfig{}, errors.New("not a built-in Milky config")
	}
	return canonical, nil
}

func isBuiltinMilkyConfig(config adapterapi.ValidatedConfig) bool {
	canonical, err := decodeBuiltinMilkyCanonical(config)
	return err == nil && canonical.BuiltInMode != ""
}

type builtinProcessFile struct {
	Path string
	Data []byte
	Mode os.FileMode
}

type builtinProcessLaunch struct {
	Command          string
	WorkDir          string
	ResourcePath     string
	ReadinessAddress string
	QRCodeFiles      []string
	Files            []builtinProcessFile
	Env              []string
	Transport        adapterapi.AdapterRuntime
}

type builtinProcessRuntime struct {
	capabilities adapterapi.CapabilitySet
	launch       func(context.Context) (builtinProcessLaunch, error)
	resourcePath string
	runStarted   chan struct{}
	runStartOnce sync.Once

	mu          sync.Mutex
	running     bool
	cancel      context.CancelCauseFunc
	transport   adapterapi.AdapterRuntime
	process     *procs.Process
	processDone chan struct{}
	processErr  error
	workDir     string
	qrcodeFiles []string
}

func newBuiltinProcessRuntime(init adapterapi.RuntimeInit, capabilities adapterapi.CapabilitySet, launch func(context.Context) (builtinProcessLaunch, error)) *builtinProcessRuntime {
	return &builtinProcessRuntime{capabilities: capabilities, launch: launch, resourcePath: builtinResourcePath(init.EndpointID, init.Generation), runStarted: make(chan struct{})}
}

func (runtime *builtinProcessRuntime) OwnedResources() adapterapi.OwnedResourceManifest {
	if runtime == nil || runtime.resourcePath == "" {
		return adapterapi.OwnedResourceManifest{}
	}
	manifest, err := adapterapi.CanonicalOwnedResources(adapterapi.OwnedResource{Path: runtime.resourcePath, Kind: adapterapi.OwnedResourceDirectory})
	if err != nil {
		return adapterapi.OwnedResourceManifest{}
	}
	return manifest
}

func (runtime *builtinProcessRuntime) Capabilities() adapterapi.CapabilitySet {
	if runtime == nil {
		return 0
	}
	return runtime.capabilities
}

func (runtime *builtinProcessRuntime) Execute(ctx context.Context, effect adapterapi.OutboundEffect) adapterapi.EffectResult {
	if runtime == nil {
		return adapterapi.TerminalResult("builtin_runtime_unavailable", "built-in runtime unavailable")
	}
	runtime.mu.Lock()
	transport := runtime.transport
	runtime.mu.Unlock()
	if transport == nil {
		return adapterapi.TerminalResult("builtin_runtime_unavailable", "built-in runtime unavailable")
	}
	return transport.Execute(ctx, effect)
}

func (runtime *builtinProcessRuntime) Diagnostics(ctx context.Context) adapterapi.DiagnosticReport {
	if runtime == nil {
		return adapterapi.DiagnosticReport{}
	}
	runtime.mu.Lock()
	transport := runtime.transport
	runtime.mu.Unlock()
	if transport == nil {
		return adapterapi.DiagnosticReport{}
	}
	return transport.Diagnostics(ctx)
}

func (runtime *builtinProcessRuntime) ExecuteAction(ctx context.Context, request adapterapi.ActionRequest) (adapterapi.ActionResult, error) {
	if runtime == nil || request.Kind != adapterapi.ActionKindRequestQRCode {
		return adapterapi.ActionResult{}, adapterapi.ErrUnsupportedAction
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return adapterapi.ActionResult{}, err
		}
		runtime.mu.Lock()
		workDir := runtime.workDir
		candidates := append([]string(nil), runtime.qrcodeFiles...)
		running := runtime.running
		processErr := runtime.processErr
		runStarted := runtime.runStarted
		runtime.mu.Unlock()
		if workDir == "" {
			if processErr != nil {
				return adapterapi.ActionResult{}, fmt.Errorf("built-in QR runtime is unavailable: %w", processErr)
			}
			if !running {
				if runStarted == nil {
					return adapterapi.ActionResult{}, errors.New("built-in QR runtime has not started")
				}
				select {
				case <-runStarted:
					return adapterapi.ActionResult{}, errors.New("built-in QR runtime has not started")
				default:
				}
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-timer.C:
				case <-runStarted:
					timer.Stop()
				case <-ctx.Done():
					timer.Stop()
					return adapterapi.ActionResult{}, ctx.Err()
				}
				continue
			}
		}
		path, data, err := findBuiltinQRCode(workDir, candidates)
		if err == nil {
			mediaType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
			if mediaType == "" {
				mediaType = "image/png"
			}
			return adapterapi.ActionResult{ResultCode: "qr_ready", Artifact: &adapterapi.ActionArtifact{MediaType: mediaType, SafeFilename: "endpoint-qr" + filepath.Ext(path), Plaintext: data}}, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return adapterapi.ActionResult{}, ctx.Err()
		}
	}
}

func (runtime *builtinProcessRuntime) Run(ctx context.Context, core adapterapi.CorePort) (runErr error) {
	if runtime == nil || core == nil {
		return errors.New("built-in runtime or Core port is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	runtime.mu.Lock()
	if runtime.running {
		runtime.mu.Unlock()
		cancel(nil)
		return errors.New("built-in runtime already started")
	}
	runtime.running = true
	runtime.cancel = cancel
	runtime.runStartOnce.Do(func() { close(runtime.runStarted) })
	runtime.mu.Unlock()

	defer func() {
		stopped := errors.Is(context.Cause(runCtx), errBuiltinRuntimeStopped)
		cancel(nil)
		stopErr := runtime.Stop(context.Background())
		if stopped {
			runErr = stopErr
		} else if runErr == nil && stopErr != nil {
			runErr = stopErr
		}
		runtime.mu.Lock()
		runtime.running = false
		runtime.cancel = nil
		runtime.mu.Unlock()
	}()

	launch, err := runtime.launch(runCtx)
	if err != nil {
		return err
	}
	if launch.Transport == nil {
		return errors.New("built-in runtime transport is unavailable")
	}
	if err := os.MkdirAll(launch.WorkDir, 0o700); err != nil {
		return fmt.Errorf("create built-in runtime directory: %w", err)
	}
	for index := range launch.Files {
		file := &launch.Files[index]
		if err := writeBuiltinProcessFile(launch.WorkDir, *file); err != nil {
			clear(file.Data)
			return err
		}
		clear(file.Data)
		file.Data = nil
	}

	process := procs.NewProcess(launch.Command)
	process.Dir = launch.WorkDir
	process.Env = launch.Env
	process.OutputHandler = func(line, _ string) string { return "" }
	if err := process.Start(); err != nil {
		return fmt.Errorf("start built-in process: %w", err)
	}
	processDone := make(chan struct{})
	runtime.mu.Lock()
	runtime.process = process
	runtime.processDone = processDone
	runtime.processErr = nil
	runtime.transport = launch.Transport
	runtime.workDir = launch.WorkDir
	runtime.qrcodeFiles = append([]string(nil), launch.QRCodeFiles...)
	runtime.mu.Unlock()
	go func() {
		err := process.Wait()
		if err == nil {
			err = errors.New("built-in process exited")
		}
		runtime.mu.Lock()
		runtime.processErr = err
		close(processDone)
		runtime.mu.Unlock()
		if runCtx.Err() == nil {
			cancel(err)
		}
	}()
	if err := waitBuiltinPort(runCtx, launch.ReadinessAddress, processDone, runtime); err != nil {
		return err
	}
	runErr = launch.Transport.Run(runCtx, core)
	if runErr == nil && ctx.Err() == nil {
		if processErr := runtime.processError(); processErr != nil {
			return processErr
		}
	}
	return runErr
}

func (runtime *builtinProcessRuntime) Stop(ctx context.Context) error {
	if runtime == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runtime.mu.Lock()
	cancel := runtime.cancel
	transport := runtime.transport
	process := runtime.process
	processDone := runtime.processDone
	runtime.mu.Unlock()
	if cancel != nil {
		cancel(errBuiltinRuntimeStopped)
	}
	var errs []error
	if process != nil && process.Cmd != nil {
		if err := process.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if transport != nil {
		if err := transport.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if processDone != nil {
		select {
		case <-processDone:
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
		}
	}
	return errors.Join(errs...)
}

func writeBuiltinProcessFile(workDir string, file builtinProcessFile) error {
	clean := filepath.Clean(file.Path)
	if file.Path == "" || filepath.IsAbs(file.Path) || clean != file.Path || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.Contains(file.Path, `\`) {
		return errors.New("built-in runtime file path is unsafe")
	}
	mode := file.Mode
	if mode == 0 {
		mode = 0o600
	}
	path := filepath.Join(workDir, filepath.FromSlash(file.Path))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create built-in config directory: %w", err)
	}
	if err := os.WriteFile(path, file.Data, mode); err != nil {
		return fmt.Errorf("write built-in config %q: %w", file.Path, err)
	}
	return nil
}

func waitBuiltinPort(ctx context.Context, address string, processDone <-chan struct{}, runtime *builtinProcessRuntime) error {
	if address == "" {
		return nil
	}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	for {
		if err := ctx.Err(); err != nil {
			if processErr := runtime.processError(); processErr != nil {
				return fmt.Errorf("built-in process exited before readiness: %w", processErr)
			}
			return err
		}
		connection, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-processDone:
			if processErr := runtime.processError(); processErr != nil {
				return fmt.Errorf("built-in process exited before readiness: %w", processErr)
			}
			return errors.New("built-in process exited before readiness")
		case <-deadline.C:
			return fmt.Errorf("built-in process did not listen on %s", address)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (runtime *builtinProcessRuntime) processError() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.processErr
}

func findBuiltinQRCode(workDir string, candidates []string) (string, []byte, error) {
	for _, candidate := range candidates {
		clean := filepath.Clean(candidate)
		if candidate == "" || filepath.IsAbs(candidate) || clean != candidate || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || strings.Contains(candidate, `\`) {
			continue
		}
		path := filepath.Join(workDir, filepath.FromSlash(candidate))
		if data, err := readBuiltinQRCodeFile(path); err == nil {
			return path, data, nil
		}
	}
	entries, err := os.ReadDir(workDir)
	if err != nil {
		return "", nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".png" && ext != ".jpg" && ext != ".jpeg" {
			continue
		}
		path := filepath.Join(workDir, entry.Name())
		if data, readErr := readBuiltinQRCodeFile(path); readErr == nil {
			return path, data, nil
		}
	}
	return "", nil, errors.New("built-in QR code is not ready")
}

func readBuiltinQRCodeFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBuiltinQRCodeBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxBuiltinQRCodeBytes {
		return nil, errors.New("built-in QR code size is invalid")
	}
	return data, nil
}

func builtinResourcePath(endpointID adapterapi.EndpointID, generation uint64) string {
	digest := sha256.Sum256([]byte(endpointID.String() + "\x00" + strconv.FormatUint(generation, 10)))
	return filepath.ToSlash(filepath.Join("endpoints", hex.EncodeToString(digest[:16])))
}

func builtinResourceRoot(root, resourcePath string) string {
	if strings.TrimSpace(root) == "" {
		root = "."
	}
	return filepath.Join(root, filepath.FromSlash(resourcePath))
}

func locateBuiltinExecutable(relative string) (string, error) {
	if relative == "" {
		return "", errors.New("built-in executable path is empty")
	}
	candidates := make([]string, 0, 4)
	if workingDir, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(workingDir, filepath.FromSlash(relative)))
	}
	if executable, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(executable), filepath.FromSlash(relative)))
	}
	if path, err := exec.LookPath(relative); err == nil {
		candidates = append(candidates, path)
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("built-in executable %q was not found", relative)
}

func builtinCommand(executable string) string {
	return strconv.Quote(executable)
}

func builtinSignServerURL(raw string) string {
	if value := strings.TrimSpace(raw); value != "" {
		return value
	}
	if value := strings.TrimSpace(SealSignV3Url); value != "" {
		return value
	}
	return "https://sign.lagrangecore.org/api/sign"
}

func builtinLagrangeSignInfo(version, name string) ([]byte, string) {
	version = strings.TrimSpace(version)
	name = strings.TrimSpace(name)
	if version == "自定义" {
		if parsed, err := url.Parse(name); err == nil && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
			return nil, strings.TrimRight(name, "/")
		}
		return nil, builtinSignServerURL(name)
	}
	var infos []SignInfo
	if json.Unmarshal([]byte(signInfoJson), &infos) == nil {
		var fallbackURL string
		var fallbackAppInfo []byte
		for _, info := range infos {
			if version != "" && info.Version != version {
				continue
			}
			for _, server := range info.Servers {
				if server == nil || server.Ignored || server.Url == "" {
					continue
				}
				if fallbackURL == "" || server.Selected {
					fallbackURL = server.Url
					fallbackAppInfo, _ = json.Marshal(info.Appinfo)
				}
				if name == "" || server.Name == name {
					appInfo, _ := json.Marshal(info.Appinfo)
					return appInfo, server.Url
				}
			}
			if fallbackURL != "" {
				return fallbackAppInfo, fallbackURL
			}
		}
	}
	return nil, builtinSignServerURL("")
}

func resolveBuiltinSecret(ctx context.Context, resolver adapterapi.SecretResolver, ref *builtinSecretReference) (string, error) {
	if ref == nil {
		return "", nil
	}
	if resolver == nil {
		return "", errors.New("built-in runtime secret resolver is unavailable")
	}
	value, err := resolver.Resolve(ctx, adapterapi.SecretRef{Ref: ref.SecretRef, Version: ref.Version})
	if err != nil {
		return "", err
	}
	if value.Version != ref.Version || len(value.Bytes) == 0 {
		clear(value.Bytes)
		return "", errors.New("built-in runtime secret resolution is invalid")
	}
	copyBytes := append([]byte(nil), value.Bytes...)
	clear(value.Bytes)
	secret := string(copyBytes)
	clear(copyBytes)
	return secret, nil
}

func newBuiltinLagrangeRuntime(init adapterapi.RuntimeInit, config builtinOnebotCanonicalConfig) *builtinProcessRuntime {
	capabilities := adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityArtifacts | adapterapi.CapabilityRichMessages
	return newBuiltinProcessRuntime(init, capabilities, func(ctx context.Context) (builtinProcessLaunch, error) {
		port, err := GetRandomFreePort()
		if err != nil {
			return builtinProcessLaunch{}, fmt.Errorf("allocate Lagrange port: %w", err)
		}
		resourcePath := builtinResourcePath(init.EndpointID, init.Generation)
		workDir := builtinResourceRoot(init.ResourceRoot, resourcePath)
		executable, err := locateBuiltinExecutable(filepath.Join("lagrange", "Lagrange.OneBot"))
		if err != nil && runtime.GOOS == "windows" {
			executable, err = locateBuiltinExecutable(filepath.Join("lagrange", "Lagrange.OneBot.exe"))
		}
		if err != nil {
			return builtinProcessLaunch{}, err
		}
		password, err := resolveBuiltinSecret(ctx, init.Secrets, config.Password)
		if err != nil {
			return builtinProcessLaunch{}, fmt.Errorf("resolve Lagrange password: %w", err)
		}
		appInfo, signURL := builtinLagrangeSignInfo(config.SignServerVersion, config.SignServerName)
		conf := strings.ReplaceAll(defaultLagrangeConfig, "{WS端口}", strconv.Itoa(port))
		conf = strings.ReplaceAll(conf, "{NTSignServer地址}", signURL)
		conf = strings.ReplaceAll(conf, "{账号UIN}", config.Account)
		if password != "" {
			conf = strings.Replace(conf, `"Password": ""`, `"Password": `+strconv.Quote(password), 1)
		}
		transport := newOnebotRuntimeWithResources(OnebotConfig{Mode: "client", URL: fmt.Sprintf("ws://127.0.0.1:%d", port), ReverseSuffix: "/ws", AccountHint: config.Account, FriendRequestPolicy: map[bool]string{true: "ignore", false: "accept"}[config.IgnoreFriendRequest], ImageAssetBaseURL: config.ImageAssetBaseURL}, nil, init.ResourceRoot, init.ResourceAccessToken, init.ResourceServeAddress, nil)
		files := []builtinProcessFile{{Path: "appsettings.json", Data: []byte(conf), Mode: 0o600}}
		if len(appInfo) > 0 && string(appInfo) != "null" {
			files = append(files, builtinProcessFile{Path: "appinfo.json", Data: appInfo, Mode: 0o600})
		}
		return builtinProcessLaunch{Command: builtinCommand(executable), WorkDir: workDir, ResourcePath: resourcePath, ReadinessAddress: fmt.Sprintf("127.0.0.1:%d", port), QRCodeFiles: []string{fmt.Sprintf("qr-%s.png", config.Account), "qrcode.png", "qr.png"}, Files: files, Transport: transport}, nil
	})
}

func newBuiltinMilkyRuntime(init adapterapi.RuntimeInit, config milkyBuiltinCanonicalConfig) *builtinProcessRuntime {
	capabilities := adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityArtifacts
	return newBuiltinProcessRuntime(init, capabilities, func(ctx context.Context) (builtinProcessLaunch, error) {
		if err := ctx.Err(); err != nil {
			return builtinProcessLaunch{}, err
		}
		port, err := GetRandomFreePort()
		if err != nil {
			return builtinProcessLaunch{}, fmt.Errorf("allocate Milky port: %w", err)
		}
		resourcePath := builtinResourcePath(init.EndpointID, init.Generation)
		workDir := builtinResourceRoot(init.ResourceRoot, resourcePath)
		executable, err := locateBuiltinExecutable(filepath.Join("milky", config.BuiltInMode))
		if err != nil {
			if runtime.GOOS == "windows" {
				executable, err = locateBuiltinExecutable(filepath.Join("milky", config.BuiltInMode+".exe"))
			}
			if err != nil {
				return builtinProcessLaunch{}, err
			}
		}
		info := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:" + config.Account}, Adapter: &PlatformAdapterMilky{BuiltInMode: config.BuiltInMode}}
		conf := GenerateMilkyConfig(port, builtinSignServerURL(config.SignServerURL), "", info)
		if len(conf) == 0 {
			return builtinProcessLaunch{}, errors.New("milky built-in config generation failed")
		}
		transport := &milkyRuntime{config: milkyCanonicalConfig{Version: "1.0", WSGateway: fmt.Sprintf("ws://127.0.0.1:%d", port), RESTGateway: fmt.Sprintf("http://127.0.0.1:%d", port)}, httpClient: &http.Client{Timeout: 20 * time.Second}, dialer: websocket.DefaultDialer}
		return builtinProcessLaunch{Command: builtinCommand(executable), WorkDir: workDir, ResourcePath: resourcePath, ReadinessAddress: fmt.Sprintf("127.0.0.1:%d", port), QRCodeFiles: []string{"qrcode.png", "qr.png", fmt.Sprintf("qr-%s.png", config.Account)}, Files: []builtinProcessFile{{Path: milkyBuiltInConfigFileName(config.BuiltInMode), Data: conf, Mode: 0o600}}, Transport: transport}, nil
	})
}
func newBuiltinGoCQRuntime(init adapterapi.RuntimeInit, config builtinOnebotCanonicalConfig) *builtinProcessRuntime {
	capabilities := adapterapi.CapabilityLifecycle | adapterapi.CapabilityInbound | adapterapi.CapabilityOutbound | adapterapi.CapabilityActions | adapterapi.CapabilityArtifacts | adapterapi.CapabilityRichMessages
	return newBuiltinProcessRuntime(init, capabilities, func(context.Context) (builtinProcessLaunch, error) {
		return builtinProcessLaunch{}, fmt.Errorf("GoCQ built-in mode %q has no bundled process runtime", config.BuiltInMode)
	})
}
