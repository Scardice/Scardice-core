package managerstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	"Scardice-core/eventstore"
)

const (
	AggregateType                = "manager"
	AggregateID                  = "global"
	ProjectionName               = "manager"
	ProjectionVersion            = "v1"
	EventSchemaVersion    uint16 = 1
	EventBaselineImported        = "manager.baseline_imported"
	EventSnapshotReplaced        = "manager.snapshot_replaced"
	AuthSecretRef                = "vault:manager-auth"
)

var (
	ErrInvalidEvent          = errors.New("managerstate: invalid event")
	ErrInvalidState          = errors.New("managerstate: invalid state")
	ErrRepositoryUnavailable = errors.New("managerstate: repository unavailable")
)

type BackupCleanConfig struct {
	Strategy     int    `json:"strategy"`
	KeepCount    int    `json:"keepCount"`
	KeepDuration int64  `json:"keepDuration"`
	Trigger      int    `json:"trigger"`
	Cron         string `json:"cron,omitempty"`
}

type PublicConfig struct {
	ServeAddress        string            `json:"serveAddress,omitempty"`
	TrayTooltip         string            `json:"trayTooltip,omitempty"`
	WebUIAddress        string            `json:"webUIAddress,omitempty"`
	HelpDocEngineType   int               `json:"helpDocEngineType"`
	DiceRandomMode      string            `json:"diceRandomMode,omitempty"`
	AutoBackupEnable    bool              `json:"autoBackupEnable"`
	AutoBackupTime      string            `json:"autoBackupTime,omitempty"`
	AutoBackupSelection uint64            `json:"autoBackupSelection"`
	BackupClean         BackupCleanConfig `json:"backupClean"`
	ServiceName         string            `json:"serviceName,omitempty"`
	ConfigVersion       int               `json:"configVersion"`
	DiceDataDirs        map[string]string `json:"diceDataDirs,omitempty"`
}

type Auth struct {
	UIPasswordSalt string   `json:"uiPasswordSalt"`
	UIPasswordHash string   `json:"uiPasswordHash"`
	AccessTokens   []string `json:"accessTokens,omitempty"`
}

type State struct {
	Version           uint64       `json:"version"`
	Public            PublicConfig `json:"public"`
	AuthSecretRef     string       `json:"authSecretRef"`
	AuthSecretVersion uint64       `json:"authSecretVersion"`
}

type SnapshotV1 struct {
	Public            PublicConfig `json:"public"`
	AuthSecretRef     string       `json:"authSecretRef"`
	AuthSecretVersion uint64       `json:"authSecretVersion"`
}

func Stream() eventstore.StreamID {
	return eventstore.StreamID{AggregateType: AggregateType, AggregateID: AggregateID}
}

func NewSnapshotV1(public PublicConfig, secretVersion uint64) SnapshotV1 {
	return SnapshotV1{Public: public, AuthSecretRef: AuthSecretRef, AuthSecretVersion: secretVersion}
}

func MarshalSnapshotV1(event SnapshotV1) ([]byte, error) {
	if err := validateSnapshot(event); err != nil {
		return nil, err
	}
	return json.Marshal(event)
}

func DecodeSnapshotV1(payload []byte) (SnapshotV1, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var event SnapshotV1
	if err := decoder.Decode(&event); err != nil {
		return SnapshotV1{}, ErrInvalidEvent
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return SnapshotV1{}, ErrInvalidEvent
	}
	if err := validateSnapshot(event); err != nil {
		return SnapshotV1{}, err
	}
	return event, nil
}

func Apply(state State, event SnapshotV1) (State, error) {
	if err := validateSnapshot(event); err != nil {
		return State{}, err
	}
	if state.Version != 0 && (event.AuthSecretRef != state.AuthSecretRef || event.AuthSecretVersion != state.AuthSecretVersion+1) {
		return State{}, ErrInvalidState
	}
	return State{Version: state.Version + 1, Public: event.Public, AuthSecretRef: event.AuthSecretRef, AuthSecretVersion: event.AuthSecretVersion}, nil
}

func ValidateState(state State) error {
	if state.Version == 0 || state.AuthSecretVersion != state.Version {
		return ErrInvalidState
	}
	return validateSnapshot(SnapshotV1{Public: state.Public, AuthSecretRef: state.AuthSecretRef, AuthSecretVersion: state.AuthSecretVersion})
}

func NormalizeAuth(auth Auth) Auth {
	auth.AccessTokens = append([]string(nil), auth.AccessTokens...)
	sort.Strings(auth.AccessTokens)
	return auth
}

func MarshalAuth(auth Auth) ([]byte, error) {
	auth = NormalizeAuth(auth)
	for _, token := range auth.AccessTokens {
		if strings.TrimSpace(token) == "" || strings.ContainsRune(token, '\x00') {
			return nil, ErrInvalidEvent
		}
	}
	return json.Marshal(auth)
}

func DecodeAuth(payload []byte) (Auth, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var auth Auth
	if err := decoder.Decode(&auth); err != nil {
		return Auth{}, ErrInvalidEvent
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Auth{}, ErrInvalidEvent
	}
	canonical, err := MarshalAuth(auth)
	if err != nil {
		return Auth{}, err
	}
	if err = json.Unmarshal(canonical, &auth); err != nil {
		return Auth{}, err
	}
	return auth, nil
}

func validateSnapshot(event SnapshotV1) error {
	if event.AuthSecretRef != AuthSecretRef || event.AuthSecretVersion == 0 {
		return ErrInvalidEvent
	}
	if len(event.Public.ServeAddress) > 1024 || len(event.Public.TrayTooltip) > 1024 || len(event.Public.WebUIAddress) > 1024 || len(event.Public.DiceRandomMode) > 64 || len(event.Public.AutoBackupTime) > 1024 || len(event.Public.BackupClean.Cron) > 1024 || len(event.Public.ServiceName) > 1024 {
		return ErrInvalidEvent
	}
	for diceID, dataDir := range event.Public.DiceDataDirs {
		if strings.TrimSpace(diceID) == "" || strings.TrimSpace(dataDir) == "" ||
			len(diceID) > 1024 || len(dataDir) > 4096 ||
			strings.ContainsRune(diceID, '\x00') || strings.ContainsRune(dataDir, '\x00') {
			return ErrInvalidEvent
		}
	}
	return nil
}
