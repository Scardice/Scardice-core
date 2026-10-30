package attributestate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"Scardice-core/eventstore"
)

const (
	AggregateType                = "attributes"
	ProjectionName               = "attributes"
	ProjectionVersion            = "v1"
	EventSchemaVersion    uint16 = 1
	EventBaselineImported        = "attributes.baseline_imported"
	EventSnapshotReplaced        = "attributes.snapshot_replaced"
)

var (
	ErrInvalidIdentity       = errors.New("attributestate: invalid identity")
	ErrInvalidEvent          = errors.New("attributestate: invalid event")
	ErrInvalidState          = errors.New("attributestate: invalid state")
	ErrRepositoryUnavailable = errors.New("attributestate: repository unavailable")
	// ErrSecretUnavailable distinguishes a missing snapshot secret from a missing attribute stream.
	ErrSecretUnavailable = errors.New("attributestate: snapshot secret unavailable")
)

type State struct {
	Version           uint64 `json:"version"`
	DiceID            string `json:"diceId"`
	ID                string `json:"id"`
	AttrsType         string `json:"attrsType,omitempty"`
	BindingSheetID    string `json:"bindingSheetId,omitempty"`
	Name              string `json:"name,omitempty"`
	OwnerID           string `json:"ownerId,omitempty"`
	SheetType         string `json:"sheetType,omitempty"`
	Hidden            bool   `json:"hidden"`
	SecretRef         string `json:"secretRef"`
	SecretVersion     uint64 `json:"secretVersion"`
	CreatedAt         int64  `json:"createdAt,omitempty"`
	UpdatedAt         int64  `json:"updatedAt,omitempty"`
	PrivacySubjectKey []byte `json:"-"`
}

type BaselineImportedV1 struct {
	DiceID         string `json:"diceId"`
	ID             string `json:"id"`
	AttrsType      string `json:"attrsType,omitempty"`
	BindingSheetID string `json:"bindingSheetId,omitempty"`
	Name           string `json:"name,omitempty"`
	OwnerID        string `json:"ownerId,omitempty"`
	SheetType      string `json:"sheetType,omitempty"`
	Hidden         bool   `json:"hidden"`
	SecretRef      string `json:"secretRef"`
	SecretVersion  uint64 `json:"secretVersion"`
	CreatedAt      int64  `json:"createdAt,omitempty"`
	UpdatedAt      int64  `json:"updatedAt,omitempty"`
}

func Stream(diceID, id string) eventstore.StreamID {
	if !validPart(diceID) || !validPart(id) {
		return eventstore.StreamID{AggregateType: AggregateType}
	}
	aggregateID := fmt.Sprintf("%d:%s%d:%s", len(diceID), diceID, len(id), id)
	if len(aggregateID) > 255 {
		return eventstore.StreamID{AggregateType: AggregateType}
	}
	return eventstore.StreamID{AggregateType: AggregateType, AggregateID: aggregateID}
}

func NewBaselineImportedV1(state State) BaselineImportedV1 {
	return BaselineImportedV1{
		DiceID: state.DiceID, ID: state.ID, AttrsType: state.AttrsType,
		BindingSheetID: state.BindingSheetID, Name: state.Name, OwnerID: state.OwnerID,
		SheetType: state.SheetType, Hidden: state.Hidden, SecretRef: state.SecretRef,
		SecretVersion: state.SecretVersion, CreatedAt: state.CreatedAt, UpdatedAt: state.UpdatedAt,
	}
}

func MarshalBaselineImportedV1(event BaselineImportedV1) ([]byte, error) {
	if err := validateBaseline(event); err != nil {
		return nil, err
	}
	return json.Marshal(event)
}

func DecodeBaselineImportedV1(payload []byte) (BaselineImportedV1, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var event BaselineImportedV1
	if err := decoder.Decode(&event); err != nil {
		return BaselineImportedV1{}, ErrInvalidEvent
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return BaselineImportedV1{}, ErrInvalidEvent
	}
	if err := validateBaseline(event); err != nil {
		return BaselineImportedV1{}, err
	}
	return event, nil
}

func Apply(state State, event BaselineImportedV1) (State, error) {
	if err := validateBaseline(event); err != nil {
		return State{}, err
	}
	if state.Version != 0 && (state.DiceID != event.DiceID || state.ID != event.ID || state.SecretRef != event.SecretRef || event.SecretVersion != state.SecretVersion+1) {
		return State{}, ErrInvalidState
	}
	version := state.Version + 1
	return State{
		Version: version, DiceID: event.DiceID, ID: event.ID, AttrsType: event.AttrsType,
		BindingSheetID: event.BindingSheetID, Name: event.Name, OwnerID: event.OwnerID,
		SheetType: event.SheetType, Hidden: event.Hidden, SecretRef: event.SecretRef,
		SecretVersion: event.SecretVersion, CreatedAt: event.CreatedAt, UpdatedAt: event.UpdatedAt,
	}, nil
}

func ValidateState(state State) error {
	if state.Version == 0 || state.SecretVersion != state.Version {
		return ErrInvalidState
	}
	return validateBaseline(NewBaselineImportedV1(state))
}

func validateBaseline(event BaselineImportedV1) error {
	if Stream(event.DiceID, event.ID).AggregateID == "" || !validPart(event.SecretRef) || event.SecretVersion == 0 {
		return ErrInvalidIdentity
	}
	if len(event.AttrsType) > 64 || len(event.BindingSheetID) > 255 || len(event.Name) > 1024 || len(event.OwnerID) > 255 || len(event.SheetType) > 255 {
		return ErrInvalidEvent
	}
	return nil
}

func validPart(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 255 && !strings.ContainsRune(value, '\x00')
}
