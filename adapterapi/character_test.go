package adapterapi

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestCharacterRequestValidation(t *testing.T) {
	valid := CharacterRequest{Operation: CharacterOperationGet, UserID: "user-1", GroupID: "channel-1"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := (CharacterRequest{Operation: CharacterOperationInvalid}).Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invalid operation error = %v", err)
	}
	if err := (CharacterRequest{Operation: CharacterOperationSet, UserID: "bad\nid"}).Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("invalid identifier error = %v", err)
	}
	tooDeep := any(map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": map[string]any{"f": map[string]any{"g": map[string]any{"h": map[string]any{"i": "x"}}}}}}}}})
	deepRequest := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: map[string]any{"root": tooDeep}, AttrsSet: true}
	if err := deepRequest.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("deep attribute error = %v", err)
	}
	wide := make(map[string]any, MaxCharacterAttributes+1)
	for i := 0; i <= MaxCharacterAttributes; i++ {
		wide["k"+strconv.Itoa(i)] = float64(i)
	}
	wideRequest := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: wide, AttrsSet: true}
	if err := wideRequest.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("wide attribute error = %v", err)
	}
	unsupportedValue := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: map[string]any{"bad": struct{}{}}, AttrsSet: true}
	if err := unsupportedValue.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("unsupported attribute value error = %v", err)
	}
	allowed := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: map[string]any{"nested": map[string]any{"list": []any{float64(1), "two", true}}}, AttrsSet: true}
	if err := allowed.Validate(); err != nil {
		t.Fatalf("nested attribute rejected: %v", err)
	}
}

func TestCharacterRequestAllowsFreeTextNamesAndKeys(t *testing.T) {
	// Display names and skill keys legitimately contain spaces and punctuation.
	request := CharacterRequest{
		Operation: CharacterOperationSet, UserID: "user-1", GroupID: "channel-1",
		Name: "John Smith (Jr.)", NameSet: true, SheetType: "Call of Cthulhu 7e", SheetSet: true,
		Attributes: map[string]any{"Close Combat (Brawl)": float64(45), "母语": "英语"}, AttrsSet: true,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("free-text request rejected: %v", err)
	}
	emptyKey := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: map[string]any{"": float64(1)}, AttrsSet: true}
	if err := emptyKey.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("empty attribute key error = %v", err)
	}
	oversizedValue := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1", Attributes: map[string]any{"k": strings.Repeat("x", MaxCharacterValueBytes+1)}, AttrsSet: true}
	if err := oversizedValue.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("oversized attribute value error = %v", err)
	}
	aggregate := CharacterRequest{Operation: CharacterOperationSet, UserID: "user-1"}
	aggregate.Attributes = map[string]any{}
	for i := range MaxCharacterAttributes {
		aggregate.Attributes["k"+strconv.Itoa(i)] = strings.Repeat("x", MaxCharacterAttributeBytes/MaxCharacterAttributes+16)
	}
	if err := aggregate.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("aggregate attribute payload error = %v", err)
	}
	oversizedName := CharacterRequest{Operation: CharacterOperationNew, UserID: "user-1", Name: strings.Repeat("n", MaxCharacterFieldBytes+1), NameSet: true}
	if err := oversizedName.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("oversized name error = %v", err)
	}
}

func TestCharacterRequestBoundsAggregateNumericValues(t *testing.T) {
	values := make([]any, MaxCharacterAttributes)
	for index := range values {
		values[index] = float64(index)
	}
	request := CharacterRequest{
		Operation:  CharacterOperationSet,
		UserID:     "user-1",
		Attributes: make(map[string]any, MaxCharacterAttributes),
		AttrsSet:   true,
	}
	for index := range MaxCharacterAttributes {
		request.Attributes[strconv.Itoa(index)] = values
	}
	if err := request.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Fatalf("aggregate numeric payload error = %v", err)
	}
}

func TestCharacterOperationValid(t *testing.T) {
	for _, operation := range []CharacterOperation{
		CharacterOperationGet, CharacterOperationSet, CharacterOperationList, CharacterOperationNew,
		CharacterOperationSave, CharacterOperationTag, CharacterOperationUntagAll, CharacterOperationLoad, CharacterOperationDelete,
	} {
		if !operation.Valid() {
			t.Fatalf("operation %d should be valid", operation)
		}
	}
	if CharacterOperation(0).Valid() || CharacterOperation(99).Valid() {
		t.Fatal("out-of-range operations must be invalid")
	}
}
