package adapterapi

import (
	"context"
	"fmt"
	"unicode/utf8"
)

const (
	// MaxCharacterFieldBytes bounds a single character identifier, name, or
	// attribute key.
	MaxCharacterFieldBytes = 4 * 1024
	// MaxCharacterValueBytes bounds a single string attribute value.
	MaxCharacterValueBytes = 256 * 1024
	// MaxCharacterAttributeBytes bounds the aggregate attribute payload.
	MaxCharacterAttributeBytes = 256 * 1024
	// MaxCharacterAttributes bounds the attribute count at one nesting level.
	MaxCharacterAttributes = 1024
	// MaxCharacterAttributeDepth bounds nested attribute values.
	MaxCharacterAttributeDepth = 8
)

// CharacterOperation is a closed enumeration of provider character-sheet
// requests. Provider runtimes translate their native request names into these
// operations; Core validates the operation instead of executing arbitrary
// provider-supplied API names.
type CharacterOperation uint8

const (
	CharacterOperationInvalid CharacterOperation = iota
	CharacterOperationGet
	CharacterOperationSet
	CharacterOperationList
	CharacterOperationNew
	CharacterOperationSave
	CharacterOperationTag
	CharacterOperationUntagAll
	CharacterOperationLoad
	CharacterOperationDelete
)

func (operation CharacterOperation) Valid() bool {
	return operation > CharacterOperationInvalid && operation <= CharacterOperationDelete
}

// CharacterRequest carries the bounded facts of one provider character API
// request. It intentionally has no endpoint, generation, or desired-version
// field: Supervisor binds the fenced requester identity out of band so a
// runtime cannot forge a different endpoint.
//
// The optional presence flags distinguish "absent" from "present but empty" for
// fields whose emptiness is meaningful to the legacy protocol.
type CharacterRequest struct {
	Operation  CharacterOperation `json:"operation"`
	UserID     string             `json:"userId,omitempty"`
	GroupID    string             `json:"groupId,omitempty"`
	Character  string             `json:"character,omitempty"`
	Name       string             `json:"name,omitempty"`
	NameSet    bool               `json:"nameSet,omitempty"`
	SheetType  string             `json:"sheetType,omitempty"`
	SheetSet   bool               `json:"sheetSet,omitempty"`
	Attributes map[string]any     `json:"attributes,omitempty"`
	AttrsSet   bool               `json:"attrsSet,omitempty"`
}

// Validate rejects malformed or oversized character requests before they reach
// the Core-owned character service.
func (request CharacterRequest) Validate() error {
	if !request.Operation.Valid() {
		return fmt.Errorf("%w: character operation", ErrInvalidContract)
	}
	// Identifiers travel as provider ids and never contain whitespace.
	for _, value := range []string{request.UserID, request.GroupID, request.Character} {
		if !validOptionalIdentifier(value) {
			return fmt.Errorf("%w: character identifier", ErrInvalidContract)
		}
	}
	// Names are free-form display text: spaces and non-identifier characters
	// are legitimate, so only encoding and length are bounded.
	for _, value := range []string{request.Name, request.SheetType} {
		if !validCharacterText(value, MaxCharacterFieldBytes) {
			return fmt.Errorf("%w: character text field", ErrInvalidContract)
		}
	}
	if len(request.Attributes) == 0 {
		return nil
	}
	if len(request.Attributes) > MaxCharacterAttributes {
		return fmt.Errorf("%w: character attribute count", ErrInvalidContract)
	}
	budget := byteBudget{limit: MaxCharacterAttributeBytes}
	for key, value := range request.Attributes {
		if !validCharacterText(key, MaxCharacterFieldBytes) || key == "" {
			return fmt.Errorf("%w: character attribute key", ErrInvalidContract)
		}
		if err := budget.add(len(key)); err != nil {
			return err
		}
		if err := validateCharacterAttributeValue(value, 0, &budget); err != nil {
			return err
		}
	}
	return nil
}

// byteBudget bounds text bytes and value count across the entire attribute tree.
type byteBudget struct {
	limit int
	used  int
}

func (budget *byteBudget) add(size int) error {
	budget.used += size
	if budget.used > budget.limit {
		return fmt.Errorf("%w: character attribute payload", ErrInvalidContract)
	}
	return nil
}

// Character names and keys are UTF-8 text, not whitespace-free identifiers.
func validCharacterText(value string, limit int) bool {
	if value == "" {
		return true
	}
	return len(value) <= limit && utf8.ValidString(value)
}

// validateCharacterAttributeValue bounds nested attribute values so a provider
// cannot push an unbounded JSON blob across the Core seam. Strings are bounded
// individually and collectively against the gateway frame budget.
func validateCharacterAttributeValue(value any, depth int, budget *byteBudget) error {
	if depth > MaxCharacterAttributeDepth {
		return fmt.Errorf("%w: character attribute depth", ErrInvalidContract)
	}
	if err := budget.add(1); err != nil {
		return err
	}
	switch typed := value.(type) {
	case nil, bool, float64, int, int64, uint64:
		return nil
	case string:
		if !validCharacterText(typed, MaxCharacterValueBytes) {
			return fmt.Errorf("%w: character attribute value", ErrInvalidContract)
		}
		return budget.add(len(typed))
	case map[string]any:
		if len(typed) > MaxCharacterAttributes {
			return fmt.Errorf("%w: character attribute count", ErrInvalidContract)
		}
		for key, nested := range typed {
			if !validCharacterText(key, MaxCharacterFieldBytes) || key == "" {
				return fmt.Errorf("%w: character attribute key", ErrInvalidContract)
			}
			if err := budget.add(len(key)); err != nil {
				return err
			}
			if err := validateCharacterAttributeValue(nested, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	case []any:
		if len(typed) > MaxCharacterAttributes {
			return fmt.Errorf("%w: character attribute count", ErrInvalidContract)
		}
		for _, nested := range typed {
			if err := validateCharacterAttributeValue(nested, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: character attribute value", ErrInvalidContract)
	}
}

// CharacterSummary is one entry of a character list response.
type CharacterSummary struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SheetType string `json:"sheetType"`
	UpdatedAt int64  `json:"updatedAt"`
}

// CharacterResponse is the provider-neutral result of a CharacterOperation.
// OK reports whether the Core-owned service accepted the request; Error carries
// a bounded human-readable reason when it did not.
type CharacterResponse struct {
	OK            bool               `json:"ok"`
	Error         string             `json:"error,omitempty"`
	ID            string             `json:"id,omitempty"`
	Name          string             `json:"name,omitempty"`
	SheetType     string             `json:"sheetType,omitempty"`
	Attributes    map[string]any     `json:"attributes,omitempty"`
	AttributesSet bool               `json:"attributesSet,omitempty"`
	Action        string             `json:"action,omitempty"`
	BoundGroupID  string             `json:"boundGroupId,omitempty"`
	UnboundGroups []string           `json:"unboundGroups,omitempty"`
	List          []CharacterSummary `json:"list,omitempty"`
}

// CharacterCorePort is an optional capability a CorePort may implement so
// provider runtimes can relay character-sheet requests to the Core-owned
// character service. Runtimes type-assert their CorePort; providers without a
// character concept never call it.
type CharacterCorePort interface {
	HandleCharacter(ctx context.Context, request CharacterRequest) (CharacterResponse, error)
}
