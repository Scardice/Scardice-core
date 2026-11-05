package eventsourcing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

// decodeLegacyGroupJSONFields reads the historical group_info JSON object
// without constructing the live GroupInfo execution facade. Unknown fields are
// retained in the raw map so each historical consumer can decode the fields it
// owns without relaxing their concrete JSON types.
func decodeLegacyGroupJSONFields(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%w: invalid legacy group JSON text", ErrValidation)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil || fields == nil {
		return nil, fmt.Errorf("%w: invalid legacy group JSON object", ErrValidation)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing legacy group JSON", ErrValidation)
	}
	return fields, nil
}

func legacyGroupJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// legacyGroupJSONDropNulls removes null members. The historical group loader
// (sonic decoding into GroupInfo) leaves a field at its zero value for a JSON
// null, so for a group row null is the same as absent. The scalar helpers stay
// strict because the story-log snapshot decoder shares them and does not
// extend that tolerance.
func legacyGroupJSONDropNulls(fields map[string]json.RawMessage) {
	for name, raw := range fields {
		if legacyGroupJSONNull(raw) {
			delete(fields, name)
		}
	}
}

func legacyGroupJSONString(fields map[string]json.RawMessage, name string) (string, bool, error) {
	raw, exists := fields[name]
	if !exists {
		return "", false, nil
	}
	var value string
	if legacyGroupJSONNull(raw) || json.Unmarshal(raw, &value) != nil {
		return "", false, fmt.Errorf("%w: legacy group field %s is not a string", ErrValidation, name)
	}
	return value, true, nil
}

func legacyGroupJSONBool(fields map[string]json.RawMessage, name string) (bool, bool, error) {
	raw, exists := fields[name]
	if !exists {
		return false, false, nil
	}
	var value bool
	if legacyGroupJSONNull(raw) || json.Unmarshal(raw, &value) != nil {
		return false, false, fmt.Errorf("%w: legacy group field %s is not a boolean", ErrValidation, name)
	}
	return value, true, nil
}

func legacyGroupJSONInt64(fields map[string]json.RawMessage, name string) (int64, bool, error) {
	raw, exists := fields[name]
	if !exists {
		return 0, false, nil
	}
	var value int64
	if legacyGroupJSONNull(raw) || json.Unmarshal(raw, &value) != nil {
		return 0, false, fmt.Errorf("%w: legacy group field %s is not an integer", ErrValidation, name)
	}
	return value, true, nil
}

func legacyGroupJSONInt(fields map[string]json.RawMessage, name string) (int, bool, error) {
	raw, exists := fields[name]
	if !exists {
		return 0, false, nil
	}
	var value int
	if legacyGroupJSONNull(raw) || json.Unmarshal(raw, &value) != nil {
		return 0, false, fmt.Errorf("%w: legacy group field %s is not an integer", ErrValidation, name)
	}
	return value, true, nil
}

func legacyGroupJSONCollection[T any](fields map[string]json.RawMessage, name string) (T, bool, error) {
	var zero T
	raw, exists := fields[name]
	if !exists || legacyGroupJSONNull(raw) {
		return zero, false, nil
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return zero, false, fmt.Errorf("%w: legacy group field %s has invalid shape", ErrValidation, name)
	}
	return value, true, nil
}

// legacyGroupJSONExtensions reads activatedExtList the way the historical
// GroupInfo.UnmarshalJSON did: only each entry's name matters, and entries
// that are null or carry no (or an empty) name are skipped. An entry that is
// not an object, or whose name is not a string, cannot be interpreted and is
// rejected.
func legacyGroupJSONExtensions(fields map[string]json.RawMessage, name string) ([]string, bool, error) {
	items, present, err := legacyGroupJSONCollection[[]json.RawMessage](fields, name)
	if err != nil || !present {
		return nil, present, err
	}
	extensions := make([]string, 0, len(items))
	for index, item := range items {
		if legacyGroupJSONNull(item) {
			continue
		}
		itemFields, decodeErr := decodeLegacyGroupJSONFields(item)
		if decodeErr != nil {
			return nil, false, fmt.Errorf("%w: legacy group field %s[%d] is not an extension object", ErrValidation, name, index)
		}
		legacyGroupJSONDropNulls(itemFields)
		extensionID, _, decodeErr := legacyGroupJSONString(itemFields, "name")
		if decodeErr != nil {
			return nil, false, decodeErr
		}
		if extensionID == "" {
			continue
		}
		extensions = append(extensions, extensionID)
	}
	return extensions, true, nil
}

func legacyGroupJSONStringSet(fields map[string]json.RawMessage, name string) (map[string]bool, bool, error) {
	entries, present, err := legacyGroupJSONCollection[map[string]json.RawMessage](fields, name)
	if err != nil || !present {
		return nil, present, err
	}
	result := make(map[string]bool, len(entries))
	for key, raw := range entries {
		// StringSet is map[string]struct{}: the historical decoder accepts any
		// JSON object (or null) as the zero struct, so the key is a member.
		// A scalar or array marker is a type error there and cannot be
		// interpreted here either.
		if !legacyGroupJSONNull(raw) {
			var marker map[string]json.RawMessage
			if json.Unmarshal(raw, &marker) != nil || marker == nil {
				return nil, false, fmt.Errorf("%w: legacy group field %s[%q] is not a set marker object", ErrValidation, name, key)
			}
		}
		result[key] = true
	}
	return result, true, nil
}
