package jsengine

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/golang-module/carbon"
)

// UserScriptDependency is a dependency declaration in a UserScript header.
type UserScriptDependency struct {
	Author     string
	Name       string
	Constraint string
	RawKey     string
}

// UserScriptMetadata is the runtime-neutral result of parsing a UserScript
// metadata block.
type UserScriptMetadata struct {
	Name         string
	Version      string
	Author       string
	License      string
	HomePage     string
	Description  string
	UpdateTime   int64
	UpdateURLs   []string
	Etag         string
	Depends      []UserScriptDependency
	SealVersion  string
	NeedCompiled bool
	StoreID      string
	Runtime      string
}

// RuntimeSelector identifies one explicit runtime preference from @runtime.
type RuntimeSelector struct {
	ID     EngineID
	Author string
}

var (
	errMalformedUserScriptRuntime = errors.New("malformed @runtime selector")
)

// ParseRuntimeSelectors parses comma-separated runtime selectors in the form
// runtimeID:author. Empty items are rejected so typos cannot silently change
// the fallback order.
func ParseRuntimeSelectors(raw string) ([]RuntimeSelector, error) {
	parts := strings.Split(raw, ",")
	selectors := make([]RuntimeSelector, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("%w: empty selector", errMalformedUserScriptRuntime)
		}
		idRaw, author, ok := strings.Cut(part, ":")
		id := NormalizeEngineID(idRaw)
		author = strings.TrimSpace(author)
		if !ok || id == "" || author == "" {
			return nil, fmt.Errorf("%w %q, expected runtimeID:author", errMalformedUserScriptRuntime, part)
		}
		selectors = append(selectors, RuntimeSelector{ID: id, Author: author})
	}
	return selectors, nil
}

// ParseUserScript parses the shared UserScript metadata syntax.
// Scripts without a complete metadata block have empty metadata.
func ParseUserScript(source string) (UserScriptMetadata, error) {
	metadata := UserScriptMetadata{}
	block, ok := userScriptBlock(source)
	if !ok {
		return metadata, nil
	}

	var parseErrors []error
	runtimeSeen := false
	for block != "" {
		line, rest, _ := strings.Cut(block, "\n")
		block = rest
		key, value := userScriptField(line)
		switch key {
		case "name":
			metadata.Name = value
		case "homepageURL":
			metadata.HomePage = value
		case "license":
			metadata.License = value
		case "author":
			metadata.Author = value
		case "version":
			metadata.Version = value
		case "description":
			metadata.Description = strings.ReplaceAll(value, "\\n", "\n")
		case "timestamp":
			if timestamp, err := strconv.ParseInt(value, 10, 64); err == nil {
				metadata.UpdateTime = timestamp
			} else if parsed := carbon.Parse(value); parsed.IsValid() {
				metadata.UpdateTime = parsed.Timestamp()
			}
		case "updateUrl":
			metadata.UpdateURLs = append(metadata.UpdateURLs, value)
		case "etag":
			metadata.Etag = value
		case "depends":
			dependency, err := parseUserScriptDependency(value)
			if err != nil {
				parseErrors = append(parseErrors, fmt.Errorf("插件「%s」指定依赖格式不正确，应为 作者:插件名:[SemVer版本约束，可选]，现为「%s」", metadata.Name, value))
				continue
			}
			metadata.Depends = append(metadata.Depends, dependency)
		case "sealVersion":
			metadata.SealVersion = value
		case "needCompiled":
			metadata.NeedCompiled = true
		case "storeID":
			metadata.StoreID = value
		case "runtime":
			// Match the first declaration used for provider selection.
			if !runtimeSeen {
				metadata.Runtime = value
				runtimeSeen = true
			}
			if _, err := ParseRuntimeSelectors(value); err != nil {
				parseErrors = append(parseErrors, err)
			}
		}
	}
	return metadata, errors.Join(parseErrors...)
}

func parseUserScriptDependency(raw string) (UserScriptDependency, error) {
	author, name, ok := strings.Cut(raw, ":")
	author = strings.TrimSpace(author)
	name = strings.TrimSpace(name)
	if !ok || author == "" || name == "" {
		return UserScriptDependency{}, errors.New("invalid dependency")
	}
	dependency := UserScriptDependency{Author: author, RawKey: raw}
	if namePart, constraint, ok := strings.Cut(name, ":"); ok {
		namePart = strings.TrimSpace(namePart)
		constraint = strings.TrimSpace(constraint)
		if namePart == "" || constraint == "" {
			return UserScriptDependency{}, errors.New("invalid dependency")
		}
		dependency.Name = namePart
		dependency.Constraint = constraint
		return dependency, nil
	}
	dependency.Name = name
	return dependency, nil
}

// UserScriptRuntimeHint extracts only @runtime from the shared metadata header
// for provider selection, without validating unrelated metadata fields.
func UserScriptRuntimeHint(source string) (string, bool) {
	block, ok := userScriptBlock(source)
	if !ok {
		return "", false
	}
	for block != "" {
		line, rest, _ := strings.Cut(block, "\n")
		block = rest
		if key, value := userScriptField(line); key == "runtime" {
			return value, true
		}
	}
	return "", false
}

func userScriptBlock(source string) (string, bool) {
	blockStart := -1
	for offset := 0; offset < len(source); {
		line, rest, hasNewline := strings.Cut(source[offset:], "\n")
		next := len(source) - len(rest)
		comment, ok := strings.CutPrefix(strings.TrimSpace(line), "//")
		if ok {
			switch strings.TrimSpace(comment) {
			case "==UserScript==":
				if blockStart < 0 && hasNewline {
					blockStart = next
				}
			case "==/UserScript==":
				if blockStart >= 0 {
					return source[blockStart:offset], true
				}
			}
		}
		offset = next
	}
	return "", false
}

func userScriptField(line string) (string, string) {
	comment, ok := strings.CutPrefix(strings.TrimSpace(line), "//")
	if !ok {
		return "", ""
	}
	payload, ok := strings.CutPrefix(strings.TrimSpace(comment), "@")
	if !ok {
		return "", ""
	}
	payload = strings.TrimSpace(payload)
	separator := strings.IndexFunc(payload, unicode.IsSpace)
	if separator < 0 {
		return payload, ""
	}
	return payload[:separator], strings.TrimSpace(payload[separator:])
}
