package quickjs_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"Scardice-core/utils/jsengine"
	legacyquickjs "Scardice-core/utils/jsengine/quickjs"
	"Scardice-core/utils/jsengine/native"
)

type corpusEntry struct {
	Filename string `json:"filename"`
	Kind     string `json:"kind"`
	Source   string `json:"source"`
}

type corpusFixture struct {
	Name               string        `json:"name"`
	Entries            []corpusEntry  `json:"entries"`
	Observe            string        `json:"observe"`
	Pump               string        `json:"pump"`
	WaitMS             int           `json:"waitMS"`
	Host               bool          `json:"host"`
	ExpectError        bool          `json:"expectError"`
	RequiresCapability string        `json:"requiresCapability"`
}

type corpusObservation struct {
	Status        string
	Result        string
	ErrorCategory string
	ErrorMessage  string
	StackPresent  bool
	Filename      string
	HostCalls     int
	HostEvents    string
	Note          string
}

type corpusExtensionHost struct {
	Calls  int
	Events []string
}

func (h *corpusExtensionHost) Register(name string) bool {
	h.Calls++
	h.Events = append(h.Events, "register:"+name)
	return name == "parity-extension"
}

func (h *corpusExtensionHost) Dispatch(callback func(string) string, value string) string {
	h.Events = append(h.Events, "dispatch:start")
	result := callback(value)
	h.Events = append(h.Events, "dispatch:end")
	return result
}

type corpusSealHost struct {
	Version string             `jsbind:"version"`
	Ext     *corpusExtensionHost `jsbind:"ext"`
}

func loadCorpus(t *testing.T) []corpusFixture {
	t.Helper()
	entries, err := os.ReadDir("testdata/corpus")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := make([]corpusFixture, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join("testdata/corpus", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var fixture corpusFixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		if fixture.Name == "" || len(fixture.Entries) == 0 || fixture.Observe == "" {
			t.Fatalf("%s: incomplete fixture", entry.Name())
		}
		fixtures = append(fixtures, fixture)
	}
	sort.Slice(fixtures, func(i, j int) bool { return fixtures[i].Name < fixtures[j].Name })
	return fixtures
}

func entryKind(raw string) (jsengine.EntryKind, error) {
	switch raw {
	case "script":
		return jsengine.EntryScript, nil
	case "commonjs":
		return jsengine.EntryCommonJS, nil
	case "esm":
		return jsengine.EntryESModule, nil
	case "extension":
		return jsengine.EntryExtension, nil
	default:
		return 0, fmt.Errorf("unknown corpus entry kind %q", raw)
	}
}

func corpusErrorCategory(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, native.ErrNativeTimeout) || strings.Contains(strings.ToLower(err.Error()), "timeout") {
		return "timeout"
	}
	if errors.Is(err, native.ErrNativeHost) {
		return "host"
	}
	return "javascript"
}
func corpusErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	raw := err.Error()
	if marker := strings.Index(raw, "Error:"); marker >= 0 {
		raw = raw[marker+len("Error:"):]
	}
	if line := strings.IndexByte(raw, '\n'); line >= 0 {
		raw = raw[:line]
	}
	return strings.TrimSpace(raw)
}

var stackLine = regexp.MustCompile(`(?:^|\n)\s*at\s+[^\n]+`)

func runCorpusFixture(t *testing.T, fixture corpusFixture, open func(*testing.T) (jsengine.Loop, jsengine.Descriptor), start bool) corpusObservation {
	t.Helper()
	loop, descriptor := open(t)
	if fixture.RequiresCapability != "" {
		_ = loop.Close()
		return corpusObservation{Status: "unsupported", Note: fmt.Sprintf("capability %q is not advertised by %s (%d)", fixture.RequiresCapability, descriptor.ID, descriptor.Capabilities)}
	}
	defer loop.Close()
	if start {
		if err := legacyquickjs.Start(loop); err != nil {
			return corpusObservation{Status: "error", ErrorCategory: corpusErrorCategory(err), Note: err.Error()}
		}
	}
	var host *corpusExtensionHost
	if fixture.Host {
		host = &corpusExtensionHost{}
		if err := loop.Run(func(runtime jsengine.Runtime) error {
			return runtime.Bind("seal", &corpusSealHost{Version: "14.0.0", Ext: host})
		}); err != nil {
			return corpusObservation{Status: "error", ErrorCategory: corpusErrorCategory(err), Note: err.Error()}
		}
	}

	var runErr error
	for _, raw := range fixture.Entries {
		kind, err := entryKind(raw.Kind)
		if err != nil {
			return corpusObservation{Status: "error", ErrorCategory: "fixture", Note: err.Error()}
		}
		runErr = loop.LoadEntry(jsengine.Entry{Filename: raw.Filename, Source: raw.Source, Kind: kind})
		if runErr != nil {
			break
		}
	}
	if fixture.WaitMS > 0 {
		time.Sleep(time.Duration(fixture.WaitMS) * time.Millisecond)
	}
	if runErr == nil && fixture.Pump != "" {
		runErr = loop.Run(func(runtime jsengine.Runtime) error {
			_, err := runtime.RunString(fixture.Name+"-pump.js", fixture.Pump)
			return err
		})
	}

	observation := corpusObservation{Status: "ok"}
	if runErr != nil {
		observation.Status = "error"
		observation.ErrorCategory = corpusErrorCategory(runErr)
		observation.ErrorMessage = corpusErrorMessage(runErr)
		observation.StackPresent = stackLine.MatchString(runErr.Error())
		observation.Filename = fixture.Entries[len(fixture.Entries)-1].Filename
		if !strings.Contains(runErr.Error(), observation.Filename) {
			observation.Filename = ""
		}
		observation.Note = runErr.Error()
	}
	var observed string
	observeErr := loop.Run(func(runtime jsengine.Runtime) error {
		value, err := runtime.RunString(fixture.Name+"-observe.js", fixture.Observe)
		if err != nil {
			return err
		}
		primitive, err := value.ExportPrimitive()
		if err != nil {
			return err
		}
		var ok bool
		observed, ok = primitive.(string)
		if !ok {
			return fmt.Errorf("observer returned %T, want string", primitive)
		}
		return nil
	})
	if observeErr != nil {
		if runErr == nil {
			observation.Status = "error"
			observation.ErrorCategory = corpusErrorCategory(observeErr)
			observation.ErrorMessage = corpusErrorMessage(observeErr)
			observation.StackPresent = stackLine.MatchString(observeErr.Error())
			observation.Note = observeErr.Error()
		}
	} else {
		observation.Result = observed
	}
	if host != nil {
		observation.HostCalls = host.Calls
		observation.HostEvents = strings.Join(host.Events, ",")
		hostNote := fmt.Sprintf("host calls=%d events=%s", host.Calls, observation.HostEvents)
		if observation.Note == "" {
			observation.Note = hostNote
		} else {
			observation.Note += "; " + hostNote
		}
	}
	return observation
}

func openLegacyCorpus(t *testing.T) (jsengine.Loop, jsengine.Descriptor) {
	t.Helper()
	loop, err := legacyquickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	return loop, loop.Descriptor()
}

func openNativeCorpus(t *testing.T) (jsengine.Loop, jsengine.Descriptor) {
	t.Helper()
	root := os.Getenv("SCARDICE_QUICKJS_PACKAGE")
	if root == "" {
		t.Skip("SCARDICE_QUICKJS_PACKAGE is not set; native parity provider is unavailable")
	}
	candidates, err := native.Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("Discover returned %d candidates, want one", len(candidates))
	}
	provider, err := candidates[0].Load()
	if err != nil {
		t.Fatal(err)
	}
	loop, err := provider.Open(context.Background(), jsengine.RuntimeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return loop, loop.Descriptor()
}

func TestQuickJSBlackBoxCorpusParity(t *testing.T) {
	fixtures := loadCorpus(t)
	if os.Getenv("SCARDICE_QUICKJS_PACKAGE") == "" {
		t.Skip("SCARDICE_QUICKJS_PACKAGE is not set; native parity provider is unavailable")
	}
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			legacy := runCorpusFixture(t, fixture, openLegacyCorpus, true)
			native := runCorpusFixture(t, fixture, openNativeCorpus, false)
			t.Logf("matrix fixture=%s legacy=%+v native=%+v", fixture.Name, legacy, native)
			if legacy.Status != native.Status ||
				legacy.Result != native.Result ||
				legacy.ErrorCategory != native.ErrorCategory ||
				legacy.ErrorMessage != native.ErrorMessage ||
				legacy.StackPresent != native.StackPresent ||
				legacy.Filename != native.Filename ||
				legacy.HostCalls != native.HostCalls ||
				legacy.HostEvents != native.HostEvents {
				t.Fatalf("observable divergence: legacy=%+v native=%+v", legacy, native)
			}
			if fixture.ExpectError {
				filename := fixture.Entries[len(fixture.Entries)-1].Filename
				for provider, observation := range map[string]corpusObservation{"legacy": legacy, "native": native} {
					if observation.Status != "error" || observation.ErrorCategory != "javascript" || !observation.StackPresent || !strings.Contains(observation.Note, filename) {
						t.Fatalf("%s missing source-located JavaScript error %q: %+v", provider, filename, observation)
					}
				}
			}
		})
	}
}
