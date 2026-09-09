package adapterapi

import "fmt"

const (
	MaxDiagnosticEntries     = 64
	MaxDiagnosticFields      = 32
	MaxDiagnosticCodeBytes   = 256
	MaxDiagnosticMessageBytes = 8 * 1024
	MaxDiagnosticValueBytes  = 4 * 1024
)

// DiagnosticSeverity is a closed severity vocabulary.
type DiagnosticSeverity uint8

const (
	DiagnosticSeverityInvalid DiagnosticSeverity = iota
	DiagnosticInfo
	DiagnosticWarning
	DiagnosticError
)

func (severity DiagnosticSeverity) Valid() bool {
	return severity >= DiagnosticInfo && severity <= DiagnosticError
}

// DiagnosticField is already redacted provider metadata. Sensitive values must
// be represented by Value="[REDACTED]" and Redacted=true before crossing the
// seam; the contract has no raw-value escape hatch.
type DiagnosticField struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Redacted bool   `json:"redacted"`
}

// DiagnosticEntry is bounded, secret-free status information.
type DiagnosticEntry struct {
	Severity DiagnosticSeverity `json:"severity"`
	Code     string             `json:"code"`
	Message  string             `json:"message"`
	Fields   []DiagnosticField  `json:"fields,omitempty"`
}

// DiagnosticReport is a bounded snapshot. Implementations should return a
// stable snapshot rather than a live logger or SDK object.
type DiagnosticReport struct {
	Entries []DiagnosticEntry `json:"entries"`
}

func RedactedDiagnosticField(key string) DiagnosticField {
	return DiagnosticField{Key: key, Value: "[REDACTED]", Redacted: true}
}

func (report DiagnosticReport) Validate() error {
	if len(report.Entries) > MaxDiagnosticEntries {
		return fmt.Errorf("%w: diagnostic entry limit exceeded", ErrInvalidContract)
	}
	for _, entry := range report.Entries {
		if !entry.Severity.Valid() || len(entry.Code) == 0 || len(entry.Code) > MaxDiagnosticCodeBytes || len(entry.Message) > MaxDiagnosticMessageBytes || len(entry.Fields) > MaxDiagnosticFields {
			return fmt.Errorf("%w: invalid diagnostic entry", ErrInvalidContract)
		}
		for _, field := range entry.Fields {
			if len(field.Key) == 0 || len(field.Key) > MaxDiagnosticCodeBytes || len(field.Value) > MaxDiagnosticValueBytes {
				return fmt.Errorf("%w: diagnostic field exceeds bounds", ErrInvalidContract)
			}
			if field.Redacted && field.Value != "[REDACTED]" {
				return fmt.Errorf("%w: redacted diagnostic field is not redacted", ErrInvalidContract)
			}
		}
	}
	return nil
}
