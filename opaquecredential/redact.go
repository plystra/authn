package opaquecredential

import (
	"fmt"
	"io"
	"log/slog"
)

// Shared methods redact nested values, every fmt verb, JSON, text and slog.
// Explicit accessors, not generic serialization, are the delivery/storage API.
type redacted struct{}

func (redacted) String() string   { return "opaquecredential(redacted)" }
func (redacted) GoString() string { return "opaquecredential(redacted)" }
func (redacted) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "opaquecredential(redacted)")
}
func (redacted) MarshalText() ([]byte, error) { return []byte("opaquecredential(redacted)"), nil }
func (redacted) MarshalJSON() ([]byte, error) { return []byte(`"opaquecredential(redacted)"`), nil }
func (redacted) UnmarshalText([]byte) error   { return ErrSerialization }
func (redacted) UnmarshalJSON([]byte) error   { return ErrSerialization }
func (redacted) LogValue() slog.Value         { return slog.StringValue("opaquecredential(redacted)") }
