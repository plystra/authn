package accountstore

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[REDACTED accountstore]"

func (StageRegistrationRequest) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (StageRegistrationRequest) String() string               { return redacted }
func (StageRegistrationRequest) GoString() string             { return redacted }
func (StageRegistrationRequest) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (StageRegistrationRequest) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
func (StageRegistrationRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

func (StageRegistrationResult) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (StageRegistrationResult) String() string               { return redacted }
func (StageRegistrationResult) GoString() string             { return redacted }
func (StageRegistrationResult) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (StageRegistrationResult) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
func (StageRegistrationResult) LogValue() slog.Value { return slog.StringValue(redacted) }

func (FindRegistrationRequest) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (FindRegistrationRequest) String() string               { return redacted }
func (FindRegistrationRequest) GoString() string             { return redacted }
func (FindRegistrationRequest) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (FindRegistrationRequest) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
func (FindRegistrationRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

func (Registration) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (Registration) String() string               { return redacted }
func (Registration) GoString() string             { return redacted }
func (Registration) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Registration) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Registration) LogValue() slog.Value         { return slog.StringValue(redacted) }

func (PasswordForEmailRequest) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (PasswordForEmailRequest) String() string               { return redacted }
func (PasswordForEmailRequest) GoString() string             { return redacted }
func (PasswordForEmailRequest) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (PasswordForEmailRequest) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
func (PasswordForEmailRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

func (PasswordRecord) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, redacted) }
func (PasswordRecord) String() string               { return redacted }
func (PasswordRecord) GoString() string             { return redacted }
func (PasswordRecord) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (PasswordRecord) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (PasswordRecord) LogValue() slog.Value         { return slog.StringValue(redacted) }
