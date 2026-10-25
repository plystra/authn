// Package credentialinput validates unverified HTTP credential candidates from
// Core context metadata. Parsing grants no identity or authority. The selected
// authentication implementation must reject ambiguous usable credentials and
// verify the chosen credential against authoritative state.
package credentialinput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/plystra/kernel/capability"
	"github.com/plystra/kernel/contextmetadata"
)

// MetadataKey identifies the closed Core HTTP credential metadata schema.
const MetadataKey = "plystra.http-credential-metadata/v1"

// ErrInvalidMetadata contains no credential or rejected input.
var ErrInvalidMetadata = errors.New("invalid HTTP credential metadata")

// Candidates contains immutable, unverified input for one request. Its zero
// value is empty. Formatting and serialization redact all contents. Neither this
// value nor any credential obtained from it may be retained after ctx ends.
type Candidates struct{ value *input }

type input struct {
	ctx         context.Context
	transport   string
	interfaceID string
	bearer      string
	cookies     []cookie
}

type cookie struct{ name, value string }

func (Candidates) String() string   { return "credentialinput(redacted)" }
func (Candidates) GoString() string { return "credentialinput(redacted)" }
func (Candidates) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "credentialinput(redacted)")
}
func (Candidates) MarshalText() ([]byte, error) {
	return []byte("credentialinput(redacted)"), nil
}
func (Candidates) MarshalJSON() ([]byte, error) {
	return []byte(`"credentialinput(redacted)"`), nil
}
func (Candidates) LogValue() slog.Value { return slog.StringValue("credentialinput(redacted)") }

// FromContext reads a defensive metadata copy and validates every field and
// bound, including anonymous input. Missing metadata returns a zero value,
// false, nil. Malformed metadata returns a zero value, false, ErrInvalidMetadata;
// cancellation returns the context error. A present valid value is still
// unverified and may contain both a Bearer and cookies.
func FromContext(ctx context.Context) (Candidates, bool, error) {
	if ctx == nil {
		return Candidates{}, false, ErrInvalidMetadata
	}
	if err := ctx.Err(); err != nil {
		return Candidates{}, false, err
	}
	payload, present, err := contextmetadata.Bytes(ctx, MetadataKey)
	if err != nil {
		return Candidates{}, false, ErrInvalidMetadata
	}
	if !present {
		return Candidates{}, false, nil
	}
	if len(payload) == 0 || len(payload) > 262144 || !utf8.Valid(payload) {
		return Candidates{}, false, ErrInvalidMetadata
	}
	parsed, err := parse(payload)
	if err != nil {
		return Candidates{}, false, ErrInvalidMetadata
	}
	if err := ctx.Err(); err != nil {
		return Candidates{}, false, err
	}
	parsed.ctx = ctx
	return Candidates{value: parsed}, true, nil
}

// Transport returns connect or rest, or empty after context completion.
func (c Candidates) Transport() string {
	if !c.live() {
		return ""
	}
	return c.value.transport
}

// InterfaceID returns the invoked canonical Interface ID, or empty after
// context completion. It is input provenance, not authorization evidence.
func (c Candidates) InterfaceID() string {
	if !c.live() {
		return ""
	}
	return c.value.interfaceID
}

// Bearer returns the raw, unverified candidate without its scheme.
func (c Candidates) Bearer() (string, bool) {
	if !c.live() || c.value.bearer == "" {
		return "", false
	}
	return c.value.bearer, true
}

// Cookie returns only the exact named cookie. An empty cookie value is present
// input, not an absent cookie. The authentication contract owns cookie naming
// and the rejection of simultaneous usable Bearer and session credentials.
func (c Candidates) Cookie(name string) (string, bool) {
	if !c.live() {
		return "", false
	}
	index := sort.Search(len(c.value.cookies), func(i int) bool { return c.value.cookies[i].name >= name })
	if index == len(c.value.cookies) || c.value.cookies[index].name != name {
		return "", false
	}
	return c.value.cookies[index].value, true
}

// CookieCount returns the bounded number of cookies, or zero after completion.
func (c Candidates) CookieCount() int {
	if !c.live() {
		return 0
	}
	return len(c.value.cookies)
}

func (c Candidates) live() bool { return c.value != nil && c.value.ctx.Err() == nil }

func parse(payload []byte) (*input, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !delimiter(decoder, '{') {
		return nil, ErrInvalidMetadata
	}
	result := &input{}
	seen := uint8(0)
	for decoder.More() {
		key, ok := stringToken(decoder)
		if !ok {
			return nil, ErrInvalidMetadata
		}
		var bit uint8
		switch key {
		case "transport":
			bit = 1
			result.transport, ok = stringToken(decoder)
			ok = ok && (result.transport == "connect" || result.transport == "rest")
		case "interface_id":
			bit = 2
			result.interfaceID, ok = stringToken(decoder)
			if ok {
				id, err := capability.ParseIdentifier(result.interfaceID)
				ok = err == nil && id.String() == result.interfaceID
			}
		case "bearer":
			bit = 4
			result.bearer, ok = stringToken(decoder)
			ok = ok && validBearer(result.bearer)
		case "cookies":
			bit = 8
			result.cookies, ok = parseCookies(decoder)
		default:
			return nil, ErrInvalidMetadata
		}
		if !ok || seen&bit != 0 {
			return nil, ErrInvalidMetadata
		}
		seen |= bit
	}
	if seen&11 != 11 || !delimiter(decoder, '}') {
		return nil, ErrInvalidMetadata
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidMetadata
	}
	return result, nil
}

func parseCookies(decoder *json.Decoder) ([]cookie, bool) {
	if !delimiter(decoder, '[') {
		return nil, false
	}
	var cookies []cookie
	total := 0
	for decoder.More() {
		if len(cookies) == 32 || !delimiter(decoder, '{') {
			return nil, false
		}
		var pair cookie
		seen := uint8(0)
		for decoder.More() {
			key, ok := stringToken(decoder)
			if !ok {
				return nil, false
			}
			value, ok := stringToken(decoder)
			if !ok {
				return nil, false
			}
			var bit uint8
			switch key {
			case "name":
				bit, pair.name = 1, value
			case "value":
				bit, pair.value = 2, value
			default:
				return nil, false
			}
			if seen&bit != 0 {
				return nil, false
			}
			seen |= bit
		}
		if seen != 3 || !delimiter(decoder, '}') || !validCookie(pair) {
			return nil, false
		}
		if len(cookies) > 0 && cookies[len(cookies)-1].name >= pair.name {
			return nil, false
		}
		total += len(pair.name) + len(pair.value)
		if total > 65536 {
			return nil, false
		}
		cookies = append(cookies, pair)
	}
	return cookies, delimiter(decoder, ']')
}

func stringToken(decoder *json.Decoder) (string, bool) {
	token, err := decoder.Token()
	value, ok := token.(string)
	return value, err == nil && ok
}

func delimiter(decoder *json.Decoder, expected json.Delim) bool {
	token, err := decoder.Token()
	return err == nil && token == expected
}

func validBearer(value string) bool {
	if len(value) == 0 || len(value) > 65536 {
		return false
	}
	for i := range len(value) {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validCookie(pair cookie) bool {
	if len(pair.name) == 0 || len(pair.name) > 256 || len(pair.value) > 4096 {
		return false
	}
	for i := range len(pair.name) {
		b := pair.name[i]
		if b < 0x21 || b > 0x7e || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b)) {
			return false
		}
	}
	// Match the parsed cookie-value bytes accepted by net/http.ParseCookie at
	// ingress, including the space and comma in quoted cookie values.
	for i := range len(pair.value) {
		b := pair.value[i]
		if b < 0x20 || b >= 0x7f || b == '"' || b == ';' || b == '\\' {
			return false
		}
	}
	return true
}
