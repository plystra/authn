package credentialinput_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plystra/authn/credentialinput"
	"github.com/plystra/kernel/contextmetadata"
)

const anonymous = `{"transport":"connect","interface_id":"order.read/v1","cookies":[]}`

func withPayload(t testing.TB, ctx context.Context, payload []byte) context.Context {
	t.Helper()
	result, err := contextmetadata.WithBytes(ctx, credentialinput.MetadataKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decode(t testing.TB, payload string) credentialinput.Candidates {
	t.Helper()
	value, present, err := credentialinput.FromContext(withPayload(t, context.Background(), []byte(payload)))
	if err != nil || !present {
		t.Fatalf("decode: present=%v err=%v", present, err)
	}
	return value
}

func TestFromContextReadsOnlyBoundedUnverifiedCandidates(t *testing.T) {
	value := decode(t, `{"cookies":[{"value":"","name":"a"},{"name":"session","value":"abc ,xyz"}],"bearer":"unverified","interface_id":"order.read/v1","transport":"rest"}`)
	if value.Transport() != "rest" || value.InterfaceID() != "order.read/v1" || value.CookieCount() != 2 {
		t.Fatal("wrong provenance or cookie count")
	}
	if bearer, present := value.Bearer(); bearer != "unverified" || !present {
		t.Fatal("bearer lost")
	}
	if cookie, present := value.Cookie("session"); cookie != "abc ,xyz" || !present {
		t.Fatal("parsed cookie bytes lost")
	}
	if cookie, present := value.Cookie("a"); cookie != "" || !present {
		t.Fatal("empty cookie became absent")
	}
	for _, name := range []string{"Session", "missing", ""} {
		if cookie, present := value.Cookie(name); cookie != "" || present {
			t.Fatal("cookie lookup was not exact")
		}
	}
	if bearer, present := decode(t, anonymous).Bearer(); bearer != "" || present {
		t.Fatal("anonymous input acquired credential")
	}
}

func TestFromContextRejectsInvalidClosedSchema(t *testing.T) {
	inputs := map[string]string{
		"null":                `null`,
		"array":               `[]`,
		"empty":               `{}`,
		"truncated":           anonymous[:len(anonymous)-1],
		"trailing":            anonymous + `{}`,
		"unknown":             strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"secret":"canary"`, 1),
		"duplicate":           strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"cookies":[]`, 1),
		"escaped duplicate":   strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"cook\u0069es":[]`, 1),
		"duplicate transport": strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"transport":"rest"`, 1),
		"duplicate interface": strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"interface_id":"other.read/v1"`, 1),
		"duplicate bearer":    strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"bearer":"one","bearer":"two"`, 1),
		"missing transport":   `{"interface_id":"order.read/v1","cookies":[]}`,
		"missing interface":   `{"transport":"connect","cookies":[]}`,
		"missing cookies":     `{"transport":"connect","interface_id":"order.read/v1"}`,
		"unknown transport":   strings.Replace(anonymous, `"connect"`, `"http"`, 1),
		"null transport":      strings.Replace(anonymous, `"connect"`, `null`, 1),
		"wrong transport":     strings.Replace(anonymous, `"connect"`, `[]`, 1),
		"invalid interface":   strings.Replace(anonymous, `order.read/v1`, `order.read/v01`, 1),
		"wrong interface":     strings.Replace(anonymous, `"order.read/v1"`, `false`, 1),
		"null cookies":        strings.Replace(anonymous, `[]`, `null`, 1),
		"wrong cookies":       strings.Replace(anonymous, `[]`, `{}`, 1),
		"empty bearer":        strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"bearer":""`, 1),
		"null bearer":         strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"bearer":null`, 1),
		"wrong bearer":        strings.Replace(anonymous, `"cookies":[]`, `"cookies":[],"bearer":42`, 1),
	}
	cookies := map[string]string{
		"null pair":         `[null]`,
		"array pair":        `[[]]`,
		"empty pair":        `[{}]`,
		"missing name":      `[{"value":"a"}]`,
		"missing value":     `[{"name":"a"}]`,
		"unknown field":     `[{"name":"a","value":"b","extra":"c"}]`,
		"duplicate name":    `[{"name":"a","name":"b","value":"c"}]`,
		"duplicate value":   `[{"name":"a","value":"b","value":"c"}]`,
		"escaped duplicate": `[{"name":"a","value":"b","val\u0075e":"c"}]`,
		"duplicate cookie":  `[{"name":"a","value":"b"},{"name":"a","value":"c"}]`,
		"unsorted":          `[{"name":"b","value":"c"},{"name":"a","value":"b"}]`,
		"wrong name type":   `[{"name":123,"value":"a"}]`,
		"wrong value type":  `[{"name":"a","value":{}}]`,
		"null value":        `[{"name":"a","value":null}]`,
		"empty name":        `[{"name":"","value":"a"}]`,
		"surrogate name":    `[{"name":"\ud800","value":"a"}]`,
		"surrogate value":   `[{"name":"a","value":"\ud800"}]`,
	}
	for name, pairs := range cookies {
		inputs["cookie "+name] = strings.Replace(anonymous, `[]`, pairs, 1)
	}
	for name, payload := range inputs {
		t.Run(name, func(t *testing.T) { reject(t, []byte(payload)) })
	}
	invalidUTF8 := append([]byte(anonymous[:len(anonymous)-1]+`,"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`":"x"}`)...)
	reject(t, invalidUTF8)
}

func reject(t testing.TB, payload []byte) {
	t.Helper()
	value, present, err := credentialinput.FromContext(withPayload(t, context.Background(), payload))
	if !errors.Is(err, credentialinput.ErrInvalidMetadata) || present || value.InterfaceID() != "" || value.CookieCount() != 0 {
		t.Fatalf("malformed metadata accepted: present=%v err=%v", present, err)
	}
	if err.Error() != "invalid HTTP credential metadata" {
		t.Fatal("error exposed rejected input")
	}
}

func TestFromContextEnforcesByteAndCountBounds(t *testing.T) {
	encode := func(bearer string, pairs []map[string]string) []byte {
		t.Helper()
		input := map[string]any{"transport": "connect", "interface_id": "order.read/v1", "cookies": pairs}
		if bearer != "" {
			input["bearer"] = bearer
		}
		result, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	accept := func(payload []byte) {
		t.Helper()
		if _, present, err := credentialinput.FromContext(withPayload(t, context.Background(), payload)); err != nil || !present {
			t.Fatalf("valid boundary rejected: %v", err)
		}
	}
	accept(encode(strings.Repeat("a", 65536), []map[string]string{}))
	reject(t, encode(strings.Repeat("a", 65537), []map[string]string{}))
	for _, bearer := range []string{"a b", "a\t", "a\n", "a\r", "a\x00", "a\x7f", "a\u0080"} {
		reject(t, encode(bearer, []map[string]string{}))
	}
	accept(encode("", []map[string]string{{"name": strings.Repeat("a", 256), "value": strings.Repeat("b", 4096)}}))
	reject(t, encode("", []map[string]string{{"name": strings.Repeat("a", 257), "value": ""}}))
	reject(t, encode("", []map[string]string{{"name": "a", "value": strings.Repeat("b", 4097)}}))
	for _, name := range []string{"a b", "a\t", "a\x00", "a\x7f", "a\u0080", "a(", "a)", "a<", "a>", "a@", "a,", "a;", "a:", "a\\", "a\"", "a/", "a[", "a]", "a?", "a=", "a{", "a}"} {
		reject(t, encode("", []map[string]string{{"name": name, "value": ""}}))
	}
	for _, value := range []string{"a\t", "a\n", "a\r", "a\x00", "a\x7f", "a\u0080", "a\"", "a;", "a\\"} {
		reject(t, encode("", []map[string]string{{"name": "a", "value": value}}))
	}
	pairs := make([]map[string]string, 32)
	for i := range pairs {
		pairs[i] = map[string]string{"name": fmt.Sprintf("cookie%02d", i), "value": ""}
	}
	accept(encode("", pairs))
	reject(t, encode("", append(pairs, map[string]string{"name": "cookie32", "value": ""})))
	// Sixteen 4,088-byte values and eight-byte names reach exactly 65,536.
	for i := range 16 {
		pairs[i]["value"] = strings.Repeat("v", 4088)
	}
	pairs = pairs[:16]
	accept(encode("", pairs))
	pairs[15]["value"] += "v"
	reject(t, encode("", pairs))
	// Legal JSON whitespace cannot exceed the generic metadata storage bound.
	padding := bytes.Repeat([]byte(" "), 262144-len(anonymous))
	accept(append(padding, []byte(anonymous)...))
}

func TestCandidatesAreImmutableConcurrentAndRedacted(t *testing.T) {
	const canary = "credential-canary-should-never-appear"
	payload := []byte(strings.Replace(anonymous, `[]`, `[{"name":"session","value":"`+canary+`"}]`, 1))
	ctx := withPayload(t, context.Background(), payload)
	clear(payload)
	copyOfPayload, _, err := contextmetadata.Bytes(ctx, credentialinput.MetadataKey)
	if err != nil {
		t.Fatal(err)
	}
	clear(copyOfPayload)
	value, present, err := credentialinput.FromContext(ctx)
	if err != nil || !present {
		t.Fatal("caller mutated stored input")
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			for range 100 {
				if cookie, ok := value.Cookie("session"); !ok || cookie != canary {
					t.Error("concurrent cookie read changed input")
				}
			}
		})
	}
	group.Wait()
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p"} {
		if rendered := fmt.Sprintf(format, value); strings.Contains(rendered, canary) {
			t.Fatalf("format %s disclosed credential", format)
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || strings.Contains(string(encoded), canary) {
		t.Fatal("JSON disclosed credential")
	}
	text, err := value.MarshalText()
	if err != nil || strings.Contains(string(text), canary) {
		t.Fatal("text disclosed credential")
	}
	for _, jsonLog := range []bool{false, true} {
		var output bytes.Buffer
		var handler slog.Handler = slog.NewTextHandler(&output, nil)
		if jsonLog {
			handler = slog.NewJSONHandler(&output, nil)
		}
		slog.New(handler).Info("input", "candidate", value)
		if strings.Contains(output.String(), canary) {
			t.Fatal("structured log disclosed credential")
		}
	}
}

func TestCookieBytesMatchHTTPIngress(t *testing.T) {
	for b := range 256 {
		for _, field := range []string{"name", "value"} {
			pair := map[string]string{"name": "session", "value": "x"}
			pair[field] = "a" + string([]byte{byte(b)}) + "b"
			line := pair["name"] + "=\"" + pair["value"] + "\""
			parsed, parseErr := http.ParseCookie(line)
			// Ingress rejects non-ASCII and control bytes before ParseCookie.
			accepted := b >= 0x20 && b <= 0x7e && parseErr == nil && len(parsed) == 1 && parsed[0].Name == pair["name"] && parsed[0].Value == pair["value"]
			payload, err := json.Marshal(map[string]any{"transport": "connect", "interface_id": "order.read/v1", "cookies": []map[string]string{pair}})
			if err != nil {
				t.Fatal(err)
			}
			_, present, err := credentialinput.FromContext(withPayload(t, context.Background(), payload))
			if present != accepted || (err == nil) != accepted {
				t.Fatalf("%s byte %d: ingress=%v candidate=%v err=%v", field, b, accepted, present, err)
			}
		}
	}
}

func TestFromContextMissingNilAndCompletion(t *testing.T) {
	value, present, err := credentialinput.FromContext(context.Background())
	if err != nil || present || value.InterfaceID() != "" {
		t.Fatal("missing metadata is not empty")
	}
	if _, present, err := credentialinput.FromContext(nil); present || !errors.Is(err, credentialinput.ErrInvalidMetadata) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = withPayload(t, ctx, []byte(strings.Replace(anonymous, `"cookies":[]`, `"cookies":[{"name":"session","value":"x"}],"bearer":"y"`, 1)))
	value, present, err = credentialinput.FromContext(ctx)
	if err != nil || !present {
		t.Fatal("live context rejected")
	}
	cancel()
	if _, present, err := credentialinput.FromContext(ctx); present || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled context accepted")
	}
	if value.Transport() != "" || value.InterfaceID() != "" || value.CookieCount() != 0 {
		t.Fatal("completed request still exposes provenance")
	}
	if _, present := value.Bearer(); present {
		t.Fatal("completed request still exposes bearer")
	}
	if _, present := value.Cookie("session"); present {
		t.Fatal("completed request still exposes cookie")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, present, err := credentialinput.FromContext(expired); present || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired context accepted")
	}
}

func FuzzFromContextClosedSchema(f *testing.F) {
	for _, seed := range []string{anonymous, `null`, `{"transport":"rest","interface_id":"authn.session.verify/v1","cookies":[],"bearer":"a"}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 || len(payload) > 262144 {
			return
		}
		value, present, err := credentialinput.FromContext(withPayload(t, context.Background(), payload))
		if err != nil && (!errors.Is(err, credentialinput.ErrInvalidMetadata) || present || value.InterfaceID() != "") {
			t.Fatal("invalid input escaped safe failure")
		}
		if present && (err != nil || value.CookieCount() > 32 || (value.Transport() != "connect" && value.Transport() != "rest")) {
			t.Fatal("accepted input escaped bounds")
		}
	})
}
