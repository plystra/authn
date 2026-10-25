package opaquecredential_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/plystra/authn/opaquecredential"
)

func key(t testing.TB, id string, version uint32, material []byte) opaquecredential.Key {
	t.Helper()
	k, err := opaquecredential.NewKey(opaquecredential.KeyRef{ID: id, Version: version}, material)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func ring(t testing.TB, active opaquecredential.Key, previous ...opaquecredential.Key) *opaquecredential.Ring {
	t.Helper()
	r, err := opaquecredential.New(active, previous...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func binding() opaquecredential.Binding {
	return opaquecredential.Binding{Kind: opaquecredential.Session, Purpose: "session.user", ID: "credential-test-id"}
}

func material() []byte { return []byte("public-test-only-hmac-key-canary-01") }

func generate(t testing.TB, r *opaquecredential.Ring, b opaquecredential.Binding) (opaquecredential.Secret, opaquecredential.Digest) {
	t.Helper()
	s, d, err := r.Generate(b)
	if err != nil {
		t.Fatal(err)
	}
	return s, d
}

func TestOpaqueSecretGenerationAndParsing(t *testing.T) {
	r := ring(t, key(t, "primary", 1, material()))
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		s, d := generate(t, r, binding())
		encoded := s.Reveal()
		raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(raw) != 32 || len(encoded) != 43 || seen[encoded] {
			t.Fatal("secret size, encoding or uniqueness failure")
		}
		seen[encoded] = true
		parsed, err := opaquecredential.Parse(encoded)
		if err != nil || parsed.Reveal() != encoded {
			t.Fatal("canonical secret did not round trip")
		}
		result, err := r.Verify(binding(), parsed, d)
		if err != nil || !result.Match || result.NeedsRehash {
			t.Fatal("generated secret failed verification")
		}
	}
	if (opaquecredential.Secret{}).Reveal() != "" {
		t.Fatal("zero secret exposed material")
	}
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, bad := range []string{"", valid[:42], valid + "A", valid + "=", " " + valid, valid[:21] + "\n" + valid[22:], valid[:21] + "\r" + valid[22:], strings.Repeat("A", 42) + "B", valid[:42] + "+", valid[:42] + "/", string([]byte{0xff}) + valid[1:], "ply_rt_" + valid, strings.Repeat("x", 65536)} {
		if s, err := opaquecredential.Parse(bad); !errors.Is(err, opaquecredential.ErrInvalidSecret) || s.Reveal() != "" {
			t.Fatal("accepted noncanonical or oversized secret")
		}
	}
}

func TestOpaqueHMACTranscriptAndBindings(t *testing.T) {
	ref := opaquecredential.KeyRef{ID: "primary", Version: 7}
	r := ring(t, key(t, ref.ID, ref.Version, material()))
	b := binding()
	s, d := generate(t, r, b)
	raw, _ := base64.RawURLEncoding.DecodeString(s.Reveal())
	var transcript bytes.Buffer
	transcript.WriteString("plystra.authn.opaque-credential/hmac-sha256/v1")
	if err := binary.Write(&transcript, binary.BigEndian, uint32(1)); err != nil {
		t.Fatal(err)
	}
	for i, value := range [][]byte{[]byte(ref.ID), []byte(b.Kind), []byte(b.Purpose), []byte(b.ID), raw} {
		if i == 1 {
			if err := binary.Write(&transcript, binary.BigEndian, ref.Version); err != nil {
				t.Fatal(err)
			}
		}
		if err := binary.Write(&transcript, binary.BigEndian, uint32(len(value))); err != nil {
			t.Fatal(err)
		}
		transcript.Write(value)
	}
	mac := hmac.New(sha256.New, material())
	mac.Write(transcript.Bytes())
	if !hmac.Equal(mac.Sum(nil), d.Bytes()) || d.Version() != 1 || d.Key() != ref {
		t.Fatal("digest is not the specified keyed versioned transcript")
	}
	for _, kind := range []opaquecredential.Kind{opaquecredential.Session, opaquecredential.Refresh, opaquecredential.ApplicationKey, opaquecredential.AgentKey, opaquecredential.OneTime, opaquecredential.DeviceCode} {
		other := b
		other.Kind = kind
		candidate, stored := generate(t, r, other)
		if result, err := r.Verify(other, candidate, stored); err != nil || !result.Match {
			t.Fatal("supported kind failed")
		}
		if kind != b.Kind {
			if result, err := r.Verify(other, s, d); err != nil || result != (opaquecredential.Result{}) {
				t.Fatal("type domain separation failed")
			}
		}
	}
	for _, other := range []opaquecredential.Binding{
		{Kind: b.Kind, Purpose: b.Purpose + "other", ID: b.ID},
		{Kind: b.Kind, Purpose: b.Purpose, ID: b.ID + "other"},
		{Kind: b.Kind, Purpose: "session.operator", ID: b.ID},
	} {
		if result, err := r.Verify(other, s, d); err != nil || result != (opaquecredential.Result{}) {
			t.Fatal("purpose or record binding was ignored")
		}
	}
	other, _ := generate(t, r, b)
	if result, err := r.Verify(b, other, d); err != nil || result != (opaquecredential.Result{}) {
		t.Fatal("wrong secret matched")
	}
	// Field lengths prevent purpose/ID concatenation collisions.
	left := opaquecredential.Binding{Kind: opaquecredential.OneTime, Purpose: "ab", ID: "c"}
	right := opaquecredential.Binding{Kind: opaquecredential.OneTime, Purpose: "a", ID: "bc"}
	s, d = generate(t, r, left)
	if result, err := r.Verify(right, s, d); err != nil || result.Match {
		t.Fatal("ambiguous transcript framing")
	}
}

func TestOpaqueKeyRingValidation(t *testing.T) {
	ref := opaquecredential.KeyRef{ID: "primary", Version: 1}
	for _, bad := range []opaquecredential.KeyRef{{}, {ID: "primary"}, {ID: "", Version: 1}, {ID: "bad\n", Version: 1}, {ID: string([]byte{0xff}), Version: 1}, {ID: strings.Repeat("x", 65), Version: 1}} {
		if k, err := opaquecredential.NewKey(bad, material()); !errors.Is(err, opaquecredential.ErrInvalidKey) || k != (opaquecredential.Key{}) {
			t.Fatal("accepted invalid key reference")
		}
	}
	for _, n := range []int{0, 31, 65, 1024} {
		if _, err := opaquecredential.NewKey(ref, make([]byte, n)); !errors.Is(err, opaquecredential.ErrInvalidKey) {
			t.Fatal("accepted invalid key size")
		}
	}
	for _, n := range []int{32, 64} {
		if _, err := opaquecredential.NewKey(ref, bytes.Repeat([]byte{1}, n)); err != nil {
			t.Fatal("rejected supported key size")
		}
	}
	active := key(t, ref.ID, ref.Version, material())
	if r, err := opaquecredential.New(opaquecredential.Key{}); r != nil || !errors.Is(err, opaquecredential.ErrInvalidRing) {
		t.Fatal("accepted missing active key")
	}
	for _, previous := range [][]opaquecredential.Key{{active}, {opaquecredential.Key{}}, {key(t, "other", 2, material()), key(t, "other", 2, material())}} {
		if r, err := opaquecredential.New(active, previous...); r != nil || !errors.Is(err, opaquecredential.ErrInvalidRing) {
			t.Fatal("accepted duplicate or invalid ring key")
		}
	}
	previous := make([]opaquecredential.Key, 0, 31)
	for i := uint32(2); i <= 32; i++ {
		previous = append(previous, key(t, "primary", i, material()))
	}
	ring(t, active, previous...)
	previous = append(previous, key(t, "primary", 33, material()))
	if r, err := opaquecredential.New(active, previous...); r != nil || !errors.Is(err, opaquecredential.ErrInvalidRing) {
		t.Fatal("accepted oversized ring")
	}
}

func TestOpaqueDigestRestoreAndDefensiveCopies(t *testing.T) {
	input := material()
	original := append([]byte(nil), input...)
	k := key(t, "primary", 1, input)
	r := ring(t, k)
	clear(input)
	k = opaquecredential.Key{}
	b := binding()
	s, d := generate(t, r, b)
	reference := ring(t, key(t, "primary", 1, original))
	if result, err := reference.Verify(b, s, d); err != nil || !result.Match {
		t.Fatal("key constructor retained provisioning buffer")
	}
	storedBytes := d.Bytes()
	restored, err := opaquecredential.Restore(d.Version(), d.Key(), storedBytes)
	if err != nil {
		t.Fatal(err)
	}
	clear(storedBytes)
	if result, err := r.Verify(b, s, restored); err != nil || !result.Match {
		t.Fatal("restore retained caller storage")
	}
	exported := restored.Bytes()
	exported[0] ^= 0xff
	if result, err := r.Verify(b, s, restored); err != nil || !result.Match {
		t.Fatal("digest accessor exposed mutable state")
	}
	if result, err := r.Verify(b, s, d); err != nil || !result.Match {
		t.Fatal("digest export changed original")
	}
	for _, version := range []uint32{0, 2, ^uint32(0)} {
		if value, err := opaquecredential.Restore(version, d.Key(), d.Bytes()); !errors.Is(err, opaquecredential.ErrInvalidDigest) || value != (opaquecredential.Digest{}) {
			t.Fatal("accepted unsupported format version")
		}
	}
	for _, size := range []int{0, 31, 33, 256} {
		if _, err := opaquecredential.Restore(1, d.Key(), make([]byte, size)); !errors.Is(err, opaquecredential.ErrInvalidDigest) {
			t.Fatal("accepted invalid digest length")
		}
	}
	if _, err := opaquecredential.Restore(1, opaquecredential.KeyRef{}, d.Bytes()); !errors.Is(err, opaquecredential.ErrInvalidDigest) {
		t.Fatal("accepted invalid persisted key reference")
	}
	if (opaquecredential.Digest{}).Bytes() != nil {
		t.Fatal("zero digest exported valid storage")
	}
	// A leaked digest is not itself a bearer secret.
	parsed, err := opaquecredential.Parse(base64.RawURLEncoding.EncodeToString(d.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := r.Verify(b, parsed, d); err != nil || result.Match {
		t.Fatal("digest accepted as secret")
	}
}

func TestOpaqueRotationAndKeyMetadataBinding(t *testing.T) {
	old := key(t, "primary", 1, material())
	current := key(t, "primary", 2, []byte("public-test-only-new-hmac-key-canary"))
	b := binding()
	s, d := generate(t, ring(t, old), b)
	r := ring(t, current, old)
	result, err := r.Verify(b, s, d)
	if err != nil || !result.Match || !result.NeedsRehash || result.Replacement.Key() != (opaquecredential.KeyRef{ID: "primary", Version: 2}) {
		t.Fatal("old key match did not produce explicit upgrade")
	}
	if d.Key().Version != 1 {
		t.Fatal("verification silently changed stored digest")
	}
	currentOnly := ring(t, current)
	if check, err := currentOnly.Verify(b, s, result.Replacement); err != nil || !check.Match || check.NeedsRehash {
		t.Fatal("replacement does not verify with active key only")
	}
	if check, err := currentOnly.Verify(b, s, d); !errors.Is(err, opaquecredential.ErrKeyUnavailable) || check != (opaquecredential.Result{}) {
		t.Fatal("missing old key triggered fallback")
	}
	wrong, _ := generate(t, r, b)
	if check, err := r.Verify(b, wrong, d); err != nil || check != (opaquecredential.Result{}) {
		t.Fatal("mismatch produced upgrade")
	}
	// Same bytes under another ID/version still cannot validate altered metadata.
	for _, ref := range []opaquecredential.KeyRef{{ID: "primary", Version: 2}, {ID: "other", Version: 1}} {
		other := key(t, ref.ID, ref.Version, material())
		withOther := ring(t, other, old)
		altered, err := opaquecredential.Restore(d.Version(), ref, d.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if check, err := withOther.Verify(b, s, altered); err != nil || check.Match {
			t.Fatal("key metadata was not MAC bound")
		}
	}
	differentMaterial := ring(t, key(t, "primary", 1, []byte("public-test-only-different-key-value")))
	if check, err := differentMaterial.Verify(b, s, d); err != nil || check.Match {
		t.Fatal("verification ignored key bytes")
	}
}

func TestOpaqueInvalidInputsFailClosed(t *testing.T) {
	r := ring(t, key(t, "primary", 1, material()))
	b := binding()
	s, d := generate(t, r, b)
	for _, bad := range []opaquecredential.Binding{{}, {Kind: "unknown", Purpose: b.Purpose, ID: b.ID}, {Kind: b.Kind, Purpose: "", ID: b.ID}, {Kind: b.Kind, Purpose: b.Purpose, ID: ""}, {Kind: b.Kind, Purpose: "bad\n", ID: b.ID}, {Kind: b.Kind, Purpose: strings.Repeat("x", 129), ID: b.ID}, {Kind: b.Kind, Purpose: b.Purpose, ID: strings.Repeat("界", 86)}, {Kind: b.Kind, Purpose: b.Purpose, ID: string([]byte{0xff})}} {
		if secret, digest, err := r.Generate(bad); !errors.Is(err, opaquecredential.ErrInvalidBinding) || secret.Reveal() != "" || digest != (opaquecredential.Digest{}) {
			t.Fatal("invalid binding generated credential")
		}
		if result, err := r.Verify(bad, s, d); !errors.Is(err, opaquecredential.ErrInvalidBinding) || result != (opaquecredential.Result{}) {
			t.Fatal("invalid binding verified")
		}
	}
	boundary := opaquecredential.Binding{Kind: b.Kind, Purpose: strings.Repeat("p", 128), ID: strings.Repeat("界", 85) + "x"}
	generate(t, r, boundary)
	for _, r := range []*opaquecredential.Ring{nil, {}} {
		if secret, digest, err := r.Generate(b); !errors.Is(err, opaquecredential.ErrInvalidRing) || secret.Reveal() != "" || digest != (opaquecredential.Digest{}) {
			t.Fatal("zero ring generated credentials")
		}
		if result, err := r.Verify(b, s, d); !errors.Is(err, opaquecredential.ErrInvalidRing) || result != (opaquecredential.Result{}) {
			t.Fatal("zero ring verified")
		}
	}
	if result, err := r.Verify(b, opaquecredential.Secret{}, d); !errors.Is(err, opaquecredential.ErrInvalidSecret) || result != (opaquecredential.Result{}) {
		t.Fatal("accepted zero secret")
	}
	if result, err := r.Verify(b, s, opaquecredential.Digest{}); !errors.Is(err, opaquecredential.ErrInvalidDigest) || result != (opaquecredential.Result{}) {
		t.Fatal("accepted zero digest")
	}
}

func TestOpaqueRedactionAndSerialization(t *testing.T) {
	keyBytes := material()
	k := key(t, "private-reference-canary", 1, keyBytes)
	r := ring(t, k)
	b := binding()
	b.ID = "private-record-canary"
	b.Purpose = "private-purpose-canary"
	s, d := generate(t, r, b)
	result, err := r.Verify(b, s, d)
	if err != nil {
		t.Fatal(err)
	}
	canaries := []string{string(keyBytes), base64.RawURLEncoding.EncodeToString(keyBytes), hex.EncodeToString(keyBytes), s.Reveal(), hex.EncodeToString(d.Bytes()), base64.RawURLEncoding.EncodeToString(d.Bytes()), b.ID, b.Purpose, d.Key().ID}
	values := []any{k, &k, r, *r, b, &b, s, &s, d, &d, d.Key(), result, struct {
		Secret opaquecredential.Secret
		Digest opaquecredential.Digest
	}{s, d}}
	for _, value := range values {
		var outputs []string
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
			outputs = append(outputs, fmt.Sprintf(verb, value))
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		outputs = append(outputs, string(encoded))
		if text, ok := value.(encoding.TextMarshaler); ok {
			raw, err := text.MarshalText()
			if err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, string(raw))
		}
		for _, jsonHandler := range []bool{false, true} {
			var output bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&output, nil)
			if jsonHandler {
				handler = slog.NewJSONHandler(&output, nil)
			}
			slog.New(handler).Info("test", "value", value)
			outputs = append(outputs, output.String())
		}
		for _, output := range outputs {
			for _, canary := range canaries {
				if strings.Contains(output, canary) {
					t.Fatal("ordinary formatting or serialization leaked credential material")
				}
			}
		}
	}
	for _, target := range []any{new(opaquecredential.Key), new(opaquecredential.Ring), new(opaquecredential.Secret), new(opaquecredential.Digest)} {
		if err := json.Unmarshal([]byte(`{}`), target); !errors.Is(err, opaquecredential.ErrSerialization) {
			t.Fatal("generic JSON accepted opaque state")
		}
		if err := target.(encoding.TextUnmarshaler).UnmarshalText([]byte("private-input-canary")); !errors.Is(err, opaquecredential.ErrSerialization) {
			t.Fatal("generic text accepted opaque state")
		}
	}
	for _, err := range []error{opaquecredential.ErrInvalidKey, opaquecredential.ErrInvalidRing, opaquecredential.ErrInvalidBinding, opaquecredential.ErrInvalidSecret, opaquecredential.ErrInvalidDigest, opaquecredential.ErrKeyUnavailable, opaquecredential.ErrRandom, opaquecredential.ErrSerialization} {
		if errors.Unwrap(err) != nil || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "canary") {
			t.Fatal("unsafe error")
		}
	}
}

func TestOpaqueConcurrentUseIsNotConsumption(t *testing.T) {
	r := ring(t, key(t, "primary", 1, material()))
	b := binding()
	b.Kind = opaquecredential.OneTime
	b.Purpose = "account.recovery"
	s, d := generate(t, r, b)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Go(func() {
			for j := 0; j < 32; j++ {
				result, err := r.Verify(b, s, d)
				if err != nil || !result.Match {
					t.Error("concurrent crypto verification failed")
					return
				}
				if _, _, err := r.Generate(b); err != nil {
					t.Error("concurrent generation failed")
					return
				}
			}
		})
	}
	wg.Wait()
	// One-time consumption belongs to the durable service, not this primitive.
	if result, err := r.Verify(b, s, d); err != nil || !result.Match {
		t.Fatal("primitive silently consumed credential")
	}
}

func FuzzOpaqueCandidateAndDigest(f *testing.F) {
	r := ring(f, key(f, "primary", 1, material()))
	b := binding()
	s, d := generate(f, r, b)
	f.Add(s.Reveal(), uint32(1), d.Bytes())
	f.Add("ply_rt_invalid", uint32(2), []byte("invalid"))
	f.Fuzz(func(t *testing.T, encoded string, version uint32, value []byte) {
		secret, err := opaquecredential.Parse(encoded)
		if err != nil {
			if !errors.Is(err, opaquecredential.ErrInvalidSecret) || secret.Reveal() != "" {
				t.Fatal("invalid parse outcome")
			}
			return
		}
		digest, err := opaquecredential.Restore(version, d.Key(), value)
		if err != nil {
			if !errors.Is(err, opaquecredential.ErrInvalidDigest) {
				t.Fatal("invalid restore outcome")
			}
			return
		}
		result, err := r.Verify(b, secret, digest)
		if err != nil || result.NeedsRehash {
			t.Fatal("unexpected active-key verification outcome")
		}
	})
}
