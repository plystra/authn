// Package opaquecredential generates high-entropy secret components and stores
// only domain-separated HMAC verification digests. A cryptographic match grants
// no authentication, authorization, expiry, revocation or one-time-use guarantee.
package opaquecredential

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"unicode"
	"unicode/utf8"
)

const (
	Version     uint32 = 1
	SecretBytes        = 32
	MinKeyBytes        = 32
	MaxKeyBytes        = 64
	MaxKeys            = 32
	macDomain          = "plystra.authn.opaque-credential/hmac-sha256/v1"
)

type Kind string

const (
	Session        Kind = "session"
	Refresh        Kind = "refresh"
	ApplicationKey Kind = "application_key"
	AgentKey       Kind = "agent_key"
	OneTime        Kind = "one_time"
	DeviceCode     Kind = "device_code"
)

var (
	ErrInvalidKey     = errors.New("invalid opaque credential key")
	ErrInvalidRing    = errors.New("invalid opaque credential key ring")
	ErrInvalidBinding = errors.New("invalid opaque credential binding")
	ErrInvalidSecret  = errors.New("invalid opaque credential secret")
	ErrInvalidDigest  = errors.New("invalid opaque credential digest")
	ErrKeyUnavailable = errors.New("opaque credential verification key unavailable")
	ErrRandom         = errors.New("opaque credential randomness unavailable")
	ErrSerialization  = errors.New("opaque credential types require explicit accessors")
)

// Binding is supplied by the owning service, never inferred from a credential
// prefix. ID identifies the exact credential record, not its owner's authority.
type Binding struct {
	redacted
	Kind    Kind
	Purpose string
	ID      string
}

// KeyRef identifies one immutable provisioned HMAC key version. It is metadata,
// not a credential, and is distinct from the digest format Version.
type KeyRef struct {
	redacted
	ID      string
	Version uint32
}

type Key struct {
	redacted
	ref      KeyRef
	material [MaxKeyBytes]byte
	length   uint8
}

// Secret contains only a 256-bit entropy component, without a token prefix or
// credential ID. Generic formatting/serialization redacts it; Reveal is explicit.
type Secret struct {
	redacted
	value [SecretBytes]byte
	valid bool
}

// Digest contains no recoverable secret. Persist only its explicit Version,
// Key and Bytes accessors alongside the owning service's binding and state.
type Digest struct {
	redacted
	version uint32
	key     KeyRef
	value   [sha256.Size]byte
}

// Ring is immutable and safe for concurrent use. Construct a replacement ring
// to activate or remove a key; no key lookup performs I/O or tries other keys.
type Ring struct {
	redacted
	active KeyRef
	keys   map[KeyRef]Key
}

type Result struct {
	redacted
	Match       bool
	NeedsRehash bool
	// Replacement is valid only after a match under a non-active key. The
	// caller must persist it with revision checks, after authoritative checks.
	Replacement Digest
}

// NewKey copies 32-64 key bytes and rejects all-zero material. Callers may clear
// their provisioning buffer; key entropy and process-memory lifecycle remain
// caller concerns.
func NewKey(ref KeyRef, material []byte) (Key, error) {
	if !validRef(ref) || len(material) < MinKeyBytes || len(material) > MaxKeyBytes {
		return Key{}, ErrInvalidKey
	}
	var present byte
	for _, value := range material {
		present |= value
	}
	if present == 0 {
		return Key{}, ErrInvalidKey
	}
	k := Key{ref: ref, length: uint8(len(material))}
	copy(k.material[:], material)
	return k, nil
}

// New selects exactly one write key and at most 31 additional verification keys.
// Duplicate references, missing/invalid keys and oversized rings fail closed.
func New(active Key, previous ...Key) (*Ring, error) {
	if !validKey(active) || len(previous) >= MaxKeys {
		return nil, ErrInvalidRing
	}
	r := &Ring{active: active.ref, keys: make(map[KeyRef]Key, 1+len(previous))}
	r.keys[active.ref] = active
	for _, key := range previous {
		if !validKey(key) {
			return nil, ErrInvalidRing
		}
		if _, duplicate := r.keys[key.ref]; duplicate {
			return nil, ErrInvalidRing
		}
		r.keys[key.ref] = key
	}
	return r, nil
}

func (r *Ring) Generate(binding Binding) (Secret, Digest, error) {
	if !r.live() {
		return Secret{}, Digest{}, ErrInvalidRing
	}
	if !validBinding(binding) {
		return Secret{}, Digest{}, ErrInvalidBinding
	}
	secret := Secret{valid: true}
	if _, err := rand.Read(secret.value[:]); err != nil {
		return Secret{}, Digest{}, ErrRandom
	}
	return secret, digest(r.keys[r.active], binding, secret), nil
}

// Parse accepts exactly 43 canonical unpadded base64url characters. This parses
// an untrusted secret component; a method-specific adapter owns full wire syntax.
func Parse(encoded string) (Secret, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(SecretBytes) {
		return Secret{}, ErrInvalidSecret
	}
	for i := range encoded {
		c := encoded[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return Secret{}, ErrInvalidSecret
		}
	}
	secret := Secret{valid: true}
	n, err := base64.RawURLEncoding.Strict().Decode(secret.value[:], []byte(encoded))
	if err != nil || n != SecretBytes {
		return Secret{}, ErrInvalidSecret
	}
	return secret, nil
}

// Reveal returns secret material for explicit protected delivery. It is not a
// logging or persistence representation. The zero value returns empty text.
func (s Secret) Reveal() string {
	if !s.valid {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s.value[:])
}

// Restore validates a stored digest without accepting any raw secret. A digest
// alone never proves a match; Verify must use the exact expected binding and key.
func Restore(version uint32, key KeyRef, value []byte) (Digest, error) {
	if version != Version || !validRef(key) || len(value) != sha256.Size {
		return Digest{}, ErrInvalidDigest
	}
	d := Digest{version: version, key: key}
	copy(d.value[:], value)
	return d, nil
}

func (d Digest) Version() uint32 { return d.version }
func (d Digest) Key() KeyRef     { return d.key }

// Bytes returns a defensive copy intended only for protected digest storage.
func (d Digest) Bytes() []byte {
	if !validDigest(d) {
		return nil
	}
	return append([]byte(nil), d.value[:]...)
}

// Verify performs only a constant-time keyed digest comparison. After a match
// under an old key, it derives a replacement with the active key from the supplied
// secret. It neither consumes a credential nor decides whether it may be used.
func (r *Ring) Verify(binding Binding, secret Secret, stored Digest) (Result, error) {
	if !r.live() {
		return Result{}, ErrInvalidRing
	}
	if !validBinding(binding) {
		return Result{}, ErrInvalidBinding
	}
	if !secret.valid {
		return Result{}, ErrInvalidSecret
	}
	if !validDigest(stored) {
		return Result{}, ErrInvalidDigest
	}
	key, present := r.keys[stored.key]
	if !present {
		return Result{}, ErrKeyUnavailable
	}
	actual := digest(key, binding, secret)
	if !hmac.Equal(actual.value[:], stored.value[:]) {
		return Result{}, nil
	}
	result := Result{Match: true}
	if stored.key != r.active {
		result.NeedsRehash = true
		result.Replacement = digest(r.keys[r.active], binding, secret)
	}
	return result, nil
}

func digest(key Key, binding Binding, secret Secret) Digest {
	mac := hmac.New(sha256.New, key.material[:key.length])
	_, _ = mac.Write([]byte(macDomain))
	writeNumber(mac, Version)
	writeField(mac, []byte(key.ref.ID))
	writeNumber(mac, key.ref.Version)
	writeField(mac, []byte(binding.Kind))
	writeField(mac, []byte(binding.Purpose))
	writeField(mac, []byte(binding.ID))
	writeField(mac, secret.value[:])
	d := Digest{version: Version, key: key.ref}
	mac.Sum(d.value[:0])
	return d
}

func writeNumber(mac hash.Hash, value uint32) {
	var word [4]byte
	binary.BigEndian.PutUint32(word[:], value)
	_, _ = mac.Write(word[:])
}

func writeField(mac hash.Hash, value []byte) {
	writeNumber(mac, uint32(len(value)))
	_, _ = mac.Write(value)
}

func (r *Ring) live() bool      { return r != nil && len(r.keys) > 0 }
func validDigest(d Digest) bool { return d.version == Version && validRef(d.key) }
func validKey(k Key) bool {
	return validRef(k.ref) && k.length >= MinKeyBytes && k.length <= MaxKeyBytes
}
func validRef(ref KeyRef) bool { return ref.Version > 0 && identifier(ref.ID, 64) }

func validBinding(binding Binding) bool {
	switch binding.Kind {
	case Session, Refresh, ApplicationKey, AgentKey, OneTime, DeviceCode:
		return identifier(binding.Purpose, 128) && identifier(binding.ID, 256)
	}
	return false
}

func identifier(s string, max int) bool {
	if len(s) == 0 || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
