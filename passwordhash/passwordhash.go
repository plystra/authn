// Package passwordhash provides bounded Argon2id hashing and verification.
// Account password policy and atomic persistence of replacement hashes belong to
// the calling service. A Hasher has its own explicit admission budget.
package passwordhash

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const (
	MaxPasswordBytes = 1024
	MaxEncodedBytes  = 256
	MaxMemoryKiB     = 262144
	MaxIterations    = 6
	MaxParallelism   = 8
	MinSaltBytes     = 16
	MaxSaltBytes     = 64
	MinKeyBytes      = 16
	MaxKeyBytes      = 64
)

var (
	ErrInvalidOptions = errors.New("invalid password hashing options")
	ErrInvalidContext = errors.New("invalid password hashing context")
	ErrPasswordInput  = errors.New("password must contain 1 through 1024 bytes")
	ErrInvalidHash    = errors.New("invalid or unsupported password hash")
	ErrResourceLimit  = errors.New("password hash exceeds instance resource limits")
	ErrBusy           = errors.New("password hashing capacity unavailable")
	ErrRandom         = errors.New("password hashing randomness unavailable")
)

type Parameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltBytes   uint32
	KeyBytes    uint32
}

// Options uses the default profile when Parameters is entirely zero. Individual
// zero admission limits select defaults: two jobs, 131072 KiB, and eight lanes.
// Partially specified profiles are rejected, not silently completed.
type Options struct {
	Parameters    Parameters
	MaxConcurrent uint32
	MaxMemoryKiB  uint32
	MaxLanes      uint32
}

type Result struct {
	Match        bool
	NeedsUpgrade bool
}

// Hasher is immutable after construction. Copies share the same admission state.
// Admission bounds active Argon2 work, not process RSS or the Go GC heap.
type Hasher struct {
	options Options
	budget  *budget
}

type budget struct {
	sync.Mutex
	jobs, memoryKiB, lanes uint32
}

func New(options Options) (*Hasher, error) {
	if options.Parameters == (Parameters{}) {
		options.Parameters = Parameters{MemoryKiB: 65536, Iterations: 3, Parallelism: 4, SaltBytes: 16, KeyBytes: 32}
	}
	if options.MaxConcurrent == 0 {
		options.MaxConcurrent = 2
	}
	if options.MaxMemoryKiB == 0 {
		options.MaxMemoryKiB = 131072
	}
	if options.MaxLanes == 0 {
		options.MaxLanes = 8
	}
	p := options.Parameters
	if !validParameters(p) || options.MaxConcurrent > 64 || options.MaxMemoryKiB > 1048576 || options.MaxLanes > 64 || p.MemoryKiB > options.MaxMemoryKiB || uint32(p.Parallelism) > options.MaxLanes {
		return nil, ErrInvalidOptions
	}
	return &Hasher{options: options, budget: new(budget)}, nil
}

func (h *Hasher) Hash(ctx context.Context, password []byte) (string, error) {
	if err := h.validate(ctx, password); err != nil {
		return "", err
	}
	p := h.options.Parameters
	if err := h.acquire(p); err != nil {
		return "", err
	}
	defer h.release(p)
	if err := ctx.Err(); err != nil {
		return "", cancellation(err)
	}
	salt := make([]byte, p.SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", ErrRandom
	}
	// IDKey cannot be cancelled. Keep the permit until its work actually ends.
	key := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyBytes)
	defer clear(key)
	if err := ctx.Err(); err != nil {
		return "", cancellation(err)
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (h *Hasher) Verify(ctx context.Context, password []byte, encoded string) (Result, error) {
	if err := h.validate(ctx, password); err != nil {
		return Result{}, err
	}
	r, ok := parse(encoded)
	if !ok {
		return Result{}, ErrInvalidHash
	}
	defer clear(r.key)
	if err := h.acquire(r.parameters); err != nil {
		return Result{}, err
	}
	defer h.release(r.parameters)
	if err := ctx.Err(); err != nil {
		return Result{}, cancellation(err)
	}
	actual := argon2.IDKey(password, r.salt, r.parameters.Iterations, r.parameters.MemoryKiB, r.parameters.Parallelism, r.parameters.KeyBytes)
	defer clear(actual)
	match := subtle.ConstantTimeCompare(actual, r.key) == 1
	if err := ctx.Err(); err != nil {
		return Result{}, cancellation(err)
	}
	return Result{Match: match, NeedsUpgrade: match && upgrade(r.parameters, h.options.Parameters)}, nil
}

func (h *Hasher) validate(ctx context.Context, password []byte) error {
	if h == nil || h.budget == nil {
		return ErrInvalidOptions
	}
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return cancellation(err)
	}
	if len(password) == 0 || len(password) > MaxPasswordBytes {
		return ErrPasswordInput
	}
	return nil
}

func cancellation(err error) error {
	if err == context.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

func (h *Hasher) acquire(p Parameters) error {
	if p.MemoryKiB > h.options.MaxMemoryKiB || uint32(p.Parallelism) > h.options.MaxLanes {
		return ErrResourceLimit
	}
	b := h.budget
	b.Lock()
	defer b.Unlock()
	if b.jobs >= h.options.MaxConcurrent || p.MemoryKiB > h.options.MaxMemoryKiB-b.memoryKiB || uint32(p.Parallelism) > h.options.MaxLanes-b.lanes {
		return ErrBusy
	}
	b.jobs++
	b.memoryKiB += p.MemoryKiB
	b.lanes += uint32(p.Parallelism)
	return nil
}

func (h *Hasher) release(p Parameters) {
	b := h.budget
	b.Lock()
	defer b.Unlock()
	b.jobs--
	b.memoryKiB -= p.MemoryKiB
	b.lanes -= uint32(p.Parallelism)
}

func validParameters(p Parameters) bool {
	return p.Parallelism >= 1 && p.Parallelism <= MaxParallelism && p.Iterations >= 1 && p.Iterations <= MaxIterations && p.MemoryKiB >= 8*uint32(p.Parallelism) && p.MemoryKiB <= MaxMemoryKiB && p.SaltBytes >= MinSaltBytes && p.SaltBytes <= MaxSaltBytes && p.KeyBytes >= MinKeyBytes && p.KeyBytes <= MaxKeyBytes
}

type record struct {
	parameters Parameters
	salt, key  []byte
}

func parse(encoded string) (record, bool) {
	if len(encoded) > MaxEncodedBytes {
		return record{}, false
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return record{}, false
	}
	params := strings.Split(parts[3], ",")
	if len(params) != 3 {
		return record{}, false
	}
	memory, okM := decimal(strings.TrimPrefix(params[0], "m="), MaxMemoryKiB)
	iterations, okT := decimal(strings.TrimPrefix(params[1], "t="), MaxIterations)
	lanes, okP := decimal(strings.TrimPrefix(params[2], "p="), MaxParallelism)
	if !strings.HasPrefix(params[0], "m=") || !strings.HasPrefix(params[1], "t=") || !strings.HasPrefix(params[2], "p=") || !okM || !okT || !okP || memory < 8*lanes {
		return record{}, false
	}
	// Bound both decoded lengths before allocating either buffer. Only canonical
	// unpadded standard base64 is accepted; even CR/LF must not be ignored.
	saltLen, okS := decodedLength(parts[4], MinSaltBytes, MaxSaltBytes)
	keyLen, okK := decodedLength(parts[5], MinKeyBytes, MaxKeyBytes)
	if !okS || !okK {
		return record{}, false
	}
	salt, key := make([]byte, saltLen), make([]byte, keyLen)
	encoding := base64.RawStdEncoding.Strict()
	if _, err := encoding.Decode(salt, []byte(parts[4])); err != nil {
		return record{}, false
	}
	if _, err := encoding.Decode(key, []byte(parts[5])); err != nil {
		clear(key)
		return record{}, false
	}
	return record{parameters: Parameters{MemoryKiB: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(lanes), SaltBytes: uint32(saltLen), KeyBytes: uint32(keyLen)}, salt: salt, key: key}, true
}

func decimal(s string, max uint64) (uint64, bool) {
	if len(s) == 0 || len(s) > 10 || s[0] == '0' {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		digit := uint64(s[i] - '0')
		if n > max/10 || (n == max/10 && digit > max%10) {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

func decodedLength(s string, min, max int) (int, bool) {
	if len(s) < base64.RawStdEncoding.EncodedLen(min) || len(s) > base64.RawStdEncoding.EncodedLen(max) || len(s)%4 == 1 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
			return 0, false
		}
	}
	n := base64.RawStdEncoding.DecodedLen(len(s))
	return n, n >= min && n <= max
}

func effectiveMemory(p Parameters) uint32 {
	segment := 4 * uint32(p.Parallelism)
	return p.MemoryKiB / segment * segment
}

func upgrade(stored, target Parameters) bool {
	// Parallelism alone is not a strength ordering. Conservatively avoid every
	// memory/time/salt/key downgrade, including Argon2's lane memory rounding.
	if target.MemoryKiB < stored.MemoryKiB || effectiveMemory(target) < effectiveMemory(stored) || target.Iterations < stored.Iterations || target.SaltBytes < stored.SaltBytes || target.KeyBytes < stored.KeyBytes {
		return false
	}
	return effectiveMemory(target) > effectiveMemory(stored) || target.Iterations > stored.Iterations || target.SaltBytes > stored.SaltBytes || target.KeyBytes > stored.KeyBytes
}

func (Hasher) Format(s fmt.State, _ rune) { fmt.Fprint(s, "[authn password hasher]") }
func (Hasher) LogValue() slog.Value       { return slog.StringValue("[authn password hasher]") }
