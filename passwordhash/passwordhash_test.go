package passwordhash_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plystra/authn/passwordhash"
	"golang.org/x/crypto/argon2"
)

func smallParameters() passwordhash.Parameters {
	return passwordhash.Parameters{MemoryKiB: 64, Iterations: 1, Parallelism: 1, SaltBytes: 16, KeyBytes: 32}
}

func hasher(t testing.TB, options passwordhash.Options) *passwordhash.Hasher {
	t.Helper()
	h, err := passwordhash.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func fixture(password []byte, p passwordhash.Parameters) string {
	salt := bytes.Repeat([]byte("s"), int(p.SaltBytes))
	key := argon2.IDKey(password, salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyBytes)
	defer clear(key)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.MemoryKiB, p.Iterations, p.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

func TestPasswordHashDefaultsAndRandomSalt(t *testing.T) {
	ctx := context.Background()
	password := []byte("public test password")
	h := hasher(t, passwordhash.Options{})
	encoded, err := h.Hash(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=65536,t=3,p=4$") || len(encoded) > passwordhash.MaxEncodedBytes {
		t.Fatal("incorrect default profile")
	}
	parts := strings.Split(encoded, "$")
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != 16 {
		t.Fatal("incorrect salt encoding")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) != 32 {
		t.Fatal("incorrect key encoding")
	}
	actual := argon2.IDKey(password, salt, 3, 65536, 4, 32)
	defer clear(actual)
	if !bytes.Equal(actual, key) {
		t.Fatal("hash is not the requested Argon2id derivation")
	}
	result, err := h.Verify(ctx, password, encoded)
	if err != nil || !result.Match || result.NeedsUpgrade {
		t.Fatal("default verification failed")
	}
	h = hasher(t, passwordhash.Options{Parameters: smallParameters()})
	a, err := h.Hash(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.Hash(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Split(a, "$")[4] == strings.Split(b, "$")[4] {
		t.Fatal("salt was reused")
	}
}

func TestPasswordHashOptionsAndInputs(t *testing.T) {
	base := passwordhash.Options{Parameters: smallParameters()}
	changes := []func(*passwordhash.Options){
		func(o *passwordhash.Options) { o.Parameters.MemoryKiB = 0 },
		func(o *passwordhash.Options) { o.Parameters.MemoryKiB = 7 },
		func(o *passwordhash.Options) { o.Parameters.MemoryKiB = passwordhash.MaxMemoryKiB + 1 },
		func(o *passwordhash.Options) { o.Parameters.MemoryKiB = ^uint32(0) },
		func(o *passwordhash.Options) { o.Parameters.Iterations = 0 },
		func(o *passwordhash.Options) { o.Parameters.Iterations = passwordhash.MaxIterations + 1 },
		func(o *passwordhash.Options) { o.Parameters.Parallelism = 0 },
		func(o *passwordhash.Options) { o.Parameters.Parallelism = passwordhash.MaxParallelism + 1 },
		func(o *passwordhash.Options) { o.Parameters.SaltBytes = 15 },
		func(o *passwordhash.Options) { o.Parameters.SaltBytes = 65 },
		func(o *passwordhash.Options) { o.Parameters.KeyBytes = 15 },
		func(o *passwordhash.Options) { o.Parameters.KeyBytes = 65 },
		func(o *passwordhash.Options) { o.MaxConcurrent = 65 },
		func(o *passwordhash.Options) { o.MaxMemoryKiB = 1048577 },
		func(o *passwordhash.Options) { o.MaxLanes = 65 },
		func(o *passwordhash.Options) { o.MaxMemoryKiB = 63 },
		func(o *passwordhash.Options) { o.Parameters.Parallelism = 2; o.MaxLanes = 1 },
	}
	for i, change := range changes {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			opts := base
			change(&opts)
			if h, err := passwordhash.New(opts); h != nil || !errors.Is(err, passwordhash.ErrInvalidOptions) {
				t.Fatal("accepted invalid options")
			}
		})
	}
	h := hasher(t, base)
	base.Parameters.MemoryKiB = 0 // Constructor copied the caller's options.
	for _, password := range [][]byte{nil, {}, bytes.Repeat([]byte("x"), passwordhash.MaxPasswordBytes+1), []byte(strings.Repeat("界", 342))} {
		if encoded, err := h.Hash(context.Background(), password); encoded != "" || !errors.Is(err, passwordhash.ErrPasswordInput) {
			t.Fatal("accepted invalid password input")
		}
		if result, err := h.Verify(context.Background(), password, "untrusted record"); result != (passwordhash.Result{}) || !errors.Is(err, passwordhash.ErrPasswordInput) {
			t.Fatal("accepted invalid verification input")
		}
	}
	password := bytes.Repeat([]byte("x"), passwordhash.MaxPasswordBytes)
	encoded, err := h.Hash(context.Background(), password)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := h.Verify(context.Background(), password, encoded); err != nil || !result.Match {
		t.Fatal("rejected maximum password length")
	}
	if _, err := h.Hash(nil, []byte("x")); !errors.Is(err, passwordhash.ErrInvalidContext) {
		t.Fatal("accepted nil context")
	}
	var zero passwordhash.Hasher
	for _, h := range []*passwordhash.Hasher{nil, &zero} {
		if value, err := h.Hash(context.Background(), []byte("x")); value != "" || !errors.Is(err, passwordhash.ErrInvalidOptions) {
			t.Fatal("accepted zero hasher")
		}
		if result, err := h.Verify(context.Background(), []byte("x"), encoded); result != (passwordhash.Result{}) || !errors.Is(err, passwordhash.ErrInvalidOptions) {
			t.Fatal("accepted zero verifier")
		}
	}
}

func TestPasswordHashStrictPHCBounds(t *testing.T) {
	h := hasher(t, passwordhash.Options{Parameters: smallParameters(), MaxMemoryKiB: 64})
	password := []byte("public test password")
	valid := fixture(password, smallParameters())
	parts := strings.Split(valid, "$")
	bad := []string{"", strings.Repeat("x", 257), " " + valid, valid + "$extra", strings.Replace(valid, "argon2id", "argon2i", 1), strings.Replace(valid, "v=19", "v=16", 1), strings.Replace(valid, "v=19", "v=019", 1)}
	for _, parameters := range []string{
		"m=0,t=1,p=1", "m=7,t=1,p=1", "m=262145,t=1,p=1", "m=4294967296,t=1,p=1", "m=18446744073709551616,t=1,p=1",
		"m=-64,t=1,p=1", "m=+64,t=1,p=1", "m=064,t=1,p=1", "m=64.0,t=1,p=1", "m= 64,t=1,p=1",
		"m=64,t=0,p=1", "m=64,t=7,p=1", "m=64,t=4294967297,p=1", "m=64,t=1,p=0", "m=64,t=1,p=9", "m=64,t=1,p=257", "m=8,t=1,p=2",
		"m=64,t=1,p=1,m=64", "m=64,t=1", "m=64,t=1,x=1", "m=64,t=1,t=1", "t=1,m=64,p=1", "64,t=1,p=1", "m=64,t=1,p=1\n",
	} {
		copy := append([]string(nil), parts...)
		copy[3] = parameters
		bad = append(bad, strings.Join(copy, "$"))
	}
	for _, index := range []int{4, 5} {
		for _, value := range []string{"", base64.RawStdEncoding.EncodeToString(make([]byte, 15)), base64.RawStdEncoding.EncodeToString(make([]byte, 65)), strings.Repeat("A", 21) + "B", parts[index] + "=", parts[index] + "\n", parts[index][:2] + "\r" + parts[index][2:], "!" + parts[index][1:]} {
			copy := append([]string(nil), parts...)
			copy[index] = value
			bad = append(bad, strings.Join(copy, "$"))
		}
	}
	for i, encoded := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result, err := h.Verify(context.Background(), password, encoded)
			if result != (passwordhash.Result{}) || !errors.Is(err, passwordhash.ErrInvalidHash) {
				t.Fatal("malformed record reached derivation or admission")
			}
			if strings.Contains(err.Error(), encoded) && encoded != "" {
				t.Fatal("error echoed untrusted record")
			}
		})
	}
	// Valid but excessive per-instance costs are rejected before derivation.
	for _, parameters := range []string{"m=262144,t=6,p=8", "m=64,t=1,p=8"} {
		copy := append([]string(nil), parts...)
		copy[3] = parameters
		limited := h
		if strings.Contains(parameters, "p=8") && !strings.Contains(parameters, "262144") {
			limited = hasher(t, passwordhash.Options{Parameters: smallParameters(), MaxLanes: 1})
		}
		if result, err := limited.Verify(context.Background(), password, strings.Join(copy, "$")); result != (passwordhash.Result{}) || !errors.Is(err, passwordhash.ErrResourceLimit) {
			t.Fatal("excessive record escaped resource limits")
		}
	}
	p := smallParameters()
	p.Iterations = 6
	p.Parallelism = 8
	p.SaltBytes = 64
	p.KeyBytes = 64
	result, err := hasher(t, passwordhash.Options{Parameters: smallParameters()}).Verify(context.Background(), password, fixture(password, p))
	if err != nil || !result.Match {
		t.Fatal("rejected valid bounded PHC profile")
	}
}

func TestPasswordHashMatchAndUpgrade(t *testing.T) {
	password := []byte(" exact public password ")
	legacy := smallParameters()
	target := legacy
	target.MemoryKiB = 128
	target.Iterations = 2
	h := hasher(t, passwordhash.Options{Parameters: target})
	for _, tt := range []struct {
		name    string
		p       passwordhash.Parameters
		upgrade bool
	}{
		{"legacy", legacy, true}, {"current", target, false},
		{"stronger-memory", func() passwordhash.Parameters { p := target; p.MemoryKiB = 256; return p }(), false},
		{"mixed-cost", func() passwordhash.Parameters { p := legacy; p.MemoryKiB = 256; return p }(), false},
		{"stronger-key", func() passwordhash.Parameters { p := legacy; p.KeyBytes = 64; return p }(), false},
		{"stronger-salt", func() passwordhash.Parameters { p := legacy; p.SaltBytes = 64; return p }(), false},
		{"lanes-alone", func() passwordhash.Parameters { p := target; p.Parallelism = 2; return p }(), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			encoded := fixture(password, tt.p)
			result, err := h.Verify(context.Background(), password, encoded)
			if err != nil || !result.Match || result.NeedsUpgrade != tt.upgrade {
				t.Fatal("incorrect upgrade result")
			}
			for _, wrong := range [][]byte{[]byte("wrong"), bytes.TrimSpace(password)} {
				result, err = h.Verify(context.Background(), wrong, encoded)
				if err != nil || result != (passwordhash.Result{}) {
					t.Fatal("mismatch leaked upgrade or changed password bytes")
				}
			}
		})
	}
	// A larger lane count can round memory down: do not recommend that downgrade.
	stored := legacy
	stored.MemoryKiB = 70
	target = stored
	target.Parallelism = 8
	target.KeyBytes = 64
	h = hasher(t, passwordhash.Options{Parameters: target})
	result, err := h.Verify(context.Background(), password, fixture(password, stored))
	if err != nil || !result.Match || result.NeedsUpgrade {
		t.Fatal("ignored effective memory rounding")
	}
}

type gateContext struct {
	context.Context
	calls            atomic.Int32
	entered, release chan struct{}
}

func (c *gateContext) Err() error {
	err := c.Context.Err()
	if c.calls.Add(1) == 2 {
		close(c.entered)
		<-c.release
	}
	return err
}

func TestPasswordHashAdmissionAndCancellation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		options passwordhash.Options
	}{
		{"jobs", passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 1}},
		{"memory", passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 4, MaxMemoryKiB: 64}},
		{"lanes", passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 4, MaxLanes: 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := hasher(t, tt.options)
			copy := *h
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			gate := &gateContext{Context: parent, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(gate.release) }) }
			defer release()
			finished := make(chan error, 1)
			go func() {
				value, err := h.Hash(gate, []byte("public password"))
				if value != "" {
					finished <- errors.New("cancelled hash escaped")
					return
				}
				finished <- err
			}()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("hash did not reach admitted work")
			}
			cancel()
			// Cancellation cannot release a running operation's permit. A copied
			// Hasher must share all three budgets with the original instance.
			if value, err := copy.Hash(context.Background(), []byte("another password")); value != "" || !errors.Is(err, passwordhash.ErrBusy) {
				t.Fatal("cancelled work released capacity prematurely")
			}
			release()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("lost cancellation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("hash did not complete")
			}
			if _, err := h.Hash(context.Background(), []byte("public password")); err != nil {
				t.Fatal("capacity was not released after completion")
			}
		})
	}
}

type finalCancelContext struct {
	context.Context
	cancel context.CancelFunc
	calls  atomic.Int32
}

func TestPasswordHashVerificationAdmission(t *testing.T) {
	for _, scope := range []string{"memory", "lanes"} {
		t.Run(scope, func(t *testing.T) {
			stored := smallParameters()
			opts := passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 4, MaxMemoryKiB: 128, MaxLanes: 8}
			if scope == "memory" {
				stored.MemoryKiB = 128
			} else {
				stored.Parallelism = 2
				opts.MaxMemoryKiB = 1024
				opts.MaxLanes = 2
			}
			h := hasher(t, opts)
			password := []byte("public password")
			encoded := fixture(password, stored)
			gate := &gateContext{Context: context.Background(), entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(gate.release) }) }
			defer release()
			finished := make(chan error, 1)
			go func() {
				result, err := h.Verify(gate, password, encoded)
				if err == nil && !result.Match {
					err = errors.New("stored-cost verification failed")
				}
				finished <- err
			}()
			select {
			case <-gate.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("verification did not reach admitted work")
			}
			if _, err := h.Hash(context.Background(), password); !errors.Is(err, passwordhash.ErrBusy) {
				t.Fatal("verification admission used target costs instead of stored costs")
			}
			release()
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("verification did not complete")
			}
			if _, err := h.Hash(context.Background(), password); err != nil {
				t.Fatal("verification leaked capacity")
			}
		})
	}
}

func (c *finalCancelContext) Err() error {
	if c.calls.Add(1) == 3 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestPasswordHashContextOutcomes(t *testing.T) {
	h := hasher(t, passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 1})
	password := []byte("public password")
	encoded := fixture(password, smallParameters())
	for _, verify := range []bool{false, true} {
		parent, cancel := context.WithCancel(context.Background())
		cancel()
		var err error
		if verify {
			result, e := h.Verify(parent, password, encoded)
			err = e
			if result != (passwordhash.Result{}) {
				t.Fatal("cancelled verification escaped")
			}
		} else {
			value, e := h.Hash(parent, password)
			err = e
			if value != "" {
				t.Fatal("cancelled hash escaped")
			}
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatal("ignored cancellation before work")
		}
		parent, cancel = context.WithCancel(context.Background())
		ctx := &finalCancelContext{Context: parent, cancel: cancel}
		if verify {
			result, e := h.Verify(ctx, password, encoded)
			err = e
			if result != (passwordhash.Result{}) {
				t.Fatal("late cancellation exposed match")
			}
		} else {
			value, e := h.Hash(ctx, password)
			err = e
			if value != "" {
				t.Fatal("late cancellation exposed hash")
			}
		}
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("ignored cancellation after work")
		}
		if result, e := h.Verify(context.Background(), password, encoded); e != nil || !result.Match {
			t.Fatal("late cancellation leaked admission permit")
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := h.Hash(ctx, password); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("lost deadline classification")
	}
}

func TestPasswordHashConcurrentPublicUse(t *testing.T) {
	h := hasher(t, passwordhash.Options{Parameters: smallParameters(), MaxConcurrent: 4, MaxMemoryKiB: 256, MaxLanes: 4})
	password := []byte("public test password")
	encoded := fixture(password, smallParameters())
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 24; i++ {
		wg.Go(func() {
			for j := 0; j < 4; j++ {
				result, err := h.Verify(context.Background(), password, encoded)
				if errors.Is(err, passwordhash.ErrBusy) {
					continue
				}
				if err != nil || !result.Match || result.NeedsUpgrade {
					t.Error("concurrent verification failed")
					return
				}
				successes.Add(1)
				value, err := h.Hash(context.Background(), password)
				if errors.Is(err, passwordhash.ErrBusy) {
					continue
				}
				if err != nil || value == "" {
					t.Error("concurrent hashing failed")
				}
			}
		})
	}
	wg.Wait()
	if successes.Load() == 0 {
		t.Fatal("all admitted work disappeared")
	}
}

func FuzzPasswordHashPHC(f *testing.F) {
	password := []byte("public fuzz password")
	h := hasher(f, passwordhash.Options{Parameters: smallParameters(), MaxMemoryKiB: 64, MaxLanes: 1})
	f.Add(fixture(password, smallParameters()))
	f.Add("$argon2id$v=19$m=4294967296,t=1,p=1$invalid$invalid")
	f.Add(strings.Repeat("x", 257))
	f.Fuzz(func(t *testing.T, encoded string) {
		result, err := h.Verify(context.Background(), password, encoded)
		if err != nil {
			if result != (passwordhash.Result{}) || (!errors.Is(err, passwordhash.ErrInvalidHash) && !errors.Is(err, passwordhash.ErrResourceLimit)) {
				t.Fatal("unexpected parser outcome")
			}
		} else if result.NeedsUpgrade && !result.Match {
			t.Fatal("mismatch carried upgrade authority")
		}
	})
}
