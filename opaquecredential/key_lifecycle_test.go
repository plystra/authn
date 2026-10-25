package opaquecredential_test

import (
	"errors"
	"sync"
	"testing"

	"github.com/plystra/authn/opaquecredential"
)

func TestOpaqueRejectsAllZeroKeyMaterial(t *testing.T) {
	ref := opaquecredential.KeyRef{ID: "primary", Version: 1}
	for size := opaquecredential.MinKeyBytes; size <= opaquecredential.MaxKeyBytes; size++ {
		k, err := opaquecredential.NewKey(ref, make([]byte, size))
		if !errors.Is(err, opaquecredential.ErrInvalidKey) || k != (opaquecredential.Key{}) {
			t.Fatalf("accepted all-zero HMAC material of length %d", size)
		}
		if r, err := opaquecredential.New(k); r != nil || !errors.Is(err, opaquecredential.ErrInvalidRing) {
			t.Fatal("all-invalid ring accepted")
		}
	}
	// Validation rejects an absent key, without claiming to estimate entropy.
	// Provisioning is responsible for cryptographically random nonzero keys.
	for _, index := range []int{0, opaquecredential.MinKeyBytes - 1} {
		input := make([]byte, opaquecredential.MinKeyBytes)
		input[index] = 1
		if _, err := opaquecredential.NewKey(ref, input); err != nil {
			t.Fatal("content validation invented an entropy estimate")
		}
	}
}

func TestOpaqueStagedKeyActivation(t *testing.T) {
	old := key(t, "primary", 1, material())
	next := key(t, "primary", 2, []byte("public-test-only-new-hmac-key-canary"))
	b := binding()
	before := ring(t, old)
	oldSecret, oldDigest := generate(t, before, b)
	verificationKeys := []opaquecredential.Key{next}
	staged := ring(t, old, verificationKeys...)
	clear(verificationKeys)
	stagedSecret, stagedDigest := generate(t, staged, b)
	if stagedDigest.Key() != oldDigest.Key() {
		t.Fatal("deploying a verification key activated it for writes")
	}
	active := ring(t, next, old)
	newSecret, newDigest := generate(t, active, b)
	if newDigest.Key() != (opaquecredential.KeyRef{ID: "primary", Version: 2}) {
		t.Fatal("explicit activation did not select the new write key")
	}
	if check, err := staged.Verify(b, newSecret, newDigest); err != nil || !check.Match {
		t.Fatal("predeployed verification key cannot verify newly written records")
	}
	if check, err := before.Verify(b, newSecret, newDigest); !errors.Is(err, opaquecredential.ErrKeyUnavailable) || check != (opaquecredential.Result{}) {
		t.Fatal("old ring changed or tried an unavailable key")
	}
	for _, record := range []struct {
		secret opaquecredential.Secret
		digest opaquecredential.Digest
	}{{oldSecret, oldDigest}, {stagedSecret, stagedDigest}} {
		check, err := active.Verify(b, record.secret, record.digest)
		if err != nil || !check.Match || !check.NeedsRehash || check.Replacement.Key() != newDigest.Key() {
			t.Fatal("retained old record did not permit controlled rehash")
		}
		if result, err := ring(t, next).Verify(b, record.secret, check.Replacement); err != nil || !result.Match || result.NeedsRehash {
			t.Fatal("rehash did not survive old-key retirement")
		}
	}
	if check, err := staged.Verify(b, stagedSecret, stagedDigest); err != nil || !check.Match || check.NeedsRehash {
		t.Fatal("activation mutated the earlier ring snapshot")
	}
}

func TestOpaqueTamperingAndUnknownVersions(t *testing.T) {
	r := ring(t, key(t, "primary", 1, material()))
	b := binding()
	s, d := generate(t, r, b)
	for index := range d.Bytes() {
		bytes := d.Bytes()
		bytes[index] ^= 1
		altered, err := opaquecredential.Restore(d.Version(), d.Key(), bytes)
		if err != nil {
			t.Fatal(err)
		}
		if check, err := r.Verify(b, s, altered); err != nil || check != (opaquecredential.Result{}) {
			t.Fatal("tampered digest matched or produced replacement material")
		}
	}
	for _, ref := range []opaquecredential.KeyRef{{ID: "primary", Version: 2}, {ID: "primary", Version: ^uint32(0)}, {ID: "not-installed", Version: 1}} {
		altered, err := opaquecredential.Restore(d.Version(), ref, d.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if check, err := r.Verify(b, s, altered); !errors.Is(err, opaquecredential.ErrKeyUnavailable) || check != (opaquecredential.Result{}) {
			t.Fatal("unknown stored key reference triggered fallback")
		}
	}
}

func TestOpaqueRotationSnapshotConcurrency(t *testing.T) {
	old := key(t, "primary", 1, material())
	next := key(t, "primary", 2, []byte("public-test-only-new-hmac-key-canary"))
	staged, active := ring(t, old, next), ring(t, next, old)
	b := binding()
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			writer, reader := staged, active
			expectedVersion := uint32(1)
			if i%2 != 0 {
				writer, reader = active, staged
				expectedVersion = 2
			}
			for range 32 {
				secret, digest, err := writer.Generate(b)
				if err != nil || digest.Key().Version != expectedVersion {
					t.Error("concurrent ring lost its explicit active key")
					return
				}
				if check, err := reader.Verify(b, secret, digest); err != nil || !check.Match {
					t.Error("concurrent staged/active verification failed")
					return
				}
			}
		})
	}
	workers.Wait()
}
