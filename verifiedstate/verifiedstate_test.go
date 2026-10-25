package verifiedstate_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	verifyv1 "github.com/plystra/authn/interfaces/authn/session/verify/v1"
	"github.com/plystra/authn/verifiedstate"
	"github.com/plystra/kernel/invocation"
)

type sessionFunc func(context.Context, verifyv1.Request) (verifyv1.Response, error)

func (f sessionFunc) Verify(ctx context.Context, req verifyv1.Request) (verifyv1.Response, error) {
	return f(ctx, req)
}

var sequence atomic.Uint64

func facts() verifyv1.Response {
	id := fmt.Sprint(sequence.Add(1))
	return verifyv1.Response{Issuer: "issuer-" + id, SubjectKind: "user", SubjectID: "subject-" + id, SessionID: "session-" + id, Audience: "audience-" + id, SubjectRevision: 1, SessionRevision: 1, ExpiresAt: time.Now().Add(time.Hour)}
}
func options(r verifyv1.Response) verifiedstate.Options {
	return verifiedstate.Options{Issuer: r.Issuer, Audience: r.Audience}
}
func subject(r verifyv1.Response) verifiedstate.Subject {
	return verifiedstate.Subject{Issuer: r.Issuer, Kind: verifiedstate.SubjectKind(r.SubjectKind), ID: r.SubjectID}
}
func verifier(t *testing.T, r verifyv1.Response, reuse time.Duration) *verifiedstate.Verifier {
	t.Helper()
	opts := options(r)
	opts.MaxReuse = reuse
	v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { return r, nil }), opts)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func verify(t *testing.T, v *verifiedstate.Verifier, ctx context.Context) (context.Context, verifiedstate.Attestation) {
	t.Helper()
	next, s, err := v.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := verifiedstate.FromContext(next)
	if !ok || a.Subject() != s || !a.Same(a) {
		t.Fatal("success did not create valid exact subject state")
	}
	return next, a
}
func failed(t *testing.T, v *verifiedstate.Verifier, ctx context.Context, target error) {
	t.Helper()
	next, s, err := v.Verify(ctx)
	if next != ctx || s != (verifiedstate.Subject{}) || err == nil || (target != nil && !errors.Is(err, target)) {
		t.Fatalf("failure must retain input context, zero subject and safe classification: %v", err)
	}
	if _, ok := verifiedstate.FromContext(next); ok {
		t.Fatal("failure created trusted state")
	}
}

func TestVerifierConstruction(t *testing.T) {
	r := facts()
	good := options(r)
	binding := sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { return r, nil })
	for _, opts := range []verifiedstate.Options{{}, {Issuer: r.Issuer}, {Audience: r.Audience}, {Issuer: r.Issuer, Audience: r.Audience, MaxReuse: -1}, {Issuer: r.Issuer, Audience: r.Audience, MaxReuse: 5*time.Minute + 1}, {Issuer: string([]byte{0xff}), Audience: r.Audience}, {Issuer: r.Issuer, Audience: "a\n"}, {Issuer: strings.Repeat("a", 257), Audience: r.Audience}} {
		if v, err := verifiedstate.New(binding, opts); v != nil || !errors.Is(err, verifiedstate.ErrInvalidOptions) {
			t.Fatal("accepted invalid options")
		}
	}
	var nilFunc sessionFunc
	var nilPointer *sessionFunc
	for _, b := range []verifyv1.Interface{nil, nilFunc, nilPointer} {
		if v, err := verifiedstate.New(b, good); v != nil || !errors.Is(err, verifiedstate.ErrInvalidOptions) {
			t.Fatal("accepted nil binding")
		}
	}
	good.MaxReuse = 5 * time.Minute
	if _, err := verifiedstate.New(binding, good); err != nil {
		t.Fatal(err)
	}
	var zero verifiedstate.Verifier
	failed(t, &zero, context.Background(), verifiedstate.ErrInvalidOptions)
	failed(t, (*verifiedstate.Verifier)(nil), context.Background(), verifiedstate.ErrInvalidOptions)
	failed(t, verifier(t, r, 0), nil, verifiedstate.ErrInvalidContext)
}

func TestVerificationFacts(t *testing.T) {
	for _, kind := range []string{"user", "service"} {
		r := facts()
		r.SubjectKind = kind
		_, a := verify(t, verifier(t, r, 0), context.Background())
		if a.Subject() != subject(r) {
			t.Fatal("subject mapping changed")
		}
	}
	changes := []struct {
		name   string
		change func(*verifyv1.Response)
	}{
		{"issuer-empty", func(r *verifyv1.Response) { r.Issuer = "" }},
		{"issuer-mismatch", func(r *verifyv1.Response) { r.Issuer += "-other" }},
		{"audience-mismatch", func(r *verifyv1.Response) { r.Audience += "-other" }},
		{"kind-agent", func(r *verifyv1.Response) { r.SubjectKind = "agent" }},
		{"kind-application", func(r *verifyv1.Response) { r.SubjectKind = "application" }},
		{"kind-empty", func(r *verifyv1.Response) { r.SubjectKind = "" }},
		{"subject-empty", func(r *verifyv1.Response) { r.SubjectID = "" }},
		{"subject-bytes", func(r *verifyv1.Response) { r.SubjectID = strings.Repeat("界", 86) }},
		{"session-empty", func(r *verifyv1.Response) { r.SessionID = "" }},
		{"session-long", func(r *verifyv1.Response) { r.SessionID = strings.Repeat("x", 257) }},
		{"session-control", func(r *verifyv1.Response) { r.SessionID = "x\u0085" }},
		{"subject-invalid-utf8", func(r *verifyv1.Response) { r.SubjectID = string([]byte{0xff}) }},
		{"subject-control", func(r *verifyv1.Response) { r.SubjectID = "x\x00" }},
		{"audience-empty", func(r *verifyv1.Response) { r.Audience = "" }},
		{"subject-zero-revision", func(r *verifyv1.Response) { r.SubjectRevision = 0 }},
		{"session-zero-revision", func(r *verifyv1.Response) { r.SessionRevision = 0 }},
		{"expiry-zero", func(r *verifyv1.Response) { r.ExpiresAt = time.Time{} }},
		{"expiry-past", func(r *verifyv1.Response) { r.ExpiresAt = time.Now().Add(-time.Second) }},
	}
	for _, tt := range changes {
		t.Run(tt.name, func(t *testing.T) {
			r := facts()
			opts := options(r)
			tt.change(&r)
			v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { return r, nil }), opts)
			if err != nil {
				t.Fatal(err)
			}
			failed(t, v, context.Background(), verifiedstate.ErrInvalidResult)
		})
	}
	r := facts()
	r.SubjectID = strings.Repeat("界", 85) + "x"
	r.SessionID = strings.Repeat("s", 256)
	verify(t, verifier(t, r, 0), context.Background())
}

func TestVerificationCancellation(t *testing.T) {
	r := facts()
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { calls.Add(1); return r, nil }), options(r))
	if err != nil {
		t.Fatal(err)
	}
	failed(t, v, ctx, context.Canceled)
	if calls.Load() != 0 {
		t.Fatal("called binding after cancellation")
	}
	ctx, cancel = context.WithCancel(context.Background())
	v, err = verifiedstate.New(sessionFunc(func(got context.Context, _ verifyv1.Request) (verifyv1.Response, error) {
		if got != ctx {
			t.Fatal("replaced ordinary input context")
		}
		cancel()
		return r, nil
	}), options(r))
	if err != nil {
		t.Fatal(err)
	}
	failed(t, v, ctx, context.Canceled)
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	failed(t, verifier(t, r, 0), deadline, context.DeadlineExceeded)
	ctx, cancel = context.WithCancel(context.Background())
	next, a := verify(t, verifier(t, r, 0), ctx)
	cancel()
	for _, c := range []context.Context{next, context.WithoutCancel(next)} {
		if _, ok := verifiedstate.FromContext(c); ok {
			t.Fatal("cancelled origin was laundered")
		}
	}
	if a.Same(a) || a.Subject() != (verifiedstate.Subject{}) {
		t.Fatal("cancelled attestation remained valid")
	}
}

func TestVerificationPreservesUncertainty(t *testing.T) {
	secret := errors.New("private-uncertainty-canary")
	for _, cancelAfterCall := range []bool{false, true} {
		for _, failure := range []error{
			invocation.NewResultUnknown(secret),
			invocation.NewResultUnknown(hostileError{}),
			fmt.Errorf("private-wrapper-canary: %w", invocation.NewResultUnknown(secret)),
			invocation.NewSemanticError("invalid_credentials", invocation.NewResultUnknown(secret)),
		} {
			r := facts()
			ctx, cancel := context.WithCancel(context.Background())
			v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) {
				if cancelAfterCall {
					cancel()
				}
				return r, failure
			}), options(r))
			if err != nil {
				t.Fatal(err)
			}
			next, s, err := v.Verify(ctx)
			cancel()
			if next != ctx || s != (verifiedstate.Subject{}) || err == nil {
				t.Fatal("uncertain call created trust")
			}
			if invocation.CompletionOf(err) != invocation.CompletionResultUnknown {
				t.Fatal("verification erased uncertainty")
			}
			var marker *invocation.ResultUnknownError
			if !errors.As(err, &marker) {
				t.Fatal("redaction discarded the explicit uncertainty marker")
			}
			if cancelAfterCall && !errors.Is(err, context.Canceled) {
				t.Fatal("lost safe cancellation identity")
			}
			if errors.Is(err, secret) {
				t.Fatal("retained private cause")
			}
			for cause := err; cause != nil; cause = errors.Unwrap(cause) {
				if strings.Contains(fmt.Sprintf("%v %+v %#v", cause, cause, cause), "canary") {
					t.Fatal("error chain leaked private cause")
				}
			}
		}
	}
}

type hostileError struct{}

func (hostileError) Error() string { panic("private-error-canary") }
func (hostileError) Unwrap() error { panic("private-unwrap-canary") }

func TestVerificationFailuresAndRedaction(t *testing.T) {
	r := facts()
	canary := "private-identity-canary"
	r.SubjectID = canary
	r.SessionID = canary + "-session"
	for _, failure := range []error{errors.New(canary), hostileError{}, fmt.Errorf("%s: %w", canary, context.Canceled), invocation.NewSemanticError("invalid_credentials", errors.New(canary))} {
		v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { return r, failure }), options(r))
		if err != nil {
			t.Fatal(err)
		}
		next, s, err := v.Verify(context.Background())
		if err == nil || s != (verifiedstate.Subject{}) {
			t.Fatal("accepted response alongside error")
		}
		if _, ok := verifiedstate.FromContext(next); ok {
			t.Fatal("error created state")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), canary) || errors.Is(err, failure) {
			t.Fatal("retained private cause")
		}
	}
	v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { panic(canary) }), options(r))
	if err != nil {
		t.Fatal(err)
	}
	failed(t, v, context.Background(), verifiedstate.ErrVerification)
	for _, code := range []string{"credential_missing", "credential_ambiguous", "invalid_credentials", "account_disabled", "session_expired", "session_revoked"} {
		v, err := verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) {
			return r, invocation.NewSemanticError(code, nil)
		}), options(r))
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = v.Verify(context.Background())
		var semantic *invocation.SemanticError
		if !errors.As(err, &semantic) || semantic.Code() != code || semantic.Unwrap() != nil {
			t.Fatal("lost safe governed classification")
		}
	}
	boundary, _ := invocation.NewError(invocation.ErrorUnavailable, "private_detail")
	v, err = verifiedstate.New(sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { return r, boundary }), options(r))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = v.Verify(context.Background())
	var safe *invocation.Error
	if !errors.As(err, &safe) || safe.Code() != invocation.ErrorUnavailable || strings.Contains(err.Error(), "private_detail") {
		t.Fatal("unsafe or lost runtime classification")
	}
	v = verifier(t, r, time.Minute)
	ctx, a := verify(t, v, context.Background())
	for _, value := range []any{r, subject(r), options(r), v, *v, a, ctx} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(verb, value), canary) {
				t.Fatal("format leaked identity or session")
			}
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("test", "value", value)
		if strings.Contains(output.String(), canary) {
			t.Fatal("slog leaked identity or session")
		}
	}
}

func TestAttestationOpaqueAndReuse(t *testing.T) {
	r := facts()
	var calls atomic.Int32
	binding := sessionFunc(func(context.Context, verifyv1.Request) (verifyv1.Response, error) { calls.Add(1); return r, nil })
	v, err := verifiedstate.New(binding, options(r))
	if err != nil {
		t.Fatal(err)
	}
	ctx, a := verify(t, v, context.Background())
	_, b := verify(t, v, ctx)
	if calls.Load() != 2 || a.Same(b) {
		t.Fatal("zero reuse skipped verification")
	}
	opts := options(r)
	opts.MaxReuse = time.Minute
	v, err = verifiedstate.New(binding, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, a = verify(t, v, context.Background())
	next, b := verify(t, v, context.WithValue(ctx, "ordinary-key", true))
	if calls.Load() != 3 || !a.Same(b) {
		t.Fatal("same lineage not reused")
	}
	verify(t, v, context.Background())
	if calls.Load() != 4 {
		t.Fatal("reused across unrelated request")
	}
	other, err := verifiedstate.New(binding, opts)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, other, next)
	if calls.Load() != 5 {
		t.Fatal("independent verifier reused foreign state")
	}
	var zero verifiedstate.Attestation
	if zero.Same(zero) || a.Same(zero) || zero.Subject() != (verifiedstate.Subject{}) {
		t.Fatal("zero attestation is trusted")
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[verifiedstate.Attestation](), reflect.TypeFor[verifiedstate.Verifier]()} {
		for i := 0; i < typ.NumField(); i++ {
			if typ.Field(i).IsExported() {
				t.Fatal("exported trust field")
			}
		}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var decoded verifiedstate.Attestation
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Same(a) || decoded.Subject() != (verifiedstate.Subject{}) {
		t.Fatal("serialized fields created trust")
	}
	if _, ok := verifiedstate.FromContext(context.WithValue(context.Background(), "authn", a)); ok {
		t.Fatal("arbitrary context value created trust")
	}
	opts.MaxReuse = time.Nanosecond
	short, err := verifiedstate.New(binding, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ = verify(t, short, context.Background())
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()
	<-timer.C
	verify(t, short, ctx)
	if calls.Load() != 7 {
		t.Fatal("reuse TTL was extended")
	}
}

func TestAttestationExpiration(t *testing.T) {
	r := facts()
	r.ExpiresAt = time.Now().Add(100 * time.Millisecond)
	ctx, a := verify(t, verifier(t, r, time.Minute), context.Background())
	timer := time.NewTimer(time.Until(r.ExpiresAt) + time.Millisecond)
	defer timer.Stop()
	<-timer.C
	if _, ok := verifiedstate.FromContext(ctx); ok || a.Same(a) {
		t.Fatal("expired state remained valid")
	}
}

func TestInvalidationRevisionsAndGenerations(t *testing.T) {
	for _, scope := range []string{"session", "subject"} {
		t.Run(scope, func(t *testing.T) {
			r := facts()
			r.SessionRevision = 10
			r.SubjectRevision = 10
			v := verifier(t, r, time.Minute)
			ctx, old := verify(t, v, context.Background())
			invalidate := func(rev uint64) error {
				if scope == "session" {
					return verifiedstate.InvalidateSession(r.Issuer, r.SessionID, rev)
				}
				return verifiedstate.InvalidateSubject(subject(r), rev)
			}
			if err := invalidate(2); err != nil {
				t.Fatal(err)
			}
			if _, ok := verifiedstate.FromContext(ctx); ok || old.Same(old) {
				t.Fatal("new generation retained older state with higher revision")
			}
			fresh, newer := verify(t, v, ctx)
			for _, rev := range []uint64{2, 1} {
				if err := invalidate(rev); err != nil {
					t.Fatal(err)
				}
			}
			if a, ok := verifiedstate.FromContext(fresh); !ok || !a.Same(newer) {
				t.Fatal("equal/older event invalidated new state")
			}
			if err := invalidate(11); err != nil {
				t.Fatal(err)
			}
			failed(t, v, context.Background(), verifiedstate.ErrStaleResult)
			if scope == "session" {
				r.SessionRevision = 11
			} else {
				r.SubjectRevision = 11
			}
			verify(t, verifier(t, r, 0), context.Background())
		})
	}
	r := facts()
	ctx, a := verify(t, verifier(t, r, 0), context.Background())
	for _, err := range []error{verifiedstate.InvalidateSession(r.Issuer, r.SessionID, 0), verifiedstate.InvalidateSession("", r.SessionID, 2), verifiedstate.InvalidateSession(r.Issuer, "bad\n", 2), verifiedstate.InvalidateSubject(subject(r), 0), verifiedstate.InvalidateSubject(verifiedstate.Subject{Issuer: r.Issuer, Kind: "agent", ID: r.SubjectID}, 2)} {
		if !errors.Is(err, verifiedstate.ErrInvalidation) {
			t.Fatal("invalid invalidation accepted")
		}
	}
	if b, ok := verifiedstate.FromContext(ctx); !ok || !a.Same(b) {
		t.Fatal("invalid event changed state")
	}
	// Keys include exact issuer and kind; no cross-subject invalidation.
	if err := verifiedstate.InvalidateSession(r.Issuer+"other", r.SessionID, 99); err != nil {
		t.Fatal(err)
	}
	s := subject(r)
	s.Kind = verifiedstate.SubjectService
	if err := verifiedstate.InvalidateSubject(s, 99); err != nil {
		t.Fatal(err)
	}
	if _, ok := verifiedstate.FromContext(ctx); !ok {
		t.Fatal("invalidation crossed issuer or kind")
	}
}

func TestConcurrentVerificationInvalidation(t *testing.T) {
	r := facts()
	r.SessionRevision = 1000
	r.SubjectRevision = 1000
	v := verifier(t, r, time.Minute)
	ctx, _ := verify(t, v, context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := uint64(1); j <= 100; j++ {
				if err := verifiedstate.InvalidateSession(r.Issuer, r.SessionID, j); err != nil {
					t.Error(err)
				}
				if err := verifiedstate.InvalidateSubject(subject(r), j); err != nil {
					t.Error(err)
				}
				next, s, err := v.Verify(ctx)
				if err != nil || s != subject(r) {
					t.Error("valid revision rejected during invalidation")
				}
				verifiedstate.FromContext(next)
			}
		})
	}
	wg.Wait()
	newctx, newa := verify(t, v, context.Background())
	if err := verifiedstate.InvalidateSession(r.Issuer, r.SessionID, 100); err != nil {
		t.Fatal(err)
	}
	if a, ok := verifiedstate.FromContext(newctx); !ok || !a.Same(newa) {
		t.Fatal("repeated concurrent event changed generation")
	}
}
