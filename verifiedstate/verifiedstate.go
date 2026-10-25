// Package verifiedstate turns successful session verification facts into opaque,
// process-local authentication state. It performs no credential parsing or I/O
// beyond the explicitly injected session Interface call.
package verifiedstate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	verifyv1 "github.com/plystra/authn/interfaces/authn/session/verify/v1"
	"github.com/plystra/kernel/invocation"
)

type SubjectKind string

const (
	SubjectUser    SubjectKind = "user"
	SubjectService SubjectKind = "service"
)

// Subject identifies an authenticated principal, not an AuthZ acting member.
type Subject struct {
	Issuer string
	Kind   SubjectKind
	ID     string
}

type Options struct {
	Issuer   string
	Audience string
	MaxReuse time.Duration
}

var (
	ErrInvalidOptions = errors.New("invalid authentication verifier options")
	ErrInvalidContext = errors.New("invalid authentication context")
	ErrVerification   = errors.New("session verification failed")
	ErrInvalidResult  = errors.New("invalid session verification result")
	ErrStaleResult    = errors.New("stale session verification result")
	ErrInvalidation   = errors.New("invalid authentication invalidation")
)

// Verifier is immutable after New. Copies retain the same reuse identity.
type Verifier struct {
	binding  verifyv1.Interface
	options  Options
	identity *generation
}

// Attestation has no wire form. Its zero value is invalid.
type Attestation struct{ state *state }

type contextKey struct{}
type generation struct{ marker byte }
type sessionKey struct{ issuer, id string }
type watermark struct {
	revision   uint64
	generation *generation
}

var process = new(generation)
var invalidations = struct {
	sync.RWMutex
	sessions map[sessionKey]watermark
	subjects map[Subject]watermark
}{sessions: make(map[sessionKey]watermark), subjects: make(map[Subject]watermark)}

type state struct {
	process, owner                       *generation
	subject                              Subject
	session                              sessionKey
	audience                             string
	subjectRevision, sessionRevision     uint64
	subjectGeneration, sessionGeneration *generation
	verifiedAt, expiresAt                time.Time
	// Retain cancellation even if a caller uses context.WithoutCancel later.
	origin context.Context
}

func New(session verifyv1.Interface, options Options) (*Verifier, error) {
	if nilBinding(session) || !identifier(options.Issuer) || !identifier(options.Audience) || options.MaxReuse < 0 || options.MaxReuse > 5*time.Minute {
		return nil, ErrInvalidOptions
	}
	return &Verifier{binding: session, options: options, identity: new(generation)}, nil
}

func nilBinding(binding verifyv1.Interface) bool {
	if binding == nil {
		return true
	}
	v := reflect.ValueOf(binding)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func (v *Verifier) Verify(ctx context.Context) (context.Context, Subject, error) {
	fail := func(err error) (context.Context, Subject, error) { return ctx, Subject{}, err }
	if ctx == nil {
		return fail(ErrInvalidContext)
	}
	if err := ctx.Err(); err != nil {
		return fail(contextFailure(err))
	}
	if v == nil || v.identity == nil || nilBinding(v.binding) {
		return fail(ErrInvalidOptions)
	}
	if v.options.MaxReuse > 0 {
		if a, ok := FromContext(ctx); ok && a.state.owner == v.identity && a.state.subject.Issuer == v.options.Issuer && a.state.audience == v.options.Audience && time.Since(a.state.verifiedAt) < v.options.MaxReuse {
			return ctx, a.state.subject, nil
		}
	}
	response, err := call(v.binding, ctx)
	if failure := ctx.Err(); failure != nil {
		return fail(preserveUncertainty(contextFailure(failure), err))
	}
	if err != nil {
		return fail(preserveUncertainty(safeFailure(err), err))
	}
	subject := Subject{Issuer: response.Issuer, Kind: SubjectKind(response.SubjectKind), ID: response.SubjectID}
	if !validSubject(subject) || !identifier(response.SessionID) || !identifier(response.Audience) || response.Issuer != v.options.Issuer || response.Audience != v.options.Audience || response.SubjectRevision == 0 || response.SessionRevision == 0 {
		return fail(ErrInvalidResult)
	}
	key := sessionKey{response.Issuer, response.SessionID}
	invalidations.RLock()
	defer invalidations.RUnlock()
	sw, uw := invalidations.sessions[key], invalidations.subjects[subject]
	if response.SubjectRevision < uw.revision || response.SessionRevision < sw.revision {
		return fail(ErrStaleResult)
	}
	now := time.Now()
	if !now.Before(response.ExpiresAt) {
		return fail(ErrInvalidResult)
	}
	if err := ctx.Err(); err != nil {
		return fail(contextFailure(err))
	}
	s := &state{
		process: process, owner: v.identity, subject: subject, session: key, audience: response.Audience,
		subjectRevision: response.SubjectRevision, sessionRevision: response.SessionRevision,
		subjectGeneration: uw.generation, sessionGeneration: sw.generation,
		verifiedAt: now, expiresAt: response.ExpiresAt, origin: ctx,
	}
	return context.WithValue(ctx, contextKey{}, s), subject, nil
}

func call(binding verifyv1.Interface, ctx context.Context) (response verifyv1.Response, err error) {
	defer func() {
		if recover() != nil {
			response, err = verifyv1.Response{}, ErrVerification
		}
	}()
	return binding.Verify(ctx, verifyv1.Request{})
}

// safeFailure preserves only direct, closed Kernel classifications. Arbitrary
// wrappers and provider causes are discarded without invoking their methods.
func safeFailure(err error) error {
	switch e := err.(type) {
	case *invocation.Error:
		if e.Code().Valid() {
			safe, invalid := invocation.NewError(e.Code(), "authn.session_verification_failed")
			if invalid == nil {
				return safe
			}
		}
	case *invocation.SemanticError:
		// Governed errors are already cause-free. Never traverse an arbitrary
		// error tree here or retain a selected implementation's private cause.
		if e != nil && e.Unwrap() == nil {
			switch e.Code() {
			case "credential_missing", "credential_ambiguous", "invalid_credentials", "account_disabled", "session_expired", "session_revoked":
				return e
			}
		}
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return ErrVerification
}

func preserveUncertainty(safe, original error) error {
	// Kernel's bounded, panic-safe traversal never formats private causes and
	// treats an incomplete traversal conservatively. Retain only its certainty,
	// including when cancellation takes precedence over the primary failure.
	if original != nil && invocation.CompletionOf(original) == invocation.CompletionResultUnknown {
		return invocation.NewResultUnknown(safe)
	}
	return safe
}

func contextFailure(err error) error {
	if err == context.DeadlineExceeded {
		return context.DeadlineExceeded
	}
	return context.Canceled
}

func FromContext(ctx context.Context) (Attestation, bool) {
	if ctx == nil || ctx.Err() != nil {
		return Attestation{}, false
	}
	s, _ := ctx.Value(contextKey{}).(*state)
	a := Attestation{state: s}
	if !a.valid() {
		return Attestation{}, false
	}
	return a, true
}

func (a Attestation) valid() bool {
	s := a.state
	if s == nil || s.process != process || s.owner == nil || s.origin.Err() != nil || !time.Now().Before(s.expiresAt) {
		return false
	}
	invalidations.RLock()
	defer invalidations.RUnlock()
	sw, uw := invalidations.sessions[s.session], invalidations.subjects[s.subject]
	return s.subjectRevision >= uw.revision && s.sessionRevision >= sw.revision && s.subjectGeneration == uw.generation && s.sessionGeneration == sw.generation
}

func (a Attestation) Subject() Subject {
	if !a.valid() {
		return Subject{}
	}
	return a.state.subject
}

func (a Attestation) Same(other Attestation) bool {
	return a.valid() && other.valid() && a.state == other.state
}

func InvalidateSession(issuer, sessionID string, currentRevision uint64) error {
	if !identifier(issuer) || !identifier(sessionID) || currentRevision == 0 {
		return ErrInvalidation
	}
	invalidations.Lock()
	defer invalidations.Unlock()
	key := sessionKey{issuer, sessionID}
	if currentRevision > invalidations.sessions[key].revision {
		invalidations.sessions[key] = watermark{revision: currentRevision, generation: new(generation)}
	}
	return nil
}

func InvalidateSubject(subject Subject, currentRevision uint64) error {
	if !validSubject(subject) || currentRevision == 0 {
		return ErrInvalidation
	}
	invalidations.Lock()
	defer invalidations.Unlock()
	if currentRevision > invalidations.subjects[subject].revision {
		invalidations.subjects[subject] = watermark{revision: currentRevision, generation: new(generation)}
	}
	return nil
}

func validSubject(s Subject) bool {
	return identifier(s.Issuer) && identifier(s.ID) && (s.Kind == SubjectUser || s.Kind == SubjectService)
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Formatting exposes no identities, session IDs, bindings, or opaque state.
func (Subject) Format(s fmt.State, _ rune)     { fmt.Fprint(s, "[authn subject]") }
func (Subject) LogValue() slog.Value           { return slog.StringValue("[authn subject]") }
func (Options) Format(s fmt.State, _ rune)     { fmt.Fprint(s, "[authn verifier options]") }
func (Options) LogValue() slog.Value           { return slog.StringValue("[authn verifier options]") }
func (Verifier) Format(s fmt.State, _ rune)    { fmt.Fprint(s, "[authn verifier]") }
func (Verifier) LogValue() slog.Value          { return slog.StringValue("[authn verifier]") }
func (Attestation) Format(s fmt.State, _ rune) { fmt.Fprint(s, "[authn attestation]") }
func (Attestation) LogValue() slog.Value       { return slog.StringValue("[authn attestation]") }
func (*state) String() string                  { return "[authn verified state]" }
func (*state) GoString() string                { return "[authn verified state]" }
