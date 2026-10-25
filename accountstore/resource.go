// Package accountstore owns the first AuthN account storage declaration.
// Its Resource is an internal persistence boundary, not a registration API.
package accountstore

import "context"

// Resource borrows the selected Data database Resource. It owns no pool or
// lifecycle. Callers must validate policy, canonical inputs and password PHC
// records before invoking it, and must not expose these reads to anonymous users.
//
//plystra:resource authn.accounts.access/v1
type Resource interface {
	StageRegistration(context.Context, StageRegistrationRequest) (StageRegistrationResult, error)
	FindRegistration(context.Context, FindRegistrationRequest) (*Registration, error)
	PasswordForEmail(context.Context, PasswordForEmailRequest) (*PasswordRecord, error)
}

// StageRegistrationRequest contains no raw password. NormalizedEmail is the
// caller's canonical case-insensitive key, preserving dots and plus suffixes.
// RequestDigest binds the server-owned operation to its canonical request; it
// must not be a public unkeyed digest of a low-entropy password. Times use UTC
// Unix seconds. The caller must keep input buffers stable during the call.
type StageRegistrationRequest struct {
	AccountID       string
	OperationID     string
	NormalizedEmail string
	PasswordPHC     string
	RequestDigest   []byte
	NowUnix         int64
}

// StageRegistrationResult is returned only after an acknowledged commit. It
// does not mean the account may log in or that AuthZ provisioning is complete.
type StageRegistrationResult struct {
	AccountID       string
	OperationID     string
	SubjectRevision int64
}

type FindRegistrationRequest struct {
	OperationID string
}

// Registration permits an authorized coordinator to reconcile result_unknown.
// An absent result is a snapshot, not proof that an in-flight commit rolled back.
type Registration struct {
	AccountID         string
	OperationID       string
	Status            string
	ProvisioningState string
	SubjectRevision   int64
	RequestDigest     []byte
	CreatedAtUnix     int64
}

type PasswordForEmailRequest struct {
	NormalizedEmail string
}

// PasswordRecord is untrusted stored credential data, never authenticated state.
// A verifier must check account/workflow state, contact verification and current
// revisions before issuing anything. Reading or matching a PHC is insufficient.
type PasswordRecord struct {
	AccountID          string
	Status             string
	ProvisioningState  string
	SubjectRevision    int64
	ContactVerified    bool
	PasswordPHC        string
	CredentialRevision int64
}
