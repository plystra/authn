package verifyv1

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

//plystra:interface authn.session.verify/v1
type Interface interface {
	Verify(context.Context, Request) (Response, error)
}

// Request is empty: the selected implementation consumes bounded, unverified
// credential metadata from the invocation context, never caller identity fields.
type Request struct{}

// Response contains verification facts, not a trusted-state attestation. Only
// verifiedstate validates and binds these facts to the current context.
// These values, especially SessionID, must not enter ordinary telemetry.
type Response struct {
	Issuer          string    `json:"issuer" plystra:"1,required"`
	SubjectKind     string    `json:"subject_kind" plystra:"2,required"`
	SubjectID       string    `json:"subject_id" plystra:"3,required"`
	SessionID       string    `json:"session_id" plystra:"4,required"`
	Audience        string    `json:"audience" plystra:"5,required"`
	SubjectRevision uint64    `json:"subject_revision" plystra:"6,required"`
	SessionRevision uint64    `json:"session_revision" plystra:"7,required"`
	ExpiresAt       time.Time `json:"expires_at" plystra:"8,required"`
}

func (Response) Format(s fmt.State, _ rune) { fmt.Fprint(s, "[authn session verification facts]") }
func (Response) LogValue() slog.Value       { return slog.StringValue("[authn session verification facts]") }
