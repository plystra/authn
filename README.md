# Plystra AuthN

`github.com/plystra/authn` is an independent Plystra Project created through the public CLI.

Status: **Development; not production ready**. The Project builds and provides bounded credential-input validation, the session verification contract and its trusted-state helper. A persistent authentication service and full product acceptance remain incomplete.

AuthN owns accounts, credentials, authentication protocols, sessions and verified caller state. Persistence must use the independent `github.com/plystra/data` module and its selected Resource; AuthN never imports AuthZ or opens a second database pool.

The complete product target is specified in the separate `authn-docs` repository. Kernel and CLI remain generic. Ordinary Go contracts and explicit constructor injection connect the products.

Keep current-Project requirements, selections, Resource bindings and HTTP exposure explicit in `plystra.yaml`. The CLI owns `generated/` and `.agents/skills/plystra/`; use its public generation workflow to update them.

`credentialinput.FromContext` validates the complete Core `plystra.http-credential-metadata/v1` schema, including duplicate and unknown fields, canonical Interface identity, sorted unique cookies and all byte/count bounds. Missing input is valid; malformed input fails without reflecting credentials. Candidate formatting, JSON and structured logs redact contents, and accessors stop returning input after context completion. The selected verifier must still reject simultaneous usable Bearer and session-cookie credentials and verify authoritative session state. Parsing alone creates no trusted state.

## Session verification and trusted state

`interfaces/authn/session/verify/v1` owns the one-method `authn.session.verify/v1` contract. The request is empty; an injected implementation consumes bounded unverified credential metadata from its ordinary invocation context. Its response carries issuer, `user` or `service` subject kind, subject ID, opaque session ID, audience, positive subject/session revisions and expiry. These are facts, not authority. An AuthZ human, agent or application member is resolved separately from authenticated facts.

`verifiedstate.New(session, verifiedstate.Options{Issuer: "shop", Audience: "shop-api"})` constructs an ordinary helper. Call `ctx, subject, err := verifier.Verify(ctx)` explicitly and continue with the returned context only on success. The helper rejects malformed identifiers (1-256 UTF-8 bytes, no control characters), mismatched issuer/audience, invalid kinds or revisions, expired facts and failed or cancelled calls. Every failure returns the input context unchanged and a zero subject. Direct cause-free declared Kernel semantic errors and safe runtime classifications are retained; arbitrary provider messages, wrappers, private causes and panic values are discarded. Kernel's bounded, panic-safe `CompletionOf` traversal preserves uncertainty with a new cause-redacted `NewResultUnknown` marker, including when the context was cancelled after the call. An incomplete error traversal remains uncertain.

Only this helper creates opaque process-local attestations. `FromContext`, `Attestation.Subject` and `Attestation.Same` reject invalid, expired, cancelled or locally invalidated state. A serialized Subject, response, attestation or arbitrary context value cannot create trust. Formatting and structured logging of helper values and response facts redact identities, bindings and session IDs. Explicitly extracting fields or encoding protocol response data still requires appropriate handling by the caller.

`MaxReuse` defaults to zero: every later `Verify` calls the injected Interface again, while newly created state remains consumable. An explicit value up to five minutes allows reuse only within the originating context lineage and verifier identity, before the reuse limit, expiry, cancellation or invalidation. An independently constructed verifier does not reuse another verifier's state. Cancellation of the original verification context remains binding even through `context.WithoutCancel`.

After a persisted mutation commits, its implementation calls `InvalidateSession(issuer, sessionID, currentRevision)` or `InvalidateSubject(subject, currentRevision)`. A newer positive revision raises the local high-water mark and advances its generation; existing attestations become invalid even when their captured revision was higher. Equal/older events are no-ops. Fresh results at or above the mark can create new state. Invalid keys or revision zero change nothing. Invalidation is synchronous, concurrency-safe and performs no I/O. The tables last for the process lifetime; distributed propagation, persistence and transaction integration are not supplied by this helper. In-flight state is a bounded snapshot, not a guarantee against remote mutation or a rollback of completed effects.

No session verifier implementation, database stub, public HTTP exposure or AuthZ dependency is included. Generated Interface projections are synchronized through the public CLI; generation is not session-service acceptance. The helper is verified through named external-package normal and race tests covering malformed facts, cancellation, expiry, reuse, invalidation ordering/concurrency, opaque state and redacted failures.
