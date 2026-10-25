# Plystra AuthN

`github.com/plystra/authn` is an independent Plystra Project created through the public CLI.

Status: **Development; not production ready**. The CLI-generated Project builds. The `credentialinput` package validates bounded, unverified ingress candidates; an authentication service and product acceptance remain incomplete.

AuthN owns accounts, credentials, authentication protocols, sessions and verified caller state. Persistence must use the independent `github.com/plystra/data` module and its selected Resource; AuthN never imports AuthZ or opens a second database pool.

The complete product target is specified in the separate `authn-docs` repository. Kernel and CLI remain generic. Ordinary Go contracts and explicit constructor injection connect the products.

Keep current-Project requirements, selections, Resource bindings and HTTP exposure explicit in `plystra.yaml`. The CLI owns `generated/` and `.agents/skills/plystra/`; use its public generation workflow to update them.

`credentialinput.FromContext` validates the complete Core `plystra.http-credential-metadata/v1` schema, including duplicate and unknown fields, canonical Interface identity, sorted unique cookies and all byte/count bounds. Missing input is valid; malformed input fails without reflecting credentials. Candidate formatting, JSON and structured logs redact contents, and accessors stop returning input after context completion. The selected verifier must still reject simultaneous usable Bearer and session-cookie credentials and verify authoritative session state. Parsing alone creates no trusted state.
