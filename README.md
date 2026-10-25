# Plystra AuthN

`github.com/plystra/authn` is an independent Plystra Project created through the public CLI.

Status: **Development; not production ready**. The initial CLI-generated Project builds, but no authentication or authorization service is implemented by this baseline. Product acceptance remains incomplete.

AuthN owns accounts, credentials, authentication protocols, sessions and verified caller state. Persistence must use the independent `github.com/plystra/data` module and its selected Resource; AuthN never imports AuthZ or opens a second database pool.

The complete product target is specified in the separate `authn-docs` repository. Kernel and CLI remain generic. Ordinary Go contracts and explicit constructor injection connect the products.

Keep current-Project requirements, selections, Resource bindings and HTTP exposure explicit in `plystra.yaml`. The CLI owns `generated/` and `.agents/skills/plystra/`; use its public generation workflow to update them.
