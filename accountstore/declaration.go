package accountstore

import "github.com/plystra/data/declaration"

// Accounts is a closed Data root. Only the registration plan is callable for
// writes; its five required inserts share one serializable transaction. There
// is deliberately no activation, contact-verification or session-issuance write.
//
//plystra:data authn.accounts/v1
var Accounts = declaration.Member[Resource]{
	Namespace: "authn_accounts",
	Tables: []declaration.Table{
		{ID: "accounts", Columns: []declaration.Column{
			{ID: "id", Type: "string"}, {ID: "operation-id", Type: "string"},
			{ID: "status", Type: "string"}, {ID: "provisioning-state", Type: "string"},
			{ID: "subject-revision", Type: "int64"}, {ID: "request-digest", Type: "bytes"},
			{ID: "created-at-unix", Type: "int64"},
		}, Constraints: []declaration.Constraint{
			{ID: "accounts-pk", Kind: "primary-key", Columns: []string{"id"}},
			{ID: "accounts-operation-unique", Kind: "unique", Columns: []string{"operation-id"}},
		}},
		{ID: "normalized-contacts", Columns: []declaration.Column{
			{ID: "account-id", Type: "string"}, {ID: "kind", Type: "string"},
			{ID: "normalized-value", Type: "string"}, {ID: "verified", Type: "bool"},
			{ID: "revision", Type: "int64"},
		}, Constraints: []declaration.Constraint{
			{ID: "contacts-pk", Kind: "primary-key", Columns: []string{"account-id", "kind"}},
			{ID: "contacts-value-unique", Kind: "unique", Columns: []string{"kind", "normalized-value"}},
			{ID: "contacts-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
		}},
		{ID: "password-credentials", Columns: []declaration.Column{
			{ID: "account-id", Type: "string"}, {ID: "phc", Type: "string"},
			{ID: "revision", Type: "int64"}, {ID: "changed-at-unix", Type: "int64"},
		}, Constraints: []declaration.Constraint{
			{ID: "passwords-pk", Kind: "primary-key", Columns: []string{"account-id"}},
			{ID: "passwords-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
		}},
		{ID: "authn-audit-intents", Columns: []declaration.Column{
			{ID: "operation-id", Type: "string"}, {ID: "account-id", Type: "string"},
			{ID: "event", Type: "string"}, {ID: "plane", Type: "string"},
			{ID: "credential-type", Type: "string"}, {ID: "occurred-at-unix", Type: "int64"},
		}, Constraints: []declaration.Constraint{
			{ID: "audit-pk", Kind: "primary-key", Columns: []string{"operation-id"}},
			{ID: "audit-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
		}},
		{ID: "delivery-outbox", Columns: []declaration.Column{
			{ID: "operation-id", Type: "string"}, {ID: "event", Type: "string"},
			{ID: "delivery-state", Type: "string"}, {ID: "created-at-unix", Type: "int64"},
		}, Constraints: []declaration.Constraint{
			{ID: "outbox-pk", Kind: "primary-key", Columns: []string{"operation-id"}},
			{ID: "outbox-audit-fk", Kind: "foreign-key", Columns: []string{"operation-id"}, ReferencedTable: declaration.Ref{Symbol: "authn-audit-intents"}, ReferencedCols: []string{"operation-id"}},
		}},
	},
	Queries: []declaration.Query{
		{ID: "insert-account", Operation: "insert", Table: declaration.Ref{Symbol: "accounts"},
			Parameters: []declaration.Parameter{{ID: "account-id", Type: "string"}, {ID: "operation-id", Type: "string"}, {ID: "request-digest", Type: "bytes"}, {ID: "now-unix", Type: "int64"}},
			Assignments: []declaration.Assignment{
				{Column: "id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "account-id"}},
				{Column: "operation-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "operation-id"}},
				{Column: "request-digest", Value: declaration.Value{Kind: "bytes", Set: true, Parameter: "request-digest"}},
				{Column: "created-at-unix", Value: declaration.Value{Kind: "int64", Set: true, Parameter: "now-unix"}},
				{Column: "status", Value: declaration.Value{Kind: "string", Set: true, String: "pending"}},
				{Column: "provisioning-state", Value: declaration.Value{Kind: "string", Set: true, String: "pending-provisioning"}},
				{Column: "subject-revision", Value: declaration.Value{Kind: "int64", Set: true, Int64: 1}},
			}, Returning: []declaration.Projection{{Column: "id"}, {Column: "operation-id"}, {Column: "subject-revision"}},
			Results: []declaration.ResultField{{ID: "account-id", Source: "id", Type: "string"}, {ID: "operation-id", Source: "operation-id", Type: "string"}, {ID: "subject-revision", Source: "subject-revision", Type: "int64"}}},
		{ID: "insert-contact", Operation: "insert", Table: declaration.Ref{Symbol: "normalized-contacts"},
			Parameters: []declaration.Parameter{{ID: "account-id", Type: "string"}, {ID: "normalized-email", Type: "string"}},
			Assignments: []declaration.Assignment{
				{Column: "account-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "account-id"}},
				{Column: "normalized-value", Value: declaration.Value{Kind: "string", Set: true, Parameter: "normalized-email"}},
				{Column: "kind", Value: declaration.Value{Kind: "string", Set: true, String: "email"}},
				{Column: "verified", Value: declaration.Value{Kind: "bool", Set: true}},
				{Column: "revision", Value: declaration.Value{Kind: "int64", Set: true, Int64: 1}},
			}},
		{ID: "insert-password", Operation: "insert", Table: declaration.Ref{Symbol: "password-credentials"},
			Parameters: []declaration.Parameter{{ID: "account-id", Type: "string"}, {ID: "password-phc", Type: "string"}, {ID: "now-unix", Type: "int64"}},
			Assignments: []declaration.Assignment{
				{Column: "account-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "account-id"}},
				{Column: "phc", Value: declaration.Value{Kind: "string", Set: true, Parameter: "password-phc"}},
				{Column: "changed-at-unix", Value: declaration.Value{Kind: "int64", Set: true, Parameter: "now-unix"}},
				{Column: "revision", Value: declaration.Value{Kind: "int64", Set: true, Int64: 1}},
			}},
		{ID: "insert-audit", Operation: "insert", Table: declaration.Ref{Symbol: "authn-audit-intents"},
			Parameters: []declaration.Parameter{{ID: "account-id", Type: "string"}, {ID: "operation-id", Type: "string"}, {ID: "now-unix", Type: "int64"}},
			Assignments: []declaration.Assignment{
				{Column: "account-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "account-id"}},
				{Column: "operation-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "operation-id"}},
				{Column: "occurred-at-unix", Value: declaration.Value{Kind: "int64", Set: true, Parameter: "now-unix"}},
				{Column: "event", Value: declaration.Value{Kind: "string", Set: true, String: "registration.staged"}},
				{Column: "plane", Value: declaration.Value{Kind: "string", Set: true, String: "principal"}},
				{Column: "credential-type", Value: declaration.Value{Kind: "string", Set: true, String: "password"}},
			}},
		{ID: "insert-outbox", Operation: "insert", Table: declaration.Ref{Symbol: "delivery-outbox"},
			Parameters: []declaration.Parameter{{ID: "operation-id", Type: "string"}, {ID: "now-unix", Type: "int64"}},
			Assignments: []declaration.Assignment{
				{Column: "operation-id", Value: declaration.Value{Kind: "string", Set: true, Parameter: "operation-id"}},
				{Column: "created-at-unix", Value: declaration.Value{Kind: "int64", Set: true, Parameter: "now-unix"}},
				{Column: "event", Value: declaration.Value{Kind: "string", Set: true, String: "registration.provisioning-requested"}},
				{Column: "delivery-state", Value: declaration.Value{Kind: "string", Set: true, String: "pending"}},
			}},
		{ID: "find-registration", Method: "FindRegistration", Cardinality: "zero_or_one", Operation: "select", Table: declaration.Ref{Symbol: "accounts"},
			Parameters: []declaration.Parameter{{ID: "operation-id", GoField: "OperationID", Type: "string"}},
			Predicate:  declaration.Predicate{Kind: "equal", Left: declaration.ColumnRef{Column: "operation-id"}, Value: declaration.Value{Kind: "string", Set: true, Parameter: "operation-id"}},
			Projection: []declaration.Projection{{Column: "id"}, {Column: "operation-id"}, {Column: "status"}, {Column: "provisioning-state"}, {Column: "subject-revision"}, {Column: "request-digest"}, {Column: "created-at-unix"}},
			Results: []declaration.ResultField{
				{ID: "account-id", GoField: "AccountID", Source: "id", Type: "string"},
				{ID: "operation-id", GoField: "OperationID", Source: "operation-id", Type: "string"},
				{ID: "status", GoField: "Status", Source: "status", Type: "string"},
				{ID: "provisioning-state", GoField: "ProvisioningState", Source: "provisioning-state", Type: "string"},
				{ID: "subject-revision", GoField: "SubjectRevision", Source: "subject-revision", Type: "int64"},
				{ID: "request-digest", GoField: "RequestDigest", Source: "request-digest", Type: "bytes"},
				{ID: "created-at-unix", GoField: "CreatedAtUnix", Source: "created-at-unix", Type: "int64"},
			}},
		{ID: "password-for-email", Method: "PasswordForEmail", Cardinality: "zero_or_one", Operation: "select", Table: declaration.Ref{Symbol: "normalized-contacts"},
			Joins: []declaration.Join{
				{Kind: "inner", Table: declaration.Ref{Symbol: "accounts"}, On: declaration.JoinCondition{Left: declaration.ColumnRef{Table: declaration.Ref{Symbol: "normalized-contacts"}, Column: "account-id"}, Right: declaration.ColumnRef{Table: declaration.Ref{Symbol: "accounts"}, Column: "id"}}},
				{Kind: "inner", Table: declaration.Ref{Symbol: "password-credentials"}, On: declaration.JoinCondition{Left: declaration.ColumnRef{Table: declaration.Ref{Symbol: "accounts"}, Column: "id"}, Right: declaration.ColumnRef{Table: declaration.Ref{Symbol: "password-credentials"}, Column: "account-id"}}},
			},
			Parameters: []declaration.Parameter{{ID: "normalized-email", GoField: "NormalizedEmail", Type: "string"}},
			Predicate: declaration.Predicate{Kind: "and", Items: []declaration.Predicate{
				{Kind: "equal", Left: declaration.ColumnRef{Column: "kind"}, Value: declaration.Value{Kind: "string", Set: true, String: "email"}},
				{Kind: "equal", Left: declaration.ColumnRef{Column: "normalized-value"}, Value: declaration.Value{Kind: "string", Set: true, Parameter: "normalized-email"}},
			}},
			Projection: []declaration.Projection{
				{Table: declaration.Ref{Symbol: "accounts"}, Column: "id", Alias: "account-id"},
				{Table: declaration.Ref{Symbol: "accounts"}, Column: "status"},
				{Table: declaration.Ref{Symbol: "accounts"}, Column: "provisioning-state"},
				{Table: declaration.Ref{Symbol: "accounts"}, Column: "subject-revision"},
				{Column: "verified"}, {Table: declaration.Ref{Symbol: "password-credentials"}, Column: "phc"},
				{Table: declaration.Ref{Symbol: "password-credentials"}, Column: "revision", Alias: "credential-revision"},
			}, Results: []declaration.ResultField{
				{ID: "account-id", GoField: "AccountID", Source: "account-id", Type: "string"},
				{ID: "status", GoField: "Status", Source: "status", Type: "string"},
				{ID: "provisioning-state", GoField: "ProvisioningState", Source: "provisioning-state", Type: "string"},
				{ID: "subject-revision", GoField: "SubjectRevision", Source: "subject-revision", Type: "int64"},
				{ID: "contact-verified", GoField: "ContactVerified", Source: "verified", Type: "bool"},
				{ID: "password-phc", GoField: "PasswordPHC", Source: "phc", Type: "string"},
				{ID: "credential-revision", GoField: "CredentialRevision", Source: "credential-revision", Type: "int64"},
			}},
	},
	Plans: []declaration.Plan{{ID: "stage-registration", Method: "StageRegistration",
		Parameters: []declaration.Parameter{
			{ID: "account-id", GoField: "AccountID", Type: "string"},
			{ID: "operation-id", GoField: "OperationID", Type: "string"},
			{ID: "normalized-email", GoField: "NormalizedEmail", Type: "string"},
			{ID: "password-phc", GoField: "PasswordPHC", Type: "string"},
			{ID: "request-digest", GoField: "RequestDigest", Type: "bytes"},
			{ID: "now-unix", GoField: "NowUnix", Type: "int64"},
		},
		Statements: []declaration.PlanStatement{
			{ID: "account", Query: declaration.Ref{Symbol: "insert-account"}, Cardinality: "exactly_one", Affected: declaration.AffectedRows{Set: true, Min: 1, Max: 1}, Bindings: []declaration.PlanBinding{
				{Parameter: "account-id", FromParameter: "account-id"}, {Parameter: "operation-id", FromParameter: "operation-id"}, {Parameter: "request-digest", FromParameter: "request-digest"}, {Parameter: "now-unix", FromParameter: "now-unix"},
			}},
			{ID: "contact", Query: declaration.Ref{Symbol: "insert-contact"}, Cardinality: "none", Affected: declaration.AffectedRows{Set: true, Min: 1, Max: 1}, Bindings: []declaration.PlanBinding{
				{Parameter: "account-id", FromStatement: "account", FromResult: "account-id"}, {Parameter: "normalized-email", FromParameter: "normalized-email"},
			}},
			{ID: "password", Query: declaration.Ref{Symbol: "insert-password"}, Cardinality: "none", Affected: declaration.AffectedRows{Set: true, Min: 1, Max: 1}, Bindings: []declaration.PlanBinding{
				{Parameter: "account-id", FromStatement: "account", FromResult: "account-id"}, {Parameter: "password-phc", FromParameter: "password-phc"}, {Parameter: "now-unix", FromParameter: "now-unix"},
			}},
			{ID: "audit", Query: declaration.Ref{Symbol: "insert-audit"}, Cardinality: "none", Affected: declaration.AffectedRows{Set: true, Min: 1, Max: 1}, Bindings: []declaration.PlanBinding{
				{Parameter: "account-id", FromStatement: "account", FromResult: "account-id"}, {Parameter: "operation-id", FromStatement: "account", FromResult: "operation-id"}, {Parameter: "now-unix", FromParameter: "now-unix"},
			}},
			{ID: "outbox", Query: declaration.Ref{Symbol: "insert-outbox"}, Cardinality: "none", Affected: declaration.AffectedRows{Set: true, Min: 1, Max: 1}, Bindings: []declaration.PlanBinding{
				{Parameter: "operation-id", FromStatement: "account", FromResult: "operation-id"}, {Parameter: "now-unix", FromParameter: "now-unix"},
			}},
		},
		Outputs: []declaration.PlanOutput{{Statement: "account", Result: "account-id", GoField: "AccountID"}, {Statement: "account", Result: "operation-id", GoField: "OperationID"}, {Statement: "account", Result: "subject-revision", GoField: "SubjectRevision"}},
	}},
	Migrations: []declaration.Migration{{ID: "initial-accounts", Version: 1,
		// This literal snapshot must stay frozen when the live schema evolves.
		Snapshot: []declaration.MigrationSchema{{Namespace: "authn_accounts", Tables: []declaration.Table{
			{ID: "accounts", Columns: []declaration.Column{
				{ID: "id", Type: "string"}, {ID: "operation-id", Type: "string"},
				{ID: "status", Type: "string"}, {ID: "provisioning-state", Type: "string"},
				{ID: "subject-revision", Type: "int64"}, {ID: "request-digest", Type: "bytes"},
				{ID: "created-at-unix", Type: "int64"},
			}, Constraints: []declaration.Constraint{
				{ID: "accounts-pk", Kind: "primary-key", Columns: []string{"id"}},
				{ID: "accounts-operation-unique", Kind: "unique", Columns: []string{"operation-id"}},
			}},
			{ID: "normalized-contacts", Columns: []declaration.Column{
				{ID: "account-id", Type: "string"}, {ID: "kind", Type: "string"},
				{ID: "normalized-value", Type: "string"}, {ID: "verified", Type: "bool"},
				{ID: "revision", Type: "int64"},
			}, Constraints: []declaration.Constraint{
				{ID: "contacts-pk", Kind: "primary-key", Columns: []string{"account-id", "kind"}},
				{ID: "contacts-value-unique", Kind: "unique", Columns: []string{"kind", "normalized-value"}},
				{ID: "contacts-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
			}},
			{ID: "password-credentials", Columns: []declaration.Column{
				{ID: "account-id", Type: "string"}, {ID: "phc", Type: "string"},
				{ID: "revision", Type: "int64"}, {ID: "changed-at-unix", Type: "int64"},
			}, Constraints: []declaration.Constraint{
				{ID: "passwords-pk", Kind: "primary-key", Columns: []string{"account-id"}},
				{ID: "passwords-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
			}},
			{ID: "authn-audit-intents", Columns: []declaration.Column{
				{ID: "operation-id", Type: "string"}, {ID: "account-id", Type: "string"},
				{ID: "event", Type: "string"}, {ID: "plane", Type: "string"},
				{ID: "credential-type", Type: "string"}, {ID: "occurred-at-unix", Type: "int64"},
			}, Constraints: []declaration.Constraint{
				{ID: "audit-pk", Kind: "primary-key", Columns: []string{"operation-id"}},
				{ID: "audit-account-fk", Kind: "foreign-key", Columns: []string{"account-id"}, ReferencedTable: declaration.Ref{Symbol: "accounts"}, ReferencedCols: []string{"id"}},
			}},
			{ID: "delivery-outbox", Columns: []declaration.Column{
				{ID: "operation-id", Type: "string"}, {ID: "event", Type: "string"},
				{ID: "delivery-state", Type: "string"}, {ID: "created-at-unix", Type: "int64"},
			}, Constraints: []declaration.Constraint{
				{ID: "outbox-pk", Kind: "primary-key", Columns: []string{"operation-id"}},
				{ID: "outbox-audit-fk", Kind: "foreign-key", Columns: []string{"operation-id"}, ReferencedTable: declaration.Ref{Symbol: "authn-audit-intents"}, ReferencedCols: []string{"operation-id"}},
			}},
		}}},
		Operations: []declaration.MigrationOperation{
			{Kind: "create-table", Table: declaration.Ref{Symbol: "accounts"}},
			{Kind: "create-table", Table: declaration.Ref{Symbol: "normalized-contacts"}},
			{Kind: "create-table", Table: declaration.Ref{Symbol: "password-credentials"}},
			{Kind: "create-table", Table: declaration.Ref{Symbol: "authn-audit-intents"}},
			{Kind: "create-table", Table: declaration.Ref{Symbol: "delivery-outbox"}},
		},
	}},
}
