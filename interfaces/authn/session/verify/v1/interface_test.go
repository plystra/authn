package verifyv1_test

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	verifyv1 "github.com/plystra/authn/interfaces/authn/session/verify/v1"
	"go.yaml.in/yaml/v3"
)

func TestSessionVerifyContract(t *testing.T) {
	typ := reflect.TypeFor[verifyv1.Interface]()
	if typ.NumMethod() != 1 {
		t.Fatal("expected one operation")
	}
	m := typ.Method(0)
	if m.Name != "Verify" || m.Type.NumIn() != 2 || m.Type.In(0) != reflect.TypeFor[context.Context]() || m.Type.In(1) != reflect.TypeFor[verifyv1.Request]() || m.Type.NumOut() != 2 || m.Type.Out(0) != reflect.TypeFor[verifyv1.Response]() || m.Type.Out(1) != reflect.TypeFor[error]() {
		t.Fatal("incorrect operation shape")
	}
	if reflect.TypeFor[verifyv1.Request]().NumField() != 0 {
		t.Fatal("credential facts must not come from request fields")
	}
	names := []string{"issuer", "subject_kind", "subject_id", "session_id", "audience", "subject_revision", "session_revision", "expires_at"}
	response := reflect.TypeFor[verifyv1.Response]()
	if response.NumField() != len(names) {
		t.Fatal("unexpected verification facts")
	}
	for i, name := range names {
		field := response.Field(i)
		wantType := reflect.TypeFor[string]()
		if i == 5 || i == 6 {
			wantType = reflect.TypeFor[uint64]()
		}
		if i == 7 {
			wantType = reflect.TypeFor[time.Time]()
		}
		if field.Type != wantType || field.Tag.Get("json") != name || field.Tag.Get("plystra") != strconv.Itoa(i+1)+",required" {
			t.Fatalf("invalid field contract: %s", field.Name)
		}
	}
}

func TestSessionVerifyMetadata(t *testing.T) {
	raw, err := os.ReadFile("interface.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Description string `yaml:"description"`
		Semantics   struct {
			Kind string `yaml:"kind"`
		} `yaml:"semantics"`
		Errors []struct {
			Code        string `yaml:"code"`
			Description string `yaml:"description"`
		} `yaml:"errors"`
		Constraints map[string]map[string]any `yaml:"constraints"`
	}
	if err := yaml.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Semantics.Kind != "query" || len(metadata.Errors) != 6 || len(metadata.Constraints) != 7 {
		t.Fatal("missing query semantics or validation metadata")
	}
	want := map[string]bool{"credential_missing": true, "credential_ambiguous": true, "invalid_credentials": true, "account_disabled": true, "session_expired": true, "session_revoked": true}
	for _, e := range metadata.Errors {
		if !want[e.Code] {
			t.Fatal("unexpected semantic outcome")
		}
		delete(want, e.Code)
	}
	if len(want) != 0 {
		t.Fatal("missing semantic outcome")
	}
}
