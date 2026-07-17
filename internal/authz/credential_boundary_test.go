package authz_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	gateapi "github.com/jaezeu/agentgate/internal/api"
	"github.com/jaezeu/agentgate/internal/approval"
	"github.com/jaezeu/agentgate/internal/audit"
	"github.com/jaezeu/agentgate/internal/authz"
	"github.com/jaezeu/agentgate/internal/vaultmgr"
)

var forbiddenCredentialNames = map[string]struct{}{
	"accesskey":          {},
	"accesskeyid":        {},
	"awsaccesskey":       {},
	"awsaccesskeyid":     {},
	"awscredentials":     {},
	"awssecretaccesskey": {},
	"awssessiontoken":    {},
	"clienttoken":        {},
	"credential":         {},
	"credentials":        {},
	"leaseid":            {},
	"leasesecret":        {},
	"privatekey":         {},
	"secretaccesskey":    {},
	"securitytoken":      {},
	"sessiontoken":       {},
	"vaultlease":         {},
	"vaulttoken":         {},
}

func TestSharedContractsCannotCarryCredentialMaterial(t *testing.T) {
	models := []reflect.Type{
		reflect.TypeOf(authz.AccessRequest{}),
		reflect.TypeOf(authz.Decision{}),
		reflect.TypeOf(authz.RedemptionDescriptor{}),
		reflect.TypeOf(approval.Request{}),
		reflect.TypeOf(approval.Record{}),
		reflect.TypeOf(approval.ReviewDetails{}),
		reflect.TypeOf(audit.AuditRecord{}),
		reflect.TypeOf(vaultmgr.AccessBinding{}),
		reflect.TypeOf(vaultmgr.RevocationReport{}),
		reflect.TypeOf(gateapi.AccessRequestPayload{}),
		reflect.TypeOf(gateapi.AccessDecisionResponse{}),
		reflect.TypeOf(gateapi.RequestView{}),
		reflect.TypeOf(gateapi.RequestEventView{}),
		reflect.TypeOf(gateapi.RequestResponse{}),
		reflect.TypeOf(gateapi.RequestListResponse{}),
		reflect.TypeOf(gateapi.RevocationResponse{}),
		reflect.TypeOf(gateapi.APIError{}),
		reflect.TypeOf(gateapi.ErrorResponse{}),
	}
	visited := make(map[reflect.Type]bool)
	for _, model := range models {
		assertCredentialFreeType(t, model, visited)
	}
}

func TestVaultManagerRemainsCredentialBlind(t *testing.T) {
	manager := reflect.TypeOf((*vaultmgr.VaultManager)(nil)).Elem()
	expected := map[string]bool{"EnableAccess": true, "Revoke": true}
	if manager.NumMethod() != len(expected) {
		t.Fatalf("VaultManager has %d methods, want exactly %d credential-blind methods", manager.NumMethod(), len(expected))
	}
	for index := 0; index < manager.NumMethod(); index++ {
		method := manager.Method(index)
		if !expected[method.Name] {
			t.Fatalf("VaultManager gained prohibited method %q", method.Name)
		}
	}
}

func TestInternalJSONContractsHaveNoCredentialFields(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve credential boundary test path")
	}
	internalRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), ".."))
	err := filepath.WalkDir(internalRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			field, isField := node.(*ast.Field)
			if !isField {
				return true
			}
			if field.Tag == nil {
				return true
			}
			tagValue, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Errorf("%s has invalid struct tag: %v", path, err)
				return true
			}
			jsonName := strings.Split(reflect.StructTag(tagValue).Get("json"), ",")[0]
			if jsonName == "" || jsonName == "-" {
				return true
			}
			for _, name := range field.Names {
				if _, prohibited := forbiddenCredentialNames[normalizeCredentialName(name.Name)]; prohibited {
					t.Errorf("%s adds credential field %s", path, name.Name)
				}
			}
			if _, prohibited := forbiddenCredentialNames[normalizeCredentialName(jsonName)]; prohibited {
				t.Errorf("%s adds credential JSON field %s", path, jsonName)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("scan internal contracts: %v", err)
	}
}

func assertCredentialFreeType(t *testing.T, model reflect.Type, visited map[reflect.Type]bool) {
	t.Helper()
	for model.Kind() == reflect.Pointer || model.Kind() == reflect.Slice || model.Kind() == reflect.Array {
		model = model.Elem()
	}
	if model.PkgPath() == "time" || visited[model] {
		return
	}
	visited[model] = true
	if model.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < model.NumField(); index++ {
		field := model.Field(index)
		if !field.IsExported() {
			continue
		}
		if _, prohibited := forbiddenCredentialNames[normalizeCredentialName(field.Name)]; prohibited {
			t.Errorf("%s.%s is a prohibited credential field", model, field.Name)
		}
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if _, prohibited := forbiddenCredentialNames[normalizeCredentialName(jsonName)]; prohibited {
			t.Errorf("%s.%s has prohibited JSON name %q", model, field.Name, jsonName)
		}
		assertCredentialFreeType(t, field.Type, visited)
	}
}

func normalizeCredentialName(value string) string {
	value = strings.ToLower(value)
	return strings.NewReplacer("_", "", "-", "").Replace(value)
}
