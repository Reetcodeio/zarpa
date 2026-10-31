package vault

import (
	"os"
	"strings"
	"testing"
)

func TestSetGetListDelete(t *testing.T) {
	v := Memory()
	if err := v.Set("OPENAI_API_KEY", "sk-test-1\n"); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("ANTHROPIC_API_KEY", "a1"); err != nil {
		t.Fatal(err)
	}
	if err := v.Set("OPENAI_API_KEY", "sk-test-2"); err != nil { // replace
		t.Fatal(err)
	}
	if got, _ := v.Get("OPENAI_API_KEY"); got != "sk-test-2" {
		t.Fatalf("get = %q", got)
	}
	names, _ := v.List()
	if strings.Join(names, ",") != "ANTHROPIC_API_KEY,OPENAI_API_KEY" {
		t.Fatalf("list = %v", names)
	}
	if err := v.Delete("OPENAI_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get("OPENAI_API_KEY"); err != ErrNotFound {
		t.Fatalf("after delete: %v", err)
	}
	if err := v.Delete("NOPE"); err != ErrNotFound {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestNamesAndValuesAreValidated(t *testing.T) {
	v := Memory()
	for _, bad := range []string{"lower", "1ABC", "A-B", "A B", "", "__zarpa_index__"} {
		if v.Set(bad, "x") == nil {
			t.Errorf("accepted name %q", bad)
		}
	}
	if v.Set("EMPTY", "\n") == nil {
		t.Error("accepted empty value")
	}
}

func TestEnvOverridesAndKeepsOthers(t *testing.T) {
	v := Memory()
	must(t, v.Set("KW_TEST_A", "from-vault"))
	t.Setenv("KW_TEST_A", "from-shell")
	t.Setenv("KW_TEST_B", "keep")
	env, names, err := v.Env(nil)
	if err != nil || len(names) != 1 {
		t.Fatal(err, names)
	}
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "KW_TEST_A=from-vault") || strings.Contains(joined, "KW_TEST_A=from-shell") ||
		!strings.Contains(joined, "KW_TEST_B=keep") {
		t.Fatalf("env wrong")
	}
	_ = os.Getenv
}

func TestMacCommandNeverContainsRawValue(t *testing.T) {
	value := `sk-ant-x"; rm -rf ~ #`
	cmd := macKeychain{service: service}.setCommand("TOKEN", value)
	if strings.Contains(cmd, value) || strings.Contains(cmd, "rm -rf") {
		t.Fatalf("raw value in command: %s", cmd)
	}
	if !strings.HasPrefix(cmd, "add-generic-password -U -s zarpa-vault -a TOKEN ") {
		t.Fatalf("command: %s", cmd)
	}
}

func TestSecretsAreSeparateFromTheVault(t *testing.T) {
	s := MemorySecrets()
	if err := s.Set("cli-token", "zarpa_abc"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get("cli-token"); got != "zarpa_abc" {
		t.Fatalf("got %q", got)
	}
	if err := s.Set("CLI TOKEN", "x"); err == nil {
		t.Fatal("bad account accepted")
	}
	if err := s.Delete("cli-token"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete("cli-token"); err != nil {
		t.Fatal("deleting twice should be fine")
	}
	if cmd := (macKeychain{service: "zarpa-cloud"}).setCommand("cli-token", "v"); !strings.Contains(cmd, "-s zarpa-cloud ") {
		t.Fatalf("command: %s", cmd)
	}
}
