package metasploit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/darksilenxe/Gosploit/internal/module"
)

type stubRunner struct {
	output runOutput
	err    error
	calls  int
	lastEx string
	lastA  []string
}

func (s *stubRunner) Run(_ context.Context, executable string, args []string, _ int) (runOutput, error) {
	s.calls++
	s.lastEx = executable
	s.lastA = append([]string{}, args...)
	return s.output, s.err
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	yamlPath := filepath.Join(dir, "module.yaml")
	content := `name: metasploit/test
summary: test
metasploit:
  script: ./test.rc
  unsupported: true
`
	if err := os.WriteFile(yamlPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	_, err := Load(yamlPath)
	if err == nil {
		t.Fatal("expected error for unknown fields")
	}
}

func TestExecuteSimulationMode(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	mod, err := NewFromCLI(rcPath, "simulate", "", 10)
	if err != nil {
		t.Fatalf("new module: %v", err)
	}

	res, err := mod.Execute(context.Background(), map[string]string{})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Success {
		t.Fatal("expected success in simulate mode")
	}
	if got := res.Evidence["run.status"]; got != "simulated" {
		t.Fatalf("expected simulated status, got %q", got)
	}
}

func TestExecuteRequiresConsentInExecuteMode(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	mod, err := NewFromCLI(rcPath, "execute", "", 10)
	if err != nil {
		t.Fatalf("new module: %v", err)
	}

	_, err = mod.Execute(context.Background(), map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "set -msf-consent") {
		t.Fatalf("expected consent error, got %v", err)
	}
}

func TestExecuteWithRunnerAndOptionMapping(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	consent := true
	mod, err := newModuleFromDefinition(moduleDef(), metaSpec{
		Script:         rcPath,
		Mode:           "execute",
		Tool:           "/bin/echo",
		TimeoutSeconds: 5,
		OptionMap: map[string]string{
			"rhost": "RHOSTS",
		},
		RequiredVars:   []string{"RHOSTS"},
		RequireConsent: &consent,
	})
	if err != nil {
		t.Fatalf("new module: %v", err)
	}

	r := &stubRunner{output: runOutput{stdout: "ok"}}
	mod.runner = r

	res, err := mod.Execute(context.Background(), map[string]string{
		"rhost":        "127.0.0.1",
		"msf_consent":  "true",
		"msfvar.lport": "4444",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got message: %s", res.Message)
	}
	if r.calls != 1 {
		t.Fatalf("expected one runner call, got %d", r.calls)
	}
	args := strings.Join(r.lastA, " ")
	if !strings.Contains(args, "setg RHOSTS 127.0.0.1") {
		t.Fatalf("expected mapped variable, args=%q", args)
	}
	if !strings.Contains(args, "setg LPORT 4444") {
		t.Fatalf("expected override variable, args=%q", args)
	}
}

func TestExecuteUsesToolArgOverrides(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	consent := true
	mod, err := newModuleFromDefinition(moduleDef(), metaSpec{
		Script:         rcPath,
		Mode:           "execute",
		Tool:           "/bin/echo",
		TimeoutSeconds: 5,
		RequireConsent: &consent,
	})
	if err != nil {
		t.Fatalf("new module: %v", err)
	}

	r := &stubRunner{output: runOutput{stdout: "ok"}}
	mod.runner = r
	_, err = mod.Execute(context.Background(), map[string]string{
		"msf_consent": "true",
		"msfarg.001":  "--version",
		"msfarg.000":  "-h",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Join(r.lastA, " ") != "-h --version" {
		t.Fatalf("unexpected tool args: %v", r.lastA)
	}
}

func TestExecuteMarksFailureWithoutReturningError(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	consent := true
	mod, err := newModuleFromDefinition(moduleDef(), metaSpec{
		Script:         rcPath,
		Mode:           "execute",
		Tool:           "/bin/echo",
		TimeoutSeconds: 5,
		RequireConsent: &consent,
	})
	if err != nil {
		t.Fatalf("new module: %v", err)
	}
	mod.runner = &stubRunner{
		output: runOutput{stderr: "boom"},
		err:    errors.New("exit 1"),
	}

	res, err := mod.Execute(context.Background(), map[string]string{"msf_consent": "true"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("expected failed result")
	}
	if got := res.Evidence["run.status"]; got != "failed" {
		t.Fatalf("expected failed status, got %q", got)
	}
}

func TestTimeoutOverrideValidation(t *testing.T) {
	dir := t.TempDir()
	rcPath := filepath.Join(dir, "test.rc")
	if err := os.WriteFile(rcPath, []byte("exit -y\n"), 0o644); err != nil {
		t.Fatalf("write rc file: %v", err)
	}

	mod, err := newModuleFromDefinition(moduleDef(), metaSpec{
		Script:         rcPath,
		Mode:           "simulate",
		TimeoutSeconds: 5,
	})
	if err != nil {
		t.Fatalf("new module: %v", err)
	}
	_, err = mod.timeoutFromOptions(map[string]string{"msf_timeout": strconv.Itoa(int((10 * time.Minute).Seconds() + 1))})
	if err == nil {
		t.Fatal("expected timeout validation error")
	}
}

func moduleDef() module.Definition {
	return module.Definition{
		Name: "metasploit/test",
		Options: []module.Option{
			{Name: "rhost", Required: false},
		},
	}
}
