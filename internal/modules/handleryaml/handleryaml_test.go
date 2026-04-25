package handleryaml

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndExecute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "handler.yaml")
	content := `name: handler/reverse_tcp
summary: Example reverse TCP handler
options:
  - name: lhost
    required: true
  - name: lport
    required: true
handler:
  type: reverse_tcp
  payload: generic/shell_reverse_tcp
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	mod, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if mod.Definition().Name != "handler/reverse_tcp" {
		t.Fatalf("unexpected module name: %s", mod.Definition().Name)
	}
	if err := mod.Validate(map[string]string{"lhost": "127.0.0.1", "lport": "4444"}); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	res, err := mod.Execute(context.Background(), map[string]string{"lhost": "127.0.0.1", "lport": "4444"})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if !res.Success {
		t.Fatal("expected success")
	}
	if res.Evidence["handler.type"] != "reverse_tcp" {
		t.Fatalf("unexpected handler type: %s", res.Evidence["handler.type"])
	}
}

func TestLoadRequiresName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "handler.yaml")
	content := `summary: missing name
handler:
  type: reverse_tcp
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected load error")
	}
}
