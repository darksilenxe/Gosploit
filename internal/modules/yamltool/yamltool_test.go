package yamltool

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndExecute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool.yaml")
	content := `name: auxiliary/test/checker
summary: Example checker
options:
  - name: url
    required: true
checks:
  - id: c1
    description: first check
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write yaml file: %v", err)
	}

	mod, err := Load(path)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if mod.Definition().Name != "auxiliary/test/checker" {
		t.Fatalf("unexpected module name: %s", mod.Definition().Name)
	}
	if err := mod.Validate(map[string]string{"url": "https://example.com"}); err != nil {
		t.Fatalf("validate failed: %v", err)
	}
	res, err := mod.Execute(context.Background(), map[string]string{"url": "https://example.com"})
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if !res.Success {
		t.Fatal("expected success")
	}
}
