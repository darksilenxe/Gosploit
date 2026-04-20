package framework

import (
	"context"
	"errors"
	"testing"

	"github.com/darksilenxe/Gosploit/internal/module"
)

type stubModule struct {
	name string
}

func (s stubModule) Definition() module.Definition {
	return module.Definition{
		Name: s.name,
		Options: []module.Option{
			{Name: "url", Required: true},
		},
	}
}

func (s stubModule) Validate(options map[string]string) error {
	if options["url"] == "" {
		return errors.New("missing url")
	}
	return nil
}

func (s stubModule) Execute(_ context.Context, options map[string]string) (module.Result, error) {
	return module.Result{
		Success: true,
		Message: options["url"],
	}, nil
}

func TestRegisterAndUse(t *testing.T) {
	engine := New()
	if err := engine.Register(stubModule{name: "aux/test"}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	if err := engine.Use("aux/test"); err != nil {
		t.Fatalf("use failed: %v", err)
	}
	if _, ok := engine.ActiveModule(); !ok {
		t.Fatal("expected active module")
	}
}

func TestRunRequiresModule(t *testing.T) {
	engine := New()
	_, err := engine.Run(context.Background(), "https://example.com")
	if err != ErrNoActiveModule {
		t.Fatalf("expected ErrNoActiveModule, got %v", err)
	}
}
