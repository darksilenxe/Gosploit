package sqlinjection

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/module"
)

type Module struct{}

func New() Module {
	return Module{}
}

func (m Module) Definition() module.Definition {
	return module.Definition{
		Name:           "exploit/web/sqlinjection",
		Summary:        "Simulated SQL injection detection workflow for authorized testing",
		Author:         "Gosploit Team",
		DisclosureDate: "2026-04-20",
		References: []string{
			"https://owasp.org/www-community/attacks/SQL_Injection",
		},
		Options: []module.Option{
			{Name: "url", Description: "Target URL", Required: true},
			{Name: "param", Description: "Parameter to test", Required: true, DefaultValue: "id"},
			{Name: "method", Description: "HTTP method", Required: true, DefaultValue: "GET"},
		},
	}
}

func (m Module) Validate(options map[string]string) error {
	target := strings.TrimSpace(options["url"])
	if target == "" {
		return errors.New("url option is required")
	}
	parsed, err := url.ParseRequestURI(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("url option must be a valid absolute URL")
	}
	method := strings.ToUpper(strings.TrimSpace(options["method"]))
	if method != "GET" && method != "POST" {
		return errors.New("method option must be GET or POST")
	}
	param := strings.TrimSpace(options["param"])
	if param == "" {
		return errors.New("param option is required")
	}
	return nil
}

func (m Module) Execute(_ context.Context, options map[string]string) (module.Result, error) {
	target := strings.TrimSpace(options["url"])
	param := strings.TrimSpace(options["param"])
	method := strings.ToUpper(strings.TrimSpace(options["method"]))
	payload := fmt.Sprintf("'%s=1 OR 1=1--", param)

	return module.Result{
		Success: true,
		Message: "simulation completed; manual verification required",
		Evidence: map[string]string{
			"target":         target,
			"method":         method,
			"parameter":      param,
			"sample_payload": payload,
		},
	}, nil
}
