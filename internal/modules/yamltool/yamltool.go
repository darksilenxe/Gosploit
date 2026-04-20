package yamltool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/module"
	"gopkg.in/yaml.v3"
)

type checkDefinition struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Indicator   string `yaml:"indicator"`
}

type fileDefinition struct {
	Name       string            `yaml:"name"`
	Summary    string            `yaml:"summary"`
	Author     string            `yaml:"author"`
	References []string          `yaml:"references"`
	Options    []module.Option   `yaml:"options"`
	Checks     []checkDefinition `yaml:"checks"`
}

type Module struct {
	def fileDefinition
}

func Load(path string) (Module, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Module{}, err
	}

	var def fileDefinition
	if err := yaml.Unmarshal(content, &def); err != nil {
		return Module{}, fmt.Errorf("invalid yaml module: %w", err)
	}

	def.Name = strings.TrimSpace(def.Name)
	def.Summary = strings.TrimSpace(def.Summary)
	if def.Name == "" {
		return Module{}, errors.New("yaml module name is required")
	}
	if len(def.Checks) == 0 {
		return Module{}, errors.New("yaml module must define at least one check")
	}

	for index, check := range def.Checks {
		if strings.TrimSpace(check.ID) == "" {
			return Module{}, fmt.Errorf("check at index %d is missing id", index)
		}
		if strings.TrimSpace(check.Description) == "" {
			return Module{}, fmt.Errorf("check %q is missing description", check.ID)
		}
		if strings.TrimSpace(check.Severity) == "" {
			def.Checks[index].Severity = "info"
		}
	}

	return Module{def: def}, nil
}

func (m Module) Definition() module.Definition {
	return module.Definition{
		Name:       m.def.Name,
		Summary:    m.def.Summary,
		Author:     m.def.Author,
		References: m.def.References,
		Options:    m.def.Options,
	}
}

func (m Module) Validate(options map[string]string) error {
	for _, option := range m.def.Options {
		if option.Required && strings.TrimSpace(options[strings.ToLower(option.Name)]) == "" {
			return fmt.Errorf("missing required option: %s", option.Name)
		}
	}
	return nil
}

func (m Module) Execute(_ context.Context, options map[string]string) (module.Result, error) {
	evidence := map[string]string{
		"check_count": fmt.Sprintf("%d", len(m.def.Checks)),
	}

	for _, check := range m.def.Checks {
		key := fmt.Sprintf("check.%s", strings.ToLower(check.ID))
		evidence[key] = fmt.Sprintf("%s (%s)", check.Description, strings.ToLower(check.Severity))
		if strings.TrimSpace(check.Indicator) != "" {
			evidence[key+".indicator"] = check.Indicator
		}
	}
	for k, v := range options {
		evidence["option."+strings.ToLower(k)] = v
	}

	return module.Result{
		Success:  true,
		Message:  "yaml-defined checks loaded and executed in simulation mode",
		Evidence: evidence,
	}, nil
}
