package handleryaml

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/module"
	"gopkg.in/yaml.v3"
)

type handlerSpec struct {
	Type        string `yaml:"type"`
	Payload     string `yaml:"payload"`
	LHostOption string `yaml:"lhost_option"`
	LPortOption string `yaml:"lport_option"`
}

type fileDefinition struct {
	Name       string          `yaml:"name"`
	Summary    string          `yaml:"summary"`
	Author     string          `yaml:"author"`
	References []string        `yaml:"references"`
	Options    []module.Option `yaml:"options"`
	Handler    handlerSpec     `yaml:"handler"`
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
		return Module{}, fmt.Errorf("invalid handler yaml: %w", err)
	}

	def.Name = strings.TrimSpace(def.Name)
	def.Summary = strings.TrimSpace(def.Summary)
	if def.Name == "" {
		return Module{}, errors.New("handler yaml name is required")
	}

	if strings.TrimSpace(def.Handler.Type) == "" {
		def.Handler.Type = "generic"
	}
	if strings.TrimSpace(def.Handler.LHostOption) == "" {
		def.Handler.LHostOption = "lhost"
	}
	if strings.TrimSpace(def.Handler.LPortOption) == "" {
		def.Handler.LPortOption = "lport"
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
		"handler.type": strings.ToLower(strings.TrimSpace(m.def.Handler.Type)),
	}

	if payload := strings.TrimSpace(m.def.Handler.Payload); payload != "" {
		evidence["handler.payload"] = payload
	}

	if hostOption := strings.ToLower(strings.TrimSpace(m.def.Handler.LHostOption)); hostOption != "" {
		evidence["handler.lhost_option"] = hostOption
		evidence["handler.lhost"] = strings.TrimSpace(options[hostOption])
	}

	if portOption := strings.ToLower(strings.TrimSpace(m.def.Handler.LPortOption)); portOption != "" {
		evidence["handler.lport_option"] = portOption
		evidence["handler.lport"] = strings.TrimSpace(options[portOption])
	}

	for k, v := range options {
		evidence["option."+strings.ToLower(k)] = v
	}

	return module.Result{
		Success:  true,
		Message:  "handler loaded and executed in simulation mode",
		Evidence: evidence,
	}, nil
}
