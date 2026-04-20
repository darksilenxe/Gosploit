package framework

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/module"
)

var (
	ErrNoActiveModule = errors.New("no active module selected")
	ErrUnknownModule  = errors.New("unknown module")
)

type Framework struct {
	modules       map[string]module.Module
	activeModule  string
	activeOptions map[string]string
}

func New() *Framework {
	return &Framework{
		modules:       map[string]module.Module{},
		activeOptions: map[string]string{},
	}
}

func (f *Framework) Register(m module.Module) error {
	def := m.Definition()
	name := normalize(def.Name)
	if name == "" {
		return errors.New("module name cannot be empty")
	}
	if _, exists := f.modules[name]; exists {
		return fmt.Errorf("module %q already exists", name)
	}
	f.modules[name] = m
	return nil
}

func (f *Framework) List() []module.Definition {
	names := make([]string, 0, len(f.modules))
	for name := range f.modules {
		names = append(names, name)
	}
	sort.Strings(names)

	result := make([]module.Definition, 0, len(names))
	for _, name := range names {
		result = append(result, f.modules[name].Definition())
	}
	return result
}

func (f *Framework) Use(name string) error {
	key := normalize(name)
	mod, ok := f.modules[key]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownModule, name)
	}

	f.activeModule = key
	f.activeOptions = map[string]string{}
	for _, option := range mod.Definition().Options {
		if option.DefaultValue != "" {
			f.activeOptions[strings.ToLower(option.Name)] = option.DefaultValue
		}
	}
	return nil
}

func (f *Framework) ActiveModule() (module.Definition, bool) {
	if f.activeModule == "" {
		return module.Definition{}, false
	}
	return f.modules[f.activeModule].Definition(), true
}

func (f *Framework) ActiveOptions() map[string]string {
	return cloneMap(f.activeOptions)
}

func (f *Framework) SetOption(name, value string) error {
	if f.activeModule == "" {
		return ErrNoActiveModule
	}
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return errors.New("option name cannot be empty")
	}
	f.activeOptions[key] = strings.TrimSpace(value)
	return nil
}

func (f *Framework) Run(ctx context.Context, target string) (module.Result, error) {
	if f.activeModule == "" {
		return module.Result{}, ErrNoActiveModule
	}

	mod := f.modules[f.activeModule]
	options := cloneMap(f.activeOptions)
	if strings.TrimSpace(target) != "" {
		options["target"] = strings.TrimSpace(target)
	}
	if err := mod.Validate(options); err != nil {
		return module.Result{}, err
	}
	return mod.Execute(ctx, options)
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func cloneMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for k, v := range source {
		result[k] = v
	}
	return result
}
