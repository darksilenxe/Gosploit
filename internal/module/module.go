package module

import "context"

type Option struct {
	Name         string
	Description  string
	Required     bool
	DefaultValue string
}

type Definition struct {
	Name           string
	Summary        string
	Author         string
	DisclosureDate string
	References     []string
	Options        []Option
}

type Result struct {
	Success  bool
	Message  string
	Evidence map[string]string
}

type Module interface {
	Definition() Definition
	Validate(options map[string]string) error
	Execute(ctx context.Context, options map[string]string) (Result, error)
}
