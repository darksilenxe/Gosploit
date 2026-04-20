package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/framework"
	"github.com/darksilenxe/Gosploit/internal/modules/sqlinjection"
	"github.com/darksilenxe/Gosploit/internal/modules/yamltool"
)

type repeatedValues []string

func (r *repeatedValues) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatedValues) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func main() {
	engine := framework.New()
	must(engine.Register(sqlinjection.New()))

	var (
		listModules bool
		moduleName  string
		yamlPath    string
		target      string
		runModule   bool
		runShell    bool
		showCurrent bool
		setOptions  repeatedValues
	)

	flag.BoolVar(&listModules, "list", false, "List available modules")
	flag.StringVar(&moduleName, "module", "", "Select module name")
	flag.StringVar(&yamlPath, "yaml", "", "Load a YAML-defined auxiliary module")
	flag.StringVar(&target, "target", "", "Target identifier")
	flag.BoolVar(&runModule, "run", false, "Run the active module")
	flag.BoolVar(&runShell, "shell", false, "Launch go-shell interactive tool")
	flag.BoolVar(&showCurrent, "show", false, "Show selected module and options")
	flag.Var(&setOptions, "set", "Set option KEY=VALUE (can be repeated)")
	flag.Parse()

	if runShell {
		must(runGoShell())
		return
	}

	if listModules {
		for _, def := range engine.List() {
			fmt.Printf("%s\t%s\n", def.Name, def.Summary)
		}
	}

	if moduleName != "" {
		must(engine.Use(moduleName))
	}
	if yamlPath != "" {
		yamlModule, err := yamltool.Load(yamlPath)
		must(err)
		must(engine.Register(yamlModule))
		must(engine.Use(yamlModule.Definition().Name))
	}

	for _, pair := range setOptions {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			fatalf("invalid -set value %q, expected KEY=VALUE", pair)
		}
		must(engine.SetOption(parts[0], parts[1]))
	}

	if showCurrent {
		def, ok := engine.ActiveModule()
		if !ok {
			fatalf("no active module selected")
		}
		fmt.Printf("Module: %s\nSummary: %s\n", def.Name, def.Summary)
		fmt.Println("Options:")
		active := engine.ActiveOptions()
		for _, option := range def.Options {
			key := strings.ToLower(option.Name)
			fmt.Printf("- %s = %q\n", option.Name, active[key])
		}
	}

	if runModule {
		result, err := engine.Run(context.Background(), target)
		must(err)
		fmt.Printf("Success: %t\nMessage: %s\n", result.Success, result.Message)
		if len(result.Evidence) > 0 {
			fmt.Println("Evidence:")
			for key, value := range result.Evidence {
				fmt.Printf("- %s: %s\n", key, value)
			}
		}
	}

	if !listModules && moduleName == "" && yamlPath == "" && !runModule && !showCurrent && len(setOptions) == 0 {
		flag.Usage()
	}
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func runGoShell() error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go command is not available in PATH")
	}

	cmd := exec.Command("go", "run", "github.com/sanurb/go-shell@v0.0.0-20240610210302-f321eeeb5f28")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}
