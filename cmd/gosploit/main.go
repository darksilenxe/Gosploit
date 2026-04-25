package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/darksilenxe/Gosploit/internal/framework"
	"github.com/darksilenxe/Gosploit/internal/modules/handleryaml"
	"github.com/darksilenxe/Gosploit/internal/modules/metasploit"
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
		handlerName string
		yamlPath    string
		handlerPath string
		msfYAMLPath string
		msfRCPath   string
		msfMode     string
		msfExec     string
		msfConsent  bool
		msfTimeout  int
		target      string
		runModule   bool
		runShell    bool
		showCurrent bool
		setOptions  repeatedValues
		msfVars     repeatedValues
		msfArgs     repeatedValues
	)

	flag.BoolVar(&listModules, "list", false, "List available modules")
	flag.StringVar(&moduleName, "module", "", "Select module name")
	flag.StringVar(&yamlPath, "yaml", "", "Load a YAML-defined auxiliary module")
	flag.StringVar(&handlerName, "handler", "", "Select handler name")
	flag.StringVar(&handlerPath, "handler-yaml", "", "Load a YAML-defined handler")
	flag.StringVar(&msfYAMLPath, "metasploit-yaml", "", "Load a YAML-defined Metasploit module")
	flag.StringVar(&msfRCPath, "msf-rc", "", "Metasploit resource script path")
	flag.StringVar(&msfMode, "msf-mode", "", "Metasploit mode: simulate or execute")
	flag.StringVar(&msfExec, "msf-tool", "", "Metasploit executable or tool path/name")
	flag.BoolVar(&msfConsent, "msf-consent", false, "Explicit consent for external Metasploit execution")
	flag.IntVar(&msfTimeout, "msf-timeout", 0, "Metasploit execution timeout in seconds")
	flag.StringVar(&target, "target", "", "Target identifier")
	flag.BoolVar(&runModule, "run", false, "Run the active module")
	flag.BoolVar(&runShell, "shell", false, "Launch go-shell interactive tool")
	flag.BoolVar(&showCurrent, "show", false, "Show selected module and options")
	flag.Var(&setOptions, "set", "Set option KEY=VALUE (can be repeated)")
	flag.Var(&msfVars, "msf-var", "Set Metasploit variable KEY=VALUE (can be repeated)")
	flag.Var(&msfArgs, "msf-arg", "Set Metasploit tool argument (can be repeated)")
	flag.Parse()

	if runShell {
		must(runGoShell())
		return
	}

	must(validateMetasploitFlags(moduleName, yamlPath, handlerName, handlerPath, msfYAMLPath, msfRCPath, msfMode, msfExec, msfTimeout, msfVars, msfArgs, msfConsent))

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
	if handlerName != "" {
		must(engine.Use(handlerName))
	}
	if handlerPath != "" {
		handlerModule, err := handleryaml.Load(handlerPath)
		must(err)
		must(engine.Register(handlerModule))
		must(engine.Use(handlerModule.Definition().Name))
	}
	if msfYAMLPath != "" {
		msfModule, err := metasploit.Load(msfYAMLPath)
		must(err)
		must(engine.Register(msfModule))
		must(engine.Use(msfModule.Definition().Name))
	}
	if msfRCPath != "" {
		msfModule, err := metasploit.NewFromCLI(msfRCPath, msfMode, msfExec, msfTimeout)
		must(err)
		must(engine.Register(msfModule))
		must(engine.Use(msfModule.Definition().Name))
	}

	for _, pair := range setOptions {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			fatalf("invalid -set value %q, expected KEY=VALUE", pair)
		}
		must(engine.SetOption(parts[0], parts[1]))
	}
	applyMetasploitOverrides(engine, msfMode, msfExec, msfTimeout, msfConsent, msfVars, msfArgs)

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

	if !listModules && moduleName == "" && yamlPath == "" && handlerName == "" && handlerPath == "" && msfYAMLPath == "" && msfRCPath == "" && !runModule && !showCurrent && len(setOptions) == 0 && len(msfVars) == 0 && len(msfArgs) == 0 && msfMode == "" && msfExec == "" && msfTimeout == 0 && !msfConsent {
		flag.Usage()
	}
}

func validateMetasploitFlags(moduleName, yamlPath, handlerName, handlerPath, msfYAMLPath, msfRCPath, msfMode, msfExec string, msfTimeout int, msfVars, msfArgs repeatedValues, msfConsent bool) error {
	selected := 0
	for _, value := range []string{moduleName, yamlPath, handlerName, handlerPath, msfYAMLPath, msfRCPath} {
		if strings.TrimSpace(value) != "" {
			selected++
		}
	}
	if selected > 1 {
		return errors.New("select only one module source among -module, -yaml, -handler, -handler-yaml, -metasploit-yaml, or -msf-rc")
	}

	usingMetasploit := strings.TrimSpace(msfYAMLPath) != "" || strings.TrimSpace(msfRCPath) != ""
	usingMetasploitFlags := strings.TrimSpace(msfMode) != "" || strings.TrimSpace(msfExec) != "" || msfTimeout > 0 || len(msfVars) > 0 || len(msfArgs) > 0 || msfConsent
	if !usingMetasploit && usingMetasploitFlags {
		return errors.New("-msf-mode, -msf-tool, -msf-timeout, -msf-consent, -msf-var, and -msf-arg require -metasploit-yaml or -msf-rc")
	}
	return nil
}

func applyMetasploitOverrides(engine *framework.Framework, msfMode, msfExec string, msfTimeout int, msfConsent bool, msfVars, msfArgs repeatedValues) {
	if strings.TrimSpace(msfMode) != "" {
		must(engine.SetOption("msf_mode", msfMode))
	}
	if strings.TrimSpace(msfExec) != "" {
		must(engine.SetOption("msf_tool", msfExec))
	}
	if msfTimeout > 0 {
		must(engine.SetOption("msf_timeout", strconv.Itoa(msfTimeout)))
	}
	if msfConsent {
		must(engine.SetOption("msf_consent", "true"))
	}
	for _, pair := range msfVars {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			fatalf("invalid -msf-var value %q, expected KEY=VALUE", pair)
		}
		key := strings.TrimSpace(parts[0])
		if key == "" {
			fatalf("invalid -msf-var value %q, variable name cannot be empty", pair)
		}
		must(engine.SetOption("msfvar."+key, parts[1]))
	}
	for i, arg := range msfArgs {
		must(engine.SetOption(fmt.Sprintf("msfarg.%03d", i), arg))
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
