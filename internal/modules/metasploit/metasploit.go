package metasploit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/darksilenxe/Gosploit/internal/module"
	"gopkg.in/yaml.v3"
)

const (
	modeSimulate = "simulate"
	modeExecute  = "execute"

	defaultExecutable = "msfconsole"
	defaultTimeout    = 30 * time.Second
	maxTimeout        = 10 * time.Minute
	defaultOutputCap  = 8192
)

var variableNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

type runOutput struct {
	stdout   string
	stderr   string
	timedOut bool
}

type runner interface {
	Run(ctx context.Context, executable string, args []string, outputLimit int) (runOutput, error)
}

type execRunner struct{}

func (r execRunner) Run(ctx context.Context, executable string, args []string, outputLimit int) (runOutput, error) {
	cmd := exec.CommandContext(ctx, executable, args...)

	stdout := newLimitedBuffer(outputLimit)
	stderr := newLimitedBuffer(outputLimit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	result := runOutput{stdout: stdout.String(), stderr: stderr.String()}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.timedOut = true
	}
	return result, err
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func newLimitedBuffer(max int) *limitedBuffer {
	if max <= 0 {
		max = defaultOutputCap
	}
	return &limitedBuffer{max: max}
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	originalLen := len(p)
	if originalLen == 0 {
		return 0, nil
	}
	if l.buf.Len() >= l.max {
		l.truncated = true
		return originalLen, nil
	}
	available := l.max - l.buf.Len()
	if originalLen > available {
		p = p[:available]
		l.truncated = true
	}
	_, err := l.buf.Write(p)
	if err != nil {
		return 0, err
	}
	return originalLen, nil
}

func (l *limitedBuffer) String() string {
	if !l.truncated {
		return l.buf.String()
	}
	return l.buf.String() + "\n[truncated]"
}

type metaSpec struct {
	Script string `yaml:"script"`
	// Executable is kept for backward compatibility with earlier schema drafts.
	Executable string `yaml:"executable"`
	// Tool is the preferred field for selecting any local Metasploit executable.
	Tool           string            `yaml:"tool"`
	Mode           string            `yaml:"mode"`
	RequireConsent *bool             `yaml:"require_consent"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
	ToolArgs       []string          `yaml:"tool_args"`
	OptionMap      map[string]string `yaml:"option_map"`
	RequiredVars   []string          `yaml:"required_vars"`
	OptionalVars   []string          `yaml:"optional_vars"`
}

type fileDefinition struct {
	Name       string          `yaml:"name"`
	Summary    string          `yaml:"summary"`
	Author     string          `yaml:"author"`
	References []string        `yaml:"references"`
	Options    []module.Option `yaml:"options"`
	Metasploit metaSpec        `yaml:"metasploit"`
}

type Module struct {
	def      module.Definition
	spec     metaSpec
	runner   runner
	outLimit int
}

func Load(path string) (Module, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Module{}, err
	}

	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)

	var parsed fileDefinition
	if err := decoder.Decode(&parsed); err != nil {
		return Module{}, fmt.Errorf("invalid metasploit yaml: %w", err)
	}

	baseDir := filepath.Dir(path)
	parsed.Name = strings.TrimSpace(parsed.Name)
	parsed.Summary = strings.TrimSpace(parsed.Summary)
	parsed.Metasploit.Script = strings.TrimSpace(parsed.Metasploit.Script)
	if parsed.Name == "" {
		return Module{}, errors.New("metasploit yaml name is required")
	}
	if parsed.Metasploit.Script == "" {
		return Module{}, errors.New("metasploit yaml script is required")
	}

	absScript, err := normalizeLocalPath(resolveRelativePath(baseDir, parsed.Metasploit.Script))
	if err != nil {
		return Module{}, fmt.Errorf("invalid metasploit script path: %w", err)
	}
	parsed.Metasploit.Script = absScript

	if strings.TrimSpace(parsed.Metasploit.Executable) != "" && strings.Contains(strings.TrimSpace(parsed.Metasploit.Executable), string(filepath.Separator)) {
		absExecutable, err := normalizeLocalPath(resolveRelativePath(baseDir, parsed.Metasploit.Executable))
		if err != nil {
			return Module{}, fmt.Errorf("invalid metasploit executable path: %w", err)
		}
		parsed.Metasploit.Executable = absExecutable
	}
	if strings.TrimSpace(parsed.Metasploit.Tool) != "" && strings.Contains(strings.TrimSpace(parsed.Metasploit.Tool), string(filepath.Separator)) {
		absTool, err := normalizeLocalPath(resolveRelativePath(baseDir, parsed.Metasploit.Tool))
		if err != nil {
			return Module{}, fmt.Errorf("invalid metasploit tool path: %w", err)
		}
		parsed.Metasploit.Tool = absTool
	}

	return newModuleFromDefinition(module.Definition{
		Name:       parsed.Name,
		Summary:    parsed.Summary,
		Author:     parsed.Author,
		References: parsed.References,
		Options:    parsed.Options,
	}, parsed.Metasploit)
}

func NewFromCLI(scriptPath, mode, tool string, timeoutSeconds int) (Module, error) {
	consent := true
	def := module.Definition{
		Name:    "metasploit/resource_script",
		Summary: "Metasploit resource script execution workflow",
		Author:  "Gosploit Team",
		Options: []module.Option{
			{Name: "msf_consent", Description: "Explicit consent to execute external Metasploit process", Required: false, DefaultValue: "false"},
		},
	}
	spec := metaSpec{
		Script:         strings.TrimSpace(scriptPath),
		Mode:           strings.TrimSpace(mode),
		Tool:           strings.TrimSpace(tool),
		TimeoutSeconds: timeoutSeconds,
		RequireConsent: &consent,
	}
	return newModuleFromDefinition(def, spec)
}

func newModuleFromDefinition(def module.Definition, spec metaSpec) (Module, error) {
	if strings.TrimSpace(spec.Mode) == "" {
		spec.Mode = modeSimulate
	} else {
		mode := normalizedMode(spec.Mode)
		if mode == "" {
			return Module{}, fmt.Errorf("invalid metasploit mode %q, expected %q or %q", spec.Mode, modeSimulate, modeExecute)
		}
		spec.Mode = mode
	}
	if spec.RequireConsent == nil {
		consent := true
		spec.RequireConsent = &consent
	}
	if spec.TimeoutSeconds == 0 {
		spec.TimeoutSeconds = int(defaultTimeout.Seconds())
	}
	if spec.TimeoutSeconds < 0 {
		return Module{}, errors.New("metasploit timeout_seconds must be positive")
	}
	if spec.TimeoutSeconds > int(maxTimeout.Seconds()) {
		return Module{}, fmt.Errorf("metasploit timeout_seconds cannot exceed %d", int(maxTimeout.Seconds()))
	}
	if strings.TrimSpace(spec.Executable) == "" && strings.TrimSpace(spec.Tool) == "" {
		spec.Tool = defaultExecutable
	}
	spec.ToolArgs = sanitizeArgs(spec.ToolArgs)
	if err := validateMappings(spec.OptionMap, spec.RequiredVars, spec.OptionalVars); err != nil {
		return Module{}, err
	}
	if strings.TrimSpace(spec.Script) == "" {
		return Module{}, errors.New("metasploit script is required")
	}
	if _, err := normalizeLocalPath(spec.Script); err != nil {
		return Module{}, fmt.Errorf("invalid metasploit script path: %w", err)
	}

	return Module{def: def, spec: spec, runner: execRunner{}, outLimit: defaultOutputCap}, nil
}

func (m Module) Definition() module.Definition {
	return m.def
}

func (m Module) Validate(options map[string]string) error {
	for _, option := range m.def.Options {
		if option.Required && strings.TrimSpace(options[strings.ToLower(option.Name)]) == "" {
			return fmt.Errorf("missing required option: %s", option.Name)
		}
	}

	mode, err := m.modeFromOptions(options)
	if err != nil {
		return err
	}
	scriptPath, err := m.scriptFromOptions(options)
	if err != nil {
		return err
	}
	if _, err := os.Stat(scriptPath); err != nil {
		return fmt.Errorf("metasploit script is not accessible: %w", err)
	}
	if _, err := m.mappedVariables(options); err != nil {
		return err
	}
	if mode == modeExecute {
		if m.requireConsent() && !isTruthy(options["msf_consent"]) {
			return errors.New("metasploit execution requires explicit consent; set -msf-consent")
		}
		if _, err := m.toolFromOptions(options); err != nil {
			return err
		}
		if _, err := m.toolArgsFromOptions(options, scriptPath, map[string]string{}); err != nil {
			return err
		}
	}
	if _, err := m.timeoutFromOptions(options); err != nil {
		return err
	}
	return nil
}

func (m Module) Execute(ctx context.Context, options map[string]string) (module.Result, error) {
	if err := m.Validate(options); err != nil {
		return module.Result{}, err
	}

	mode, err := m.modeFromOptions(options)
	if err != nil {
		return module.Result{}, err
	}
	scriptPath, _ := m.scriptFromOptions(options)
	vars, _ := m.mappedVariables(options)

	evidence := map[string]string{
		"integration":       "metasploit",
		"metasploit.mode":   mode,
		"metasploit.script": scriptPath,
		"metasploit.vars":   fmt.Sprintf("%d", len(vars)),
	}
	if isTruthy(options["msf_consent"]) {
		evidence["metasploit.consent"] = "true"
	}

	if mode == modeSimulate {
		evidence["run.status"] = "simulated"
		return module.Result{Success: true, Message: "metasploit simulation prepared; execution skipped", Evidence: evidence}, nil
	}

	toolPath, _ := m.toolFromOptions(options)
	timeout, _ := m.timeoutFromOptions(options)
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args, err := m.toolArgsFromOptions(options, scriptPath, vars)
	if err != nil {
		return module.Result{}, err
	}
	output, err := m.runner.Run(execCtx, toolPath, args, m.outLimit)

	evidence["metasploit.tool"] = toolPath
	evidence["run.timeout_seconds"] = strconv.Itoa(int(timeout.Seconds()))
	evidence["run.stdout.preview"] = preview(output.stdout, 240)
	evidence["run.stderr.preview"] = preview(output.stderr, 240)
	if output.timedOut {
		evidence["run.status"] = "timed_out"
		return module.Result{Success: false, Message: "metasploit execution timed out", Evidence: evidence}, nil
	}
	if err != nil {
		evidence["run.status"] = "failed"
		return module.Result{Success: false, Message: fmt.Sprintf("metasploit execution failed: %v", err), Evidence: evidence}, nil
	}

	evidence["run.status"] = "completed"
	return module.Result{Success: true, Message: "metasploit execution completed", Evidence: evidence}, nil
}

func (m Module) modeFromOptions(options map[string]string) (string, error) {
	if overrideRaw := strings.TrimSpace(options["msf_mode"]); overrideRaw != "" {
		override := normalizedMode(overrideRaw)
		if override == "" {
			return "", fmt.Errorf("invalid metasploit mode %q, expected %q or %q", overrideRaw, modeSimulate, modeExecute)
		}
		return override, nil
	}

	modeRaw := strings.TrimSpace(m.spec.Mode)
	mode := normalizedMode(modeRaw)
	if mode == "" {
		return "", fmt.Errorf("invalid metasploit mode %q, expected %q or %q", modeRaw, modeSimulate, modeExecute)
	}
	return mode, nil
}

func (m Module) scriptFromOptions(options map[string]string) (string, error) {
	raw := strings.TrimSpace(m.spec.Script)
	if override := strings.TrimSpace(options["msf_script"]); override != "" {
		raw = override
	}
	if raw == "" {
		return "", errors.New("metasploit script is required")
	}
	path, err := normalizeLocalPath(raw)
	if err != nil {
		return "", fmt.Errorf("invalid metasploit script path: %w", err)
	}
	return path, nil
}

func (m Module) toolFromOptions(options map[string]string) (string, error) {
	raw := strings.TrimSpace(m.spec.Tool)
	if raw == "" {
		raw = strings.TrimSpace(m.spec.Executable)
	}
	if override := strings.TrimSpace(options["msf_tool"]); override != "" {
		raw = override
	}
	if override := strings.TrimSpace(options["msf_executable"]); override != "" {
		raw = override
	}
	if raw == "" {
		raw = defaultExecutable
	}
	return resolveExecutable(raw)
}

func (m Module) timeoutFromOptions(options map[string]string) (time.Duration, error) {
	raw := strings.TrimSpace(options["msf_timeout"])
	if raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return 0, errors.New("msf_timeout must be a positive integer in seconds")
		}
		if value > int(maxTimeout.Seconds()) {
			return 0, fmt.Errorf("msf_timeout cannot exceed %d seconds", int(maxTimeout.Seconds()))
		}
		return time.Duration(value) * time.Second, nil
	}

	if m.spec.TimeoutSeconds <= 0 {
		return defaultTimeout, nil
	}
	if m.spec.TimeoutSeconds > int(maxTimeout.Seconds()) {
		return 0, fmt.Errorf("metasploit timeout exceeds %d seconds", int(maxTimeout.Seconds()))
	}
	return time.Duration(m.spec.TimeoutSeconds) * time.Second, nil
}

func (m Module) mappedVariables(options map[string]string) (map[string]string, error) {
	variables := map[string]string{}

	for optionName, varName := range m.spec.OptionMap {
		optionKey := strings.ToLower(strings.TrimSpace(optionName))
		value := strings.TrimSpace(options[optionKey])
		if value == "" {
			continue
		}
		if err := validateVarName(varName); err != nil {
			return nil, err
		}
		if err := validateVarValue(value); err != nil {
			return nil, fmt.Errorf("invalid value for %s: %w", optionName, err)
		}
		variables[strings.ToUpper(strings.TrimSpace(varName))] = value
	}

	for optionName, value := range options {
		if !strings.HasPrefix(optionName, "msfvar.") {
			continue
		}
		varName := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(optionName, "msfvar.")))
		if err := validateVarName(varName); err != nil {
			return nil, fmt.Errorf("invalid override variable %q: %w", varName, err)
		}
		clean := strings.TrimSpace(value)
		if clean == "" {
			continue
		}
		if err := validateVarValue(clean); err != nil {
			return nil, fmt.Errorf("invalid override value for %s: %w", varName, err)
		}
		variables[varName] = clean
	}

	for _, required := range m.spec.RequiredVars {
		name := strings.ToUpper(strings.TrimSpace(required))
		if err := validateVarName(name); err != nil {
			return nil, err
		}
		if strings.TrimSpace(variables[name]) == "" {
			return nil, fmt.Errorf("missing required metasploit variable: %s", name)
		}
	}

	for _, optional := range m.spec.OptionalVars {
		name := strings.ToUpper(strings.TrimSpace(optional))
		if err := validateVarName(name); err != nil {
			return nil, err
		}
	}

	return variables, nil
}

func (m Module) toolArgsFromOptions(options map[string]string, scriptPath string, variables map[string]string) ([]string, error) {
	overrides := make([]string, 0)
	overrideKeys := make([]string, 0)
	for key := range options {
		if strings.HasPrefix(key, "msfarg.") {
			overrideKeys = append(overrideKeys, key)
		}
	}
	sort.Strings(overrideKeys)
	for _, key := range overrideKeys {
		clean := strings.TrimSpace(options[key])
		if clean == "" {
			continue
		}
		if err := validateToolArg(clean); err != nil {
			return nil, fmt.Errorf("invalid metasploit argument %q: %w", clean, err)
		}
		overrides = append(overrides, clean)
	}
	if len(overrides) > 0 {
		return overrides, nil
	}
	if len(m.spec.ToolArgs) > 0 {
		args := make([]string, 0, len(m.spec.ToolArgs))
		for _, arg := range m.spec.ToolArgs {
			clean := strings.TrimSpace(arg)
			if clean == "" {
				continue
			}
			if err := validateToolArg(clean); err != nil {
				return nil, fmt.Errorf("invalid metasploit tool arg %q: %w", clean, err)
			}
			args = append(args, clean)
		}
		if len(args) > 0 {
			return args, nil
		}
	}
	return buildMSFConsoleArgs(scriptPath, variables), nil
}

func (m Module) requireConsent() bool {
	if m.spec.RequireConsent == nil {
		return true
	}
	return *m.spec.RequireConsent
}

func validateMappings(optionMap map[string]string, requiredVars, optionalVars []string) error {
	for optionName, varName := range optionMap {
		if strings.TrimSpace(optionName) == "" {
			return errors.New("metasploit option_map cannot contain empty option names")
		}
		if err := validateVarName(varName); err != nil {
			return err
		}
	}
	for _, name := range requiredVars {
		if err := validateVarName(name); err != nil {
			return err
		}
	}
	for _, name := range optionalVars {
		if err := validateVarName(name); err != nil {
			return err
		}
	}
	return nil
}

func buildMSFConsoleArgs(scriptPath string, variables map[string]string) []string {
	args := []string{"-q", "-r", scriptPath}
	if len(variables) > 0 {
		keys := make([]string, 0, len(variables))
		for key := range variables {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		commands := make([]string, 0, len(keys))
		for _, key := range keys {
			commands = append(commands, fmt.Sprintf("setg %s %s", key, variables[key]))
		}
		args = append(args, "-x", strings.Join(commands, "; "))
	}
	args = append(args, "-x", "exit -y")
	return args
}

func normalizedMode(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return ""
	}
	if value == modeSimulate || value == modeExecute {
		return value
	}
	return ""
}

func validateVarName(raw string) error {
	value := strings.TrimSpace(raw)
	if !variableNamePattern.MatchString(value) {
		return fmt.Errorf("invalid metasploit variable name %q", raw)
	}
	return nil
}

func validateVarValue(value string) error {
	if strings.ContainsAny(value, "\x00\r\n`'\";&|\\") {
		return errors.New("metasploit variable values cannot contain control characters, quotes, backticks, or command separators")
	}
	if strings.Contains(value, "${") || strings.Contains(value, "$(") {
		return errors.New("metasploit variable values cannot contain shell-expansion patterns")
	}
	return nil
}

func validateToolArg(value string) error {
	if strings.ContainsAny(value, "\x00\r\n`'\";&|\\") {
		return errors.New("tool arguments cannot contain control characters, quotes, backticks, or command separators")
	}
	if strings.Contains(value, "${") || strings.Contains(value, "$(") {
		return errors.New("tool arguments cannot contain shell-expansion patterns")
	}
	return nil
}

func resolveExecutable(raw string) (string, error) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", errors.New("metasploit executable cannot be empty")
	}
	if strings.ContainsAny(candidate, " \t\n\r`$\"'|&;<>") {
		return "", errors.New("metasploit executable contains disallowed characters")
	}
	if strings.Contains(candidate, string(filepath.Separator)) {
		path, err := normalizeLocalPath(candidate)
		if err != nil {
			return "", fmt.Errorf("invalid metasploit executable path: %w", err)
		}
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("metasploit executable is not accessible: %w", err)
		}
		return path, nil
	}
	resolved, err := exec.LookPath(candidate)
	if err != nil {
		return "", fmt.Errorf("metasploit executable %q not found in PATH", candidate)
	}
	return normalizeLocalPath(resolved)
}

func normalizeLocalPath(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("path cannot be empty")
	}
	if strings.Contains(value, "://") {
		return "", errors.New("path must reference a local filesystem location")
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("path contains invalid characters")
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func resolveRelativePath(baseDir, candidate string) string {
	if filepath.IsAbs(candidate) {
		return candidate
	}
	return filepath.Join(baseDir, candidate)
}

func sanitizeArgs(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		clean := strings.TrimSpace(value)
		if clean != "" {
			out = append(out, clean)
		}
	}
	return out
}

func preview(value string, max int) string {
	trimmed := strings.TrimSpace(value)
	if max <= 0 || len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "..."
}

func isTruthy(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y":
		return true
	default:
		return false
	}
}
