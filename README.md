# Gosploit

Gosploit is a Go-based exploit development and security testing framework scaffold inspired by Metasploit.

## Current capabilities

- Module registry and runtime engine
- Built-in simulated SQL injection module
- YAML-defined auxiliary scanner/vulnerability-check modules
- CLI entrypoint to list, select, configure, and run modules

> Use only on systems you own or are explicitly authorized to test.

## Quick start

```bash
go run ./cmd/gosploit -list
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/security_headers.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/cors_misconfig.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/cookie_flags.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/network/tls_configuration.yaml -set host=example.com -set port=443 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/linux/ssh_hardening.yaml -set host=linux.example.com -set port=22 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/windows/smb_hardening.yaml -set host=win.example.com -set port=445 -show -run
go run ./cmd/gosploit -module exploit/web/sqlinjection -set url=https://example.com/search -set param=q -run
```

## YAML auxiliary module format

```yaml
name: auxiliary/http/security_headers
summary: Check for common missing security headers
author: Gosploit Team
references:
  - https://owasp.org/www-project-secure-headers/
options:
  - name: url
    description: Target URL for header inspection
    required: true
checks:
  - id: missing_hsts
    description: Verify Strict-Transport-Security header is present
    severity: medium
    indicator: strict-transport-security
```

The current engine executes YAML checks in simulation mode and returns structured evidence that can be extended with real protocol logic.

## Module templates

Protocol starter templates are available in `/modules/templates`:

- `modules/templates/http_module_template.yaml`
- `modules/templates/smb_module_template.yaml`
- `modules/templates/rdp_module_template.yaml`
- `modules/templates/rpc_module_template.yaml`

Copy one, replace placeholders, then load it with:

```bash
go run ./cmd/gosploit -yaml /path/to/your_module.yaml -show -run
```
