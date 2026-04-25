# Gosploit

Gosploit is a Go-based exploit development and security testing framework scaffold inspired by Metasploit.

## Current capabilities

- Module registry and runtime engine
- Built-in simulated SQL injection module
- YAML-defined auxiliary scanner/vulnerability-check modules
- YAML-defined handlers
- CLI entrypoint to list, select, configure, and run modules

> Use only on systems you own or are explicitly authorized to test.

## Quick start

```bash
go run ./cmd/gosploit -list
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/security_headers.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/cors_misconfig.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/http/cookie_flags.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/network/tls_configuration.yaml -set host=example.com -set port=443 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/network/dns_recursion_exposure.yaml -set host=example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/linux/ssh_hardening.yaml -set host=linux.example.com -set port=22 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/linux/ssh_crypto_posture.yaml -set host=linux.example.com -set port=22 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/windows/smb_hardening.yaml -set host=win.example.com -set port=445 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/vulnerability/http_dependency_exposure.yaml -set url=https://example.com -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/vulnerability/tls_known_weakness_indicators.yaml -set host=example.com -set port=443 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/misconfig/cloud_storage_public_access.yaml -set provider=aws -set resource=example-bucket -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/misconfig/container_runtime_hardening.yaml -set host=lab-node.local -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/patch/os_patch_verification.yaml -set host=server.example.com -set baseline=2026-04 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/patch/application_patch_verification.yaml -set application=nginx -set expected_version=1.26.1 -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/lab/local_http_security_harness.yaml -set profile=web-minimum -set environment=lab -show -run
go run ./cmd/gosploit -yaml ./modules/auxiliary/lab/local_network_segmentation_harness.yaml -set profile=segmentation-baseline -set environment=lab -show -run
go run ./cmd/gosploit -yaml ./modules/exploit/web/sqli_safe_probe.yaml -set url=https://example.com/search -set param=q -show -run
go run ./cmd/gosploit -yaml ./modules/exploit/api/idor_safe_probe.yaml -set base_url=https://api.example.com -set endpoint=/users/1 -show -run
go run ./cmd/gosploit -handler-yaml ./modules/handlers/reverse_tcp.yaml -set lhost=127.0.0.1 -set lport=4444 -show -run
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

## Defensive module packs

This repository now includes additional defensive YAML module packs for:

- Vulnerability scanners/checkers (`modules/auxiliary/vulnerability`)
- Misconfiguration audits (`modules/auxiliary/misconfig`)
- Patch verification workflows (`modules/auxiliary/patch`)
- Secure local lab-only validation harnesses (`modules/auxiliary/lab`)

All modules execute in simulation mode through the same YAML framework and are designed for authorized defensive testing.

## Remediation workflow reporting

Use remediation workflow guidance in:

- `docs/remediation_workflow.md`

This guide maps findings to triage, ownership, validation, and closure evidence so teams can move from detection to tracked remediation.

## YAML handler format

```yaml
name: handler/reverse_tcp
summary: Simulated reverse TCP listener profile
author: Gosploit Team
options:
  - name: lhost
    description: Local host/IP for callback
    required: true
  - name: lport
    description: Local listener port
    required: true
handler:
  type: reverse_tcp
  payload: generic/shell_reverse_tcp
  lhost_option: lhost
  lport_option: lport
```

Load and run a handler profile:

```bash
go run ./cmd/gosploit -handler-yaml ./modules/handlers/reverse_tcp.yaml -set lhost=127.0.0.1 -set lport=4444 -show -run
```

Available handler YAML profiles:

- `modules/handlers/reverse_tcp.yaml`
- `modules/handlers/bind_tcp.yaml`
- `modules/handlers/reverse_http.yaml`
- `modules/handlers/reverse_https.yaml`

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
