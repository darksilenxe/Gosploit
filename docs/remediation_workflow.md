# Remediation Workflow Guide

This guide defines a practical workflow for using Gosploit defensive module findings to drive remediation in authorized environments.

## 1) Intake and triage

- Capture module name, check ID, severity, and evidence fields.
- Tag findings as `vulnerability`, `misconfiguration`, `patch-gap`, or `lab-control`.
- Route critical/high findings to on-call or incident response queues immediately.

## 2) Ownership assignment

- Assign each finding to a named service, platform, or infrastructure owner.
- Record accountable team and target closure date.
- Link each finding to the relevant change-management ticket.

## 3) Reproduction and validation

- Re-run the same module with identical options to confirm reproducibility.
- For local-lab harness modules, verify `environment` remains `lab` and scope is controlled.
- Attach command line used and resulting evidence to the ticket.

## 4) Remediation execution

- Apply hardening, configuration correction, or patch deployment.
- For patch modules, update the expected baseline/version value in the change record.
- Capture affected assets and deployment window.

## 5) Verification and closure

- Re-run corresponding verification module:
  - `auxiliary/patch/os_patch_verification`
  - `auxiliary/patch/application_patch_verification`
  - related vulnerability/misconfiguration module
- Close only when:
  - control indicator is present,
  - high/critical finding state is resolved,
  - evidence is attached to the ticket.

## 6) Reporting cadence

- Weekly: open findings by severity and owner.
- Monthly: mean time to remediate (MTTR), repeat finding rate, overdue criticals.
- Quarterly: baseline review of module checks and patch verification criteria.

## Suggested evidence template

- Finding ID:
- Module:
- Asset/Scope:
- Severity:
- Evidence:
- Assigned owner:
- Planned fix date:
- Verification run command:
- Verification result:
- Closure approval:
