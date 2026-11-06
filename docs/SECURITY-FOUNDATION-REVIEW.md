# Security foundation review

Reviewed upstream commit: `7684791c55b44a7d4bba1ee72173b129422601b6`

## Decision

Mergen is a useful starting point for a local-first macOS posture application. It already provides a native SwiftUI interface, a Go CLI, a broad set of configuration checks, dry-run support, reporting, signed release automation, and post-remediation verification.

It is not yet a safe foundation for unattended or vulnerability-driven remediation. Before adding advisory feeds or background auto-fix, the privilege boundary, remediation model, rule ownership, logging, and automated tests need to be hardened.

## What is worth preserving

- Clear SwiftUI scan and finding workflow.
- Separate CLI suitable for automation and recovery.
- Small dependency footprint.
- Check re-verification after remediation.
- Dry-run and report export capabilities.
- Signed, notarized release workflow with published checksums.
- MIT license and upstream history.

## Blocking findings

### 1. Privileged remediation executes shell programs assembled as strings

The Swift app runs user fixes through `/bin/bash -c` and administrator fixes through `NSAppleScript` using `do shell script ... with administrator privileges`. The CLI uses `/bin/sh -c` and batches administrator commands into an `osascript` expression.

Although the current commands are static, this creates an unsafe extension point for future vulnerability metadata, application paths, package names, or other dynamic values. It also makes it difficult to enforce per-operation authorization, validate arguments, or prove which executable will run.

Required change:

- Replace shell-string remediation in the app with a bundled `SMAppService` launch daemon and authenticated XPC.
- Represent remediation as a closed enum of typed operations and validated arguments.
- Execute fixed absolute binaries with argument arrays; do not invoke a shell.
- Keep feed and rule data declarative. Downloaded data must never introduce executable commands.

### 2. Administrator failures are intentionally converted to success

`FixManager.runAdminCommand` appends `exit 0`, suppresses intermediate command failures, and returns success for non-cancellation AppleScript errors. Several individual fixes also end with `true` or discard standard error.

Re-running a check is useful, but it cannot replace accurate execution results. A check may observe stale state, partially applied state, or a setting that changed for an unrelated reason.

Required change:

- Return a structured result for every operation: exit status, validated output, verification result, and rollback state.
- Stop a transaction when a prerequisite fails.
- Never convert an unexpected privilege or execution error into success.

### 3. “Fix All” mixes low-risk preferences with disruptive system policy

The same batch may enable the firewall, stop SSH, disable Screen Sharing, change password requirements, change sleep behavior, alter `sudoers`, disable Bonjour, and modify the root account. This can break remote access or established workflows and can lock an administrator out of a remote Mac.

Required change:

- Classify fixes as `safe`, `confirm`, `guided`, `investigate`, or `prohibited`.
- Restrict the default batch action to reversible `safe` fixes.
- Require separate, impact-specific confirmation for remote-access, authentication, sharing, power, and privacy changes.
- Detect remote sessions before offering fixes that could terminate access.

### 4. There is no rollback or transaction record

The application records that a command ran but does not capture the previous value, create a rollback plan, or distinguish partial batch completion.

Required change:

- Capture the old value and applicability before every reversible change.
- Persist a local transaction record containing requested, previous, applied, and verified states.
- Provide one-click rollback where macOS supports it.

### 5. Swift and Go implementations have already drifted

Checks and fixes are duplicated between the Swift app and Go CLI. For example, the Swift root-account remediation changes the root shell, while the CLI uses `dsenableroot -d`. Other check and remediation lists also differ.

Required change:

- Move rule metadata and platform support to a shared, versioned data model.
- Generate or share fixtures for both engines.
- Define one canonical remediation operation per rule.

### 6. No executable automated tests exist

The repository contains an Xcode test plan but no Swift test target with tests, and `go test ./...` reports no test files. CI builds and vets the code but cannot detect incorrect checks, destructive command changes, parsing regressions, or Swift/Go drift.

Required change:

- Add unit tests for every rule using command-output fixtures.
- Add contract tests for remediation classification and argument validation.
- Add snapshot tests for reports.
- Add integration tests in disposable macOS virtual machines before enabling any privileged fix.

## High-priority findings

### 7. Timed-out Swift checks continue running

`ScanManager` marks a module timed out after 15 seconds, but the underlying work is not cancelled. It may later mutate the same finding while the UI and logger are reading it.

Required change:

- Use structured concurrency with cancellation-aware check implementations.
- Make check results immutable values rather than mutable module instances.

### 8. Audit logs can contain sensitive, unescaped evidence

The logger writes raw check status text, fix commands, paths, and administrator errors to a per-day file without redaction or an explicitly restrictive creation mode. Embedded newlines and quotes can also corrupt the line-oriented format.

Required change:

- Store structured JSON Lines or SQLite records.
- Redact usernames, home paths, tokens, URLs, certificate details, and command output by default.
- Create files with mode `0600` and define retention controls.
- Do not log commands containing dynamic or sensitive arguments.

### 9. The current model conflates compliance with vulnerability risk

Every failed benchmark setting is represented as a `Vulnerability`, and percentage scoring weights low-impact preferences similarly to material exploitable exposure. This can produce alarm fatigue and misleading security claims.

Required change:

- Separate configuration findings, software vulnerabilities, exposure, malware/persistence observations, and resilience findings.
- Score with severity, exploit evidence, exposure, confidence, and remediation availability.
- Display “unknown” separately from pass or fail.

### 10. The app is unsandboxed and currently has no declared entitlements

Direct-distribution security tools may legitimately be unsandboxed, but the resulting access needs an explicit threat model. The future privileged helper must not trust the GUI merely because it has the expected bundle identifier.

Required change:

- Document why sandboxing is unavailable for each check.
- Authenticate XPC clients using code-signing requirements and audit tokens.
- Keep the helper API minimal and deny unknown operations by default.

## Product gap confirmed by the review

Mergen covers configuration compliance and remediation but intentionally makes no network calls. It has no live Apple, CISA KEV, Chrome, OSV, or vendor advisory ingestion; no installed-application CVE matching; and limited persistence or exposure analysis.

The fork should therefore focus on integration rather than recreating the existing GUI:

1. Harden remediation and add tests.
2. Add a versioned, multi-macOS rule model based primarily on NIST mSCP-compatible identifiers and attribution.
3. Add local software inventory and normalized package identifiers.
4. Add signed advisory-feed ingestion with provenance and freshness metadata.
5. Add exposure-aware matching and confidence levels.
6. Add persistence and listening-service inspection.
7. Add scheduled read-only scans and notifications.
8. Enable only reviewed, reversible remediations by default.

## Proposed first milestone

The first milestone must remain read-only:

- Establish test targets and fixtures.
- Introduce immutable `Finding`, `Evidence`, and `CheckResult` models.
- Add macOS version/build, pending updates, browser versions, listening services, and package inventory.
- Add CISA KEV and OSV clients behind explicit network/privacy controls.
- Generate a report that distinguishes confirmed, probable, possible, configuration, and informational findings.

Privileged remediation should resume only after the typed XPC helper and transaction model have passed integration review.
