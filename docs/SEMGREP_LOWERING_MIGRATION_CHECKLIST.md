# Semgrep Lowering Migration Checklist

Objective: move the lowered-bundle workflow into `phparser` so the active runtime path no longer depends on `run_semgrep_php_lowered_bundle.py` or `php-lowering/lower_methods_bundle.php`.

Current status:

- [x] Native Go parser metadata and reduce-action generation are checked in and used at runtime.
- [x] Native Go tree scan exists at `cmd/parse-tree`.
- [x] Real vulnerable plugin trees parse successfully with the Go scanner.
- [x] Native Go scan orchestration command exists for the Semgrep wrapper workflow.
- [ ] Native Go lowered-bundle builder exists.
  - [x] Basic function and lowered-method bundle emission exists at `cmd/lower-bundle`.
  - [x] Native lowered mapping emission exists for those fragments.
  - [ ] Storage, object, flow, and hook bridge planning are still pending.
- [ ] Existing hunt workflow is switched from the Python/PHP scripts to the Go path.

## Phase 1: Parser Frontend

- [x] Export parseable-file manifests from Go.
- [x] Export parseable-file lists from Go for downstream tools.
- [x] Validate the Go parser against real CVE plugin trees:
  - [x] `hide-my-wp__5.4.01`
  - [x] `forminator__1.44.2`
  - [x] `post-smtp__3.6.0`
  - [x] `acf-extended__0.9.1.1`

## Phase 2: Wrapper Port

- [x] Add a Go command under `cmd/` that replaces the target-scan part of `run_semgrep_php_lowered_bundle.py`.
- [ ] Preserve existing output artifacts:
  - [x] `README.md`
  - [x] `human-summary.md`
  - [x] `semgrep-target-raw.json`
  - [x] `semgrep-target.txt`
  - [x] `semgrep-target-console.txt`
  - [x] `semgrep-results.json`
- [ ] Preserve current config filtering behavior for lowered-capable taint rules.
- [x] Preserve existing exclude-dir behavior.
- [x] Validate the new Go target wrapper on real plugin trees:
  - [x] `hide-my-wp__5.4.01`
  - [x] `post-smtp__3.6.0`

## Phase 3: Lowerer Port

- [x] Port PHP file collection, class discovery, and method map building into Go.
- [ ] Port bridge expression parsing and bridge emission into Go.
- [ ] Port storage, object, flow, and hook bridge planning into Go.
- [x] Port lowered mapping emission into Go.
- [ ] Preserve current bridge-only vs full-lowered bundle modes.

## Phase 4: Workflow Switch

- [ ] Add a Go-native replacement for `run_semgrep_php_lowered_bundle.py`.
- [ ] Stop depending on `php-lowering/lower_methods_bundle.php` in the default path.
- [ ] Stop depending on Python in the default lowered-bundle path.
- [ ] Validate the Go-native path on CVE corpus cases.

## Exit Criteria

- [ ] The default repo workflow no longer executes `run_semgrep_php_lowered_bundle.py`.
- [ ] The default repo workflow no longer executes `php-lowering/lower_methods_bundle.php`.
- [ ] The Go-native path still finds the real sinks for the confirmed CVE regression cases.
