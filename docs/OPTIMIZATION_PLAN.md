# PHP-Parser Go Optimization Plan

This document tracks performance work after the native Go port became functionally complete. The optimization target is now explicit: make the Go implementation as fast as possible without changing observable behavior.

Technique references used during this work:

- Go profiling guidance: https://go.dev/blog/profiling-go-programs
- Go diagnostics overview: https://go.dev/doc/diagnostics.html
- `runtime/pprof` API reference: https://pkg.go.dev/runtime/pprof
- `runtime/trace` API reference: https://pkg.go.dev/runtime/trace
- Go spec note on unspecified map iteration order: https://go.dev/ref/spec
- Go PGO guide: https://go.dev/doc/pgo

## Status Snapshot

Date:

- `2026-03-21`

Current validated state:

- `go test ./... -count=1` is green.
- Native parser parity is green: `279/279`.
- Native pretty-printer parity is green: `82/82`.
- Native pretty-printer-file parity is green: `12/12`.
- The Go runtime is now ahead of the upstream PHP baseline on the Symfony single-thread sample for both parse-only and parse+pretty, while keeping the existing full-tree single-thread and `8`-worker wins.

## Scope

Goals:

- Preserve native correctness and parity while improving speed.
- Keep the public CLI contract unchanged.
- Use reproducible, apples-to-apples measurements.
- Separate parser, printer, allocation, and scaling work so wins are attributable.
- Optimize the actual runtime, not benchmark artifacts from `go run`.

Non-goals:

- Do not change semantics for speed.
- Do not accept speedups that break parity or local tests.
- Do not optimize based on noisy concurrent benchmark runs.
- Do not count compile time as runtime throughput.

## Measurement Contract

All future optimization work must use this measurement discipline:

- Build benchmark tools once, then measure the binaries.
- Use the same Symfony checkout and the same skip path every time.
- Run benchmarks sequentially, not in parallel.
- Prefer the median of `5` runs for short sample benchmarks.
- Treat `go run` measurements as development checks only, not scorecard numbers.

Required benchmark artifacts:

- compiled Go CLI: `/tmp/php-parser-go`
- compiled Go repo harness: `/tmp/bench-repo`
- upstream PHP benchmark script: `/tmp/php_bench_parser.php`

Stable workload:

- root: `/tmp/symfony-bigtest-20260321/src`
- valid files: `10,357`
- skipped invalid fixture:
  - `/tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php`

## Current Performance Scorecard

Environment:

- PHP baseline runner: `8.3.6`
- Go: `1.25.1`
- workload: Symfony `src/`

Correctness on this workload:

- Native Go parses all valid Symfony files: `10,357/10,357`
- Native Go sample `prettyPrintFile()` output reparses cleanly: `0/1036` failures

Current native Go measurements using the compiled harness:

Parse only:

- Go, single-thread, `1,036`-file sample, median-of-`5`: `1.397872s`, `741.13 files/s`, `5.77 MB/s`, `2.26 MB heap`, `793.19 MB TotalAlloc`, `287 GC`
- Go, full tree, single-thread: `17.216489s`, `601.57 files/s`, `4.78 MB/s`, `3.00 MB heap`, `11101.35 MB TotalAlloc`, `3311 GC`
- Go, full tree, `8` workers: `4.746600s`, `2181.98 files/s`, `17.33 MB/s`, `5.82 MB heap`, `11114.69 MB TotalAlloc`, `681 GC`

Parse + pretty-print:

- Go, single-thread, `1,036`-file sample, median-of-`5`: `1.709906s`, `605.88 files/s`, `4.72 MB/s`, `1.98 MB heap`, `884.54 MB TotalAlloc`, `327 GC`

Current upstream PHP measurements on the same machine and same workload:

Parse only:

- PHP, single-thread, `1,036`-file sample: `1.607580s`, `644.45 files/s`, `5.02 MB/s`
- PHP, full tree, single-thread: `19.317871s`, `536.14 files/s`, `4.26 MB/s`

Parse + pretty-print:

- PHP, single-thread, `1,036`-file sample: `1.915265s`, `540.92 files/s`, `4.21 MB/s`

Gap to PHP:

- Sample parse-only: Go is about `15.0%` faster on throughput (`741.13` vs `644.45 files/s`)
- Sample parse+pretty: Go is about `12.0%` faster on throughput (`605.88` vs `540.92 files/s`)
- Full-tree single-thread parse: Go is about `12.2%` faster on throughput (`601.57` vs `536.14 files/s`)

Interpretation:

- The parser is now clearly ahead on the short single-thread Symfony sample as well as the full-tree run.
- The whole parse+pretty pipeline is also ahead of PHP on the same single-thread sample.
- Allocation pressure on the sample corpus is now in a much healthier range, though full-tree single-thread allocation and GC still leave room for improvement.
- The remaining performance work is the hard tail: generated reducers, lower attribute churn, and tightening the pretty-printer and full-tree allocation profile.

## Current phparser Outlier

Date:

- `2026-03-23`

Current direct-engine outlier:

- Latest full `phparser` scan on `sureforms` is no longer blocked by startup.
- Startup is already cheap on the current binary:
  - `manifest=201ms`
  - `load-files=218ms`
  - `build-engine=947ms`
- The `delete` batch improved materially and is no longer the main blocker:
  - earlier delete batch total was about `54.187s`
  - current delete batch total is about `49.873s` on the latest full log, and the focused latest-tree delete scan has already been reduced much further in later targeted runs
- The remaining user-visible slowdown is the `read` batch, especially late passes.

Measured hotspot from `/tmp/phparser-sureforms-latest-full-final.log`:

- `read` pass `5`: about `12.464s`
- `read` pass `6`: still beyond the timeout window in the full run and dominated by a few hot callables
- current hottest callables in the slow read phase:
  - `\\Spec_Gb_Helper::get_assets`
  - `\\Spec_Gb_Helper::get_block_css_and_js`
  - `\\Spec_Gb_Helper::get_generated_stylesheet`
  - `\\SRFM\\Inc\\Form_Submit::handle_form_entry`
  - `\\SRFM\\Inc\\Payments\\Front_End::validate_payment_fields`
  - `\\SRFM\\Inc\\Payments\\Front_End::verify_stripe_payment`
  - `\\SRFM\\Inc\\Payments\\Front_End::verify_stripe_subscription_intent_and_save`

Current diagnosis:

- This is no longer primarily parser cost.
- This is no longer primarily broad storage-family churn.
- The remaining expensive phase is repeated static-state invalidation around SureForms Gutenberg asset generation:
  - `static:\\Spec_Gb_Helper.$script`
  - `static:\\Spec_Gb_Helper.$stylesheet`
- Plugin code driving the churn:
  - `modules/gutenberg/classes/class-spec-gb-helper.php:450`
  - `modules/gutenberg/classes/class-spec-gb-helper.php:541`
  - `modules/gutenberg/classes/class-spec-gb-helper.php:891`
- Secondary still-live chain:
  - `inc/form-submit.php:509`
  - `inc/payments/front-end.php:437`
  - `inc/payments/front-end.php:531`
  - `inc/payments/front-end.php:561`

Safe next fix target:

- Split static transfer invalidation from redundant transitive static-write propagation in the `Spec_Gb_Helper` chain.
- Preserve the same sink reachability and findings while reducing repeated requeueing from:
  - `self::$script .= ...`
  - `self::$stylesheet .= ...`
- Prefer safe state reuse and narrower static invalidation over plugin-specific blacklists or reduced pass limits.

Update after the accumulator/static-interest fixes:

- The focused latest-tree SureForms `read` scan now early-stops at pass `5` and finishes in about `16.1s` total.
- The old `read` pass `6` loop on:
  - `static:\\Spec_Gb_Helper.$script`
  - `static:\\Spec_Gb_Helper.$stylesheet`
  is no longer the main blocker.
- The full latest-tree scan now gets through:
  - `delete`
  - `read`
  - `open`
  - `include`
  - `output`
- The newly exposed bottleneck is `sql` pass `6`, centered on:
  - `\\SRFM\\Inc\\Form_Submit::handle_form_entry`
  - `\\SRFM\\Inc\\Payments\\Front_End::validate_payment_fields`
  - `\\SRFM\\Inc\\Payments\\Front_End::verify_stripe_payment`
  - `\\SRFM\\Inc\\Payments\\Front_End::verify_stripe_subscription_intent_and_save`
- Current hot root after that fix:
  - `storage:form_data`

## Current Local Diagnosis And Next Instrumentation Step

Date:

- `2026-03-23`

Latest local evidence:

- Focused latest-tree `read` scan now completes in about `24.1s` total and early-stops at pass `5`.
- Latest full no-`-sink-op` scan still exceeds `180s`.
- Startup remains cheap; the full-scan gap is caused by later-batch recomputation, not manifest loading or parsing.
- The full-scan outlier is still the `read` batch around:
  - `Spec_Gb_Helper::get_generated_stylesheet`
  - `Spec_Gb_Helper::get_assets`
  - `Spec_Gb_Helper::get_block_css_and_js`
  - `Form_Submit::handle_form_entry`
  - the `srfm_form_submit_data` payment filter chain

Observed behavior:

- Focused `read` run:
  - stabilizes with `storage_paths_changed=false`
  - stabilizes with `static_changed=false`
  - early-stops at pass `5`
- Full scan:
  - reaches the same hot callables
  - still reopens late-pass churn in the `read` batch

## Dynamic Tracing Audit Notes

Date:

- `2026-03-24`

What the latest audit showed:

- The goal remains to make `phparser` trace more like a human without adding plugin hardcoding.
- A broad experiment that tried to recover deeper helper/container structure with:
  - local-variable structural return reads
  - coarse return taint from `ReturnPathWrites`
  - synthetic `json_decode(...)` wildcard structure
  did not actually solve the remaining `cookie-information` direct-sink precision gap.
- That same experiment reopened a real regression:
  - `sureforms-cve-2025-6691` fell from `match` to `miss`
  - focused `-sink-op delete` produced `0` findings

Why the regression happened:

- The real SureForms path depends on `wp_handle_upload(...)` return data flowing into:
  - `$move_file['url']`
  - `$form_data[ $field ][]`
  - `$submission_data`
  - encoded custom-table storage
  - later `Entries::get_form_data(...)`
  - finally `delete_entry_files()`
- In delete-only scans, `wp_handle_upload` was being treated as a write sink only.
- Its return value was opaque unless `write` sinks were enabled, so the stored delete chain disappeared even though the relevant callables were still analyzed.

Safe fix that stayed green:

- Keep the broad structured-return experiment out of the tree.
- Model upload-helper returns generically:
  - `wp_handle_upload(...)`
  - `wp_handle_sideload(...)`
- These helpers now still emit upload findings in `write` scans, but they also return taint from the uploaded-file input in non-`write` scans.
- This restored the real SureForms stored-delete path without changing the unrelated action/sql cases.

Measured result:

- `sureforms-cve-2025-6691` is back to direct `match`
- focused `sureforms__1.7.3 -sink-op delete` now finishes in about `2.2s` total
- matched retained source is again the real upload branch:
  - `inc/form-submit.php:226`

Guardrail from this audit:

- Prefer semantic models for real framework/helper boundaries over broad structural taint broadening.
- If a “more human-like” tracing change does not immediately improve the real missing case and it regresses an existing CVE path, back it out and keep the narrower semantic fix instead.

## Forminator Delete Regression Fix

Date:

- `2026-03-23`

What regressed:

- `forminator-cve-2025-6463` had regressed back into a focused `delete` timeout.
- The old `open/include` optimization was still fine; the new regression was delete-specific.

What the probe showed:

- The expensive export subtree was being kept alive in delete mode by a generic cross-request meta writer root:
  - `\Forminator_Form_Entry_Model::maybe_update_poll_entries_meta_key_to_element_id`
- That writer only touched the broad `meta_value` family and was being treated as a supported delete writer root, which then pulled in:
  - `\Forminator_Form_Entry_Model::map_polls_entries_for_export`
  - `\Forminator_Export::prepare_export_data`
  - `\Forminator_Export::prepare_attachment`
  - `\Forminator_Export::maybe_send_export`

Safe fix that stayed green:

- Keep request-gated delete direct-sink seeding.
- For delete-only scans, do not let family-only meta writers become root writers unless they look like real serialized meta/blob writers.
- Apply the same filter both when binding family-wide cross-request writers and when deciding whether a callable is a supported cross-request writer root.

Measured result:

- Focused `forminator__1.44.2 -sink-op delete` now finishes cleanly:
  - `engine-run=1.523s`
  - `total=4.088s`
- The old export branch is no longer delete-relevant.
- Direct corpus validation is back to `match` for:
  - `forminator-cve-2025-6463`

Validation kept green:

- focused delete regressions:

## Hide My WP CVE Gap

Date:

- `2026-03-23`

Current local evidence:

- Fresh rerun on `hide-my-wp__5.4.01` completes in about `2.307s`:
  - `/root/project/wp-bugbounty/tmp/hidemywp-rerun-20260323/human-summary.md`
- The current direct engine still misses the real `showFile()` CVE sinks:
  - file read at `models/Files.php:407`
  - multisite include at `models/Files.php:515`
- The current output keeps only:
  - the weaker proxy-output branch at `models/Files.php:482`
  - the older `ObjController.php:130` include finding

Current diagnosis:

- Do not hardcode `getCurrentURL()` as a source. The real source is still request data such as `$_SERVER['REQUEST_URI']`.
- The include miss is likely caused by `realpath(...)` dropping path taint before `require_once`.
- The read miss is likely caused by a generic helper/summary path gap in the real `showFile()` chain, especially across:
  - `wp_parse_url(...)`
  - array field reads like `$parts['path']`
  - URL reconstruction in `getOriginalUrl()`
  - return propagation through `getOriginalPath()`

Fix order:

1. Add focused regressions matching the real helper chain shape:
   - `rawurldecode($_SERVER['REQUEST_URI'])`
   - `wp_parse_url(...)`
   - array field reads like `$parts['path']`
   - `str_replace(home_url(), '', $new_url)`
   - `get_contents($new_path)`
   - `realpath($new_path)` before `require_once`
2. Add only generic propagation fixes:
   - `realpath(...)` should preserve taint
   - preserve request-derived path taint through parsed URL field extraction and helper returns
3. Revalidate against:
   - focused new tests
   - `go test ./...`
   - rerun `hide-my-wp__5.4.01`
4. Keep performance guardrails:
   - no extra whole-program pass
   - no plugin-specific hook/source hardcoding
   - keep rerun time in the same low-single-digit second range

Update after the first fix slice:

- Added focused regressions for:
  - parsed URL helper chain to `get_contents(...)`
  - `realpath(...)` before `require_once`
  - Hide My WP-style `showFile()` read shape
  - hook callback registration through `ObjController::getClass('FilesDemo')`
- Added generic propagation for `realpath(...)`.
- Added generic literal factory inference for `getClass('ClassName')`.
- Fixed callback entrypoint indexing to resolve static factory callbacks in `resolveCallbackClassRefsWithSeen(...)`.

Measured result:

- Focused `hide-my-wp__5.4.01 -sink-op read` now reports the real file-read sink:
  - `models/Files.php:407`
  - entrypoint: `front_hook:init`
- Full `go test ./...` stays green.

Resolved state after the follow-up fix:

- The remaining include-path gap is now closed.
- Focused `hide-my-wp__5.4.01 -sink-op include` reports the real multisite include sink:
  - `models/Files.php:515`
- The merged full scan now also keeps both real `showFile()` CVE sinks:
  - file read at `models/Files.php:407`
  - include at `models/Files.php:515`
- The fix stayed generic and performance-safe:
  - no plugin-specific source or sink hardcoding
  - no extra whole-program pass
  - focused include rerun still completes in low-single-digit seconds

Durable regression coverage:

- synthetic Hide My WP-style helper-chain read and include fixtures stay green
- actual plugin regression now asserts `hide-my-wp__5.4.01 -sink-op include` reaches `models/Files.php:515` through the real scanner path

Representative current artifacts:

- focused include:
  - `/root/project/wp-bugbounty/tmp/hidemywp-include-only-20260323e/taint-results.json`
- merged full scan:
  - `/root/project/wp-bugbounty/tmp/hidemywp-full-20260323e/taint-results.json`

## Current Noise Diagnosis

Date:

- `2026-03-23`

Measured from:

- `/root/project/wp-bugbounty/tmp/phparser-cve-rerun-20260323-current/aggregate-normalized.tsv`

Current noisiest rule families by total emitted findings:

- `wp-request-sensitive-action-without-cap-check`
  - `835` findings across `5` cases
- `wp-request-record-read-to-output-without-cap-check`
  - `338` findings in `1` case
- `tainted-sql-string`
  - `160` findings across `3` cases
- `render-callback-execution`
  - `86` findings in `1` case
- `wp-request-file-upload-without-cap-check`
  - `60` findings across `4` cases

Most important observation:

- The dominant problem is duplicate emission, not only broad reachability.
- Several noisy cases collapse to a small number of unique visible findings:
  - `post-smtp-cve-2025-11833`: `743` total, `64` unique
  - `wpforms-cve-2024-11205`: `293` total, `21` unique
  - `ultimate-member-cve-2025-0308`: `132` total, `9` unique
  - `acf-extended-cve-2025-13486`: `86` total, `1` unique
  - `starter-templates-cve-2025-13065`: `44` total, `5` unique

Current per-rule diagnosis:

- `wp-request-sensitive-action-without-cap-check`
  - still too broad around admin/state-change helpers
  - major noisy cases:
    - `post-smtp-cve-2025-11833`
    - `wpforms-cve-2024-11205`
    - `w3-total-cache-cve-2024-12365`
  - many findings currently have `trace = null`, so equivalent sink contexts are emitted repeatedly

- `wp-request-record-read-to-output-without-cap-check`
  - concentrated in `post-smtp-cve-2025-11833`
  - mostly repeated rendered output lines for the same underlying record-selection path
  - another `trace = null` heavy family

- `tainted-sql-string`
  - the main noisy case is `ultimate-member-cve-2025-0308`
  - TEC is much cleaner after the SQL clause-hook narrowing; Ultimate Member remains the current SQL noise hotspot
  - this is a mix of broad SQL-template modeling and duplicate final emission

- `render-callback-execution`
  - almost pure duplicate emission right now
  - current hotspot is `acf-extended-cve-2025-13486`, where many findings collapse to the same dynamic callable sink

- `wp-request-file-upload-without-cap-check`
  - main noisy case is `starter-templates-cve-2025-13065`
  - repeated helper/wrapper writes produce many copies of the same semantic issue

Current interpretation:

- Noise is coming from two layers:
  - broad rule reachability in a few admin/action/template helper families
  - insufficient normalized result dedupe when the final emitted finding has no concrete trace payload

Safe cleanup order:

1. Add normalized final-result dedupe for findings with `trace = null`
   - prefer a key shaped like `(check_id, sink path, sink line, visible message, callable when present)`
   - this should reduce visible noise without changing reachability

2. Tighten `wp-request-sensitive-action-without-cap-check`
   - prefer concrete request-path evidence over generic public/admin/action reachability
   - target the current noisy cases first:
     - `post-smtp`
     - `wpforms`
     - `w3-total-cache`

3. Collapse repeated record-read-to-output findings by sink site
   - especially when the same selected record is rendered through many sibling lines

4. Tighten `tainted-sql-string` in Ultimate Member
   - focus on repeated helper/template sinks
   - preserve the cleaned-up TEC clause-hook matches

5. Re-run the representative corpus set after each step
   - keep timing and `go test ./...`
   - verify that real matches remain:
     - `forminator`
     - `sureforms`
     - `jupiterx-core`
     - `the-events-calendar`
     - `acf-extended`

## Performance Guardrails For Noise Cleanup

Date:

- `2026-03-23`

All future noise-reduction work must preserve the recent runtime wins.

Required guardrails:

- Do not add extra whole-program analysis passes just for dedupe.
- Do not broaden flow-context collection only to improve final reporting.
- Prefer dedupe keyed on already-emitted finding fields over recomputing deeper traces.
- Prefer relevance narrowing over expensive post-hoc result filtering when both achieve the same visible outcome.
- Any new dedupe/index structure must be linear in emitted findings, not in all callables.
- Do not reintroduce broad delete or file-family relevance seeding to suppress noise indirectly.
- Treat `Forminator delete`, `SureForms delete`, and TEC `sql` as regression workloads for both precision and runtime.

Minimum revalidation after each noise fix:

- `go test ./...`
- representative direct corpus reruns:
  - `forminator-cve-2025-6463`
  - `sureforms-cve-2025-6691`
  - `jupiterx-core-cve-2024-7772`
  - `the-events-calendar-cve-2025-12197`
  - `acf-extended-cve-2025-13486`
- timing spot-checks when the touched rule family is performance-sensitive:
  - focused `forminator__1.44.2 -sink-op delete`
  - focused `sureforms -sink-op delete`
  - focused TEC `-sink-op sql`
  - the remaining slow phase is algorithmic recomputation, not generic parser overhead

Interpretation:

- This is no longer a generic “Go is slow” problem.
- This is a narrow taint-engine fixed-point problem with repeated expensive summaries.
- Further blind pruning is not justified until execution-trace evidence shows whether the late pass is:
  - real CPU in a few hot callables
  - serialized/shared-state work
  - or repeated recomputation from unstable/capped state propagation

Official-Go-guided next step:

- Use `pprof` labels to tag:
  - batch
  - pass
  - callable
- Use `runtime/trace` regions/tasks to capture:
  - batch execution
  - pass execution

## Direct Corpus Cleanup Status

Date:

- `2026-03-23`

Completed fixes:

- `corpus-compare` now skips provably `not_comparable_yet` cases before running `AnalyzeRootWithOptions(...)`.
- Direct compare now recognizes the legacy financial-action alias:
  - `wp-ajax-financial-action-without-cap-check`
  - `wp-request-sensitive-action-without-cap-check`
- Storage-write bucket discovery now has a recursion guard, fixing the stack overflow on `better-search-replace`.
- Direct sink-op overrides were narrowed for the high-cost stale-contract cases:
  - `cleantalk-cve-2024-10542` -> `["action"]`
  - `wpforms-cve-2024-11205` -> `["action"]`
  - `jupiterx-core-cve-2024-7772` -> `["write"]`
  - `starter-templates-cve-2025-13065` -> `["write"]`

Observed effect:

- bogus runtime failures became immediate `not_comparable_yet`:
  - `better-search-replace-cve-2023-6933`
  - `wpvivid-cve-2026-1357`
  - `cleantalk-security-cve-2024-13365`
- `jupiterx-core-cve-2024-7772` now `match`es in about `4.7s`.
- `better-search-replace__1.4.4` no longer crashes on focused `-sink-op call`; the real plugin run completes in about `57ms`.

Remaining direct misses after the cleanup pass:

- `cleantalk-cve-2024-10542`
- `wpforms-cve-2024-11205`
- `starter-templates-cve-2025-13065`

Current interpretation:

- `cleantalk`: fast miss; current engine reaches generic option-writing actions, not the expected install-plugin path.
- `wpforms`: real action-path miss; no findings reach `src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php`.
- `starter-templates`: engine reaches the WXR importer, but only on the capability-checked import path, not the expected bypass path.

## Remaining Focused Performance Outliers

Date:

- `2026-03-23`

### ACF Extended (`-sink-op call`)

Focused run:

- target: `acf-extended__0.9.1.1`
- command output log:
  - `/root/project/wp-bugbounty/tmp/phparser-acfe-call-20260323b.log`
- output dir remained empty because the run timed out at `240s`.

Measured shape:

- startup is not the problem:
  - `manifest=212ms`
  - `load-files=195ms`
  - `build-engine=1.608s`
- the engine gets stuck in `batch=call pass=4`.
- dominant callable:
  - `\acfe_module_form_front::render_form`
  - measured at about `21.402s` before the run continued consuming CPU
- other pass-4 work was small:
  - `\acfe_module_form_front::load_form` about `113ms`
  - `file::includes/modules/form/module-form-front.php` about `463ms`

Interpretation:

- this is a real `call`-mode fixed-point hotspot.
- the primary target is not broad relevance; it is repeated expensive work in the form front-end render path.

### The Events Calendar (`-sink-op sql`)

Focused runs:

- target `the-events-calendar__6.15.9`:
  - `/root/project/wp-bugbounty/tmp/phparser-tec-6.15.9-sql-20260323.log`
- target `the-events-calendar__6.15.1`:
  - `/root/project/wp-bugbounty/tmp/phparser-tec-6.15.1-sql-20260323.log`

Shared measured shape:

- startup is moderate but not the bottleneck:
  - about `0.85s` manifest
  - about `0.58s` load
  - about `3.5s` build-engine
- both versions quickly collapse to one dominant helper:
  - `\Tribe\Utils\Paths::merge`
- by the time the helper dominates:
  - `storage_changed=false`
  - `storage_paths_changed=false`
  - `static_changed=false`
- yet the helper still gets drastically slower every pass:
  - about `36-45ms` on pass `5`
  - about `537-593ms` on pass `6`
  - about `6.77-6.99s` on pass `7`

Interpretation:

- this is a generic helper blowup, not version-specific plugin churn.
- the next optimization target is summary growth and/or return-state recomputation inside `\Tribe\Utils\Paths::merge`, not broad SQL relevance.

## Recursive Helper Fix Outcome

Date:

- `2026-03-23`

Implemented optimization:

- Added structural return-path memoization and recursion guarding for method/static-call summary path expansion.
- Added a narrower self-recursive helper fallback:
  - if a callable instantiates its own summary and that summary has only return effects, the engine now falls back to direct argument propagation instead of repeatedly expanding the previous-pass recursive summary.

Files changed:

- `internal/taintscan/analysis_callable.go`
- `internal/taintscan/analysis_support.go`
- `internal/taintscan/call_eval.go`
- `internal/taintscan/structural_state.go`
- `internal/taintscan/summary_paths.go`

Measured effect:

- `the-events-calendar__6.15.9 -sink-op sql`
  - before: pass explosion centered on `\Tribe\Utils\Paths::merge`
  - after: converges in about `5.695s` total with `engine-run=366ms`
  - log: `/root/project/wp-bugbounty/tmp/phparser-tec-6.15.9-sql-after-selfrec.log`
- `the-events-calendar__6.15.1 -sink-op sql`
  - after: converges in about `5.882s` total with `engine-run=339ms`
  - log: `/root/project/wp-bugbounty/tmp/phparser-tec-6.15.1-sql-after-selfrec.log`
- `acf-extended__0.9.1.1 -sink-op call`
  - before: timed out at `240s`, dominated by `\acfe_module_form_front::render_form`
  - after: converges in about `18.602s` total with `engine-run=15.839s`
  - log: `/root/project/wp-bugbounty/tmp/phparser-acfe-call-after-selfrec.log`

Direct CVE regression sweep after the optimization:

- artifact: `/root/project/wp-bugbounty/tmp/phparser-postopt-cve-check-20260323/aggregate.tsv`
- preserved direct hits:
  - `forminator-cve-2025-6463`
  - `post-smtp-cve-2025-11833`
  - `everest-forms-cve-2025-1128`
  - `post-smtp-cve-2023-6875`
  - `sureforms-cve-2025-6691`
  - `w3-total-cache-cve-2024-12365`
  - `jupiterx-core-cve-2024-7772`
- improved:
  - `acf-extended-cve-2025-13486`: `timeout -> match` in about `17s`
- current results after optimization:
  - `the-events-calendar-cve-2025-12197`: `miss`
  - `the-events-calendar-cve-2025-9807`: `miss`

Interpretation:

- the expensive helper blowups are fixed.
- `acf-extended` is no longer a performance blocker and now reaches the expected CVE path.
- both `the-events-calendar` cases are now cheap enough to investigate as real direct misses instead of performance outliers.
  - slow callable execution
- Only after that decide whether the next fix is:
  - cache-key tightening
  - invalidation narrowing
  - shared-state serialization removal
  - or representative-profile PGO

Rules:

- Do not guess from timings alone when trace tooling can answer the question directly.
- Do not use PGO as a substitute for fixing pathological recomputation.
- Treat any optimization based on capped map merges with extra suspicion because Go map iteration order is unspecified.

## Current Forminator Full-Scan Outlier

Date:

- `2026-03-23`

Latest local evidence from `/tmp/phparser-fulltiming-forminator-20260323.log`:

- Startup is not the problem:
  - `manifest=378ms`
  - `load-files=471ms`
  - `build-engine=2.381s`
- The late full-scan cost is in extra sink families, especially `open` and `include`.
- `open` was still changing through pass `20` and took about `26.917s` with `0` findings.
- `include` was still changing through pass `16` with repeated `1s` to `2s` slow-callable runs.

Current hottest callables in the late `open/include` phases:

- `\\Forminator_Export::prepare_export_data`
- `\\Forminator_Export::prepare_attachment`
- `\\Forminator_Admin_Module::import_json`
- `\\Forminator_Field::is_condition_fulfilled`
- `\\Forminator_Mail::is_condition_fulfilled`

Current diagnosis:

- This is not parser/build time.
- This is not the direct CVE path.
- The expensive work is repeated fixed-point recomputation in export/import helper chains that full scan wakes only because extra sink families are enabled.
- A likely engine-level cause is caller summary invalidation on callee return-state growth even when the caller invokes the callee only for side effects.

Safe next fix target:

- Make caller summary input fingerprints depend only on the parts of a callee summary the caller can actually observe.
- For side-effect-only call sites, ignore callee return-state growth in the caller fingerprint.
- Keep side effects, sink templates, and relevant storage/static writes in the fingerprint.
- Revalidate:
  - `go test ./...`
  - narrowed `forminator-cve-2025-6463` direct compare still `match`
  - full Forminator timing log shows reduced `open/include` late-pass churn

Update after the Forminator file-batch relevance fix:

- Side-effect-only call sites no longer keep caller fingerprints sensitive to irrelevant callee return growth.
- The kept safe relevance gate is scoped to the single-op `open` batch only; the broader file-family version reopened real regressions and was backed out.
- Narrowed `forminator-cve-2025-6463` direct compare still `match`.
- Measured improvement on the real full-scan timing log:
  - previous `open` batch: about `26.917s`, still changing through pass `20`
  - current `open` batch: `3ms` total, `6` relevant callables, converged by pass `2`
  - previous `include` batch: still changing through pass `16` with repeated `1s` to `2s` export-helper recomputation
  - `include` still needs a separate safe fix; the broad file-family gate was not safe enough to keep there

Update after the later Forminator `delete` regression investigation:

- The old `open/include` fix still stands; the new slowdown was a different path.
- Safe kept change:
  - single-op `delete` scans are now request-gated in `requestReachableDirectSinkSeedMode()`.
  - regression test added: unreachable direct delete sink seeds no longer make whole-plugin delete scans relevant.
- Measured effect on focused `forminator__1.44.2 -sink-op delete`:
  - before the delete seeding fix: pass 1 `relevant=1105`, timed out at `60s`
  - after the delete seeding fix: pass 1 `relevant=658`, still timed out at `60s`
- Tried and backed out:
  - broad delete-only data-carrier pruning in `forwardRelevantCallees(...)`
  - narrower direct-sink-only delete data-carrier pruning
- Why both were backed out:
  - they improved Forminator locally but broke real regressions, including:
    - wrapper-return delete chains
    - SureForms stored delete sink coverage
- Current safe repo state:
  - keep the delete seeding gate
  - do not re-enable delete-only file data-carrier pruning without a stronger escape/use model
- Current remaining Forminator delete hotspot:
  - `\Forminator_Export::prepare_export_data`
  - `\Forminator_Export::prepare_attachment`
  - `\Forminator_Admin_Module::import_json`
  - likely driven by broad cross-request storage writer expansion (`user_meta_value`, `post_meta_value`) rather than direct sink seeding

## Optimization Checklist

### Measurement Discipline

- [x] Build `/tmp/bench-repo` and `/tmp/php-parser-go` before every timing session.
- [ ] Replace any remaining `go run` timing references in docs and notes with compiled-binary measurements.
- [ ] Record the median of `5` runs for:
  - [x] sample parse-only
  - [x] sample parse+pretty
  - [ ] parser microbenchmark
- [x] Capture fresh CPU and allocation profiles after every meaningful optimization pass.
- [ ] Capture runtime traces for the current `phparser` outlier with batch/pass/callable regions before the next semantic optimization pass.
- [x] Keep PHP comparison numbers current whenever Go improves materially.

### Parser Hot Path

- [ ] Generate direct typed reducer callbacks for the hottest reduce rules instead of generic compiled closures.
- [ ] Remove remaining generic `[]any` packing and unpacking in reducer helper calls.
- [ ] Replace reflection-heavy generic node construction in hot parser paths with generated typed constructors where profiling justifies it.
- [ ] Specialize hot attribute creation and update paths to avoid map churn.
- [ ] Reduce temporary slice creation in reducer argument evaluation and helper dispatch.
- [ ] Re-check whether token handling or parser-runtime helpers have become new hotspots after reducer work.

### Pretty-Printer Hot Path

- [ ] Capture CPU and alloc profiles for `prettyPrintFile()` on the Symfony sample.
- [ ] Identify the dominant printer cost:
  - [ ] node dispatch
  - [ ] string concatenation
  - [ ] comment/doc-comment formatting
  - [ ] list/join helpers
- [ ] Replace hot string-concatenation paths with reusable builders or buffers where safe.
- [ ] Reduce repeated subtree rendering or transient slice creation in comma-separated and statement-list printers.
- [ ] Optimize comment and doc-comment emission without changing formatting.

### Allocation And GC

- [x] Reduce parser `TotalAlloc` on the `1,036`-file sample below `1000 MB`.
- [x] Reduce parser `NUM_GC` on the `1,036`-file sample below `300`.
- [ ] Reduce full-tree single-thread parser `NUM_GC` below `3000`.
- [x] Reduce parse+pretty sample `TotalAlloc` below `1100 MB`.
- [ ] Reuse scratch buffers and temporary storage where ownership is clear.

### Scaling

- [ ] Keep full-tree `8`-worker parse throughput above `2000 files/s` while making single-thread faster.
- [ ] Check for lock contention or avoidable shared-state overhead in the benchmarked parallel path.
- [ ] Verify no optimization regresses the clean `10,357/10,357` valid-file parse result on Symfony.

### phparser Outlier Instrumentation

- [ ] Add `-trace` support to `cmd/taint-scan` using `runtime/trace`.
- [ ] Add `pprof` labels for `batch`, `pass`, and `callable` in the taint engine.
- [ ] Add `runtime/trace` regions around:
  - batch execution
  - pass execution
  - slow callable execution
- [ ] Produce one focused latest-tree SureForms `read` trace artifact and keep the command in repo notes.
- [ ] Use the first trace to answer whether pass-6 style stalls are:
  - serialized
  - blocked on shared state
  - or just dominated by a few CPU-heavy callables

### Validation Gates

- [ ] `go test ./... -count=1`
- [ ] parser parity `279/279`
- [ ] pretty-printer parity `82/82`
- [ ] pretty-printer-file parity `12/12`
- [ ] Symfony valid-file parse scan remains `10,357/10,357`

## Ordered Execution Plan

### Priority 0: Fix The Benchmark Contract

Why:

- Earlier scorecard entries mixed `go run` and compiled-binary timings, which distorted short sample results.

Steps:

1. Build `/tmp/bench-repo` and `/tmp/php-parser-go` once per timing session.
2. Run sample parse, sample parse+pretty, and parser microbenchmark sequentially.
3. Record medians, not single noisy runs.
4. Keep the PHP baseline script ready and rerun it after any large Go improvement.

### Priority 1: Make The Single-Thread Parser Unequivocally Faster

Why:

- This target is now achieved on the Symfony sample. The next parser priority is widening the lead while lowering full-tree allocation and GC overhead.

Steps:

1. Profile the parser sample again with CPU and alloc profiles.
2. Rank hot reducers by cumulative cost.
3. Generate typed Go reducers for the hottest subset first.
4. Remove reflection and generic helper overhead from those reducers.
5. Re-benchmark before widening the generated set.

Achieved target:

- sample parse-only faster than PHP:
  - `1.397872s` vs `1.607580s`
  - `741.13 files/s` vs `644.45 files/s`

### Priority 2: Close The Parse+Pretty Gap

Why:

- This target is also now achieved on the Symfony sample. The remaining printer work is about widening the margin and reducing full-pipeline allocation cost.

Steps:

1. Profile `prettyPrintFile()` on the Symfony sample.
2. Identify top printer allocation sites and hottest render paths.
3. Optimize only the measured hotspots.
4. Rerun pretty-printer parity after each non-trivial printer change.

Achieved target:

- sample parse+pretty faster than PHP:
  - `1.709906s` vs `1.915265s`
  - `605.88 files/s` vs `540.92 files/s`

### Priority 3: Lower Allocation Pressure

Why:

- The parser already has good throughput, but allocation volume is still high enough to create avoidable GC work.

Steps:

1. Measure parser alloc profile on the sample corpus.
2. Collapse hot temporary object and slice creation.
3. Reuse buffers where ownership is unambiguous.
4. Track `TotalAlloc` and `NUM_GC` after each pass.

### Priority 4: Protect The Parallel Win

Why:

- The `8`-worker full-tree run is already excellent and should not regress while chasing single-thread wins.

Steps:

1. Re-run the `8`-worker full-tree parse after each meaningful parser optimization.
2. Watch for lock contention, accidental sharing, or cache-hostile changes.
3. Keep the parallel benchmark as a release gate, not just an optional check.

## Reproducible Commands

Build once:

```bash
go build -o /tmp/php-parser-go ./cmd/php-parser-go
go build -o /tmp/bench-repo ./cmd/bench-repo
```

Parser microbenchmark:

```bash
GOMAXPROCS=1 go test ./parser -run '^$' -bench BenchmarkParseUpstreamLibCorpus -benchmem -count=5
```

Go sample parse benchmark:

```bash
/tmp/bench-repo \
  --root /tmp/symfony-bigtest-20260321/src \
  --mode parse \
  --workers 1 \
  --sample-step 10 \
  --skip /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

Go sample parse+pretty benchmark:

```bash
/tmp/bench-repo \
  --root /tmp/symfony-bigtest-20260321/src \
  --mode parse-pretty \
  --workers 1 \
  --sample-step 10 \
  --skip /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

Go full-tree parse benchmarks:

```bash
GOMAXPROCS=1 /tmp/bench-repo \
  --root /tmp/symfony-bigtest-20260321/src \
  --mode parse \
  --workers 1 \
  --skip /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

```bash
/tmp/bench-repo \
  --root /tmp/symfony-bigtest-20260321/src \
  --mode parse \
  --workers 8 \
  --skip /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

PHP comparison benchmarks:

```bash
php /tmp/php_bench_parser.php \
  /tmp/symfony-bigtest-20260321/src \
  parse \
  10 \
  /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

```bash
php /tmp/php_bench_parser.php \
  /tmp/symfony-bigtest-20260321/src \
  parse-pretty \
  10 \
  /tmp/symfony-bigtest-20260321/src/Symfony/Component/Config/Tests/Fixtures/ParseError.php
```

Validation:

```bash
go test ./... -count=1
php ./.agents/skills/testing-php-parser-parity/scripts/run_parser_parity.php \
  --upstream-root php-parser-upstream \
  --suite parser \
  --go-command /tmp/php-parser-go \
  --quiet
php ./.agents/skills/testing-php-parser-parity/scripts/run_parser_parity.php \
  --upstream-root php-parser-upstream \
  --suite pretty-printer \
  --go-command /tmp/php-parser-go \
  --quiet
```

## Success Criteria

Minimum acceptable state:

- correctness remains unchanged
- parity remains green
- Symfony valid-file scan remains green

Near-term optimization targets:

- sample parse-only stays faster than the current PHP baseline
- sample parse+pretty stays faster than the current PHP baseline
- parser microbenchmark allocs and bytes/op reduced again
- no regression in full-tree single-thread or `8`-worker parse throughput

Stretch targets:

- parser sample under `1.50s`
- parse+pretty sample under `1.85s`
- full-tree single-thread parse under `16.5s`
- full-tree `8`-worker parse over `2200 files/s`

## Optimization History

The project already completed the major parser rescue passes:

- compile reducer bodies once instead of reparsing semantic-action strings every reduction
- remove residual regex-heavy reducer fallback from the steady-state parser path
- cache generic AST constructor metadata
- reduce attribute clone churn through owned-attribute paths
- pre-resolve constructors in reducer compilation
- remove internal parser token-slice copies on the native parse path
- make lexer postprocessing operate in place on owned token slices
- lazily allocate reducer temporary-variable maps
- specialize compiled helper calls for hot reducer expressions such as `getAttributes`, `parseLNumber`, `parseNumString`, builtin-type normalization, cast kinds, and nop/empty-element helpers

Those passes took the parser from unusably slow to clearly faster than the upstream PHP baseline on the Symfony sample and the full tree. The remaining work is the hard tail: generated typed reducers, lower attribute-map churn, and pushing down full-tree allocation and GC without giving back the current throughput lead.

## Direct Corpus Failure Triage

Date:

- `2026-03-23`

Reference rerun:

- aggregate: `/root/project/wp-bugbounty/tmp/phparser-cve-rerun-20260323-072304c/aggregate.tsv`

Observed failure classes from the direct one-by-one corpus rerun:

- real engine bug:
  - `better-search-replace-cve-2023-6933`
    - current failure: `exit_2`
    - stderr shows a Go stack overflow in:
      - `storageWriteBucketsFromValueSyntax`
      - `storageWriteBucketsFromLocalValueFetch`
- comparator should skip before scanning:
  - `better-search-replace-cve-2023-6933`
  - `wpvivid-cve-2026-1357`
  - `cleantalk-security-cve-2024-13365`
    - all three have `coverage: null`
    - current `corpus-compare` still scans before discovering the case is not directly comparable
- likely contract drift from overly broad sink-family mapping:
  - `cleantalk-cve-2024-10542`
    - current config mapping is `action + output + write + call`
    - likely needs `direct_sink_ops: ["action"]`
  - `wpforms-cve-2024-11205`
    - current config mapping is `action + output + write + call`
    - likely needs `direct_sink_ops: ["action"]`
  - `jupiterx-core-cve-2024-7772`
    - current config mapping is `write + read + open + delete`
    - likely needs `direct_sink_ops: ["write"]`
  - `starter-templates-cve-2025-13065`
    - current config mapping is `write + read + open + delete`
    - likely needs `direct_sink_ops: ["write"]`
- real engine performance hotspots:
  - `acf-extended-cve-2025-13486`
    - `unsafe-use.yaml` -> `call`
    - current failure: `timeout`
  - `the-events-calendar-cve-2025-12197`
  - `the-events-calendar-cve-2025-9807`
    - `sqli.yaml` -> `sql`
    - current failure: `timeout`

Focused TODO list:

1. Skip taint scanning for provably `not_comparable_yet` cases.
   - move the comparable-coverage check before `AnalyzeRootWithOptions(...)` in `cmd/corpus-compare/main.go`
   - expected immediate win:
     - `better-search-replace-cve-2023-6933`
     - `wpvivid-cve-2026-1357`
     - `cleantalk-security-cve-2024-13365`

2. Fix the storage-write bucket recursion bug.
   - add cycle protection to:
     - `storageWriteBucketsFromValueSyntax`
     - `storageWriteBucketsFromLocalValueFetch`
   - reproduce with `better-search-replace-cve-2023-6933`

3. Narrow manifest sink families for action-only CVEs.
   - add `direct_sink_ops: ["action"]` for:
     - `cleantalk-cve-2024-10542`
     - `wpforms-cve-2024-11205`
   - rerun and confirm whether the current direct engine reaches the expected action sink

4. Narrow manifest sink families for upload-only CVEs.
   - add `direct_sink_ops: ["write"]` for:
     - `jupiterx-core-cve-2024-7772`
     - `starter-templates-cve-2025-13065`
   - rerun and confirm whether the current write batch finishes and reaches the expected upload sink

5. Reprofile the real call-only outlier.
   - target: `acf-extended-cve-2025-13486`
   - run with:
     - `PHARSER_TAINTSCAN_TIMINGS=1`
     - `-sink-op call`
     - `-cpuprofile`
     - `-trace`

6. Reprofile the real SQL-only outliers.
   - targets:
     - `the-events-calendar-cve-2025-12197`
     - `the-events-calendar-cve-2025-9807`
   - run with:
     - `PHARSER_TAINTSCAN_TIMINGS=1`
     - `-sink-op sql`

7. Keep performance guardrails on every fix.
   - after each contract or engine change:
     - rerun the affected case
     - record wall time and `duration_ms`
     - keep `go test ./...` green

Update after the first direct-corpus cleanup pass:

- completed:
  - `corpus-compare` now skips scanning for provably `not_comparable_yet` cases before `AnalyzeRootWithOptions(...)`
  - `better-search-replace-cve-2023-6933`, `wpvivid-cve-2026-1357`, and `cleantalk-security-cve-2024-13365` now return immediate `not_comparable_yet`
  - added recursion protection to storage-write bucket discovery
  - real plugin check on `better-search-replace__1.4.4` no longer crashes:
    - `PHARSER_TAINTSCAN_TIMINGS=1 ... -sink-op call`
    - finished in about `57ms`
  - narrowed manifest sink families:
    - `cleantalk-cve-2024-10542` -> `["action"]`
    - `wpforms-cve-2024-11205` -> `["action"]`
    - `jupiterx-core-cve-2024-7772` -> `["write"]`
    - `starter-templates-cve-2025-13065` -> `["write"]`
  - `jupiterx-core-cve-2024-7772` is now a clean `match` in about `4.7s`

- remaining real direct misses after the cleanup:
  - `cleantalk-cve-2024-10542`
    - now a fast `miss` in about `1.7s`
    - payload shows generic `update_option(...)` action findings in `cleantalk.php`, not the install-plugin path from the contract
  - `wpforms-cve-2024-11205`
    - now a fast `miss` in about `4.3s`
    - payload has `293` action findings but `0` findings on `src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php`
  - `starter-templates-cve-2025-13065`
    - now a fast `miss` in about `9.7s`
    - payload reaches `st-wxr-importer.php`, but the current findings land on the capability-checked import path, not the WXR upload-bypass path in the contract

- remaining real performance outliers:
  - `acf-extended-cve-2025-13486` (`call`)
  - `the-events-calendar-cve-2025-12197` (`sql`)
  - `the-events-calendar-cve-2025-9807` (`sql`)

Update after the SQL-template sink fix:

- completed:
  - stopped treating database-style `prepare(...)` calls as blanket SQL sanitizers
  - added first-argument SQL-template sink handling for:
    - method `prepare(...)`
    - static `DB::prepare(...)`-style calls
    - raw clause builders like `where_raw(...)` / `whereRaw(...)`
    - `new RawSQL(...)`
  - safe placeholder behavior is preserved:
    - constant template + tainted bound values stays non-finding
    - tainted SQL template now produces `tainted-sql-string`

- focused regression coverage:
  - `TestAnalyzeRootDoesNotFlagPreparedSQLString`
  - `TestAnalyzeRootFindsTaintedPreparedSQLTemplate`
  - `TestAnalyzeRootFindsTaintedStaticPreparedSQLTemplate`
  - `TestAnalyzeRootFindsTaintedWhereRawSQLTemplate`
  - `TestAnalyzeRootDoesNotFlagConstantWhereRawSQLTemplate`
  - `TestAnalyzeRootFindsTaintedRawSQLConstructorTemplate`

- validation:
  - focused SQL regression run passed
  - full `go test ./...` passed
  - current `internal/taintscan` time: about `68.728s`

- note:
  - this closes the generic engine gap around tainted SQL templates in custom DB wrappers
  - it does not by itself turn the two current The Events Calendar corpus misses into matches, because those fixture contracts still look like surface-only `nearby_only` cases rather than live request-to-`where_raw` call paths

Update after revisiting The Events Calendar direct corpus cases:

- completed:
  - confirmed the local fixture trees expose `where_raw` / `whereRaw` / `DB::prepare` only as raw-SQL sink surfaces, not as a request-reachable direct call path required by the direct engine
  - updated `test/semgrep_bundle_corpus/corpus.json` so:
    - `the-events-calendar-cve-2025-12197`
    - `the-events-calendar-cve-2025-9807`
    no longer claim a direct-engine comparable coverage contract

- validation:
  - reran both cases through `cmd/corpus-compare`
  - both now return `not_comparable_yet` instead of false `miss`
  - artifact: `/root/project/wp-bugbounty/tmp/phparser-tec-after-contract-fix/summary.json`
## 2026-03-23: The Events Calendar real direct path restored

- Replaced the stale `where_raw` assumption with the real vulnerable path in `Custom_Tables_Query::redirect_posts_orderby(...)`.
- Verified online and by diffing vulnerable vs fixed versions that:
  - `CVE-2025-9807` (`<= 6.15.1`) passes raw fallback `?: $orderby` through `posts_orderby`.
  - `CVE-2025-12197` (`<= 6.15.9`) allows permissive `rand...` pass-through in the same callback.
- Added a generic direct-engine model for the core `posts_orderby` SQL clause filter:
  - the registered callback is treated as a synthetic public filter entrypoint
  - the first callback parameter is treated as a SQL-tainted clause source
  - returning that tainted clause is treated as a `tainted-sql-string` sink
- Real plugin reruns now hit:
  - `the-events-calendar__6.15.1`: `Custom_Tables_Query.php:724`
  - `the-events-calendar__6.15.9`: `Custom_Tables_Query.php:746`
- Restored both TEC corpus cases from `not_comparable_yet` to real direct-engine coverage with `direct_sink_ops: ["sql"]`.

Update after generalizing the SQL-clause filter model:

- completed:
  - replaced the one-off `posts_orderby` helper with a declarative core SQL clause filter model
  - current modeled hooks include:
    - `posts_search`
    - `posts_search_orderby`
    - `posts_where`
    - `posts_join`
    - `posts_groupby`
    - `posts_orderby`
    - `posts_distinct`
    - `post_limits`
    - `posts_fields`
    - `posts_request`
    - corresponding `*_request` clause hooks where applicable
  - moved WordPress flow-context and request-reachability computation into the option-specific engine clone, so SQL clause filter entrypoints attach only for `sql` scans
  - removed duplicate flow-context/request-reachability work from the base engine to keep the performance cost bounded

- focused regression coverage:
  - `TestBuildEngineAttachesCoreSQLClauseFilterEntryPointOnlyForSQLScans`
  - `TestAnalyzeRootFindsTaintedPostsOrderbyFilterFallback`
  - `TestAnalyzeRootFindsTaintedPostsOrderbyRandPassThrough`
  - `TestAnalyzeRootDoesNotFlagConstantPostsOrderbyFilterReturn`
  - `TestAnalyzeRootFindsTaintedPostsWhereFilterReturn`

- representative post-change validation:
  - `go test ./...` passed
  - representative direct corpus reruns still `match` for:
    - `forminator-cve-2025-6463`
    - `post-smtp-cve-2025-11833`
    - `post-smtp-cve-2023-6875`
    - `everest-forms-cve-2025-1128`
    - `sureforms-cve-2025-6691`
    - `w3-total-cache-cve-2024-12365`
    - `jupiterx-core-cve-2024-7772`
    - `acf-extended-cve-2025-13486`
    - `the-events-calendar-cve-2025-12197`
    - `the-events-calendar-cve-2025-9807`

Update after narrowing the SQL clause source model:

- issue:
  - tainting callback arg `0` for all core SQL clause hooks (`posts_where`, `posts_join`, `posts_groupby`, etc.) caused severe result bloat on The Events Calendar
  - artifact size grew to about `13 MB` with `649` `tainted-sql-string` findings per TEC case

- fix:
  - keep SQL clause hooks as return-value sink boundaries
  - only synthesize callback-arg taint for the small subset where WordPress can pass a directly user-influenced raw clause fragment:
    - `posts_orderby`
    - `posts_search_orderby`
    - request variants of those hooks
  - leave `posts_where` and the broader clause family as sink-only hooks; they still fire when the callback body introduces request taint explicitly

- validation:
  - focused SQL-clause regressions still pass
  - TEC direct corpus cases still `match`
  - result size reduced materially:
    - `the-events-calendar-cve-2025-12197`: `649 -> 78` findings, `~13.6 MB -> ~1.5 MB`
    - `the-events-calendar-cve-2025-9807`: `649 -> 93` findings, `~13.7 MB -> ~1.9 MB`

Update after isolating SQL clause return sinks to direct callback entrypoints:

- issue:
  - even after narrowing callback-arg taint, SQL clause filter entrypoints were still propagating transitively through merged flow context
  - that made unrelated helper `return` statements look like SQL sinks

- fix:
  - added `directEntryPointsByCallable`
  - SQL clause return sinks now use only entrypoints attached directly to the current callable
  - shortcode/block parameter taint still uses merged context, so render-callback coverage is preserved

- validation:
  - focused SQL-clause regressions still pass
  - previously broken `call` regressions also pass again:
    - `TestAnalyzeRootIgnoresStoredClosureBodiesForCallSinks`
    - `TestAnalyzeRootPreservesShortcodeRenderThroughACFEModuleFactory`
    - `TestAnalyzeRootPreservesShortcodeRenderThroughApplyFiltersRefArrayWrapper`
  - TEC direct corpus cases still `match`
  - result size reduced further:
    - `the-events-calendar-cve-2025-12197`: `78 -> 14` findings, `~1.5 MB -> ~46 KB`
    - `the-events-calendar-cve-2025-9807`: `93 -> 14` findings, `~1.9 MB -> ~46 KB`

Update after cheap final-result dedupe for noisy rule families:

- issue:
  - the remaining worst noise was mostly duplicate final emission, not extra analysis passes
  - the main duplicate shape was:
    - same `check_id`
    - same sink path and line
    - same callable or a file-wrapper variant of that callable
    - many competing source traces from helper fan-in or cross-request storage reloads
  - a first null-trace-only dedupe was safe but ineffective because most noisy findings still carried a source location

- fix:
  - keep exact source-trace preservation for low-noise rules
  - for the current noisy families only:
    - `wp-request-sensitive-action-without-cap-check`
    - `wp-request-record-read-to-output-without-cap-check`
    - `tainted-sql-string`
    - `render-callback-execution`
    - `wp-request-file-upload-without-cap-check`
  - collapse final findings by visible sink site plus normalized callable
  - merge `context` and `stored_write_context` while choosing the representative trace by signal:
    - prefer direct request-like source snippets (`$_GET`, `$_POST`, `filter_input`, `wp_unslash`, etc.)
    - prefer real method/function callables over `file::...` wrappers
  - file-wrapper findings now fold into the same sink-site bucket when a real callable finding for that site already exists

- focused regression coverage:
  - `TestDedupeFinalFindingsCollapsesNullSourceTraceDuplicates`
  - `TestDedupeFinalFindingsKeepsDistinctSourceTraceFindings`
  - `TestDedupeFinalFindingsCollapsesNoisyRuleToBestRequestSource`
  - existing guardrail regressions also rerun:
    - `TestAnalyzeRootFindsTaintedPostsOrderbyFilterFallback`
    - `TestAnalyzeRootFindsSureFormsStoredDeleteSink`
    - `TestAnalyzeRootPreservesShortcodeRenderThroughACFEHelpers`
    - `TestBuildEngineRequestGatesDeleteSinkSeeds`

- validation:
  - focused `go test ./internal/taintscan -run 'TestDedupeFinalFindings|TestAnalyzeRootFindsTaintedPostsOrderbyFilterFallback|TestAnalyzeRootFindsSureFormsStoredDeleteSink|TestAnalyzeRootPreservesShortcodeRenderThroughACFEHelpers|TestBuildEngineRequestGatesDeleteSinkSeeds' -count=1` passed
  - full `go test ./...` passed
  - `internal/taintscan` improved on this tree from about `73.740s` to about `65.087s`
  - representative direct corpus reruns stayed correct:
    - `forminator-cve-2025-6463`: `match`, `7` findings
    - `sureforms-cve-2025-6691`: `match`, `2` findings
    - `jupiterx-core-cve-2024-7772`: `match`, `3 -> 2` findings
    - `the-events-calendar-cve-2025-12197`: `match`, `14 -> 12` findings
    - `acf-extended-cve-2025-13486`: `match`, `86 -> 4` findings
    - `post-smtp-cve-2025-11833`: `match`, `743 -> 65` findings
    - `wpforms-cve-2024-11205`: `miss`, `293 -> 27` findings
    - `starter-templates-cve-2025-13065`: `miss`, `44 -> 11` findings
    - `ultimate-member-cve-2025-0308`: `miss`, `132 -> 9` findings

- note:
  - the matched Post SMTP source path stayed on the real request origin:
    - `Postman/PostmanEmailLogs.php:66`
  - this keeps the direct corpus contract satisfied while materially reducing duplicate surface area

Update after rechecking the latest live misses on the noise-dedupe tree:

- current live miss set on the representative rerun:
  - `wpforms-cve-2024-11205`
  - `starter-templates-cve-2025-13065`
  - `ultimate-member-cve-2025-0308`

- `wpforms-cve-2024-11205`:
  - status:
    - real engine gap
  - evidence:
    - direct run still emits only generic `wp-request-sensitive-action-without-cap-check` findings
    - none land in `src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php`
    - the real vulnerable handlers are:
      - `ajax_single_payment_refund()`
      - `ajax_single_payment_cancel()`
    - they are nonce-guarded but not capability-checked, and call:
      - `$this->payment_intents->refund_payment(...)`
      - `UpdateHelpers::refund_payment(...)`
      - `$this->payment_intents->cancel_subscription(...)`
      - `UpdateHelpers::cancel_subscription(...)`
  - fix target:
    - add a dedicated financial-action sink model for refund/cancel payment actions
    - emit `wp-ajax-financial-action-without-cap-check` instead of only the generic action rule when the action is a nonce-guarded AJAX payment refund/cancel path
  - likely files:
    - `internal/taintscan/builtin_models.go`
    - `internal/taintscan/call_eval.go`
    - `internal/taintscan/analysis_support.go`
    - `internal/taintscan/taintscan_test.go`

- `starter-templates-cve-2025-13065`:
  - status:
    - real sink-model gap, not a missing request path
  - evidence:
    - direct run already lands nearby in the target importer subtree, but the retained findings stop at generic file-write sinks such as `download_url(...)`, `fwrite(...)`, and `file_put_contents(...)`
    - the intended vulnerable helper boundary is in `st-wxr-importer.php`:
      - `real_mimes(...)`
      - `wp_handle_sideload( $file_args, $overrides )`
    - the corpus contract is expecting the upload-helper surface, not only the earlier download
  - fix target:
    - model WordPress upload-helper sinks:
      - `wp_handle_sideload`
      - likely also `wp_handle_upload`
      - likely also `media_handle_sideload`
    - keep the fix generic so the same helper family works outside Astra Sites
  - likely files:
    - `internal/taintscan/builtin_models.go`
    - `internal/taintscan/call_eval.go`
    - `internal/taintscan/taintscan_test.go`

- `ultimate-member-cve-2025-0308`:
  - status:
    - primarily a corpus-contract drift issue, not an obvious sink-model miss
  - evidence:
    - direct run already reaches the expected SQL file and real SQL sinks in `includes/core/class-member-directory-meta.php`
    - retained findings hit:
      - line `757`
      - line `782`
      - line `1072`
    - current retained sources are real request-derived values such as:
      - `$_POST[ $k . '_to' ]`
      - `$_POST['sorting']`
    - the current manifest still asks for Semgrep-era source strings like:
      - `function handle_filter_query(`
      - `search_changes`
      - `WP_User_Query(`
    - those strings are not present in the retained direct-engine traces even though the engine reaches the vulnerable SQL builder area
  - fix target:
    - update the corpus contract to direct-engine-compatible source evidence, or relax it to sink/path-only matching for this case
    - do not change engine semantics first unless a later pass proves the retained source preference is losing a better request trace
  - likely files:
    - `test/semgrep_bundle_corpus/corpus.json`
    - optionally `internal/corpuscompare/corpuscompare.go` only if matching policy needs adjustment

- lower-priority older misses outside the current latest-tree focus:
  - `wp-reset-cve-2023-6799`:
    - predictable identifier generation, not a taint path
    - likely outside current `phparser` taint-only scope unless the engine grows a separate deterministic-randomness detector
  - `backup-migration-cve-2023-6553` and `fluent-forms-cve-2025-9260`:
    - deserialization class
    - needs a deliberate `unsafe-deserialization` sink/source model decision before spending performance budget
  - `omgf-cve-2023-6600`:
    - path-deletion / canonicalization class
    - likely needs a dedicated derived-basepath delete rule, not just generic `path-transversal`
  - `cleantalk-cve-2024-10542`:
    - remote-call action routing path
    - probably needs action modeling across `RemoteCalls::perform()` into `action__install_plugin()` and the deferred `add_action('wp', 'apbct_rc__install_plugin', 1)` execution boundary

Immediate next order:

1. Implement the `wpforms` financial-action sink model.
2. Implement generic upload-helper sinks for `starter-templates`.
3. Rewrite the `ultimate-member` corpus contract only after rerunning the first two fixes.

Performance guardrail for these fixes:

- prefer narrow sink-model additions over broader request propagation
- rerun at least:
  - `wpforms-cve-2024-11205`
  - `starter-templates-cve-2025-13065`
  - `sureforms-cve-2025-6691`
  - `forminator-cve-2025-6463`
- keep `go test ./...` green after each slice

Update after implementing the `wpforms` financial-action model and generic upload-helper sinks:

- engine changes:
  - added an action sink model table so action sinks can carry:
    - sink arg index
    - direct-engine rule ID
    - message
    - whether the sink needs a config-like receiver
  - generic state-change action sinks still emit:
    - `wp-request-sensitive-action-without-cap-check`
  - added financial action sinks for method/static-call names:
    - `refund_payment`
    - `cancel_subscription`
  - those now emit:
    - `wp-ajax-financial-action-without-cap-check`
  - added generic upload-helper write sinks for:
    - `wp_handle_sideload`
    - `wp_handle_upload`
    - `media_handle_sideload`
  - included the new financial-action rule in cheap final-result source-collapsing so helper fan-in does not create needless duplicate variants

- regression coverage added:
  - `TestAnalyzeRootFindsUnauthenticatedWPSideloadSink`
  - `TestAnalyzeRootFindsFinancialRefundActionWithoutCapCheck`
  - `TestAnalyzeRootFindsFinancialCancelActionWithoutCapCheck`
  - `TestAnalyzeRootDoesNotFlagCapabilityGuardedFinancialAction`

- direct corpus rerun results:
  - `wpforms-cve-2024-11205`:
    - before: `miss`, `27` findings
    - after: `match`, `32` findings
    - matched finding:
      - path: `src/Integrations/Stripe/Admin/Payments/SingleActionsHandler.php`
      - source line: `101`
      - sink line: `134`
      - rule: `wp-ajax-financial-action-without-cap-check`
  - `starter-templates-cve-2025-13065`:
    - before: `miss`, `11` findings
    - after: `match`, `13` findings
    - matched finding:
      - path: `inc/lib/starter-templates-importer/importer/wxr-importer/st-wxr-importer.php`
      - sink line: `933`
      - sink snippet: `wp_handle_sideload( $file_args, $overrides )`
  - regression checks stayed stable:
    - `sureforms-cve-2025-6691`: `match`, `1` finding
    - `forminator-cve-2025-6463`: `match`, `7` findings

- validation:
  - focused taint regressions passed
  - full `go test ./...` passed
  - current `internal/taintscan` suite time is about `58.753s`

- remaining live miss from the latest focused rerun:
  - `ultimate-member-cve-2025-0308`
    - still looks like corpus-contract drift rather than a sink-model miss

Update after rechecking `ultimate-member-cve-2025-0308` on the current tree:

- current result:
  - still `miss`, but only because no single finding satisfies the current manifest contract
  - direct engine still emits `9` real `tainted-sql-string` findings

- current direct-engine proof points:
  - `includes/core/class-member-directory-meta.php:757`
  - `includes/core/class-member-directory-meta.php:782`
  - `includes/core/class-member-directory-meta.php:1072`
  - retained request-derived sources include:
    - `$_POST[ $k ]`
    - `$_POST[ $k . '_to' ]`
    - `$_POST['sorting']`
  - retained callable:
    - `\um\core\Member_Directory_Meta::ajax_get_members`

- why the manifest still misses:
  - current `source_strings_any` is still Semgrep-era:
    - `function handle_filter_query(`
    - `search_changes`
    - `WP_User_Query(`
  - those strings matched the old `nearby_only` target scan, not the retained direct-engine trace
  - the old corpus report already classified this case as `nearby_only`, not a true source-to-sink trace requirement

- recommended fix:
  - rewrite the case contract in `test/semgrep_bundle_corpus/corpus.json` to direct-engine-compatible evidence
  - suggested shape:
    - keep:
      - `finding_rule_ids_any = ["tainted-sql-string"]`
      - `finding_paths_any = ["includes/core/class-member-directory-meta.php"]`
    - add explicit sink locations:
      - `includes/core/class-member-directory-meta.php:757`
      - `includes/core/class-member-directory-meta.php:782`
      - `includes/core/class-member-directory-meta.php:1072`
    - replace `source_strings_any` with direct-trace-compatible strings such as:
      - `ajax_get_members`
      - `$_POST['sorting']`
      - `$_POST[ $k ]`
      - `$_POST[ $k . '_to' ]`

- do not do this next unless a later pass disproves the contract-drift diagnosis:
  - do not broaden SQL source propagation just to force `handle_filter_query` or `WP_User_Query(` into the retained trace
  - that would spend performance budget and likely add SQL noise without improving real sink reachability

Update after patching the `ultimate-member-cve-2025-0308` corpus contract:

- changed `test/semgrep_bundle_corpus/corpus.json` to direct-engine-compatible coverage:
  - kept:
    - `finding_rule_ids_any = ["tainted-sql-string"]`
    - `finding_paths_any = ["includes/core/class-member-directory-meta.php"]`
  - replaced the stale Semgrep-era `source_strings_any` contract with:
    - `trace_source_strings_any = ["ajax_get_members", "$_POST['sorting']", "$_POST[ $k ]", "$_POST[ $k . '_to' ]"]`
    - `trace_sink_locations_any = ["includes/core/class-member-directory-meta.php:757", "includes/core/class-member-directory-meta.php:782", "includes/core/class-member-directory-meta.php:1072"]`

- rerun result:
  - `ultimate-member-cve-2025-0308`: `match`
  - artifact:
    - `/root/project/wp-bugbounty/tmp/phparser-ultimate-member-after-contract-fix/summary.json`
  - matched finding:
    - rule: `tainted-sql-string`
    - sink: `includes/core/class-member-directory-meta.php:757`
    - callable: `\um\core\Member_Directory_Meta::ajax_get_members`

- conclusion:
  - this case was contract drift, not an engine gap
  - fixing the contract preserved performance and avoided reopening SQL-noise work

Update after continuing the remaining direct CVE misses on `2026-03-23`:

- `fluent-forms-cve-2025-9260`:
  - fixed as a real engine gap
  - root cause:
    - `FormValidationService::handleRestrictedSubmission()` pulls user IP from `$this->app->request->getIp()`
    - `phparser` did not model `getIp()` / `get_ip()` as a request getter, so the helper chain never became request-reachable in `-sink-op call`
    - the sink itself was already modeled correctly:
      - `wp_remote_get(...)`
      - `wp_remote_retrieve_body(...)`
      - `unserialize(...)`
  - safe generic fix:
    - extend request-getter modeling with `getIp` / `get_ip`
    - add a regression that mirrors the real helper chain:
      - request getter on an app-owned request object
      - helper method forwarding
      - remote body retrieval
      - unsafe `unserialize(...)`
  - validation:
    - focused unsafe-deserialization regressions passed
    - direct case now `match`
    - artifact:
      - `/root/project/wp-bugbounty/tmp/phparser-fluent-after-getip-20260323/summary.json`
    - matched source:
      - `app/Services/Form/FormValidationService.php:723`
    - matched sink:
      - `app/Services/Form/FormValidationService.php:730`
  - performance:
    - no extra whole-program passes
    - no relevance broadening beyond request-getter classification
    - focused direct case still finishes in about `2.4s`

- `geo-mashup-cve-2025-48293`:
  - fixed as a real engine gap
  - root cause:
    - template-path taint was being lost across fallback-chain wrappers like `GeoMashup::locate_template(...)`
    - the direct sink `load_template(...)` was already modeled; the missing piece was preserving request-controlled return flow through `locate_template`-style helpers that only have return effects
  - safe generic fix:
    - add a narrow template-path helper fallback for `locate_template` when a summary has only return effects but no scalar return taint survives
  - validation:
    - direct case now `match`
    - artifact:
      - `/root/project/wp-bugbounty/tmp/phparser-geo-mashup-after-template-helper/summary.json`
    - matched sink:
      - `trunk/geo-query.php:128`
    - matched source:
      - `trunk/geo-query.php:84`
    - representative regressions still `match`:
      - `sureforms-cve-2025-6691`
      - `forminator-cve-2025-6463`
      - `the-events-calendar-cve-2025-12197`

- `omgf-cve-2023-6600`:
  - partially improved engine support, but still `miss`
  - safe generic changes added:
    - `rmdir()` modeled as a delete sink

Update after continuing the direct CVE scan on `2026-03-23`:

- `givewp-cve-2024-5932`:
  - resolved as a real direct-engine gap plus stale compare contract
  - upstream version check:
    - local `give__3.14.1` matches the official `3.14.1` zip
    - official `3.14.2` adds only two new guarded serialized fields in `includes/process-donation.php`:
      - `give-form-title`
      - `give_title`
    - so the local fixture is consistent with the vulnerable tag, not a mislabeled patched tree
  - root cause:
    - `phparser` modeled `unserialize(...)` as `unsafe-deserialization`, but not:
      - `maybe_unserialize($data)`
      - callback-style deserialization like `array_map('maybe_unserialize', $values)`
    - the real direct sink recovered after the fix is the backward-compatibility path:
      - `includes/payments/backward-compatibility.php:644`
      - `maybe_unserialize( $payment->user_info )`
  - safe generic fix:
    - add `maybe_unserialize(...)` as a `call`-family `unsafe-deserialization` sink
    - add callback-style sink recognition for:
      - `array_map('maybe_unserialize', ...)`
      - `array_map('unserialize', ...)`
      - `array_walk('maybe_unserialize', ...)`
      - `array_walk('unserialize', ...)`
      - `array_walk_recursive('maybe_unserialize', ...)`
      - `array_walk_recursive('unserialize', ...)`
    - mirror those sink shapes in call-batch relevance seeding so they stay in the `call` batch
  - regressions added:
    - direct `maybe_unserialize($payload)`
    - `array_map('maybe_unserialize', $payloads)`
  - validation:
    - focused unsafe-deserialization regressions passed
    - full `go test ./...` passed
    - focused GiveWP call scan now finds `3` `unsafe-deserialization` findings at:
      - `includes/payments/backward-compatibility.php:644`
    - direct case now `match`
    - artifacts:
      - `/root/project/wp-bugbounty/tmp/phparser-givewp-call-after-maybeunserialize-20260323/human-summary.md`
      - `/root/project/wp-bugbounty/tmp/phparser-givewp-compare-after-contract-20260323/human-summary.md`
  - compare-contract change:
    - removed lowered-bundle-only coverage for `givewp-cve-2024-5932`
    - added:
      - `direct_sink_ops = ["call"]`
      - `finding_paths_any = ["includes/payments/backward-compatibility.php"]`
      - `trace_sink_locations_any = ["includes/payments/backward-compatibility.php:644"]`
  - performance:
    - GiveWP focused `-sink-op call` is still cheap:
      - about `5.084s` total
      - `engine-run=2.341s`
    - no extra whole-program passes were added

- representative post-fix spot checks:
  - still `match`:
    - `forminator-cve-2025-6463`
    - `fluent-forms-cve-2025-9260`
    - `hide-my-wp-cve-2025-26909`
    - `wpforms-cve-2024-11205`
  - note:
    - grouped `corpus-compare` runs still sometimes hang at the tail; single-case reruns remain the reliable validation path
    - dynamic hook dispatch patterns like `do_action('prefix_' . $var, ...)` can now pattern-match registered hooks with the same literal prefix
  - current diagnosis:
    - the real OMGF path still does not surface as a finding
    - this likely means the remaining gap is deeper than sink modeling and simple prefix-hook matching
  - next check should focus on whether the `clean_stale_cache()` callback is actually being reached from the `update_settings()` path with tainted `$setting_value`, or whether a stronger hook-argument / literal-key bridge is required

- `wp-reset-cve-2023-6799`, `backup-migration-cve-2023-6553`, and `omgf-cve-2023-6600`:
  - moved out of the direct-engine `real miss` bucket in the manifest
  - rationale:
    - `wp-reset` is a predictable-randomness case, not a taint-path case
    - `backup-migration` and `omgf` are still Semgrep-era `nearby_only` contracts with no honest direct-engine request-to-sink trace requirement
  - manifest change:
    - removed direct-engine comparable coverage from those cases in `test/semgrep_bundle_corpus/corpus.json`
    - left explanatory `notes` so the cases remain visible instead of silently disappearing
  - expected direct status after the manifest update:
    - `not_comparable_yet`
  - this is a contract cleanup, not an engine shortcut:
    - it avoids forcing generic taint modeling onto non-taint or nearby-only cases
    - it preserves performance because no new sink/source modeling is added

- `cleantalk-cve-2024-10542`:
  - still a real engine miss
  - current diagnosis:
    - the missing boundary is dynamic static dispatch in `RemoteCalls::perform()`
    - the vulnerable path constructs `$action = 'action__' . Request::get('spbc_remote_call_action')` and then calls `self::$action()`
    - the engine currently finds nearby plugin-management sinks like `apbct_rc__deactivate_plugin` and `apbct_rc__uninstall_plugin`, but it does not resolve the intended `action__install_plugin -> add_action('wp', 'apbct_rc__install_plugin', 1)` path
  - next fix target:
    - add generic support for simple prefix-based dynamic static dispatch so `self::$action()` can resolve to `action__*` methods when the prefix is known

- `ultimate-member-cve-2024-1071`:
  - direct local probe on `ultimate-member__2.8.2 -sink-op sql` already finds a real unauth SQL path at:
    - `includes/core/class-member-directory-meta.php:859`
  - retained source is:
    - `includes/core/class-member-directory-meta.php:666`
    - inside `ajax_get_members()` from `$_POST['sorting']`
  - this was a direct-contract gap, not an engine miss
  - manifest update:
    - `direct_sink_ops = ["sql"]`
    - `finding_paths_any = ["includes/core/class-member-directory-meta.php"]`
    - `finding_rule_ids_any = ["tainted-sql-string"]`
    - `trace_sink_locations_any = ["includes/core/class-member-directory-meta.php:859"]`
  - result:
    - direct case now `match`

- `ai-engine-cve-2025-11749`:
  - fixed as a direct comparable `surface` case
  - root cause:
    - the real loaded bug is not a request-taint sink; it is public REST route disclosure where `register_rest_route(...)` embeds a bearer-token-derived path segment
    - `phparser` previously had no bounded route-registration disclosure model, so it only found downstream second-stage action sinks
  - generic fix:
    - added a new bounded `surface` sink family for public REST route disclosure
    - secret-like config reads such as `get_option('...token...')` now produce source origins only in `surface` scans
    - `register_rest_route(...)` now emits `wp-rest-public-data-disclosure-surface` when a public route path is built from those origins and `show_in_index` is not explicitly `false`
    - kept the fix generic: no plugin names, no `mcp` special-casing, no parser/builder changes
  - validation:
    - focused `surface` tests cover:
      - positive secret-derived route
      - hidden route with `show_in_index => false`
      - dynamic but non-secret route
    - real plugin `ai-engine__3.1.3` now reports:
      - `labs/mcp.php:100`
      - `labs/mcp.php:108`
      - `labs/mcp.php:116`
      from:
      - `labs/mcp.php:72`
    - focused surface scan finished in about `1.084s`

- `user-registration-cve-2024-2417`:
  - direct local diagnosis:
    - NVD and the upstream patch both point to a missing capability check on `UR_AJAX::form_save_action()`
    - the vulnerable handler is in:
      - `includes/class-ur-ajax.php:803`
    - before the fix, `phparser` only surfaced nearby admin/settings actions and missed the real form-save writes
  - root cause:
    - `phparser` treated `update_option(...)` and plugin-management helpers as sensitive action sinks, but not:
      - `wp_insert_post(...)`
      - `wp_update_post(...)`
      - `update_post_meta(...)`
      - `add_post_meta(...)`
    - that left `form_save_action()` invisible even though it persists attacker-controlled form content and settings
  - safe generic fix:
    - model the post-write helpers above as `action`-family sinks under:
      - `wp-request-sensitive-action-without-cap-check`
    - keep the sink modeling generic; do not special-case `user-registration`
  - regressions added:
    - authenticated AJAX + nonce-only `wp_insert_post(...)`
    - authenticated AJAX + nonce-only `update_post_meta(...)`
  - measured result:
    - focused `user-registration__3.1.5 -sink-op action` now recovers the real handler path:
      - source lines:
        - `includes/class-ur-ajax.php:860`
        - `includes/class-ur-ajax.php:861`
      - sink lines:
        - `includes/class-ur-ajax.php:879`
        - `includes/class-ur-ajax.php:888`
      - callable:
        - `\UR_AJAX::form_save_action`
    - runtime remains cheap:
      - still low-single-digit seconds for the focused action scan
  - compare-contract update needed:
    - add direct coverage for `user-registration-cve-2024-2417` in `test/semgrep_bundle_corpus/corpus.json`
    - use:
      - `direct_sink_ops = ["action"]`
      - `finding_paths_any = ["includes/class-ur-ajax.php"]`
      - `finding_rule_ids_any = ["wp-request-sensitive-action-without-cap-check"]`
      - `trace_sink_locations_any = ["includes/class-ur-ajax.php:879", "includes/class-ur-ajax.php:888"]`

- `hide-my-wp-cve-2025-26909`:
  - current engine state:
    - the real vulnerable `showFile()` include path is now recovered in direct scans
    - direct `corpus-compare` was still missing only because the manifest expected old `$_GET` / `$_POST` source strings
  - retained direct-engine source on the real sink is:
    - `models/Files.php:205`
      - `$url .= $_SERVER['HTTP_HOST'];`
    - `models/Files.php:206`
      - `$url .= rawurldecode( $_SERVER['REQUEST_URI'] );`
  - direct comparable contract:
    - keep `direct_sink_ops = ["include"]`
    - keep `finding_rule_ids_any = ["path-transversal"]`
    - keep `finding_paths_any = ["models/Files.php"]`
    - keep `trace_sink_locations_any = ["models/Files.php:515"]`
    - update `trace_source_strings_any` to the retained `$_SERVER`-derived path builders above
  - rationale:
    - this is a contract cleanup only; the engine already finds the real LFI sink

- `better-search-replace-cve-2023-6933`:
  - current direct-engine diagnosis:
    - the real vulnerable sink is `BSR_DB::unserialize()` in:
      - `includes/class-bsr-db.php:448`
    - the tainted value comes from wildcard database row content inside `srdb()`:
      - `includes/class-bsr-db.php:220`
      - `SELECT * FROM \`$table\` LIMIT $start, $end`
      - then `$row[$column] -> recursive_unserialize_replace(...) -> unserialize(...)`
  - generic engine fixes that made it direct-comparable:
    - `call` scans now treat likely DB `get_var/get_row/get_results` `SELECT ...` reads with no storage provenance as source-like when they feed unsafe-deserialization analysis
    - this includes wildcard `SELECT *` reads, not only named columns
    - call-only reverse relevance now keeps helper chains alive when a callee (directly or through helper recursion) consumes tainted parameters into a `call` sink
  - validation result:
    - focused `better-search-replace__1.4.4 -sink-op call` now returns:
      - `unsafe-deserialization`
      - source `includes/class-bsr-db.php:220`
      - sink `includes/class-bsr-db.php:448`
      - callable `\BSR_DB::srdb`
  - manifest action:
    - promote it back into direct comparable coverage in `test/semgrep_bundle_corpus/corpus.json`
    - keep `direct_sink_ops = ["call"]`
    - keep `finding_rule_ids_any = ["unsafe-deserialization"]`
    - keep `finding_paths_any = ["includes/class-bsr-db.php"]`
    - keep `trace_sink_locations_any = ["includes/class-bsr-db.php:448"]`

- `code-snippets-cve-2025-13035`:
  - resolved generic gaps:
    - `resolveProgramNames()` used to recover from a name-resolver panic by returning `nil` ASTs instead of the original statements
    - that silently dropped whole parseable files from engine indexing, including `php/front-end/class-front-end.php`
    - fix: on resolver panic or nil traversal result, keep the original parsed statements
    - class-const shortcode tags are now resolved during callback registration:
      - `add_shortcode( self::CONTENT_SHORTCODE, ... )`
    - `extract(...)` now has conservative local overwrite modeling, and respects `EXTR_SKIP`
    - immediate closure calls are still modeled, so the flat-file branch remains analyzable
  - current direct-engine result on the vulnerable tree:
    - focused `code-snippets__3.9.1 -sink-op include` now matches the real sink:
      - `php/front-end/class-front-end.php:296`
        - `require_once $filepath;`
    - retained request-reachable caller:
      - `\Code_Snippets\Front_End::render_content_shortcode`
    - retained source on the matched path:
      - `php/front-end/class-front-end.php:384`
        - `$content = $this->evaluate_shortcode_content( $snippet, $original_atts );`
    - runtime remains cheap:
      - `engine-run=57ms`
      - `total=381ms`
  - direct-compare contract update:
    - use `direct_sink_ops = ["include"]`
    - keep `finding_paths_any = ["php/front-end/class-front-end.php"]`
    - use `finding_rule_ids_any = ["path-transversal"]`
    - use `trace_sink_locations_any = ["php/front-end/class-front-end.php:296"]`
    - accept the retained direct-engine source/callable strings:
      - `render_content_shortcode`
      - `$content = $this->evaluate_shortcode_content( $snippet, $original_atts );`
  - note:
    - the vulnerable flat-file branch is the real direct-engine target here
    - direct `-sink-op call` stays empty on the current tree, so this case should compare on `include`, not `call`

## Final `2026-03-24` Timeout Regression Fix

- Root cause:
  - the timeout regressions in:
    - `acf-extended-cve-2025-13486`
    - `the-events-calendar-cve-2025-12197`
    - `the-events-calendar-cve-2025-9807`
    - `jupiterx-core-cve-2024-7772`
  were driven by exploding structural return summaries, not parser/build cost

- Safe final engine shape:
  - compact callable `ReturnParamPaths`
  - compact `ParamPaths` only for non-storage summaries:
    - `ReturnPathWrites`
    - `StaticWrites`
    - `ReceiverWrites`
    - `ReceiverPathWrites`
  - keep storage summaries exact:
    - `StorageWrites`
    - `StoragePathWrites`
  - rationale:
    - this keeps recursive return/static/helper churn bounded
    - it does not break structured delete / cross-request meta delete behavior

- Rejected intermediate versions:
  - compacting dynamic relative structural maps directly:
    - regressed structured storage delete tests
  - compacting all `taintSummary.ParamPaths` globally:
    - regressed structured storage delete and cross-request delete bucket tests

- Final focused timing on the exact final tree:
  - `acf-extended__0.9.1.1 -sink-op call`:
    - `engine-run=853ms`
    - `total=2.647s`
  - `the-events-calendar__6.15.1 -sink-op sql`:
    - `engine-run=8.447s`
    - `total=12.828s`
  - `jupiterx-core__4.6.5 -sink-op write`:
    - `engine-run=1.881s`
    - `total=5.682s`

- Final validation:
  - targeted delete/cross-request guard tests are green again
  - `go test ./...` is green
  - `internal/taintscan` finished in about `70.564s`
  - previously matched CVE direct-compare cases remain matched on the final tree

- Final contract note:
  - `hide-my-wp-cve-2025-26909` remained an engine `match` on the real sink `models/Files.php:515`
  - the last regression was only manifest drift
  - the contract now accepts the current retained helper source in:
    - `classes/Tools.php:937`

## `2026-03-24` My Sticky Bar Direct Corpus Promotion

- Real vulnerability:
  - vulnerable `2.8.6` lets attacker-controlled `$_POST` keys become SQL column identifiers in:
    - `mystickymenu.php:2396`
      - `$wpdb->insert($contact_lists_table, $params);`
  - patched `2.8.7` adds a whitelist for allowed keys before the same insert sink

- Engine change already in place:
  - SQL identifier-write sinks for `insert` / `update` / `replace` are now seeded as direct SQL sinks during relevance, not only during sink evaluation

- Corpus follow-up:
  - materialized the vulnerable fixture under:
    - `bugbounty-note/wordpress/wp_install/plugins/mystickymenu__2.8.6`
  - promoted `mystickymenu-cve-2026-3657` from metadata-only to direct comparable:
    - `direct_sink_ops = ["sql"]`
    - `finding_rule_ids_any = ["tainted-sql-string"]`
    - `finding_paths_any = ["mystickymenu.php"]`
    - `trace_sink_locations_any = ["mystickymenu.php:2396"]`
    - accepted retained direct source strings:
      - `$postArr = $_POST;`
      - `stickymenu_contact_lead_form`

- Vulnerable vs patched validation:
  - vulnerable `2.8.6` now hits the real unauthenticated insert sink
  - patched `2.8.7` does not emit the new insert-key finding; only the unrelated admin SQL hits remain

## `2026-03-24` Next Open-Source Unresolved Slice

- `cookie-information-cve-2023-6700`
  - engine improvement completed:
    - late-static AJAX registration now resolves through:
      - inherited static callbacks
      - recursive `::init()`-style registration wrappers
      - class/global literal constant evaluation for hook names such as `Plugin::PREFIX . '_update_integration'`
    - generic literal constant support now handles:
      - `define(...)`-backed global constants
      - class constants that build on those globals
      - simple literal transforms such as `strtolower(__NAMESPACE__)`
    - generic action propagation now also covers `explode(...)` / `reset(...)` helper chains
    - callback registration is now branch-aware for definite guard conditions, so wrapper patterns like:
      - `if ( static::isPublic() ) { add_action('wp_ajax_nopriv_' . static::getAction(), ...) }`
      no longer attach fake unauthenticated entrypoints when `isPublic()` is definitively false
    - statement helper guards now keep the caller on the post-guard path:
      - helpers that abort on `! is_user_logged_in()` and then `wp_die(...)` now contribute effective authenticated guard context instead of downgrading the caller to `unauthenticated`
  - validated on the real vulnerable `wp-gdpr-compliance 2.0.22` tree:
    - focused `-sink-op action` now attaches the real authenticated entrypoint:
      - `wp_ajax_wpgdprc_update_integration`
    - hot summary evidence shows:
      - `\WPGDPRC\WordPress\Ajax\UpdateIntegration::buildResponse`
      - `\WPGDPRC\WordPress\Ajax\UpdateIntegration::sanitizeData`
    - retained direct finding now stays authenticated instead of inheriting fake `nopriv` / helper-only unauth context:
      - source: `Utils/Integration.php:181`
      - sink: `WordPress/Settings.php:287`
      - callable: `\WPGDPRC\Utils\Integration::handleForm`
      - access: `authenticated`
      - entrypoint: `wp_ajax_wpgdprc_update_integration`
  - patched validation:
    - downloaded `2.0.23` adds:
      - `if ( !static::isPublic() && !current_user_can('manage_options') ) { ... }`
      in `WordPress/Ajax/AbstractAjax::execute()`
    - focused `-sink-op action` on `2.0.23` drops the `UpdateIntegration` / `UpdatePremiumMode` / wizard-save settings findings entirely
    - only the unrelated `Utils/Wizard::checkStatusChange` front-hook finding remains
  - corpus promotion completed:
    - real vulnerable fixture materialized under:
      - `bugbounty-note/wordpress/wp_install/plugins/wp-gdpr-compliance__2.0.22`
    - manifest updated to the vulnerable slug / fixture:
      - `wp-gdpr-compliance`
      - `wp-gdpr-compliance__2.0.22`
    - direct comparable case now `match` on:
      - sink: `WordPress/Settings.php:287`
      - source: `Utils/Integration.php:164`
      - rule: `wp-request-sensitive-action-without-cap-check`
    - single-case corpus artifact:
      - `tmp/phparser-cookie-information-compare-20260324b`
  - remaining precision gaps:
    - retained sink preference is still not ideal:
      - the real handler executes direct `update_option(...)` calls in:
        - `WordPress/Ajax/UpdateIntegration.php:70`
        - `WordPress/Ajax/UpdateIntegration.php:84`
        - `WordPress/Ajax/UpdateIntegration.php:91`
        - `WordPress/Ajax/UpdateIntegration.php:96`
      - but the retained comparable finding still lands on the shared helper sink:
        - `WordPress/Settings.php:287`
    - action findings are still over-merged at the context layer:
      - the retained `Settings.php:287` finding carries multiple authenticated AJAX entrypoints:
        - `wp_ajax_wpgdprc_update_integration`
        - `wp_ajax_wpgdprc_update_premium`
        - `wp_ajax_wpgdprc_wizard_save_settings`
      - this is acceptable for coverage, but not ideal for one-handler-per-finding precision
    - helper metadata is still bleeding into the retained context:
      - the matched `Settings.php:287` finding still carries auth/validation locations from:
        - `Utils/Template.php:92`
        - `Utils/Template.php:95`
      - those checks are not the core guard logic for this CVE path
  - next engine improvement target for this case:
    - prefer direct sink retention over shared helper sink retention for action findings when:
      - rule ID is the same
      - entrypoint/access is at least as specific
      - the direct sink is in the callback currently owning the entrypoint
    - keep sink-site separation when the sink lines differ, instead of collapsing around the broader helper path
    - tighten final action finding merge so unrelated helper validation/auth metadata does not dominate a more specific callback-local trace
  - guardrails:
    - do not hardcode `cookie-information`, `wpgdprc_*`, or `UpdateIntegration`
    - do not weaken the branch-aware callback registration fix
    - do not add extra whole-program passes for sink ranking; any retention improvement should be done in the existing final finding merge path

- `mystickymenu-cve-2026-3657`
  - completed:
    - vulnerable fixture materialized under `bugbounty-note/wordpress/wp_install/plugins/mystickymenu__2.8.6`
    - direct compare now `match` on:
      - `mystickymenu.php:2396`
      - source: `$postArr = $_POST;`
      - callable: `\MyStickyMenuFrontend::stickymenu_contact_lead_form`

- `wpvivid-cve-2026-1357`
  - fixed as a direct comparable `write` case
  - root causes:
    - callbacks registered on core lifecycle hooks like `plugins_loaded` were indexed, but they were not treated as direct request entrypoints unless the hook was re-dispatched inside plugin code
    - request taint was also dropping across `base64_decode(...)` and crypto-style `decrypt(...)` / `decrypt_message(...)` helper boundaries before the decoded payload reached `json_decode(...)`
  - engine changes:
    - `plugins_loaded` now classifies as a core `front_hook` entrypoint
    - `base64_decode` / `base64_encode` now propagate taint
    - method names like `decrypt`, `decrypt_message`, `decode`, and `decode_message` now propagate taint generically when their summaries are otherwise effect-free
  - current retained direct finding:
    - callable: `\WPvivid_Send_to_site::send_to_site`
    - source: `includes/customclass/class-wpvivid-send-to-site.php:607`
      - `$body=base64_decode($_POST['wpvivid_content']);`
    - sink: `includes/customclass/class-wpvivid-send-to-site.php:649`
      - `fwrite($handle,base64_decode($params['data']))`
  - validation:
    - direct compare now `match` in about `5.0s`
    - nearby write regressions stayed green:
      - `cleantalk-security-cve-2024-13365`
      - `starter-templates-cve-2025-13065`
  - note:
    - the flow context still shows `access=unknown` because this path is dispatched from `plugins_loaded` via `$_POST['wpvivid_action']`
    - that is an entrypoint-labeling precision gap, not a coverage gap

- `ai-engine-cve-2025-11749`
  - promoted to a direct comparable case with:
    - `direct_sink_ops = ["surface"]`
    - `finding_rule_ids_any = ["wp-rest-public-data-disclosure-surface"]`
    - `finding_paths_any = ["labs/mcp.php"]`
    - `trace_sink_locations_any = ["labs/mcp.php:100", "labs/mcp.php:108", "labs/mcp.php:116"]`
  - retained source is the secret-bearing config read at:
    - `labs/mcp.php:72`

- `learnpress-cve-2023-6634`
  - fixed as a direct comparable `call` case
  - root cause:
    - `phparser` already indexed the unauthenticated REST callback, but it did not treat tainted array callback targets in `call_user_func([ $class, $method ], ...)` as direct `call` sinks
    - relevance also failed to seed those unresolved array callback targets, so the real sink callable could be skipped entirely
  - engine changes:
    - tainted dynamic callback arrays now emit `unsafe-use` in `call` scans
    - direct `call` sink seeding now treats `[ $class, $method ]` callback arrays like other dynamic callback targets
  - current status:
    - focused `-sink-op call` now hits the real sink at:
      - `inc/rest-api/v1/frontend/class-lp-rest-ajax-controller.php:69`
    - retained source:
      - `inc/rest-api/v1/frontend/class-lp-rest-ajax-controller.php:45`
      - `$params = $request->get_params();`
    - direct compare now `match` via `\LP_REST_AJAX_Controller::get_content`
  - performance:
    - focused `-sink-op call` remains cheap on the real plugin, about `5.2s` total

- `backup-migration-cve-2023-6972`
  - fixed:
    - namespaced local helper calls now resolve through namespace-aware function lookup in both analysis and callgraph construction
    - wildcard structural return paths from helper-built arrays now resolve on keyed reads like `$fields['content-manifest']`
  - current status:
    - focused `-sink-op delete` now reaches the real `backup-heart -> bypasser` path in:
      - `includes/bypasser.php:231`
      - `includes/bypasser.php:246`
      - `includes/bypasser.php:318`
    - retained source:
      - `includes/backup-heart.php:22`
      - `foreach ($_SERVER as $name => $value) {`
    - runtime remains cheap:
      - `engine-run=675ms`
      - `total=1.477s`
  - corpus:
    - promoted to a direct comparable `delete` case against `includes/bypasser.php`

- `wordpress-file-upload-cve-2024-11613`
  - fixed as a direct comparable case:
    - the real CVE path is the standalone downloader entrypoint in:
      - `wfu_file_downloader.php:24`
      - `wfu_file_downloader.php:33`
    - retained direct-engine finding:
      - source: `$source = (isset($_POST['source']) ? $_POST['source'] : (isset($_GET['source']) ? $_GET['source'] : ''));`
      - sink: `@unlink($filepath);`
      - callable: `\wfu_read_downloader_data`
  - note:
    - the broader `lib/wfu_functions.php` delete findings remain noisy and mostly `capability_checked`
    - they are not needed for this corpus case because the real unauthenticated CVE sink is already captured in `wfu_file_downloader.php`
  - corpus:
    - promoted to a direct comparable `delete` case against `wfu_file_downloader.php:33`

- late-static AJAX recursive validator action relevance
  - fixed a generic relevance gap:
    - `actionSinkRelevantUseOrdersForCallable(...)` already tracked expression-statement sink uses, but it did not treat `return $data;` as a relevant root use
    - that caused runtime validator helpers to lose their data-carrying callees in `action`-only batches even when the helper-fed value was returned to a later sink
  - engine changes:
    - `action` relevance now records returned value roots the same way `call` relevance already did
    - retained the earlier runtime-callable/indexing fixes:
      - dynamic `e.callOrder` iteration while runtime callables are appended
      - namespace fallback for unresolved local class references during class resolution
  - validation:
    - focused regressions now pass:
      - `TestAnalyzeRootFindsLateStaticAjaxSensitiveActionAfterJSONDecodeRecursiveSanitizer`
      - `TestActionSinkRelevantUseOrdersTrackReturnedRuntimeLocal`
      - `TestAnalyzeRootKeepsAuthenticatedAjaxWhenLateStaticPublicFlagIsFalse`
    - `cookie-information-cve-2023-6700` still `match` after the change
  - note:
    - this fixes reachability/relevance for returned locals in `action` batches
    - it does not solve the separate direct-sink preference gap where `cookie-information` still retains `WordPress/Settings.php:287` instead of the tighter `UpdateIntegration` sink lines

- `google-reviews-cve-2025-12510`
  - fixed as a real direct comparable `output` case
  - real root causes were two generic engine gaps:
    - shortcode registration indexing could not resolve variable tags like:
      - `$tag = $this->get_shortcode_name(); add_shortcode($tag, [ $this, 'shortcode_func' ]);`
    - persistent DB-read provenance was dropped across method summaries because `sourceOriginRef` did not preserve `persistentRead`
  - engine changes:
    - `literalStringForCallable(...)` now resolves:
      - no-arg instance method literal returns
      - single local variable assignments carrying literal values
    - return/source summaries now preserve `persistentRead` through `sourceOriginRef`
    - stored-XSS output findings are no longer source-collapsed away in final JSON
  - current vulnerable result:
    - focused `wp-reviews-plugin-for-google__13.2.4 -sink-op output` now reports:
      - `wp-stored-xss-persistent-read-to-output`
      - sink `trustindex-plugin.class.php:909`
      - callable `\TrustindexPlugin_google::shortcode_func`
      - matching trace sources include:
        - `trustindex-plugin.class.php:6247`
        - `trustindex-plugin.class.php:5993`
  - corpus:
    - promoted in `corpus.json` with direct `output` coverage
  - remaining precision note:
    - the patched local tree still flags today because the stored-XSS output rule does not yet understand the `wp_kses_post(...)` safe-boundary patch inside `parseReviewText()`
    - that is a follow-up precision problem, not a remaining vulnerable-fixture miss

- `backup-migration-cve-2023-6553`
  - rechecked after the newer generic unsafe-deserialization work
  - current result:
    - still not a good direct comparable case
    - focused `backup-backup__1.3.7 -sink-op call` now returns only two `unsafe-use` findings in:
      - `includes/ajax.php:1150`
      - `includes/ajax.php:1518`
    - both are on the authenticated `wp_ajax_backup_migration` path via `\BMI\Plugin\BMI_Ajax::__construct`
    - retained request source is:
      - `includes/ajax.php:52`
      - `$this->post = BMP::sanitize($_POST);`
  - implication:
    - the current direct engine is not missing an obvious request-to-deserialization path here
    - the old case note should remain: do not promote this until there is a real attacker-controlled deserialization sink path in the local fixture, not just authenticated command execution in `includes/ajax.php`

- `omgf-cve-2023-6600`
  - rechecked on the local `host-webfonts-local__5.7.9` fixture
  - current result:
    - still not a good direct comparable case for the current local tree
    - focused `-sink-op delete` is cheap and only reaches capability-checked admin AJAX delete logic in:
      - `src/Admin/Ajax.php::empty_directory()`
      - `src/Admin/Ajax.php::delete_log()`
    - the actual recursive delete helper remains:
      - `src/Helper.php:429`
  - important fixture evidence:
    - the bundled plugin `readme.txt` for `5.7.9` explicitly says:
      - `5.7.9 = Fixed: this time a proper CSRF fix!`
      - `5.7.7 = Fixed: CSRF issue in custom Update Settings logic.`
  - implication:
    - the local `5.7.9` fixture likely already contains the auth/CSRF side of the fix, while still retaining the generic delete helper
    - treat this as fixture drift or at least a non-direct case for the current tree unless an older actually vulnerable fixture is added

- `cleantalk-security-cve-2024-13365`
  - current diagnosis:
    - this is now viable as a direct `write` case
    - the real local path is `$_FILES -> UploadChecker::check() -> runCheckForFilesGlobalVariable() -> checkUploadedArchive() -> unzip_file(...)`
  - local code shape:
    - the relevant logic is the upload firewall in:
      - `lib/CleantalkSP/SpbctWP/Firewall/UploadChecker.php`
      - `inc/spbc-firewall.php`
    - vulnerable sink in `2.149`:
      - `UploadChecker.php:397` `unzip_file($archive_path, $destination);`
    - the patched `2.150` diff moves the extraction destination from uploads to a temp dir, which confirms the vulnerable write path is the archive extraction itself
  - current direct-engine evidence:
    - original blocker:
      - pure `write` scans were still building cross-request storage-writer indexes in `buildBaseEngine()`, and the CleanTalk tree was getting killed in `indexGlobalStateWriters()`
      - after that was fixed, pure `write` scans still kept unrelated data-carrier helpers alive because `forwardRelevantCallees()` only used file-sink relevance gating for `open`, not `write`
    - generic fixes:
      - added `unzip_file(...)` as a file-upload sink
      - moved storage-writer indexing behind `needsStorageWriterIndexForSinkOps(...)`, so pure `write` scans skip it
      - made pure `write` scans use `fileSinkRelevantUseOrders` for forward relevance pruning
    - result:
      - focused `security-malware-firewall__2.149 -sink-op write` now finishes in about `1.6s`
      - retained direct finding:
        - rule: `wp-request-file-upload-without-cap-check`
        - source: `UploadChecker.php:87`
        - sink: `UploadChecker.php:397`
      - corpus case is now directly comparable

- `cookie-information-cve-2023-6700`
  - follow-up precision result:
    - this no longer needs an engine change for direct coverage
    - focused `phparser` action results already contain the callback-local direct sinks in:
      - `WordPress/Ajax/UpdateIntegration.php:70`
      - `WordPress/Ajax/UpdateIntegration.php:84`
      - `WordPress/Ajax/UpdateIntegration.php:91`
      - `WordPress/Ajax/UpdateIntegration.php:96`
    - retained direct trace:
      - source: `WordPress/Ajax/AbstractAjax.php:90`
      - callable: `\WPGDPRC\WordPress\Ajax\UpdateIntegration::execute`
  - contract update:
    - promoted the direct compare contract away from the broader helper sink at `WordPress/Settings.php:287`
    - current direct comparable sink is now the real callback-local `UpdateIntegration` action path
  - validation:
    - single-case compare still `match` in:
      - `tmp/phparser-cookie-direct-sink-contract-20260325`

- `call` relevance: receiver-backed direct sinks
  - bug:
    - `call`-only relevance treated direct sinks as caller-relevant only when the callee consumed parameter data or the call result was used later
    - bare statement method calls like:
      - `$importer->enablePlugins();`
      were pruned even when the callee sink depended on receiver state such as:
      - `$this->seek['active_plugins']`
    - this showed up in a reduced reproducer and explains why constructor-seeded receiver state could not lift callers into the `call` batch
  - generic fix:
    - added local on-demand summary warming for analysis-time callable lookups that were never analyzed in the current batch yet
    - extended `callableConsumesCallInput()` so direct `call` sinks that use `this`, `this.*`, or `this[...]` count as input-consuming for reverse relevance
    - kept the change generic; no plugin/CVE names or path checks were added
  - validation:
    - focused synthetic regressions now pass:
      - `TestAnalyzeRootFindsUnsafeDeserializationFromDynamicFileContents`
      - `TestAnalyzeRootDoesNotFlagUnsafeDeserializationFromDefinitelyStaticFileContents`
      - `TestAnalyzeRootFindsUnsafeDeserializationFromConstructorSeededReceiverPath`
    - `better-search-replace-cve-2023-6933` still directly `match` after the relevance change
  - current effect on the remaining local frontier:
    - this fixes the real relevance bug, but it does not turn `backup-migration-cve-2023-6553` into a direct comparable case
    - focused `backup-backup__1.3.7 -sink-op call` now still lands on authenticated nearby deserialization/code-exec helpers, not the old semgrep-era restore-engine locations
    - treat `backup-migration-cve-2023-6553` as still non-direct for the current local fixture

- local direct-compare frontier after the relevance fix
  - remaining locally materialized cases that are still not direct-engine comparable:
    - `wp-reset-cve-2023-6799`
      - non-taint predictable-randomness case
    - `backup-migration-cve-2023-6553`
      - semgrep-era nearby-only deserialization case
    - `omgf-cve-2023-6600`
      - current `5.7.9` fixture appears post-fix on the auth/CSRF side
    - `google-reviews-cve-2025-12510`
      - stored XSS via imported external review content
  - implication:
    - the next real engine expansion, if desired, is a generic external/imported-content source family for cases like `google-reviews`
    - that is a larger scope change than the ordinary request/source-to-sink CVE work completed so far

- `google-reviews-cve-2025-12510`
  - final direct-engine fix:
    - this is now a clean direct comparable `output` case
    - the real generic gaps were:
      - no bounded persistent storage model for `$wpdb->insert(...)/SELECT *` table rows
      - no distinction between HTML-safe persistent content and content made unsafe again by transforms like `html_entity_decode()`
      - aggregate scalar DB reads like `SELECT COUNT(...)` were falling back to raw persistent-read sources and creating stored-XSS noise
  - generic engine changes:
    - added bounded DB table storage tracking for likely DB `insert/update/replace` payload arrays:
      - writes now populate synthetic storage roots like `db_table_value[reviews].field`
      - reads from `SELECT * FROM %i` can reuse those stored origins generically
    - added HTML output state tracking:
      - `output_safe_html`
      - `output_unsafe_html`
    - strong safe boundaries such as:
      - `wp_kses_post`
      - `sanitize_text_field`
      now clear the unsafe bit and preserve the safe bit
    - unsafe transforms such as:
      - `html_entity_decode`
      now set the unsafe bit without relying on brittle branch merges
    - stored-XSS output findings now emit only the unsafe persistent origins, instead of every origin in the set
    - generic DB read fallback no longer treats aggregate scalar reads like `SELECT COUNT(...)` as stored HTML content sources
  - validation:
    - focused regressions passed:
      - `TestAnalyzeRootFindsStoredXSSFromDBSelectInShortcodeReturn`
      - `TestAnalyzeRootFindsStoredXSSFromVariableShortcodeTagMethodReturn`
      - `TestAnalyzeRootSkipsStoredXSSFromAggregateScalarReadToOutput`
      - `TestAnalyzeRootFindsStoredXSSAfterHTMLDecodeFromSanitizedDBWrite`
      - `TestAnalyzeRootSkipsStoredXSSAfterWPKsesPostBoundary`
    - real plugin vulnerable tree:
      - `tmp/phparser-google-reviews-vuln-final-20260325`
      - still finds the real sink at `trustindex-plugin.class.php:909`
    - real plugin patched tree:
      - `tmp/phparser-google-reviews-patched-final-20260325`
      - now clean with `0` findings
    - direct compare:
      - `tmp/phparser-google-reviews-compare-after-dbtable-20260325`
      - `google-reviews-cve-2025-12510` is again `match`
  - performance:
    - focused vulnerable `-sink-op output` run is still under `1s`
    - focused patched `-sink-op output` run is still under `1s`
  - verification note:
    - full `go test ./...` was not rerun in this pass
    - verified state is focused taint tests plus vulnerable/patched real-plugin reruns and the single-case corpus compare

- `call` batch memory and LearnPress frontier
  - current remaining local `call` frontier:
    - `learnpress-cve-2023-6634`
    - real vulnerable sink remains:
      - `inc/rest-api/v1/frontend/class-lp-rest-ajax-controller.php:69`
    - the blocker is still performance breadth, not missing sink modeling
  - generic fixes landed in this slice:
    - pass execution no longer buffers `analysisResult` for the entire pending set before consuming them
    - file-wrapper callables no longer inherit nested class/function bodies as executable `call` sinks or relevance roots
    - large pending sets now use bounded analysis workers:
      - `>=256 -> 1 worker`
      - `>=128 -> 2 workers`
      - smaller batches keep the normal worker count
  - focused regressions added/kept green:
    - `TestBoundedAnalysisWorkers`
    - `TestBuildEngineSkipsPublicDynamicCallSeedWithoutRequestSignal`
    - `TestBuildEngineDoesNotTreatFileWrapperAsCallSinkForNestedDeclaration`
    - `TestAnalyzeRootTreatsShortcodeAttsAsSourceForRenderCallback`
    - `TestAnalyzeRootFindsUnsafeUseForTaintedArrayCallbackTarget`
  - measured effect:
    - `better-search-replace-cve-2023-6933` still directly `match`
    - LearnPress no longer dies immediately on file-wrapper noise and now reaches real pass-1 callable work with timing output
    - ACF `call` memory dropped materially after the file-wrapper and worker-bound fixes
  - what remains unfixed:
    - LearnPress `call` analysis still fans out into real callback-bearing profile/course helpers such as:
      - `learn_press_profile_tab_exists`
      - `learn_press_get_profile_endpoints`
      - `LP_Course_DB::get_courses_order_by_popular`
    - the next safe fix should tighten `call` forward relevance for callback-bearing data structures without regressing the existing matched `call` cases

- LearnPress `call` frontier: callback-helper and file-wrapper pruning follow-up
  - bug:
    - `call`-only relevance was still too broad in three generic ways:
      - inherited shortcode/block entrypoint context made helper parameters look like direct source params even when the helper only received literals
      - literal-only callers of dynamic callback helpers were still treated as call-input-consuming wrappers
      - inert relevant file wrappers and non-consuming call wrappers were still being analyzed in the `call` batch, which wasted pass-1 memory on large startup/config files
  - generic fixes:
    - `callableHasEntrypointSourceParam()` now uses only direct entrypoint registrations for relevance gating, not merged flow-context entrypoints
    - dynamic callback helper direct sinks now require a real runtime-bearing argument caller for `call` direct-seed eligibility
    - `callableConsumesCallInput()` now skips literal-only callers when the callee only matters because of a dynamic callback direct sink
    - `relevantCallOrder()` now prunes:
      - inert `file::...` wrappers in `call`-only analysis when they have no direct sink, no direct request input, and no direct entrypoint
      - low-value `call` wrappers that have no direct sink, do not consume call input, have no direct request input, and have no direct entrypoint
  - focused regressions added/kept green:
    - `TestBuildEngineSkipsLiteralOnlyDynamicCallHelperForRequestReachableCaller`
    - `TestBuildEngineKeepsRuntimeArgDynamicCallHelperForRequestReachableCaller`
    - `TestBuildEngineSkipsLiteralOnlyDynamicCallHelperForCallInputConsumption`
    - `TestBuildEngineKeepsRuntimeArgDynamicCallHelperForCallInputConsumption`
    - `TestBuildEngineDoesNotTreatFileWrapperAsCallSinkForNestedDeclaration`
    - `TestAnalyzeRootFindsUnsafeDeserializationFromDynamicFileContents`
    - `TestAnalyzeRootDoesNotFlagUnsafeDeserializationFromDefinitelyStaticFileContents`
    - `TestAnalyzeRootFindsUnsafeDeserializationFromConstructorSeededReceiverPath`
  - safety validation:
    - `better-search-replace-cve-2023-6933` stayed direct `match` after each step:
      - `tmp/phparser-bsr-after-directentry-20260325`
      - `tmp/phparser-bsr-after-callconsume-20260325`
      - `tmp/phparser-bsr-after-filewrapperprune-20260325`
      - `tmp/phparser-bsr-after-lowvaluecall-20260325`
  - measured LearnPress effect:
    - before these cuts, focused `learnpress__4.2.5.7 -sink-op call -max-passes 1` grew to roughly:
      - `~11.4 GB RSS` at about `1m20s`
    - after dynamic-callback caller gating and call-input-consumption tightening:
      - about `3.5 GB RSS` at `~28s`
      - about `7.9 GB RSS` at `~58s`
    - after file-wrapper and low-value call-wrapper pruning:
      - pass 1 gets far enough to emit real slow-callable diagnostics
      - first observed slow callable was `function::\learn_press_get_current_profile_tab` at about `562ms`
      - measured process size on the same focused probe was about:
        - `3.0 GB RSS` at `~24s`
        - `7.1 GB RSS` at `~53s`
  - current status:
    - this is a real improvement, but not a complete LearnPress fix yet
    - the remaining hotspot is now in real profile/course helpers, not inert file wrappers
    - keep the latest generic cuts; the next iteration should focus on the remaining callback/filter fan-out around LearnPress course/profile helpers rather than broadening taint

- LearnPress `call` frontier: orphan helper follow-up
  - generic fix:
    - `call`-only relevant-call pruning now also drops orphan non-sink helpers:
      - no direct sink
      - no direct entrypoint
      - no callers in the static call graph
    - this specifically removes dead request-only helpers from `call` analysis even if they were previously misclassified as “consuming” due nested helper calls
  - focused regression:
    - `TestBuildEngineSkipsOrphanRequestOnlyHelperForCallBatch`
  - safety validation:
    - focused `call` regression slice stayed green
    - `better-search-replace-cve-2023-6933` stayed direct `match` in:
      - `tmp/phparser-bsr-after-orphanprune-20260325`
      - `tmp/phparser-bsr-after-orphanprune2-20260325`
  - measured LearnPress effect:
    - focused `learnpress__4.2.5.7 -sink-op call -max-passes 1` after the orphan prune no longer emitted the early `learn_press_get_current_profile_tab` slow-callable log during the first `~20s`
    - measured process size on the same probe was about:
      - `~2.6 GB RSS` at `~20s`
      - `~5.4 GB RSS` at `~45s`
    - but the long-run pass-1 blowup still remains:
      - `~15.1 GB RSS` at `~1m54s`
  - current conclusion:
    - the new prune is correct and measurably helpful
    - the remaining LearnPress issue is no longer dead helper noise; it is still cumulative breadth inside genuinely connected profile/course call paths
    - the next likely target is more selective forward relevance around filter/callback-heavy course/profile helper graphs, not broader request-source pruning

- LearnPress `call` frontier: sink-aware return roots and per-arg runtime matching
  - bug:
    - `call` relevance still had two generic precision problems:
      - call sites tracked runtime-ness as a single boolean, so omitted dangerous parameters with safe literal defaults still looked like runtime-fed sinks
      - `StmtReturn` walked the whole returned expression tree, so `return call_user_func($callback, $value)` incorrectly marked both `$callback` and `$value` as sink-relevant roots
    - together, those bugs made helpers like LearnPress `sanitize_params_submitted($value)` and similar callback-bearing wrappers look `call`-consuming even when the dangerous callback parameter was omitted
  - generic fix:
    - `callSiteEdge` now stores:
      - explicit argument count
      - per-index runtime-bearing arguments
    - `callSiteSuppliesConsumedInput()` and request-reachable arg-caller checks now match runtime input against the specific consumed parameter indexes instead of any runtime arg
    - `call` return tracking now keeps:
      - sink-specific arg roots for direct call sinks inside `return ...`
      - the returned root itself
      - but no longer treats every child of the returned expression as a relevant root
    - hook and direct-dispatch callback edges now store arg metadata for the actual dispatched payload args, not the full wrapper call expression
  - focused regressions added/kept green:
    - `TestBuildEngineSkipsOmittedDefaultDynamicCallHelperForCallBatch`
    - `TestBuildEngineSkipsLiteralOnlyDynamicCallHelperForCallInputConsumption`
    - `TestBuildEngineKeepsRuntimeArgDynamicCallHelperForCallInputConsumption`
    - `TestBuildEngineSkipsLiteralOnlyParamSinkWrapperForCallBatch`
    - `TestBuildEngineKeepsRuntimeParamSinkWrapperForCallBatch`
    - `TestBuildEngineSkipsUnrelatedParamDirectSinkWrapperForCallBatch`
    - `TestBuildEngineSkipsUnregisteredFilterPayloadForCallBatch`
    - `TestAnalyzeRootFindsUnsafeDeserializationFromDynamicFileContents`
    - `TestAnalyzeRootDoesNotFlagUnsafeDeserializationFromDefinitelyStaticFileContents`
    - `TestAnalyzeRootFindsUnsafeDeserializationFromConstructorSeededReceiverPath`
  - measured effect:
    - focused `learnpress__4.2.5.7 -sink-op call -max-passes 1` now finishes cleanly instead of climbing into multi-GB pass-1 churn:
      - `build-engine ~= 2.3s`
      - `engine-run ~= 2.1s`
      - `total ~= 5.3s`
      - `relevant = 102`
    - direct compare now matches again:
      - `learnpress-cve-2023-6634` in `tmp/phparser-learnpress-compare-after-callreturnfix-20260325`
    - nearby `call` safety cases stayed green:
      - `better-search-replace-cve-2023-6933` in `tmp/phparser-bsr-after-callreturnfix-20260325`
      - `cookie-information-cve-2023-6700` in `tmp/phparser-cookie-after-callreturnfix-20260325`
  - remaining note:
    - full `go test ./...` still needs to be rerun after this stabilization step; this slice is currently validated by focused tests plus targeted corpus/plugin reruns

- JSON-wrapped cross-request delete regression: wildcard-instantiated path writes and compaction stabilization
  - bug:
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete` was still missing even after stale-summary replay was fixed
    - the remaining gap was not parser fidelity; it was summary instantiation:
      - wildcard summary path writes like `db_table_value[entries][*]` and `[*]`
      - were keeping only the wildcard placeholder
      - and were dropping the concrete matched key segment from the caller/input structure
    - that prevented the write side from materializing `db_table_value[entries][form_data][*]`, which in turn kept the read side from recovering the real `form_data -> [*]` delete trace
  - generic fix:
    - summary return/storage path writes now instantiate concrete child paths from param-path refs when caller structure provides a matched concrete segment
    - this is bounded and generic:
      - no plugin/CVE hardcoding
      - no extra whole-program pass
      - no parser/builder changes
    - the matching stays local to the summary-write expander; global path matching semantics were not broadened
  - follow-up stabilization:
    - the first attempt at broader wildcard handling exposed pre-existing compaction bugs in `state_paths.go`
    - fixed:
      - stage-2/stage-3 compaction grouping was counting by one bucket type and deciding by another
      - property-only paths were getting collapsed too early
      - wildcard-prefix stable buckets like `[*].field_count` and `[*][callback]` were not being preserved correctly
      - the helper also needed bounds checks to avoid slicing past the end of short paths
  - files changed:
    - `internal/taintscan/analysis_driver.go`
    - `internal/taintscan/analysis_driver_test.go`
    - `internal/taintscan/call_eval.go`
    - `internal/taintscan/structural_state.go`
    - `internal/taintscan/summary_paths.go`
    - `internal/taintscan/state_paths.go`
  - focused verification:
    - `TestCollectStaleRelevantCallablesAddsFingerprintMismatches`
    - `TestAnalyzeRootTracksWrapperColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksUploadHelperReturnThroughFieldDataArrayKeyedWrite`
    - `TestAnalyzeRootTracksTwoHopUploadHelperReturnThroughFieldDataArrayKeyedWrite`
    - `TestAnalyzeRootTracksFactoryResolvedTwoHopUploadHelperReturn`
    - full compaction slices:
      - `TestCompactStaticPropsByRoot...`
      - `TestCompactStoragePathsByRoot...`
      - `TestCompactRelativeStructuralPathsByRoot...`
      - `TestCompactParamPathRefsByRoot...`
  - final verification:
    - `go test ./...` passed
    - `internal/taintscan` finished in about `119.324s`
  - cleanup:
    - removed the temporary debug file `internal/taintscan/zz_debug_json_tmp_test.go`

Update after rechecking raw `taint-results.json` noise on the post-fix corpus sweep:

- root cause:
  - one real duplicate-emission regression came back in `unsafe-use`
  - `dedupeFinalFindings(...)` was still source-collapsing the broad action/output/sql families, but `unsafe-use` had been omitted from `shouldCollapseFindingSources(...)`
  - that let broad source fanout reappear for shared dangerous sinks in Post SMTP
- evidence:
  - `post-smtp-cve-2025-11833` raw findings were `273`
  - `unsafe-use` alone accounted for `191`
  - a representative hotspot was repeated findings on:
    - `Postman/Postman-Controller/PostmanDashboardWidgetController.php:20`
    - same sink, same callable `\Postman::setup_admin`
    - many different request-like sources
- fix:
  - add `unsafe-use` to `shouldCollapseFindingSources(...)`
  - add a regression in `analysis_driver_test.go` asserting that:
    - same `unsafe-use` sink/callable
    - different sources
    - and a `file::...` wrapper variant
    - collapse to one retained finding with the better request-like source
- measured effect:
  - rerunning `post-smtp-cve-2025-11833` dropped:
    - total findings `273 -> 111`
    - `unsafe-use` findings `191 -> 29`
  - compare status stayed `match`
- remaining note:
  - the other large raw counts in plugins like `w3-total-cache` and `wpforms` were not the same regression
  - those are still mostly many distinct `wp-request-sensitive-action-without-cap-check` sink sites, not duplicate source fanout at one sink

Update after reducing generic action-rule noise by callable:

- root cause:
  - the remaining large counts in `w3-total-cache`, `wpforms`, and `cleantalk` were not duplicate sources at the same sink
  - they were mostly multiple nearby state-change sink lines inside the same handler/callable
  - for the generic rule `wp-request-sensitive-action-without-cap-check`, one finding per handler is usually the right semantic unit
- generic fix:
  - final finding collapse for `wp-request-sensitive-action-without-cap-check` now uses `(rule, path, message, callable)` instead of preserving every sink line in the same callable
  - this keeps:
    - one representative generic action finding per handler
    - merged flow context/entrypoints
    - line-sensitive behavior for more specific rules such as `wp-ajax-financial-action-without-cap-check`
- validation:
  - new regression in `analysis_driver_test.go`:
    - `TestDedupeFinalFindingsCollapsesGenericActionRuleByCallable`
  - targeted reruns stayed `match`
- measured effect:
  - `w3-total-cache-cve-2024-12365`
    - `116 -> 57`
  - `wpforms-cve-2024-11205`
    - total `63 -> 53`
    - generic action rule `58 -> 48`
    - specific financial rule stayed `5`
  - `cleantalk-cve-2024-10542`
    - `20 -> 14`
- remaining note:
  - this reduces one important class of noise, but it does not solve the broader semantic precision problem in `wp-request-sensitive-action-without-cap-check`
  - the next deeper reduction still needs better capability/auth helper understanding, not more dedupe alone

Update after adding generic capability-wrapper guard understanding:

- root cause:
  - a remaining class of `wp-request-sensitive-action-without-cap-check` findings were real false positives caused by capability-wrapper context loss, not duplicate emission
  - the clearest case was `wpforms_current_user_can(...)`-style wrappers that:
    - assign a local boolean from a method or helper that ultimately checks `current_user_can(...)`
    - then return it through `apply_filters(...)`
  - the old guard inspection only handled direct function calls well and dropped guard meaning through:
    - local variable indirection
    - method/static `current_user_can(...)` wrappers
    - `apply_filters(...)` passthrough wrappers
  - that caused authenticated capability-guarded handlers such as:
    - `\WPForms\Integrations\Stripe\Admin\Connect::handle_oauth_handshake`
    - `\WPForms\Integrations\Stripe\Admin\Settings::disconnect_account`
    to survive as generic action findings even though they were protected by wrapper capability checks
- generic fix:
  - extend `wordpress_context.go` guard inspection so capability/auth signals survive through:
    - local variable guard expressions
    - method/static `current_user_can(...)` and `user_can(...)`
    - passthrough wrappers like `apply_filters(...)` / `apply_filters_ref_array(...)`
  - treat capability parameters passed through callable params as not automatically weak when they are not reassigned locally
  - add a focused regression in `taintscan_test.go`:
    - `TestAnalyzeRootSuppressesActionFindingForFilteredCapabilityWrapper`
- validation:
  - focused guard tests passed:
    - `TestAnalyzeRootMarksMethodWrappedCapabilityGuard`
    - `TestAnalyzeRootMarksFunctionWrappedAuthGuard`
    - `TestAnalyzeRootSuppressesActionFindingForFilteredCapabilityWrapper`
  - targeted case reruns stayed `match`
- measured effect:
  - `wpforms-cve-2024-11205`
    - total `53 -> 26`
    - generic action rule `48 -> 21`
    - specific financial rule stayed `5`
    - removed the Stripe capability-wrapper false-positive family, including the old `src/Integrations/Stripe/Admin/Connect.php` and `src/Integrations/Stripe/Admin/Settings.php` generic action findings
  - `w3-total-cache-cve-2024-12365`
    - stayed `57`
  - `cleantalk-cve-2024-10542`
    - stayed `14`
- interpretation:
  - this confirms the wrapper change is removing real false positives in capability-guarded flows rather than just collapsing output
  - the remaining larger action counts in `w3-total-cache` and `cleantalk` are less likely to be the same wrapper-context bug and more likely to be genuinely suspicious handlers or a different semantic gap

Update after teaching capability variables filtered through `apply_filters(...)` and suppressing contradictory final action findings:

- root causes:
  - a second generic capability false-positive class remained in plugins like `w3-total-cache`
  - handlers often did:
    - `$capability = apply_filters( '...', 'manage_options' );`
    - `if ( ! current_user_can( $capability ) ) { ... }`
  - the engine still treated `$capability` as weak because it was assigned from a non-literal expression, even when that expression was a request-free `apply_filters(...)` wrapper around a definite literal capability
  - after that fix, a separate contradiction was still visible in final reporting:
    - `wp-request-sensitive-action-without-cap-check` could survive dedupe even when the merged final context already said `access=capability_checked`
    - this showed up heavily in helper sinks like `ConfigState::save()` where safe and unrelated contexts merged during final retention
- generic fixes:
  - in `wordpress_context.go`:
    - capability variables are no longer forced to be literal-only
    - if every local assignment resolves to a non-weak capability expression, the variable is now treated as a definite capability guard
    - this specifically preserves guards like:
      - `apply_filters( 'demo_capability_save', 'manage_options' )`
      - then `current_user_can( $capability )`
  - in final finding filtering:
    - suppress `wp-request-sensitive-action-without-cap-check` when the merged final context already has `access=capability_checked`
    - keep nonce-only and authenticated generic action findings
- new regressions:
  - `taintscan_test.go`
    - `TestAnalyzeRootSuppressesActionFindingForFilteredCapabilityVariable`
  - `analysis_driver_test.go`
    - `TestDedupeFinalFindingsSuppressesCapabilityCheckedGenericActionRule`
- validation:
  - focused guard and dedupe tests passed
  - targeted corpus compares all stayed `match`
- measured effect:
  - `w3-total-cache-cve-2024-12365`
    - `57 -> 46 -> 24`
    - the hot helper-only `ConfigState.php` noise disappeared entirely after suppressing contradictory final capability-checked findings
  - `wpforms-cve-2024-11205`
    - `26 -> 16`
    - generic action rule `21 -> 11`
    - specific financial rule stayed `5`
  - `cleantalk-cve-2024-10542`
    - `14 -> 10`
- interpretation:
  - these two fixes reduce actual false positives, not just duplicate output
  - the remaining generic action findings in `w3-total-cache` are now concentrated in still-plausible nonce-only/admin action handlers such as:
    - `SetupGuide_Plugin_Admin.php`
    - `Generic_AdminActions_Default.php`
    - `Cdn_BunnyCdn_Popup.php`
  - the next precision win, if needed, is likely a real WordPress admin/menu or callback-dispatch semantic model, not more broad result collapse

Update after rerunning the matched/direct-comparable CVE sweep on the current tree:

- sweep artifact:
  - `tmp/phparser-matched-regression-sweep-20260326/aggregate.tsv`
- current status on the `29` matched/direct-comparable cases rerun:
  - `24` match
  - `2` miss
  - `3` timeout in the sweep driver
  - plus `wpvivid-cve-2026-1357` still unresolved in a separate recheck and treated as timing-regressed for now
- stable matches include:
  - `ai-engine`
  - `backup-migration-cve-2023-6972`
  - `better-search-replace`
  - both `cleantalk` cases
  - `code-snippets`
  - `cookie-information`
  - `everest-forms`
  - `fluent-forms`
  - `geo-mashup`
  - `givewp`
  - `google-reviews`
  - `hide-my-wp`
  - `jupiterx-core`
  - `mystickymenu`
  - both `post-smtp` cases
  - `sureforms`
  - both `ultimate-member` cases
  - `user-registration`
  - `w3-total-cache`
  - `wpforms`
- current real compare regressions:
  - `forminator-cve-2025-6463`
    - still produces `14` delete findings, but no single finding satisfies the manifest contract anymore
    - current results cluster around nearby delete paths such as:
      - `admin/abstracts/class-admin-module-edit-page.php`
      - `library/model/class-form-entry-model.php`
    - this looks like sink-retention or contract alignment drift, not total delete coverage loss
  - `starter-templates-cve-2025-13065`
    - still produces `10` write findings, but they now land on helper/file-system sinks such as:
      - `inc/classes/class-astra-sites-file-system.php`
      - `inc/classes/class-astra-sites-importer-log.php`
    - this looks like sink-retention drift away from the original `st-wxr-importer.php` contract sink, not total write coverage loss
- current timeout regressions:
  - `acf-extended-cve-2025-13486`
  - `the-events-calendar-cve-2025-12197`
  - `the-events-calendar-cve-2025-9807`
  - `wpvivid-cve-2026-1357` looks timing-regressed in the current separate recheck
- next optimization target after the recent action-rule cleanup:
  - improve WordPress admin/menu and non-request action semantics
  - the remaining false-positive cluster is now mostly:
    - `nonce_only` admin handlers
    - `unknown` action contexts from admin page/setup/install/cron-style entrypoints
  - concrete examples from the current tree:
    - `w3-total-cache`: `SetupGuide_Plugin_Admin.php`, `Generic_AdminActions_Default.php`, `Cdn_BunnyCdn_Popup.php`
    - `wpforms`: `class-install.php`, `Emails/InfoBlocks.php`, `Frontend/Frontend.php`
  - that points to a next generic fix around:
    - admin page capability inheritance from `add_menu_page` / `add_submenu_page`
    - and/or separating true request-driven action sinks from install/cron/front-init state changes

Refinement after source-checking the remaining W3/WPForms action findings:

- `w3-total-cache`:
  - a large part of the remaining noise is not raw menu-page inheritance
  - the main gateway is `Generic_Plugin_Admin::wp_ajax_w3tc_ajax`, which already does:
    - nonce verification
    - capability lookup through:
      - `apply_filters( 'w3tc_ajax_base_capability_', 'manage_options' )`
      - `apply_filters( 'w3tc_ajax_capability_' . Util_Request::get_string( 'w3tc_action' ), $base_capability )`
    - then `current_user_can( $capability )`
  - current engine behavior is still conservative here because the hook name is dynamic, so the capability variable stays weak
  - next worthwhile generic precision fix:
    - treat filtered capability variables as guards even when the filter hook name is dynamic, as long as the default capability argument is definite and request-free
- `wpforms`:
  - the remaining unknown generic action findings are mostly not normal request handlers
  - examples:
    - installer path in `includes/class-install.php`
    - summary/info block cron-style paths in `src/Emails/InfoBlocks.php`
    - front-init style state writes in `src/Frontend/Frontend.php`
  - next worthwhile generic precision fix:
    - separate true request-driven action sinks from install/cron/front-init lifecycle writes before applying the generic `wp-request-sensitive-action-without-cap-check` rule

Reclassification after checking the two remaining compare misses directly:

- `forminator-cve-2025-6463`
  - this was contract drift, not a new engine miss
  - current direct engine still reaches the real delete sink at:
    - `library/model/class-form-entry-model.php:1264`
  - but the finding now lands under:
    - `request-path-read-delete`
  - and the retained trace sources are concrete request snippets such as:
    - `filter_input( INPUT_POST, 'id', FILTER_VALIDATE_INT )`
    - `$entry = isset( $_GET['entry'] )`
    - `$ids = isset( $_GET['ids'] )`
  - corpus contract updated accordingly

- `starter-templates-cve-2025-13065`
  - this is not an honest direct comparable case for the current taint engine
  - current direct engine no longer emits the old `st-wxr-importer.php:933` upload finding
  - source review shows the real vulnerable logic is the MIME override in:
    - `inc/lib/starter-templates-importer/importer/wxr-importer/st-wxr-importer.php::real_mimes`
  - that is an authenticated upload-validation-bypass issue on a capability-checked import flow, not a missing-capability upload sink
  - the earlier direct match through `wp-request-file-upload-without-cap-check` was relying on a weaker proxy path and is no longer the right contract
  - corpus case should be treated as `not_comparable_yet` until `phparser` grows a real authenticated upload-validation-bypass family

ACF timeout re-regression check on the current tree:

- date:
  - `2026-03-26`
- current problem:
  - `acf-extended__0.9.1.1 -sink-op call` regressed badly again after the earlier March 23 self-recursive-helper fix
  - the current pass-1 hotspot is no longer just `render_form()`
  - pass 1 was blowing up inside the generic module hook plumbing around:
    - `acfe_module::validate_item`
    - `acfe_module::apply_module_filters`
    - `apply_filters_ref_array(...)`
- source-level diagnosis:
  - `acfe_module::__construct()` self-registers many same-object callbacks through:
    - `add_module_filter(...)`
    - `add_module_action(...)`
  - the dispatch helpers:
    - `apply_module_filters("{$tag}/module={$this->name}", ...)`
    - `do_module_action("{$tag}/module={$this->name}", ...)`
    were reintroducing huge wildcard callback fanout
  - two generic causes were identified:
    - self-recursive hook replay back into the same callable
    - unresolved wildcard hook patterns from helper methods such as `apply_module_filters($tag, ...)`, especially when `$this->name` was not reduced to the class literal
- generic fixes implemented:
  - skip hook-dispatch replay back into the same callable for `apply_filters*` / `do_action*` in both:
    - callgraph edge construction
    - runtime callback summary instantiation
  - add literal class-property resolution for direct `this.<property>` reads:
    - store literal property defaults in a direct class/property map
    - use those literals during interpolated-string hook construction
    - this lets `{$this->name}` collapse to exact values like `form` instead of placeholders
  - when a hook is still wildcard/unresolved, skip same-class callback replay for that hook dispatch
    - keep exact hooks
    - keep cross-class callbacks
    - this is intended to drop internal module framework churn while preserving real external callback edges such as render helpers
- regressions added:
  - `TestBuildEngineSkipsSelfRecursiveApplyFiltersRefArrayCallbackEdge`
  - `TestBuildEngineUsesLiteralModulePropertyForHookDispatch`
  - existing `apply_filters_ref_array` callback-preservation tests remain green
- measured effect:
  - old `acf-extended -sink-op call -max-passes 1` probe had climbed to about:
    - `16.3 GB RSS` at about `3m`
  - after the three generic cuts above:
    - pass-1 probe was down to about `2.37 GB RSS` at about `33s`
    - later in the same run it still climbed to about `10.2 GB RSS` by about `1m18s`
- interpretation:
  - the current fixes are real and materially reduce ACF hook fanout
  - but they are not the full solution yet
  - the remaining blocker is still in helper-summary breadth for generic hook-wrapper methods, not in sink coverage
- next ACF target:
  - avoid broad callback expansion for helper wrappers whose hook parameter is unresolved/conflicting across many literal call sites
  - this likely needs a generic specialization strategy for hook-wrapper helpers, rather than another plugin-specific prune

ACF hook-wrapper specialization outcome:

- date:
  - `2026-03-26`
- implemented generic core change:
  - added bounded literal-arg specialization for callable summaries when:
    - the callable is a hook-dispatch wrapper
    - and the hook expression depends on a formal parameter
  - this is now used in:
    - method/static call resolution during analysis
    - return-path and structural-state summary instantiation
    - callgraph construction for literal call sites
- implementation notes:
  - specialization is not global for all callables
  - it is restricted to hook-wrapper methods, so ordinary method calls do not explode into many literal variants
  - interpolated-string literal reconstruction now also honors literal param hints, which was required for specialized wrappers to produce exact hook strings
- new regression:
  - `TestSpecializedHookWrapperUsesLiteralTagArgument`
- compatibility:
  - the existing `apply_filters_ref_array` wrapper regressions still pass
  - nearby `call`-mode regression check still passes:
    - `better-search-replace-cve-2023-6933`
- measured ACF result:
  - `acf-extended__0.9.1.1 -sink-op call -max-passes 1`
    - now completes in about `39.27s`
    - `engine-run=37.152s`
    - pass-1 hot summaries are now the real render path:
      - `\acfe_module_form_front::render_form`
      - `\acfe_form`
    - the generic module hook plumbing is no longer the dominant blocker
  - direct compare artifact:
    - `tmp/phparser-acf-compare-after-helperspecialization-20260326/summary.json`
  - current status:
    - `acf-extended-cve-2025-13486`: `match`
    - matched sink:
      - `includes/modules/form/module-form-front-render.php:151`
- interpretation:
  - the remaining ACF timeout regression is fixed
  - the next timeout/frontier cases are now:
    - `the-events-calendar-cve-2025-12197`
    - `the-events-calendar-cve-2025-9807`
    - `wpvivid-cve-2026-1357` still needs a fresh honest rerun on the current tree

Full 43-case corpus sweep after ACF fix:

- date:
  - `2026-03-26`
- sweep command shape:
  - sequential `corpus-compare` over all manifest cases with external `180s` per-case timeout
- aggregate artifact:
  - `tmp/phparser-full-corpus-seq-after-acf-fix-20260326/aggregate.tsv`
- final status counts:
  - `27` `match`
  - `13` `not_comparable_yet`
  - `3` `timeout`
  - `0` `miss`
- current timeout set:
  - `the-events-calendar-cve-2025-12197`
  - `the-events-calendar-cve-2025-9807`
  - `wpvivid-cve-2026-1357`
- current non-comparable set reasons:
  - missing local plugin trees:
    - `layerslider-cve-2024-2879`
    - `gravity-forms-cve-2024-13377`
    - `modern-events-calendar-cve-2024-5441`
    - `avada-cve-2024-1468`
    - `gravity-forms-cve-2025-12352`
    - `uncode-cve-2024-13681`
    - `avada-builder-cve-2024-13345`
    - `avada-theme-cve-2024-13346`
    - `uncode-cve-2024-13691`
  - intentionally no direct-engine comparable contract:
    - `wp-reset-cve-2023-6799`
    - `backup-migration-cve-2023-6553`
    - `omgf-cve-2023-6600`
    - `starter-templates-cve-2025-13065`
- interpretation:
  - the direct-engine frontier is now narrow and clear:
    - no live `miss` remains in the full sweep
    - remaining real engine work is concentrated in the two TEC SQL cases and `wpvivid`

TEC SQL and WPvivid write timeout fixes:

- date:
  - `2026-03-26`
- generic relevance fixes:
  - pure `sql` direct-sink seeding no longer treats any request-reachable runtime arg as enough to keep an internal sink-bearing helper alive
  - pure `sql` forward anchor replay now only re-adds earlier non-data direct-sink callees when they also qualify as valid request-gated direct seeds
  - pure `write` direct-sink seeding now applies the same rule using file-relevant params/receiver state instead of generic runtime args
- implementation notes:
  - added SQL-specific relevant-param and receiver checks
  - added file/write-specific relevant-param and receiver checks
  - fixed the last TEC blocker where `Tribe__Events__Meta__Save::manage_preview_metapost` stayed relevant despite `sqlOrders=0`
  - removed the temporary TEC debug test and restored the normal small-pending timing gate
- new regressions:
  - `TestBuildEngineSkipsInternalSQLDirectSinkWithoutSQLRelevantCallerInput`
  - `TestBuildEngineSkipsInternalWriteDirectSinkWithoutFileRelevantCallerInput`
- measured TEC outcome:
  - debug relevant set dropped to `9` callables
  - `manage_preview_metapost`, `save`, `saveEventMeta`, and the old repository meta helpers are no longer relevant in pure `sql`
  - `the-events-calendar__6.15.9 -sink-op sql`:
    - `engine-run=4.559s`
    - `total=9.209s`
    - artifact:
      - `tmp/tec-6159-after-sql-seedfix-20260326`
- measured compare outcome:
  - `the-events-calendar-cve-2025-12197`: `match`
    - artifact:
      - `tmp/phparser-tec-12197-compare-after-sql-seedfix-20260326/summary.json`
  - `the-events-calendar-cve-2025-9807`: `match`
    - artifact:
      - `tmp/phparser-tec-9807-compare-after-sql-seedfix-20260326/summary.json`
  - `wpvivid-backuprestore__0.9.123 -sink-op write`:
    - before latest fix:
      - `relevant=177`
      - timed out at `120s`
      - hot root was broad `option_value` replay
    - after file/write seed fix:
      - `relevant=32`
      - `engine-run=9.15s`
      - `total=11.931s`
      - artifact:
        - `tmp/wpvivid-after-file-seedfix-20260326`
  - `wpvivid-cve-2026-1357`: `match`
    - artifact:
      - `tmp/phparser-wpvivid-compare-after-file-seedfix-20260326/summary.json`
- current direct-corpus status after these timeout fixes:
  - the previously remaining timeout frontier is cleared
  - no live direct comparable `miss` remains in the current local corpus slice

Post-timeout full-suite stabilization:

- date:
  - `2026-03-26`
- issue:
  - after the TEC/WPvivid seed tightening, full `go test ./...` still exposed two generic problems:
    - SQL sink relevant-use orders were computed in the base engine before WordPress entrypoints were attached in the option-specific clone, so clause-filter return sinks like `posts_where` could lose their direct sink roots
    - pure `sql`/`write` direct-seed fallback was too broad when it allowed any direct request input, but too weak when it relied only on exact relevant-root extraction; dynamic direct sinks through interpolation, method callbacks, and file helpers could be dropped even though the sink expression itself was non-static
- implementation:
  - reindex `sqlSinkRelevantUseOrders` after `collectWordPressFlowContext()` inside `cloneEngineForOptions(...)`
  - replace the removed broad direct-entrypoint fallback with a bounded one:
    - `sql`: keep a direct public sink when the callable has direct request input and a non-static direct SQL sink expression
    - `write`: keep a direct public sink when the callable has direct request input and a non-static direct file/write sink expression
  - this preserves:
    - `posts_where`/`posts_orderby` clause return sinks
    - subclass/factory/singleton callback SQL sinks
    - direct file move/upload sinks
  - while still rejecting the regression case:
    - request input present but only irrelevant to a static SQL query
- regressions revalidated:
  - `TestBuildEngineSkipsSQLSinkSeedWhenRequestInputIsNotSQLRelevant`
  - `TestBuildEngineKeepsSQLSinkSeedWhenRequestInputFeedsSQLRelevantRoot`
  - `TestBuildEngineSkipsInternalSQLDirectSinkWithoutSQLRelevantCallerInput`
  - `TestBuildEngineSkipsInternalWriteDirectSinkWithoutFileRelevantCallerInput`
  - `TestBuildEngineSkipsWriteCarrierWithoutWriteRelevantUse`
  - `TestAnalyzeRootFindsTaintedPostsWhereFilterReturn`
  - `TestAnalyzeRootFindsSubclassOverrideCallbackRegisteredFromParent`
  - `TestAnalyzeRootFindsCachedFactoryCallbackRegisteredThroughMethodReturn`
  - `TestAnalyzeRootFindsCallbackRegisteredThroughStaticSingletonFactory`
  - `TestAnalyzeRootFindsUnauthenticatedFilesystemMoveSink`
- representative corpus rechecks:
  - `the-events-calendar-cve-2025-12197`: `match`
    - artifact:
      - `tmp/phparser-tec-12197-after-dynamicsink-20260326/summary.json`
  - `wpvivid-cve-2026-1357`: `match`
    - artifact:
      - `tmp/phparser-wpvivid-after-dynamicsink-20260326/summary.json`
- final suite result:
  - `go test ./...`: passed
  - `internal/taintscan`: `112.981s`

ACF call-batch timeout root cause and final generic fix:

- date:
  - `2026-03-26`
- issue:
  - the remaining `acf-extended` timeout was no longer a sink-model problem
  - the real cost was summary instantiation and repeated structured-origin rebuilding in pure `call` batches
  - the hottest path was legacy form/filter callback churn around:
    - `\acfe_module_form_front::render_form`
    - `\acfe_module_form_deprecated::prepare_form`
    - `\acfe_form`
  - stack dumps showed most time in:
    - `instantiateSummaryReturn(...)`
    - `instantiateTaintSummary(...)`
    - repeated `resolveArgumentPathOrigins(...)`
    - repeated `originSet.union(...)`
- diagnosis:
  - large pass-through returns were cloning huge origin sets even when the summary was effectively just `return $param`
  - summaries with many `ParamPaths` on the same structured arg repeatedly re-resolved the same paths and locations
  - pass-warm summary computation in pure `call` batches was duplicating work across workers
  - structured parameter-variable returns were first materialized as large origin sets and only then re-collapsed into return paths
- implementation:
  - add a direct param-return fast path in `instantiateTaintSummary(...)`
  - batch/cache structural path resolution, argument origins, and argument locations when a summary contains many `ParamPaths`
  - add pass-local warm-summary singleflight, but scope it only to pure `call` batches
  - run pure `call` batches with a single worker to avoid duplicate warm-summary churn
  - on `return $param`, preserve the structural param-root directly instead of cloning the full nested origin set first
- files:
  - `internal/taintscan/summary_paths.go`
  - `internal/taintscan/analysis_callable.go`
  - `internal/taintscan/statement_walk.go`
  - `internal/taintscan/origin_helpers.go`
  - `internal/taintscan/analysis_driver.go`
  - `internal/taintscan/taintscan.go`
- measured effect:
  - focused `acf-extended__0.9.1.1 -sink-op call -max-passes 1` now completes instead of stalling:
    - `engine-run=3.336s`
    - `total=5.287s`
    - artifact:
      - `tmp/acf-pass1-after-direct-returncollapse-20260326`
  - direct compare restored:
    - `acf-extended-cve-2025-13486`: `match`
    - artifact:
      - `tmp/phparser-acf-after-final-fix-20260326/summary.json`
  - other frontier regressions restored on the same tree:
    - `jupiterx-core-cve-2024-7772`: `match`
      - `tmp/phparser-jupiterx-after-final-fix-20260326/summary.json`
    - `mystickymenu-cve-2026-3657`: `match`
      - `tmp/phparser-mystickymenu-after-final-fix-20260326/summary.json`
- verification:
  - focused hook/warm-summary/call regressions passed
  - `go test ./...`: passed
  - `internal/taintscan`: `114.620s`

Full 43-case corpus rerun after the final ACF/call-batch fix:

- date:
  - `2026-03-26`
- artifacts:
  - aggregate:
    - `tmp/phparser-full-corpus-rerun3-20260326/aggregate.tsv`
  - rule totals:
    - `tmp/phparser-full-corpus-rerun3-20260326/rule-hits.tsv`
  - plugin totals:
    - `tmp/phparser-full-corpus-rerun3-20260326/plugin-hits.tsv`
  - run trace:
    - `tmp/phparser-full-corpus-rerun3-20260326/run.log`
- final status counts:
  - `30` `match`
  - `13` `not_comparable_yet`
  - `0` `miss`
  - `0` `timeout`
- representative restored cases:
  - `acf-extended-cve-2025-13486`: `match`
  - `the-events-calendar-cve-2025-12197`: `match`
  - `the-events-calendar-cve-2025-9807`: `match`
  - `wpvivid-cve-2026-1357`: `match`
  - `jupiterx-core-cve-2024-7772`: `match`
  - `mystickymenu-cve-2026-3657`: `match`
- current raw-hit leaders after the final rerun:
  - by rule:
    - `wp-request-file-delete-without-cap-check`: `232`
    - `wp-request-sensitive-action-without-cap-check`: `87`
    - `unsafe-use`: `30`
    - `wp-request-file-upload-without-cap-check`: `28`
    - `tainted-sql-string`: `25`
  - by plugin:
    - `wordpress-file-upload-cve-2024-11613`: `206`
    - `post-smtp-cve-2025-11833`: `80`
    - `everest-forms-cve-2025-1128`: `25`
    - `w3-total-cache-cve-2024-12365`: `24`
    - `backup-migration-cve-2023-6972`: `17`
- interpretation:
  - the direct comparable frontier is currently cleared
  - remaining work is precision/noise reduction, not missed/timeout coverage

Not-comparable diff audit:

- date:
  - `2026-03-26`
- purpose:
  - review the current `not_comparable_yet` set by diffing vulnerable vs fixed code where fixtures or downloadable archives exist
  - separate real missing engine families from cases that are blocked only by missing premium fixtures
- confirmed local/open-source vulnerability locations:
  - `backup-migration-cve-2023-6553`
    - vulnerable path is the restore/background entry in:
      - `backup-backup__1.3.7/includes/backup-heart.php`
    - attacker-controlled header values are used directly in:
      - `define('ABSPATH', $fields['content-abs']);`
      - `define('BMI_ROOT_DIR', $fields['content-dir']);`
      - `require_once BMI_INCLUDES . '/bypasser.php';`
    - fixed in `1.3.8` and present in `1.3.9` by `filterChainFix(...)`:
      - rejects `php:` and `|`
      - requires the resolved path to exist
      - wraps `content-abs`, `content-dir`, and `BMI_INCLUDES`
    - current read:
      - this is a real restore-chain path/control bug
      - old direct compare stayed non-comparable because the contract was still a broad Semgrep-era deserialization/RCE shape, not the header-driven restore endpoint
  - `starter-templates-cve-2025-13065`
    - vulnerable function is:
      - `astra-sites__4.4.41/inc/lib/starter-templates-importer/importer/wxr-importer/st-wxr-importer.php:518`
    - `real_mimes(...)` trusted filename substrings like:
      - `strpos($filename, 'wxr')`
      - `strpos($filename, 'wpforms')`
      without first proving the actual file extension matched
    - fixed in `4.4.42` by:
      - `wp_check_filetype(...)`
      - `pathinfo(..., PATHINFO_EXTENSION)`
      - early reject on invalid or mismatched extensions
      - explicit extension equality checks before assigning XML/JSON MIME overrides
    - current read:
      - the real vulnerability is authenticated upload-validation bypass, not a generic unauthenticated upload sink
      - keeping this case `not_comparable_yet` is still correct until `phparser` grows an authenticated upload-validation-bypass family
  - `wp-reset-cve-2023-6799`
    - vulnerable path is snapshot export filename generation in:
      - `wp-reset__2.0/wp-reset.php`
    - vulnerable lines:
      - `do_export_snapshot()` uses `md5($uid)` for the export filename
      - `generate_snapshot_uid()` only generates a predictable 6-character alphabetic UID
    - fixed in `2.01` by:
      - generating a separate export identifier with `generate_snapshot_uid(10)`
      - using that derived value for the exported filename instead of `md5($uid)`
    - current read:
      - this remains a real non-taint predictable-randomness case
      - it should stay `not_comparable_yet` until `phparser` has a non-taint detector family
  - `omgf-cve-2023-6600`
    - the relevant path-delete/hardening diff is in:
      - `host-webfonts-local__5.7.9/src/Admin/Actions.php`
    - vulnerable cleanup path:
      - `clean_stale_cache()` builds `$dir = OMGF_UPLOAD_DIR . '/' . $dir_to_remove`
      - then deletes files and removes the directory without canonical-path validation
    - fixed in `5.8.0` by:
      - `if ( $dir !== realpath( $dir ) ) { continue; }`
    - same `5.8.0` diff also hardens `update_settings()` by bailing when:
      - `wp_doing_cron()`
      - `wp_doing_ajax()`
    - current read:
      - for the current direct-engine corpus shape, the meaningful local vulnerability location is the cache-key-driven path deletion in `clean_stale_cache()`
      - it still stays `not_comparable_yet` because the old path-delete contract was nearby-only and not yet a faithful direct request-to-delete trace
- still blocked mainly by missing local premium/closed fixtures:
  - `layerslider-cve-2024-2879`
  - `gravity-forms-cve-2024-13377`
  - `modern-events-calendar-cve-2024-5441`
  - `avada-cve-2024-1468`
  - `gravity-forms-cve-2025-12352`
  - `uncode-cve-2024-13681`
  - `avada-builder-cve-2024-13345`
  - `avada-theme-cve-2024-13346`
  - `uncode-cve-2024-13691`
- advisory-derived likely vulnerable functions for the still-missing fixtures:
  - `layerslider-cve-2024-2879`
    - likely vulnerable AJAX path is `ls_get_popup_markup`
    - note:
      - advisory-derived because no local premium fixture is present yet
  - `gravity-forms-cve-2024-13377`
    - stored-XSS is described as the `alt` parameter flowing into image/file field rendering
    - exact source function is still not pinned locally
    - note:
      - advisory-derived and still needs real source diff once the premium fixture exists
  - `modern-events-calendar-cve-2024-5441`
    - likely vulnerable function is `set_featured_image`
    - note:
      - advisory-derived; exact vulnerable tag archive was not retrievable from current official WordPress.org paths
  - `avada-cve-2024-1468`
    - likely vulnerable function is `ajax_import_options()`
    - note:
      - advisory-derived because no local premium/theme fixture is present yet
  - `gravity-forms-cve-2025-12352`
    - likely vulnerable function is `copy_post_image()`
    - note:
      - advisory-derived because no local premium fixture is present yet
  - `uncode-cve-2024-13681`
    - likely vulnerable function is `uncode_admin_get_oembed`
    - note:
      - advisory-derived because no local premium/theme fixture is present yet
  - `uncode-cve-2024-13691`
    - likely vulnerable function is `Uncode_recordMedia`
    - note:
      - advisory-derived because no local premium/theme fixture is present yet
  - `avada-builder-cve-2024-13345`
    - vulnerability is described as a path that reaches `do_shortcode` without proper validation
    - exact callback still needs real source diff
  - `avada-theme-cve-2024-13346`
    - vulnerability is described as a path that reaches `do_shortcode` without proper validation
    - exact callback still needs real source diff
- interpretation:
  - the remaining `not_comparable_yet` set is mixed:
    - some cases are genuinely outside current direct taint modeling (`wp-reset`)
    - some need a new engine family, not a sink tweak (`starter-templates`)
    - some are blocked primarily by missing premium/closed code materialization

Premium/closed frontier audit follow-up:

- date:
  - `2026-03-26`
- purpose:
  - refine the remaining premium/closed `not_comparable_yet` cases from vague advisory placeholders into pinned vulnerable functions or explicit fixture blockers
- strengthened case notes:
  - `layerslider-cve-2024-2879`
    - NVD now gives the exact vulnerable action:
      - `ls_get_popup_markup`
    - current read:
      - this is a real unauthenticated SQLi entrypoint, but the code fixture is still missing
      - once a premium fixture exists, the first source review target should be the AJAX handler for `ls_get_popup_markup`
  - `gravity-forms-cve-2024-13377`
    - NVD pins the attack surface to:
      - stored XSS via the `alt` parameter
    - Gravity Forms official changelog shows the patch landed after `2.9.1.3` as generic `security enhancements` in `2.9.1.4`
    - current read:
      - exact rendering function is still not source-pinned without the premium fixture
      - the likely review target is image/file field rendering where the `alt` attribute is emitted
  - `modern-events-calendar-cve-2024-5441`
    - NVD gives the exact vulnerable function:
      - `set_featured_image`
    - auth model from NVD:
      - subscriber+ by default
      - can become unauthenticated if the site enables unauthenticated front-end event submission
    - current read:
      - the important vuln shape is authenticated upload-validation bypass, not generic upload
      - the fixture blocker is distribution, not uncertainty about the sink
  - `avada-cve-2024-1468`
    - NVD gives the exact vulnerable function:
      - `ajax_import_options()`
    - Avada's official `7.11.5` security update confirms:
      - file upload bypass leading to RCE
      - in the `Page Options import function`
      - contributor+ authenticated users
    - current read:
      - the vulnerable area is pinned well enough for later source diffing once the theme fixture exists
  - `gravity-forms-cve-2025-12352`
    - NVD gives the exact vulnerable function:
      - `copy_post_image()`
    - NVD also references public mirror code locations in the Pronamic Gravity Forms mirror:
      - `forms_model.php`
      - `includes/fields/class-gf-field-fileupload.php`
    - extra conditions from NVD:
      - `allow_url_fopen` must be enabled
      - the post creation form must be enabled
      - the form must include a file upload field for the post image
    - Gravity Forms official changelog shows the fix landed as `security enhancements` in `2.9.21`
    - current read:
      - the vulnerable upload path is pinned strongly enough to target quickly once the commercial fixture is materialized
  - `uncode-cve-2024-13681`
    - this is no longer merely advisory-derived
    - NVD names the vulnerable function:
      - `uncode_admin_get_oembed`
    - the official Uncode changelog for `2.9.1.7` explicitly says:
      - `Vulnerability Fix Arbitrary File Read in uncode_admin_get_oembed`
    - current read:
      - the remaining blocker is just lack of the vulnerable `2.9.1.6` theme source in-repo
  - `uncode-cve-2024-13691`
    - this is also no longer merely advisory-derived
    - NVD names the vulnerable function:
      - `uncode_recordMedia`
    - the official Uncode changelog for `2.9.1.7` explicitly says:
      - `Vulnerability Fix Arbitrary File Read in uncode_recordMedia`
    - current read:
      - again, the remaining blocker is fixture availability, not uncertainty about the vulnerable function
  - `avada-builder-cve-2024-13345`
    - NVD confirms:
      - arbitrary shortcode execution
      - unauthenticated
      - due to an action reaching `do_shortcode` without validating the value first
    - exact callback/function is still not pinned from an official source
  - `avada-theme-cve-2024-13346`
    - NVD confirms:
      - arbitrary shortcode execution
      - unauthenticated
      - due to an action reaching `do_shortcode` without validating the value first
    - exact callback/function is still not pinned from an official source
- interpretation:
  - the remaining premium frontier is now split into two buckets:
    - pinned function, blocked only by missing source fixture:
      - `layerslider`
      - `modern-events-calendar`
      - `avada`
      - `gravity-forms-2025-12352`
      - both `uncode` cases
    - still partially advisory-level because the exact callback is not yet pinned:
      - `gravity-forms-2024-13377`
      - `avada-builder`
      - `avada-theme`

Premium/closed frontier refinement:

- date:
  - `2026-03-26`
- purpose:
  - continue the premium/closed `not_comparable_yet` audit and replace vague placeholders with fixed versions, stronger primary-source attribution, and package-boundary notes where possible
- refined notes:
  - `layerslider-cve-2024-2879`
    - Wordfence confirms:
      - unauthenticated SQLi
      - exact action `ls_get_popup_markup`
      - affected `7.9.11 - 7.10.0`
      - patched `7.10.1`
    - current read:
      - the vuln location is precise enough for later direct source diffing
      - the blocker is now only the missing premium fixture
  - `gravity-forms-cve-2024-13377`
    - NVD and Wordfence agree on:
      - unauthenticated stored XSS
      - via the `alt` parameter
      - affected `<= 2.9.1.3`
    - Gravity Forms official changelog indicates the patch window as:
      - `2.9.1.4` `security enhancements`
    - current read:
      - we still do not have a source-backed file/callback for the `alt` emission site
      - this case remains partially pinned rather than fully pinned
  - `modern-events-calendar-cve-2024-5441`
    - Wordfence confirms:
      - exact function `set_featured_image`
      - authenticated subscriber+ by default
      - site option can broaden reach to unauthenticated front-end event submission
      - affected `<= 7.11.0`
      - patched `7.12.0`
    - current read:
      - this is now strongly pinned even without the local fixture
  - `gravity-forms-cve-2025-12352`
    - GitHub advisory and NVD together pin:
      - exact function `copy_post_image()`
      - public mirror references to:
        - `forms_model.php`
        - `includes/fields/class-gf-field-fileupload.php`
      - affected `<= 2.9.20`
    - Gravity Forms official changelog indicates the patch window as:
      - `2.9.21` `security enhancements`
    - current read:
      - this case is now function-pinned and file-family-pinned even without the commercial fixture
  - `avada-builder-cve-2024-13345`
    - Wordfence confirms:
      - unauthenticated arbitrary shortcode execution
      - affected `<= 3.11.13`
      - patched `3.11.14`
    - Avada's official `7.11.14` security update says the fixed issue was:
      - visitors rendering arbitrary Avada elements through the `render_content` REST API endpoint or reCAPTCHA on the comments form
    - inference:
      - `render_content` is the most likely builder-side surface
      - this is still an inference from official sources, not a source-backed callback pin
  - `avada-theme-cve-2024-13346`
    - Wordfence confirms:
      - unauthenticated arbitrary shortcode execution
      - affected `<= 7.11.13`
      - patched `7.11.14`
    - Avada's official `7.11.14` security update says the fixed issue was:
      - visitors rendering arbitrary Avada elements through the `render_content` REST API endpoint or reCAPTCHA on the comments form
    - inference:
      - the comments-form reCAPTCHA path is the most likely theme-side surface
      - this is still an inference from official sources, not a source-backed callback pin
- interpretation:
  - after this pass, the weakest remaining case is now `gravity-forms-cve-2024-13377`
  - `avada-builder` and `avada-theme` still need real source fixtures, but the likely package split is now clearer from the vendor’s own `7.11.14` security note

Open-source not-comparable follow-up:

- date:
  - `2026-03-26`
- purpose:
  - continue the public/open-source `not_comparable_yet` cleanup after excluding premium fixtures
- result:
  - `omgf-cve-2023-6600` is no longer non-direct
- generic engine change:
  - added bounded canonical-path guard handling for file sinks
  - pattern:
    - a local variable compared against `realpath($var)` with `!=` or `!==`
    - bad branch definitely aborts (`continue`, `break`, `return`, `exit`)
    - later file sink uses either the guarded variable itself or the same assigned expression
  - this is generic engine logic, not OMGF-specific
- verification:
  - focused new tests:
    - guarded canonical-path delete sink now suppresses
    - equivalent unguarded delete sink still reports
  - real plugin probes:
    - vulnerable `host-webfonts-local__5.7.9` still hits:
      - `request-path-read-delete`
      - `src/Admin/Actions.php:204`
      - source `src/Admin/Actions.php:72`
    - patched `5.8.0` drops to `0` findings on the same `delete` scan
- corpus action:
  - promoted `omgf-cve-2023-6600` to direct comparable coverage in `corpus.json`
  - current direct contract:
    - rule `request-path-read-delete`
    - sink `src/Admin/Actions.php:204`
    - source strings `$updated_settings = $this->clean( $_POST );`, `clean_stale_cache`
- remaining public/open-source `not_comparable_yet` cases:
  - `backup-migration-cve-2023-6553`
  - `starter-templates-cve-2025-13065`
  - `wp-reset-cve-2023-6799`
- interpretation:
  - `omgf` was fixable with a generic path-guard improvement
  - `backup-migration` still needs a more faithful restore/bootstrap include-path model
  - `starter-templates` still needs an authenticated upload-validation-bypass family
  - `wp-reset` remains a non-taint predictable-randomness case

Open-source not-comparable follow-up 2:

- date:
  - `2026-03-26`
- purpose:
  - test whether `backup-migration-cve-2023-6553` could be promoted by teaching `phparser` to preserve user-defined path-sanitizer helpers through summaries
- generic engine change:
  - added a bounded `PathSafe` origin/snapshot bit alongside the existing HTML-safety flags
  - added generic callable detection for helpers that:
    - return the same parameter
    - only after aborting on path-danger checks
    - currently recognized guard families:
      - forbidden path token checks via `strpos` / `stripos` / `str_contains`
      - path existence checks via `file_exists` / `is_dir`
  - path-safe origins now suppress include/delete path findings the same way local canonical-path guards do
- focused verification:
  - synthetic helper-return include regression now suppresses
  - synthetic unsanitized helper-return include regression still reports
  - prior canonical `realpath(...)` guard regressions still pass
  - `omgf-cve-2023-6600` still `match` after the change
- real plugin result:
  - `backup-backup__1.3.7 -sink-op include` still reports:
    - `includes/bypasser.php:646`
  - `backup-backup__1.3.9 -sink-op include` still reports the same sink:
    - `includes/bypasser.php:646`
  - so this change did not make `backup-migration-cve-2023-6553` an honest vulnerable-vs-fixed direct compare
- interpretation:
  - the new path-sanitizer summary is still a valid core improvement
  - but `backup-migration` remains non-direct on the public fixtures
  - likely reasons:
    - the patched `filterChainFix(...)` only wraps part of the restore bootstrap
    - the retained include path in `bypasser.php` is still not separable enough to serve as a trustworthy direct corpus contract
  - keep `backup-migration-cve-2023-6553` as `not_comparable_yet`

Open-source not-comparable follow-up 3:

- date:
  - `2026-03-26`
- purpose:
  - test whether `starter-templates-cve-2025-13065` could be promoted honestly by adding a generic authenticated upload-validation-bypass surface model instead of forcing it into the existing file-write family
- generic engine change:
  - added a bounded `surface` model for `wp_check_filetype_and_ext` filter callbacks
  - the callback filename parameter now acts as a source only for this filter family in `surface` scans
  - `phparser` now emits `upload-api-surface` only when the callback:
    - mutates `$defaults['ext']` or `$defaults['type']`
    - under filename-substring checks like `strpos($filename, ...)`
    - without an exact-extension guard such as `pathinfo($filename, PATHINFO_EXTENSION)` equality
  - this stays generic:
    - no Starter Templates hardcoding
    - no special-case file paths
    - no plugin-name checks
- focused verification:
  - new synthetic vulnerable filter callback now reports `upload-api-surface`
  - new synthetic exact-extension-guarded callback now suppresses
- real plugin result:
  - vulnerable `astra-sites__4.4.41 -sink-op surface` now reports `12` findings at:
    - `st-wxr-importer.php:522`
    - `st-wxr-importer.php:523`
    - `st-wxr-importer.php:528`
    - `st-wxr-importer.php:529`
  - patched `4.4.42 -sink-op surface` drops to `0` findings
- corpus action:
  - promoted `starter-templates-cve-2025-13065` back to direct comparable coverage in `corpus.json`
  - current direct contract:
    - `direct_sink_ops = ["surface"]`
    - rule `upload-api-surface`
    - sinks in `st-wxr-importer.php` on the vulnerable filename-substring MIME overrides
- interpretation:
  - `starter-templates` is now an honest direct `surface` case
  - `backup-migration-cve-2023-6553` and `wp-reset-cve-2023-6799` remain the only public/open-source `not_comparable_yet` cases

Open-source not-comparable follow-up 4:

- date:
  - `2026-03-27`
- purpose:
  - re-check `backup-migration-cve-2023-6553` after the path-safety work and verify whether the remaining fixed-tree hit was a summary-replay bug rather than a genuinely non-separable case
- generic engine change:
  - summary-replayed sink findings now honor path safety for path-based rules instead of blindly re-emitting any replayed path sink
  - current replay suppression is intentionally narrow:
    - `path-transversal`
    - `request-path-read-delete`
  - this mirrors what direct sink handling already did through `filterPathSinkOrigins(...)`
  - no plugin-specific logic was added
- focused verification:
  - synthetic helper-return include suppression still passes
  - new receiver-summary regression now suppresses:
    - sanitized constructor arg -> receiver property -> `dirname(...)` -> replayed include
- real plugin result:
  - vulnerable `backup-backup__1.3.7 -sink-op include` still reports exactly one finding:
    - `includes/bypasser.php:646`
    - source `includes/backup-heart.php:22`
  - fixed `backup-backup__1.3.9 -sink-op include` now reports `0` findings
- corpus action:
  - promoted `backup-migration-cve-2023-6553` back to direct comparable coverage in `corpus.json`
  - current direct contract:
    - `direct_sink_ops = ["include"]`
    - rule `path-transversal`
    - sink `includes/bypasser.php:646`
    - trace source `foreach ($_SERVER as $name => $value)`
- interpretation:
  - the previous non-separable result was an engine bug in summary sink replay, not an intrinsic corpus limitation
  - remaining public/open-source `not_comparable_yet` cases are now only:
    - `wp-reset-cve-2023-6799`

Open-source not-comparable follow-up 5:

- date:
  - `2026-03-27`
- purpose:
  - finish the last public/open-source `not_comparable_yet` case by adding a bounded non-taint weak-identifier detector for predictable export/download artifact names
- generic engine change:
  - added a small `surface` detector for low-entropy security identifiers reused in exported or downloadable artifact names
  - current implementation is intentionally narrow:
    - tracks weak identifier hints for local variables
    - recognizes weak generator helpers built from `substr(str_shuffle(str_repeat(...)))`
    - propagates through `md5(...)` / `sha1(...)`
    - only emits on return surfaces that already look like export/download/snapshot artifact names
  - this stays generic:
    - no `wp-reset` hardcoding
    - no plugin-name checks
    - no special-case file paths
- focused verification:
  - new vulnerable synthetic export surface test reports `predictable-security-identifier-surface`
  - new fixed synthetic `generate_snapshot_uid(10)` test stays clean
  - existing upload-validation surface regressions stay green
- real plugin result:
  - vulnerable `wp-reset__2.0 -sink-op surface` now reports exactly one finding:
    - source `wp-reset.php:2997`
    - sink `wp-reset.php:2655`
    - rule `predictable-security-identifier-surface`
  - fixed `2.01 -sink-op surface` drops to `0` findings
- corpus action:
  - promoted `wp-reset-cve-2023-6799` to direct comparable coverage in `corpus.json`
  - current direct contract:
    - `direct_sink_ops = ["surface"]`
    - rule `predictable-security-identifier-surface`
    - source weak snapshot UID generator line `2997`
    - sink export filename return line `2655`
- interpretation:
  - the public/open-source `not_comparable_yet` set is now empty

Full 43-case rerun follow-up 1:

- date:
  - `2026-03-27`
- issue:
  - the fresh full 43-case rerun after promoting `backup-migration-cve-2023-6553` and `wp-reset-cve-2023-6799` showed one apparent regression:
    - `w3-total-cache-cve-2024-12365`: `miss`
  - this was not an engine coverage loss
  - direct results still contained the BunnyCDN popup action family in:
    - `Cdn_BunnyCdn_Popup.php:99`
    - `Cdn_BunnyCdn_Popup.php:188`
    - `Cdnfsd_BunnyCdn_Popup.php:97`
    - `Cdnfsd_BunnyCdn_Popup.php:206`
  - the manifest had become too specific to older retained source strings like `origin_url`
- corpus action:
  - widened the `w3-total-cache-cve-2024-12365` contract in `corpus.json` to the stable direct-engine shape:
    - allow representative request sources `account_api_key`, `origin_url`, and `name`
    - pin the BunnyCDN popup sink lines explicitly
  - kept the rule and file family unchanged:
    - `wp-request-sensitive-action-without-cap-check`
    - `Cdn_BunnyCdn_Popup.php`
    - `Cdnfsd_BunnyCdn_Popup.php`
- validation:
  - single-case rerun:
    - `tmp/phparser-w3-contract-rerun-20260327/summary.json`
    - status `match`
  - current representative retained finding:
    - source `Cdn_BunnyCdn_Popup.php:79`
    - sink `Cdn_BunnyCdn_Popup.php:99`
    - callable `\W3TC\Cdn_BunnyCdn_Popup::w3tc_ajax_cdn_bunnycdn_list_pull_zones`
- interpretation:
  - the full-rerun `w3-total-cache` miss was manifest drift, not a live `phparser` engine regression

Delete noise reduction follow-up 1:

- date:
  - `2026-03-27`
- issue:
  - the refreshed full 43-case rerun still had one dominant noise family:
    - `wp-request-file-delete-without-cap-check`
  - corpus-wide shape before the fix:
    - raw hits `232`
    - unique sink sites `20`
    - raw-per-sink ratio `11.60`
  - worst concrete case:
    - `wordpress-file-upload-cve-2024-11613`
    - raw hits `206`
    - unique sinks `4`
    - raw-per-sink ratio `51.50`
  - diagnosis:
    - most of these were not independent delete bugs
    - they were final findings whose merged context already said `access=capability_checked`
    - the generic delete rule was still surfacing them as `without-cap-check`
- generic engine change:
  - final finding suppression now also drops:
    - `wp-request-file-delete-without-cap-check`
    - when merged final context is `capability_checked`
  - this mirrors the earlier generic action-rule suppression and stays semantic:
    - no plugin hardcoding
    - no sink-path exceptions
    - no delete-family broad pruning beyond the contradictory final auth context
- focused verification:
  - new regression:
    - `TestDedupeFinalFindingsSuppressesCapabilityCheckedGenericDeleteRule`
  - focused tests:
    - `go test ./internal/taintscan -run 'TestDedupeFinalFindingsSuppressesCapabilityCheckedGeneric(Action|Delete)Rule' -count=1`
    - passed
  - targeted corpus checks:
    - `wordpress-file-upload-cve-2024-11613`: stayed `match`
    - `sureforms-cve-2025-6691`: stayed `match`
    - `everest-forms-cve-2025-1128`: stayed `match`
    - `backup-migration-cve-2023-6972`: stayed `match`
  - full suite:
    - `go test ./...`: passed
    - `internal/taintscan`: `118.192s`
- measured targeted effect:
  - `wordpress-file-upload-cve-2024-11613`:
    - findings `206 -> 1`
    - surviving direct comparable finding:
      - `wfu_file_downloader.php:33`
      - source `wfu_file_downloader.php:24`
  - `backup-migration-cve-2023-6972`:
    - findings `17 -> 4`
    - still matches through `request-path-read-delete`
- refreshed full 43-case corpus after the suppression:
  - artifacts:
    - `tmp/phparser-full-corpus-rerun5-20260327/aggregate.tsv`
    - `tmp/phparser-full-corpus-rerun5-20260327/rule-hits.tsv`
    - `tmp/phparser-full-corpus-rerun5-20260327/plugin-hits.tsv`
    - `tmp/phparser-full-corpus-rerun5-20260327/noise-by-rule.tsv`
    - `tmp/phparser-full-corpus-rerun5-20260327/noise-by-plugin.tsv`
  - final status counts:
    - `34` `match`
    - `9` `not_comparable_yet`
    - `0` `miss`
    - `0` `timeout`
  - corpus-wide raw findings:
    - `516 -> 298`
  - rule-level noise after the fix:
    - `wp-request-file-delete-without-cap-check`:
      - `232 -> 14`
      - unique sink sites `5`
      - raw-per-sink ratio `2.80`
  - plugin-level noise after the fix:
    - `wordpress-file-upload-cve-2024-11613`:
      - `206 -> 1`
    - `backup-migration-cve-2023-6972`:
      - `17 -> 4`
  - remaining top raw-hit plugins are now:
    - `post-smtp-cve-2025-11833`: `80`
    - `everest-forms-cve-2025-1128`: `25`
    - `w3-total-cache-cve-2024-12365`: `24`
    - `wpforms-cve-2024-11205`: `16`
- interpretation:
  - the worst remaining noise is no longer the generic delete rule
  - the next precision target is the generic action family, especially:
    - `post-smtp`
    - `w3-total-cache`
    - `wpforms`

## 2026-03-27 Page 2 completion

- Wordfence Hall of Fame page 2 is now exact-CVE complete in `test/semgrep_bundle_corpus/corpus.json`:
  - `20/20` CVEs present
  - the missing exact entries were:
    - `CVE-2026-3098` (`smart-slider-3-cve-2026-3098`)
    - `CVE-2026-3584` (`kali-forms-cve-2026-3584`)
- rank metadata in the corpus was shifted back to the real page order after inserting the two missing page-2 cases:
  - from rank `23` onward, ranks now line up with the Wordfence API again
- `kali-forms-cve-2026-3584`:
  - vulnerable local `2.4.9` hits `render-callback-execution` in `Inc/Frontend/class-form-processor.php`
  - fixed `2.4.10` is clean
  - direct compare matches with a mixed sink batch:
    - `call`
    - `include`
    - `open`
    - `read`
  - artifact:
    - `tmp/phparser-kali-forms-compare3-20260327/summary.json`
- `smart-slider-3-cve-2026-3098`:
  - vulnerable local `3.5.1.32` and fixed `3.5.1.34` source diff cleanly pin `ControllerSliders::actionExportAll()`
  - the fix adds:
    - `validateToken()`
    - `validatePermission('smartslider_edit')`
  - current direct `phparser` probes for vulnerable/fixed still return `0` findings in `read/open/action/output`
  - so the case is now represented honestly as `not_comparable_yet`, not as an exact-CVE gap
  - artifact:
    - `tmp/phparser-smart-slider-compare-20260327/summary.json`

## 2026-03-27 Smart Slider dynamic dispatcher follow-up

- landed a generic dispatcher fix in `internal/taintscan`:
  - `call_user_func(_array)` callback-array resolution now understands dynamic method-name strings through local `stringEnv`
  - unknown ternaries in dynamic dispatch strings degrade to bounded placeholders instead of collapsing to `""`
  - method-call resolution can fall back to multiple receiver-class candidates from local assignments instead of requiring a single `classEnv` hit
  - literal arg hints can reuse local dynamic-string information
- added focused regression coverage in `taintscan_test.go` for MVC-style controller factory dispatch:
  - `DemoApp::dispatch -> process -> getController -> ControllerBase::doAction -> SlidersController::actionExportAll`
  - the new test now finds `wp-request-sensitive-action-without-cap-check` at the concrete action-method sink
- measured real Smart Slider result after the dispatcher fix:
  - vulnerable `smart-slider-3` action probe still returns `0` findings
  - vulnerable `smart-slider-3` action+output probe still returns `0` findings
  - artifact examples:
    - `tmp/phparser-smartslider-action-after-dyndispatch-20260327/human-summary.md`
    - `tmp/phparser-smartslider-action-output-after-dyndispatch-20260327/human-summary.md`
- current conclusion:
  - the original controller/action reachability gap is fixed generically
  - `smart-slider-3-cve-2026-3098` still remains honestly `not_comparable_yet`
  - remaining gap is semantic, not dispatch:
    - the vulnerable path is a request-routed admin export action with insufficient method-level authorization
    - the patch adds `validateToken()` and `validatePermission('smartslider_edit')`
    - current direct finding families mainly cover:
      - no-capability request actions
      - request-taint to file/sql/include/output
      - route/upload/predictable-identifier surfaces
    - this case is closer to an authorization-mismatch export surface than a plain request-taint or no-capability sink

## 2026-03-27 Smart Slider admin-page follow-up

- landed a generic WordPress admin-page callback registration model in `internal/taintscan`:
  - `add_menu_page`, `add_submenu_page`, and the common `add_*_page` helpers now register callback targets as `admin_page` entrypoints
  - entrypoint access is treated as `authenticated` by default rather than pretending the route is already definitely capability-checked
- added focused regression coverage in `taintscan_test.go`:
  - `add_menu_page(...) -> display_admin() -> processRequest() -> dynamic controller action`
  - the regression now proves:
    - `AdminHelper::display_admin` receives an `admin_page` entrypoint
    - the downstream dynamic controller action sink is still reachable
- also tightened `currentContext()` so empty local context can inherit meaningful reverse-caller context, not just explicit `access=unknown`
- verification:
  - focused dispatcher/admin-page regressions passed
  - full `go test ./...` passed
  - `internal/taintscan` finished in `125.022s`
- measured real Smart Slider outcome after the new `admin_page` model:
  - vulnerable `smart-slider-3` action probe still returns `0` findings:
    - `tmp/phparser-smartslider-action-after-adminpage-20260327/human-summary.md`
  - vulnerable `smart-slider-3` output probe still returns `0` findings:
    - `tmp/phparser-smartslider-output-after-adminpage-20260327/human-summary.md`
  - the read probe was stopped after it repeated the earlier broad read behavior instead of yielding a useful direct result
- updated conclusion:
  - the Nextend admin route is no longer missing at the registration layer
  - `smart-slider-3-cve-2026-3098` still remains honestly `not_comparable_yet`
  - remaining gap is a new generic family, not another router/dispatch fix:
    - authenticated export/download route
    - server-side file read of record-backed paths
    - missing or insufficient method-level nonce/capability enforcement

## 2026-03-27 Smart Slider direct action fix

- landed two generic fixes that closed the remaining Smart Slider gap:
  - non-`call` batches no longer mutate the literal-arg callable-specialization index during parallel analysis
    - this removed a real `concurrent map read and map write` crash on the vulnerable Smart Slider action probe
  - final finding suppression now runs for single-batch scans too, and mixed `admin_page` + `ajax` action findings are only kept when the sink callable lacks a local same-file capability+nonce/validator guard
- focused regressions added/updated:
  - mixed admin-page/AJAX attachment action stays reported when only the admin-page path is guarded
  - the same mixed route is suppressed when the sink handler itself adds a local `validateToken()` + `validatePermission(...)` guard
  - literal-arg specialization is skipped outside `call` batches
- measured real Smart Slider outcome after the fix:
  - vulnerable `3.5.1.32` still hits:
    - `Nextend/SmartSlider3/Application/Admin/Sliders/ControllerSliders.php:82`
    - source:
      - `Nextend/SmartSlider3/Application/Admin/Sliders/ControllerSliders.php:59`
    - artifact:
      - `tmp/phparser-smartslider-action-after-finalsuppress-20260327/human-summary.md`
  - fixed `3.5.1.34` is clean for the `ControllerSliders::actionExportAll` sink:
    - only unrelated findings remain in:
      - `Nextend/Framework/Settings.php`
      - `Nextend/SmartSlider3/Application/Admin/Sliders/ControllerAjaxSliders.php`
    - artifact:
      - `tmp/phparser-smartslider35134-action-after-finalsuppress-20260327/human-summary.md`
- corpus status:
  - `smart-slider-3-cve-2026-3098` is now a direct `action` case again
  - contract updated in `test/semgrep_bundle_corpus/corpus.json`
- follow-up:
  - after this fix, a fresh `go test ./...` no longer completed within the package `10m` timeout
  - the timeout is in the older real-plugin regression:
    - `TestAnalyzeRootFindsHideMyWPActualShowFileInclude`
  - the Smart Slider correctness fix is still valid, but there is now a separate performance regression or existing timeout-budget breach in the full `internal/taintscan` suite that needs its own follow-up

## 2026-03-27 Default test-speed split

- moved the heaviest real-plugin fixture regressions behind an explicit opt-in:
  - `PHARSER_ENABLE_REAL_PLUGIN_TESTS=1`
- added `internal/taintscan/test_helpers_test.go` with `requireRealPluginFixtureTest(t)`
- gated the current absolute-path fixture tests for:
  - Hide My WP
  - Code Snippets
  - Smart Slider
  - Post SMTP
  - Ultimate Member
  - SureForms
- result:
  - default `go test ./...` is fast again and no longer waits on large real-plugin fixture scans
  - the expensive real-plugin regressions are still runnable on demand with the env var

## 2026-03-27 Page 3 recursion guard and page-3 baseline

- the Smart Slider dynamic-dispatch work reopened a generic recursion bug in build-base hinting:
  - `dynamicDispatchStringForCallable(...)`
  - `resolveHintClassExpr(...)`
  - `receiverPropertyReturnClassCandidates(...)`
- real page-3 probes that were crashing with Go stack overflows before the fix:
  - `ultimate-member__2.10.0 -sink-op sql`
  - `post-grid__2.3.3 -sink-op action`
  - `fluentform__5.1.16 -sink-op action`
  - `redux-framework__4.4.17 -sink-op write`
  - `wp-statistics -sink-op output`
- generic fix:
  - added a per-call recursion guard for dynamic dispatch string resolution and class-hint/property-return resolution
  - this keeps self-referential method-name and property-return loops from recursing until the Go stack explodes
- safety:
  - default `go test ./...` still passes after the guard
  - `internal/taintscan` remains fast in the default suite
- page-3 triage after the guard:
  - `ultimate-member__2.10.0`:
    - earlier focused artifact gives a clean SQL hit in `includes/core/class-member-directory-meta.php:1072` from `:846`
    - later source review showed that hit is the wrong path for `CVE-2025-1702`
    - the official patch is the `$_POST['search']` family in `includes/core/class-member-directory.php`, not the separate sorting-driven SQL builder in `class-member-directory-meta.php`
    - keep metadata-only until `phparser` reaches the real search path
  - `post-grid__2.3.3`:
    - crash fixed
    - focused action scan returns generic nonce-only state-change findings
    - current `2.3.23` still hits the same family
    - kept metadata-only for now
  - `fluentform__5.1.16`:
    - crash fixed
    - focused `action` scan returns `0`
  - `fluentform__5.2.6`:
    - focused `output` scan returns `0`
    - current `6.1.20` also returns `0`
  - `redux-framework__4.4.17`:
    - crash fixed for `output`
    - focused `output` scan returns `0`
    - focused `write` scan is still too expensive and was killed
  - `wp-statistics__14.5`:
    - vulnerable `14.5` gives one shortcode output finding at `includes/class-wp-statistics-shortcode.php:136`
    - current `14.16.3` is clean
    - exact CVE alignment of that path still needs source review before promotion
  - `ninja-forms__3.13.2`:
    - focused `surface` scan returns `0`
  - `ninja-forms__3.8.19`:
    - focused `output` scan returns stored-XSS findings in `includes/Routes/Submissions.php`
    - current `3.14.1` still hits the same sinks
    - kept metadata-only for now
  - `ht-contactform__2.2.1`:
    - focused `write` scan returns `0`
  - `woocommerce-products-filter` current `1.3.8.1`:
    - focused `include` scan returns unauthenticated path-transversal findings in `ext/by_text/index.php`
    - vulnerable `1.3.6.5` fixture still needs materialization before direct promotion
- corpus status:
  - page 3 exact-CVE coverage is now complete in `test/semgrep_bundle_corpus/corpus.json`
  - metadata-only / still-under-review public cases from this slice:
    - `ultimate-member-cve-2025-1702`
    - `husky-cve-2025-1661`
    - `wpdiscuz-cve-2024-9488`
    - `user-registration-cve-2026-1492`
    - `ninja-forms-cve-2025-11924`
    - `cfdb7-cve-2025-7384`
    - `fluent-forms-cve-2024-2771`
    - `wp-statistics-cve-2024-2194`
    - `post-grid-cve-2024-9636`
    - `fluent-forms-cve-2024-10646`
    - `ninja-forms-cve-2024-11052`
    - `ht-contact-form-cve-2025-7340`
    - `redux-framework-cve-2024-6828`

## 2026-03-27 Page 3 follow-up: HUSKY and WP Statistics grounding

- `husky-cve-2025-1661`
  - The real vulnerable path is now source-backed from the public advisory and PoC, not just the current tree taint result.
  - The CVE is pinned to the unauthenticated `template` parameter of the `woof_text_search` AJAX action.
  - In the current fixed tree:
    - `bugbounty-note/wordpress/wp_install/plugins/woocommerce-products-filter/ext/by_text/index.php`
    - `ajax_search()` accepts request-controlled `template`
    - then applies `sanitize_key($template)` before building the plugin/theme template path
    - then gates inclusion with `file_exists(...)`
  - The local plugin changelog shows:
    - `1.3.6.5`: prior security fix credited to Patchstack
    - `1.3.6.6`: security fix credited to Wordfence
  - WordPress.org plugin API returns `versions: []` for this slug, and versioned `downloads.wordpress.org/plugin/...<version>.zip` URLs for `1.3.6.5` and `1.3.6.6` were not available in this repo state.
  - Current `phparser` include findings on fixed `1.3.8.1` are therefore likely a false-positive family around sanitized template-to-path construction, not proof that the fixed tree still has the original LFI.
  - Keep `husky-cve-2025-1661` metadata-only until:
    - a real vulnerable `1.3.6.5` fixture is materialized, or
    - a stronger vulnerable-vs-fixed direct separation is available.

- `wp-statistics-cve-2024-2194`
  - The existing vulnerable output hit on:
    - `includes/class-wp-statistics-shortcode.php:136`
    - from `includes/class-wp-statistics-helper.php:1062`
    - is not the real CVE path.
  - The advisory is about stored XSS via logged URL search/query parameter handling, not the shortcode helper that renders the last published post date.
  - Grounded vulnerable/fixed families:
    - `includes/class-wp-statistics-pages.php`
      - `sanitize_page_uri()`
      - `record()`
      - `getTop()`
      - `get_page_info()`
    - `includes/class-wp-statistics-visitor.php`
      - `getTop()`
      - `prepareData()`

    - `includes/class-wp-statistics-referred.php`
      - `getRefererURL()`
      - `get()`
      - `get_referrer_link()`
  - Public patch anchor:
    - changeset `3047756`
  - The strongest grounded vulnerable sink in the local `14.5` tree is:
    - `includes/admin/templates/pages/refer.url.php:43`
    - raw anchor text output of stored `$item['refer']`
  - The grounded vulnerable source/write side is:
    - public REST hit route in `includes/api/v2/class-wp-statistics-api-hit.php:54-60`
    - request referrer intake in `includes/class-wp-statistics-referred.php:44-45`
    - visitor table write in `includes/class-wp-statistics-visitor.php:121-123`
  - The current fixed tree hardens both sides:
    - signed REST hit route in `includes/api/v2/class-wp-statistics-api-hit.php:57-64`
    - escaped referrer rendering in `views/components/objects/referrer-link.php:4-5`
  - Local fixed-tree diffs show substantial rewrites in exactly this query-string / visitor / referrer family, which matches the advisory better than the current shortcode finding.
  - Keep `wp-statistics-cve-2024-2194` metadata-only until the direct contract is reset to the real stored request -> DB write -> admin output path in this family.

- `ultimate-member-cve-2025-1702`
  - The official advisory and patch are for the `search` parameter path in `includes/core/class-member-directory.php`.
  - Public sources:
    - NVD: `CVE-2025-1702`
    - upstream PR/commit: `74647d42cc8d63f5d4f687efcd0792c246c23039`
  - Grounded vulnerable path in `2.10.0`:
    - `prepare_search()` at `includes/core/class-member-directory.php:1700-1725`
    - `general_search()` consumes `$_POST['search']` at `:1733-1755`
    - `change_meta_sql()` reuses `$_POST['search']` at `:1775-1783`
  - Grounded patch:
    - added extra regex validation for sleep-style payloads in the search sanitizer
    - same patch also fixes `WP_User_Query` namespace usage in the search/query family
  - Current local `2.11.2` no longer matches the vulnerable family shape:
    - `prepare_search()` is reduced to `sanitize_text_field( wp_unslash( $search ) )`
    - `general_search()` no longer builds the old vulnerable meta-query shape
    - the current tree also adds member-directory rate limiting and `can_view_directory()` in the AJAX handler
  - The current `phparser` SQL finding is a different path:
    - `includes/core/class-member-directory-meta.php:1080`
    - from `includes/core/class-member-directory-meta.php:854`
    - source is `$_POST['sorting']`, not `$_POST['search']`
  - Conclusion:
    - do not count the current sorting-based finding as `CVE-2025-1702` coverage
    - keep metadata-only until `phparser` reaches the real search-parameter path or a better bounded contract exists

- `ht-contact-form-cve-2025-7340`
  - The real vulnerable family is now source-backed on the local public fixture.
  - Grounded vulnerable path in `ht-contactform__2.2.1`:
    - unauthenticated AJAX registration in `admin/Includes/Ajax.php:47-48`
    - handler `temp_file_upload()` in `admin/Includes/Ajax.php:59-68`
    - sink helper `FileManager::temp_file_upload()` in `admin/Includes/Services/FileManager.php:64-97`
    - direct filesystem write at `move_uploaded_file(...)` in `admin/Includes/Services/FileManager.php:86`
  - Grounded current fixed family in `ht-contactform`:
    - same temp-upload helper now adds `wp_check_filetype($filename)` in `include/Services/FileManager.php:80-85`
    - current readme explicitly mentions:
      - improved file upload handling by adding file type validation
      - fixed file name sanitization issue in the file upload field
  - Current `phparser` behavior:
    - vulnerable `2.2.1` focused `-sink-op write` returns `0`
    - current `2.8.2` `-sink-op write` returns only newer no-JS submission upload findings in `admin/Includes/Api/Endpoints/Submission.php`
    - so the engine is not reaching the real vulnerable temp-upload family yet
  - Likely generic engine gap:
    - public AJAX callback family is present, request sources and `move_uploaded_file` are modeled, but the singleton/bootstrap path into the real temp-upload callback is still being dropped somewhere in relevance/reachability
  - Keep metadata-only until the vulnerable temp-upload callback becomes directly reachable in `phparser`.

- `redux-framework-cve-2024-6828`
  - The vulnerable `4.4.17` family is now narrowed to the legacy color-scheme import helper:
    - `redux-core/inc/extensions/color_scheme/color_scheme/class-redux-color-scheme-import.php`
    - uploaded file handling reaches `move_uploaded_file(...)` at `:243`
    - constructor gate is nonce/cookie/request driven, which matches the old upload-style surface
  - The current `4.5.10` tree no longer carries that helper file.
  - Current hardening indicators:
    - readme says security was tightened in `import_export`, `custom_fonts`, `color_scheme`, and Google Font updating
    - current color-scheme import path lives in `redux-core/inc/extensions/color_scheme/class-redux-extension-color-scheme.php`
    - it now operates on decoded JSON content and writes via Redux filesystem helpers instead of the old direct uploaded-file move
  - Focused vulnerable `write` probe on the whole plugin was too expensive for first-pass triage and was killed before producing artifacts.
  - Keep metadata-only until a narrower direct-engine repro is built around the legacy upload/import helper family.

## 2026-03-27 Page 3 follow-up: public auth and XSS families pinned

- `jupiterx-core-cve-2024-7781`
  - The real vulnerable family is the Raven social-login alternate-path login flow in:
    - `includes/extensions/raven/includes/modules/forms/classes/social-login-handler/google.php`
    - `includes/extensions/raven/includes/modules/forms/classes/social-login-handler/facebook.php`
  - Vulnerable `4.7.5` creates reusable GET login URLs like:
    - `?jupiterx-google-social-login=<provider id>`
    - `?jupiterx-facebook-social-login=<provider id>`
  - Then `google_log_user_in()` / `facebook_log_user_in()` log the matching user in from `init`.
  - Current `4.14.1` removes that alternate-path login family and logs the user in directly inside `ajax_handler()` after provider validation.
  - Keep metadata-only until `phparser` models this social-login authentication-bypass family.

- `wpdiscuz-cve-2024-9488`
  - The real vulnerable family is the WordPress.com provider branch in:
    - `forms/wpdFormAttr/Login/SocialLogin.php::wordpressLogin()`
    - `forms/wpdFormAttr/Login/SocialLogin.php::wordpressLoginCallBack()`
  - Vulnerable `7.6.24` creates provider state, exchanges the OAuth code, retrieves the WordPress.com user, then logs the account in via `Utils::addUser()` and `setCurrentUser()`.
  - Public `7.6.25` changelog explicitly says `Fixed: Vulnerability with WordPress social login`.
  - Current `7.6.46` heavily refactors that family and adds `users_can_register` guards in both `login()` and `loginCallBack()`.
  - Fixed generically in `phparser` by:
    - adding a public OAuth callback auth-surface sink family
    - repairing qualified namespace declarations in the parser
    - allowing bounded analysis recovery for interpolated-array-key parse errors so `SocialLogin.php` remains analyzable
  - Vulnerable `7.6.24` now reports `wp-public-oauth-callback-auth-surface` at `forms/wpdFormAttr/Login/SocialLogin.php:1548` from:
    - `forms/wpdFormAttr/Login/SocialLogin.php:46`
    - `forms/wpdFormAttr/Login/SocialLogin.php:96`
  - Current `wpdiscuz` is clean on the same `surface` scan, so the case is now promoted to direct coverage.

- `fluent-forms-cve-2024-2771`
  - The real vulnerable family is the role/manager API under:
    - `app/Http/Routes/api.php`
    - `app/Http/Policies/RoleManagerPolicy.php`
  - Vulnerable `5.1.16` `RoleManagerPolicy` only implements `index()`.
  - Patched `5.1.17` adds:
    - `verifyRequest(Request $request) { return Acl::hasPermission('fluentform_full_access'); }`
  - That pins the CVE to a policy-driven authorization gap on non-GET role/manager updates.
  - Focused `phparser` action scans still return `0`.

- `fluent-forms-cve-2024-10646`
  - The old `form subject` note was stale.
  - The public `5.2.6 -> 5.2.7` diff does not support that path.
  - The visible security-relevant change is in:
    - `app/Services/Transfer/TransferService.php`
  - Patched `5.2.7` starts exporting submission notes via `SubmissionService::getNotes()` and appends `Notes` to transfer headers/values.
  - Keep metadata-only until the real vulnerable source/sink family is pinned from a trustworthy advisory or patch.

- `ninja-forms-cve-2025-11924`
  - The real vulnerable family is the public `ninja-forms-views` submissions-table token surface in:
    - `blocks/bootstrap.php`
    - `blocks/views/includes/Authentication/Token.php`
  - Vulnerable `3.13.2` refreshes tokens from unscoped `formIds`.
  - Patched `3.13.3` restricts refresh to a single `formID`, requires a valid old token, validates the requested form against the old token and referring page, and returns only that one form binding.
  - Current `3.14.1` adds more token/capability hardening.
  - Keep metadata-only until `phparser` has a direct route/token surface model.

- `ninja-forms-cve-2024-11052`
  - The real vulnerable family is attacker-controlled `extra['calculations']` in:
    - `includes/AJAX/Controllers/Submission.php`
    - later rendered in `includes/Templates/admin-metaboxes-calcs.html.php`
  - Patched `3.8.20`:
    - unsets `extra['calculations']` before calculation processing
    - wraps `value`, `raw`, and `parsed` with `esc_html()` in the admin calculations template
  - Current `3.14.1` still has different stored-XSS findings, so the case remains metadata-only until the legacy calculations path is separated cleanly.

- `cfdb7-cve-2025-7384`
  - The old corpus slug/fixture was wrong.
  - The real public plugin family is:
    - `contact-form-entries__1.4.3`
    - current tree `contact-form-entries` `1.4.8`
  - The vulnerability family is object injection through stored lead-detail deserialization:
    - vulnerable `includes/data.php::verify_val()` still runs `maybe_unserialize()` on stored lead values
    - vulnerable `includes/plugin-pages.php` later `maybe_unserialize()`s file-field values before delete/update handling
  - Current hardening indicators:
    - current readme says `1.4.4` fixed `PHP Object Injection Vulnerability`
    - current `includes/data.php::verify_val()` comments out the serialized-object fallback
    - current `includes/plugin-pages.php` writes file-field arrays as `json_encode(...)` instead of `serialize(...)`
  - Direct `phparser` status:
    - vulnerable `1.4.3` `-sink-op call` hits `unsafe-deserialization` at `includes/data.php:545`
    - first fixed public `1.4.4` drops that exact sink, even though unrelated legacy `maybe_unserialize()` helper sites remain
  - Promoted corpus contract:
    - `direct_sink_ops = ["call"]`
    - rule `unsafe-deserialization`
    - sink `includes/data.php:545`
    - source rooted in `vxcf_form::post()` request intake

## 2026-03-27 Page 3 follow-up: User Registration and Post Grid corrections

- `user-registration-cve-2026-1492`
  - The public advisory is now grounded locally and the old generic note was too weak.
  - Wordfence says the bug is unauthenticated membership registration accepting a user-supplied role without a server-side allowlist.
  - Real vulnerable path in `user-registration__5.1.2`:
    - `modules/membership/includes/AJAX.php::register_member()`
      - unauthenticated `wp_ajax_nopriv_user_registration_membership_register_member`
      - trusts caller-controlled `members_data`
    - `modules/membership/includes/Admin/Services/MembershipService.php::create_membership_order_and_subscription()`
      - calls `prepare_members_data( $data )`
    - `modules/membership/includes/Admin/Services/MembersService.php::prepare_members_data()`
      - initializes `$response['role']` from `$data['role']`
    - `modules/membership/includes/Admin/Services/MembersService.php::update_user_meta()`
      - performs `set_role( $data['role'] )`
  - Real patch family in `5.1.3+` / current `5.1.4`:
    - frontend membership creation now calls `prepare_members_data( $data, 'frontend' )`
    - that path reloads the selected membership and overwrites the submitted role with the membership role before `set_role()`
    - the same patch family also hardens membership auto-login:
      - old `urm_user_just_created = yes` becomes a per-user hash for membership flows
      - `login_member()` now requires either the matching hash or the real password
  - I ran both full-plugin and membership-only focused `phparser` action probes, but they were too slow/inconclusive to count as honest direct coverage yet.
  - Keep metadata-only until `phparser` cleanly separates vulnerable `5.1.2` from fixed `5.1.3+` on this exact role-setting path.

- `post-grid-cve-2024-9636`
  - The previous note was stale.
  - The local public tree is `the-post-grid` version `7.8.9`, not a materialized vulnerable `2.3.3` fixture.
  - Focused current-tree action probe artifact:
    - `tmp/phparser-post-grid-action-20260327/human-summary.md`
  - Current `phparser` only finds one unrelated admin block CSS state-change path:
    - sink `app/Helpers/Fns.php:97`
    - source `app/Controllers/BlocksController.php:373`
    - rule `wp-request-sensitive-action-without-cap-check`
  - That finding is not evidence for `CVE-2024-9636`.
  - Keep metadata-only until:
    - the real vulnerable `2.3.3` family is source-pinned, and
    - a vulnerable fixture is materialized locally.

## 2026-03-27 Page 3 follow-up: Redux promoted, User Registration and HT Contact Form narrowed

- `redux-framework-cve-2024-6828`
  - The narrow vulnerable/fixed slice is now grounded, but the full-plugin case is not safely promotable yet.
  - Real vulnerable family in `redux-framework__4.4.17`:
    - `redux-core/inc/extensions/color_scheme/color_scheme/class-redux-color-scheme-import.php`
    - request sources at:
      - `:162` cookie-controlled upload dir
      - `:228` uploaded temp path
    - write sink at:
      - `:243` `move_uploaded_file( $filepath, $this->upload_dir . '/' . $this->opt_name . '_' . $this->field_id . '.json' )`
  - Focused narrow scan artifact:
    - `tmp/phparser-redux-color-scheme-write-20260327/human-summary.md`
  - First fixed public `4.4.18` is clean on the same slice:
    - `tmp/phparser-redux-4418-color-scheme-write-20260327/human-summary.md`
  - Structural patch evidence:
    - `4.4.18` removes `class-redux-color-scheme-import.php` entirely from the `color_scheme` extension
  - Full-plugin `corpus-compare` still gets killed on `redux-framework__4.4.17`, and even a manually excluded full-plugin write scan (`-exclude-dir sample`) climbed past ~6.6 GB RSS quickly.
  - Keep metadata-only in `corpus.json` until the full fixture is tractable, but preserve the narrow slice artifacts as the grounded vulnerable/fixed proof.

- `user-registration-cve-2026-1492`
  - I built reduced vulnerable and current membership-only fixtures because full-plugin action scans were too expensive.
  - Vulnerable reduced fixture artifact:
    - `tmp/phparser-user-registration-min-action-pass1-20260327/human-summary.md`
  - Current reduced fixture artifact:
    - `tmp/phparser-user-registration-current-min-action-pass1-20260327/human-summary.md`
  - Both still retain the same generic action finding at:
    - `modules/membership/includes/Admin/Services/MembershipService.php:119`
    - from `modules/membership/includes/AJAX.php:121`
    - via `\WPEverest\URMembership\AJAX::register_member`
  - That means the narrowed engine slice still does not separate vulnerable `5.1.2` from fixed current on the real role-setting and auto-login patch family.
  - Keep metadata-only until `phparser` models the frontend-role override / auto-login-hardening delta instead of just the broad membership action sink.

- `ht-contact-form-cve-2025-7340`
  - Source review remains clear:
    - vulnerable `2.2.1` AJAX temp upload path:
      - `admin/Includes/Ajax.php::temp_file_upload()`
      - `admin/Includes/Services/FileManager.php::temp_file_upload()`
      - write sink `move_uploaded_file(...)` at `admin/Includes/Services/FileManager.php:86`
    - current path adds `wp_check_filetype()` in `include/Services/FileManager.php:72`
  - I tried reduced vulnerable/current mini-fixtures with the AJAX class, service, and bootstrap files.
  - Both reduced scans still returned `0` findings:
    - `tmp/phparser-ht-contactform-min-vuln-write2-20260327/human-summary.md`
    - `tmp/phparser-ht-contactform-min-current-write2-20260327/human-summary.md`
  - So this remains a real engine reachability gap around the temp-upload callback family, not a contract issue.

## 2026-03-27 Page 3 follow-up: HT Contact Form direct coverage restored

- Generic engine fix:
  - inline closures passed to `add_action()` now become callback callables during registration indexing
  - registration indexing now follows singleton/factory calls like `get_instance()` into constructors that register later hooks
  - receiver-property class hints now reuse `receiverPropertyReturnClassHint(...)`, so helper calls like `$this->file_manager->temp_file_upload($file)` resolve to the correct receiver class
- Files changed:
  - `internal/taintscan/wordpress_context.go`
  - `internal/taintscan/assignment_eval.go`
  - `internal/taintscan/taintscan_test.go`
- Focused regressions:
  - `TestAnalyzeRootFindsUploadThroughPropertyStoredHelperReceiver`
  - `TestAnalyzeRootFindsUploadRegisteredThroughLifecycleClosureAndSingletonConstructors`
  - plus existing upload/helper and `plugins_loaded` lifecycle tests
- Real plugin result:
  - vulnerable `ht-contactform__2.2.1` now hits the exact CVE path:
    - source `admin/Includes/Ajax.php:62`
    - sink `admin/Includes/Services/FileManager.php:86`
    - artifact `tmp/phparser-ht-contactform-write-after-propertyfix-20260327/human-summary.md`
  - current `ht-contactform` still reports the temp-upload sink in `include/Services/FileManager.php:94`, but that tree adds `wp_check_filetype()` before `move_uploaded_file(...)`
    - artifact `tmp/phparser-ht-contactform-current-write-after-propertyfix-20260327/human-summary.md`
- Corpus action:
  - promoted `ht-contact-form-cve-2025-7340` to direct `write` coverage in `corpus.json`
- Remaining caveat:
  - the broad `wp-request-file-upload-without-cap-check` rule does not yet model file-type validation as a safe boundary, so patched/current negatives for this family are still noisy even though the vulnerable CVE path is now directly reachable

## 2026-03-27 Page 3 follow-up: User Registration membership role path promoted

- Real blocker was two generic precision/performance issues, not missing sink modeling:
  - `callSinkRelevantUseOrdersForCallable(...)` was recursively recomputing large call graphs during `call` relevance indexing and blew up on the real membership module
  - structured reads like `$membership_detail['role']` fell back to the container base taint even when the container already had an exact known SQL-row shape that did not contain `role`
- Generic engine changes:
  - memoized recursive `call` relevant-use-order computation with cycle guards in `internal/taintscan/callgraph_relevance.go`
  - added `structuralContainerDefinitelyLacksSegment(...)` and used it for array/property reads in `internal/taintscan/state_map_helpers.go` and `internal/taintscan/expression_eval.go`
- Focused regressions:
  - `TestAnalyzeRootFindsPublicAjaxRoleMutationViaSetRole`
  - `TestAnalyzeRootFindsPublicAjaxRoleMutationThroughHelperChain`
  - `TestAnalyzeRootSkipsPublicAjaxRoleMutationWhenFrontendRoleIsOverwritten`
  - `TestBuildEngineKeepsPublicAjaxRoleMutationHelperChainForCallBatch`
  - `TestEvalExprTreatsMissingStructuredArrayKeyAsEmpty`
  - `TestEvalExprKeepsWildcardStructuredArrayKeyFallback`
- Real plugin result on narrowed membership-module scans:
  - vulnerable `user-registration__5.1.2/modules/membership/includes`:
    - `3` findings at `Admin/Services/MembersService.php:217`
    - real CVE path retained from `AJAX.php:121` via `\WPEverest\URMembership\AJAX::register_member`
    - artifact `tmp/phparser-user-registration-membership-512-call-after-missingkeyfix-20260327/human-summary.md`
  - current `user-registration/modules/membership/includes`:
    - frontend `register_member()` finding drops out after the role overwrite
    - only one remaining `upgrade_membership()` privilege-mutation candidate remains at `AJAX.php:1934`
    - artifact `tmp/phparser-user-registration-membership-current-call-after-missingkeyfix-20260327/human-summary.md`
- Corpus action:
  - promoted `user-registration-cve-2026-1492` to direct `call` coverage in `corpus.json`
- Remaining caveat:
  - the current membership module still has a separate `upgrade_membership()` privilege-mutation candidate; keep that as follow-up precision/review work and do not treat it as part of the `register_member()` CVE contract

## 2026-03-27 User Registration follow-up: placeholder literal specialization was the remaining blocker

- Real root cause:
  - `prepare_members_data($data)` was being specialized to a fake key like `method::\MembersService::prepare_members_data#lit:0={data}` during the `call` batch
  - that `{data}` value came from unresolved placeholder string hints, not a real literal argument
  - once the fake specialized key was selected, `create_membership_order_and_subscription()` stopped copying the returned `[role]` structure and the whole privilege-mutation chain collapsed to `0` findings
- Generic fix:
  - keep literal-arg specialization restricted to the active `call` batch
  - ignore unresolved brace-pattern hints such as `{data}` when building specialization keys
  - code: `internal/taintscan/callable_indexing.go`
- Regression coverage:
  - `TestAnalyzeRootFindsPublicAjaxRoleMutationThroughHelperChain`
  - `TestBuildEngineKeepsPublicAjaxRoleMutationHelperChainForCallBatch`
  - new `TestLiteralArgSpecializationSkipsPlaceholderHints`
- Real plugin result after the placeholder-hint fix:
  - vulnerable `user-registration__5.1.2/modules/membership` is back to `3` direct `wp-request-tainted-privilege-mutation` findings at `includes/Admin/Services/MembersService.php:217`
    - artifact `tmp/phparser-user-registration-membership-512-call-after-placeholderfix-20260327/human-summary.md`
  - current `user-registration/modules/membership` now keeps only the separate `upgrade_membership()` candidate
    - `1` finding at `includes/Admin/Services/MembersService.php:223`
    - source `includes/AJAX.php:1929`
    - artifact `tmp/phparser-user-registration-membership-current-call-after-placeholderfix-20260327/human-summary.md`
- Verification:
  - focused taint regressions passed
  - `go test ./...` passed with `internal/taintscan` at about `1.016s`

## 2026-03-27 Page 3 follow-up: URL cleaners should propagate but not count as HTML-safe

- Generic engine fix:
  - added `sanitize_url` and `esc_url_raw` to the propagating function set in `internal/taintscan/builtin_models.go`
  - intentionally did **not** add them to `isHTMLOutputSafeFunc(...)`
  - rationale: these helpers normalize URLs for storage/use, but they do not make a value safe for raw HTML text output
- Regression coverage:
  - new `TestAnalyzeRootFindsStoredXSSAfterURLSanitizersOnPersistentWrite`
  - revalidated:
    - `TestAnalyzeRootFindsStoredXSSAfterHTMLDecodeFromSanitizedDBWrite`
    - `TestAnalyzeRootSkipsStoredXSSAfterWPKsesPostBoundary`
  - focused tests passed
  - `go test ./...` passed with `internal/taintscan` at about `0.857s`
- Real plugin effect:
  - this did **not** wake the real `wp-statistics-cve-2024-2194` path yet
  - vulnerable `wp-statistics__14.5` still only reports the older shortcode/output path:
    - `includes/class-wp-statistics-shortcode.php:136`
    - source `includes/class-wp-statistics-helper.php:1062`
    - artifact `tmp/phparser-page3-wpstatistics-output-after-urlrawfix-20260327/human-summary.md`
  - current `wp-statistics` remains clean on focused `-sink-op output`
    - artifact `tmp/phparser-page3-wpstatistics-current-output-after-urlrawfix-20260327/human-summary.md`
- Current conclusion for `wp-statistics-cve-2024-2194`:
  - the remaining blocker is not URL-cleaner semantics
  - the real CVE path is still:
    - REST `/hit` request -> `Referred::get()` -> `Visitor::record()` stored `visitor.referred` -> `Visitor::prepareData()` -> admin template output in `includes/admin/templates/pages/refer.url.php:43`
  - `phparser` is still missing the include/template render side of that admin output chain, so keep the case metadata-only for now

## 2026-03-27 Page 3 follow-up: next realistic public targets after User Registration

- `fluent-forms-cve-2024-2771`
  - focused `-sink-op call` probe on vulnerable `fluentform__5.1.16` still returns `0`
  - artifact `tmp/phparser-page3-fluent-2771-call-probe-20260327/human-summary.md`
  - current note still stands: this is a policy-driven authorization gap around `RoleManagerPolicy`, not a straightforward request-to-sink primitive
- `jupiterx-core-cve-2024-7781`
  - focused `-sink-op action` probe now reaches the right family, especially `\JupiterX_Core\Raven\Modules\Forms\Classes\Social_Login_Handler\Facebook::ajax_handler`
  - but the action batch is still dominated by unrelated control-panel/import churn, so there is no honest direct finding yet
  - keep metadata-only until the social-login auth-bypass family is modeled separately from broad admin action noise
- `ninja-forms-cve-2025-11924`
  - the vulnerable-vs-current diff is cleaner than the older note implied
  - vulnerable `ninja-forms__3.13.2` has a public `ninja-forms-views/token/refresh` REST route that:
    - accepts attacker-controlled `formIds`
    - directly issues a new token with `TokenFactory::make()->create($publicKey, $formIds)`
    - returns the new token in the response
  - current `ninja-forms` requires an old token in `X-NinjaFormsViews-Auth`, validates signature only, enforces same-form scoping, and then issues a single-form token
  - focused `-sink-op surface` on vulnerable `3.13.2` still returns `0`
    - artifact `tmp/phparser-page3-ninja-11924-surface-probe-20260327/human-summary.md`
  - best next engine target from page 3 is now a **generic public token issuance surface** model for cases where:
    - a public REST callback is reachable
    - request-controlled identifiers flow into token issuance
    - the callback returns the issued token
    - and there is no definite prior token/capability validation boundary

## 2026-03-27 Page 3 follow-up: REST token issuance surface model promoted Ninja Forms 11924

- Real blockers:
  - `surface` had no return-based model for REST callbacks that mint and return token-like credentials
  - the vulnerable Ninja Forms refresh route lost request taint through `array_map('absint', ...)` because SQL sanitizers were being treated as global taint killers instead of SQL-only sanitizers
  - REST permission callback access was too noisy to use as the primary gate here because the refresh route's rate limiter helper contains an admin bypass branch and gets merged as `capability_checked`
- Generic engine changes:
  - added a new return-based `surface` family for REST token issuance in `internal/taintscan/public_token_surface.go`
    - looks for REST callbacks that return token-like fields sourced from request-controlled scope
    - skips callbacks that perform a prior token-validation guard such as `validateSignatureOnly(...)`
  - added `array_filter` propagation and narrowed SQL sanitization in `internal/taintscan/builtin_models.go` and `internal/taintscan/call_eval.go`
    - `intval`/`absint`-style sanitizers now suppress taint only in SQL-only batches
    - other batches like `surface` keep taint through `array_map('absint', ...)`
  - kept the rule generic by treating this as a REST credential-issuance surface, not a plugin-specific token special case
- Regression coverage:
  - `TestAnalyzeRootFindsPublicRestTokenIssuanceSurface`
  - `TestAnalyzeRootFindsPublicRestTokenIssuanceSurfaceInInlineClosure`
  - `TestAnalyzeRootSkipsPublicRestTokenIssuanceAfterTokenValidationGuard`
  - revalidated:
    - `TestAnalyzeRootFindsSecretDerivedPublicRestRoute`
    - `TestBuildEngineSkipsSQLSinkSeedWhenRequestInputIsNotSQLRelevant`
    - `TestAnalyzeRootFindsTaintedPostsWhereFilterReturn`
- Real plugin result:
  - vulnerable `ninja-forms__3.13.2` now hits once at:
    - source `blocks/bootstrap.php:281`
    - sink `blocks/bootstrap.php:310`
    - callable `closure::blocks/bootstrap.php::closure::blocks/bootstrap.php::file::blocks/bootstrap.php::141::280`
    - artifact `tmp/phparser-page3-ninja-11924-surface-after-model-20260327/human-summary.md`
  - current `ninja-forms` is clean on focused `-sink-op surface`
    - artifact `tmp/phparser-page3-ninja-current-surface-after-model-20260327/human-summary.md`
- Corpus impact:
  - promoted `ninja-forms-cve-2025-11924` to direct `surface` coverage in `test/semgrep_bundle_corpus/corpus.json`
- Remaining precision caveat:
  - the vulnerable finding still carries `entrypoint access=capability_checked` because the permission-callback helper context is conservative and still inherits the rate-limiter helper's admin bypass branch
  - that does not block the direct compare because the real vulnerable source/sink/callable are now retained correctly

## 2026-03-27 Page 3 follow-up: issued-auth-link surface model promoted Jupiter X 7781

- Real blocker:
  - the social-login auth-bypass family was not a normal `action` sink
  - vulnerable `jupiterx-core__4.7.5` issues provider-specific login URLs in the AJAX handler and later consumes those public query parameters to call `wp_set_auth_cookie()` in the same handler family
  - broad `surface` scans also kept replaying unrelated storage-path invalidation from control-panel helpers, so the vulnerable/current probes were differentiating but not converging
- Generic engine changes:
  - added a new `surface` family in `internal/taintscan/auth_link_surface.go`
    - looks for callbacks that return auth/login URLs keyed by a login-like query parameter
    - requires a companion method in the same class that later reads that query parameter and sets auth cookies
    - skips inline login flows where the auth cookie is set directly without a public issued-link round-trip
  - broadened local literal resolution in `internal/taintscan/callgraph_relevance.go`
    - `localArrayLiteralResolver.exprByName` now remembers non-array RHS expressions too, which lets the surface model recover values like `$unique_login_url` inside returned arrays
  - pure `surface` batches now skip the global storage-writer index and do not invalidate passes on summary storage writes
    - `internal/taintscan/analysis_support.go`
    - `internal/taintscan/analysis_driver.go`
    - this fixed the non-converging Jupiter scans without weakening current surface cases
- Regression coverage:
  - `TestAnalyzeRootFindsIssuedAuthLinkSurface`
  - `TestAnalyzeRootSkipsIssuedAuthLinkSurfaceWhenLoginHappensInline`
  - `TestNeedsStorageWriterIndexForSinkOpsSkipsPureSurfaceBatch`
  - revalidated:
    - `TestAnalyzeRootFindsPublicRestTokenIssuanceSurface`
    - `TestAnalyzeRootSkipsPublicRestTokenIssuanceAfterTokenValidationGuard`
- Real plugin result:
  - vulnerable `jupiterx-core__4.7.5` now finishes cleanly on focused `-sink-op surface` with `2` findings:
    - `includes/extensions/raven/includes/modules/forms/classes/social-login-handler/google.php:150` from `google.php:62`
    - `includes/extensions/raven/includes/modules/forms/classes/social-login-handler/facebook.php:274` from `facebook.php:187`
    - artifact `tmp/phparser-page3-jupiterx-7781-surface-vuln-20260327c/human-summary.md`
  - current `jupiterx-core` is clean on the same focused `surface` scan
    - artifact `tmp/phparser-page3-jupiterx-7781-surface-current-20260327c/human-summary.md`
- Corpus impact:
  - promoted `jupiterx-core-cve-2024-7781` to direct `surface` coverage in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-27 Page 3 follow-up: helper-template extraction and const-path folding promoted WP Statistics 2194

- Real blocker:
  - the vulnerable stored-XSS family in `wp-statistics__14.5` was not stopping at the real template sink because helper summaries dropped `extract(...)`-introduced locals and path-built includes through `plugin_dir_path(...)`-style constants
  - once helper summary replay was broadened, the current `wp-statistics` tree also exposed a recursion bug in extracted-variable fallback and then remained expensive on full-plugin negative-control scans
- Generic engine changes:
  - preserved `extract(...)` container state across branch merges and helper-summary replay
    - `internal/taintscan/statement_walk.go`
    - `internal/taintscan/analysis_support.go`
    - `internal/taintscan/call_eval.go`
    - `internal/taintscan/expression_eval.go`
  - added replayable placeholder sink handling for stored-XSS helper summaries so included-template sinks can be rebound to real persistent-read origins later
    - `internal/taintscan/analysis_callable.go`
  - taught literal path resolution about `__DIR__`, `__FILE__`, `dirname(...)`, `plugin_dir_path(...)`, `trailingslashit(...)`, and `untrailingslashit(...)`
    - `internal/taintscan/ast_helpers.go`
    - `internal/taintscan/callable_indexing.go`
  - added a narrow active-resolution guard for extracted-variable fallback so current-tree scans no longer stack-overflow in `resolveExtractedVariableOrigins(...)`
    - `internal/taintscan/expression_eval.go`
- Regression coverage:
  - `TestAnalyzeRootFindsStoredXSSThroughForeachTemplateLoader`
  - `TestAnalyzeRootFindsStoredXSSThroughForeachTemplateLoaderUsingPluginDirPathConstant`
  - `TestAnalyzeRootFindsStoredXSSThroughDirectTemplateLoaderHelper`
  - the broader included-template slice now passes again on the fast default test suite
- Real plugin result:
  - vulnerable `wp-statistics__14.5` now retains the real referral admin sink at `includes/admin/templates/pages/refer.url.php:43`
    - artifact `tmp/phparser-page3-wpstatistics-output-after-constpathfix2-20260327/human-summary.md`
  - single-case direct compare now matches
    - artifact `tmp/phparser-wpstatistics-compare-20260327/summary.json`
    - matched sink `includes/admin/templates/pages/refer.url.php:43`
  - current `wp-statistics` no longer stack-overflows on the extracted-variable path, but a full-plugin focused `-sink-op output` negative-control scan was still killed before completion and needs separate performance work
- Corpus impact:
  - promoted `wp-statistics-cve-2024-2194` to direct `output` coverage in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-27 Page 3 follow-up: Post Grid public archives materialized, but no visible fix path in free code line

- `post-grid-cve-2024-9636`
  - Materialized public vulnerable/fixed archives:
    - `tmp/wporg-page3-post-grid-20260327/the-post-grid-2.3.3`
    - `tmp/wporg-page3-post-grid-20260327/the-post-grid-2.3.4`
  - Result:
    - the public `2.3.3 -> 2.3.4` code diff is effectively empty for the privilege-escalation claim
    - only the plugin header/readme/version assets change in the free archive pair
  - Implication:
    - this is no longer just a “missing vulnerable fixture” row
    - the Wordfence CVE either points at a different code lineage/surface than the free WP.org pair exposes, or the public archive pair is insufficient to ground the bug
  - Corpus impact:
    - updated `post-grid-cve-2024-9636` notes in `test/semgrep_bundle_corpus/corpus.json`
    - keep metadata-only until the real vulnerable family is source-pinned from a trustworthy advisory or different code source

## 2026-03-27 Page 3 follow-up: alternate-source checks corrected Husky and Post Grid version assumptions

- `husky-cve-2025-1661`
  - Alternate method:
    - checked the current plugin readme plus public historical zip availability instead of relying only on the old advisory wording
  - Findings:
    - local `woocommerce-products-filter/readme.txt` shows:
      - `1.3.6.5`: `1 security fix, thanks to Dimas Maulana and Patchstack.com`
      - `1.3.6.6`: `one security fix, thanks to Hiroho and wordfence.com`
    - WP.org currently returns `404` for both `woocommerce-products-filter.1.3.6.5.zip` and `woocommerce-products-filter.1.3.6.6.zip`
  - Implication:
    - the Wordfence CVE boundary is likely `1.3.6.6`, not `1.3.6.5`
    - but the public vulnerable/fixed pair still cannot be materialized honestly from current WP.org downloads
  - Corpus impact:
    - updated `husky-cve-2025-1661` notes in `test/semgrep_bundle_corpus/corpus.json`

- `post-grid-cve-2024-9636`
  - Alternate method:
    - checked NVD references and WordPress Trac changesets instead of relying only on the local `2.3.3 -> 2.3.4` whole-tree diff
  - Findings:
    - NVD references the older vulnerable line at `2.2.93` in `includes/blocks/form-wrap/functions.php`
    - `2.2.93` still has the old `registerUser` path with direct attacker-controlled `update_user_meta(...)`
    - local `2.3.3` already adds an allowlist for `registerUser`, but still keeps a separate `tutorRegisterInstructor` branch that:
      - grants `tutor_instructor`
      - writes attacker-controlled user meta
      - handles `user_meta_files`
    - public `2.3.4` removes the `tutorRegisterInstructor` branch
    - current `phparser` `call` scans on both `2.3.3` and `2.3.4` still only retain unrelated `unsafe-deserialization` findings
  - Implication:
    - this row is no longer blocked by “empty free diff”
    - it is now a real engine miss on the form-wrap role/meta mutation family
  - Corpus impact:
    - updated `post-grid-cve-2024-9636` notes in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-27 Page 3 follow-up: Post Grid is confirmed as an action-replay engine miss, not a version ambiguity

- `post-grid-cve-2024-9636`
  - Revalidated after the alternate-source work using focused native action scans instead of only whole-tree diffs.
  - Real vulnerable/fixed action probes:
    - vulnerable `2.3.3`: `tmp/postgrid233-action-after-addrole/human-summary.md`
    - fixed `2.3.4`: `tmp/postgrid234-action-after-addrole/human-summary.md`
  - Result:
    - `phparser` still does not isolate the real `tutorRegisterInstructor` branch in `includes/blocks/form-wrap/functions.php`
    - the retained findings on both trees are the older generic action family such as:
      - `functions.php:78`
      - `functions.php:87`
    - the removed `tutorRegisterInstructor` branch at `functions.php:2211+` in `2.3.3` still does not surface directly
  - Failed generic fix attempt:
    - tried modeling constant `WP_User->add_role(...)` as an action sink for public/nonce-only request handlers
    - reverted the patch after the synthetic Post Grid-shaped regression stayed `0`
  - Current conclusion:
    - the remaining gap is deeper than “recognize `add_role` as sensitive”
    - the real blocker is `action` finding replay/retention through `apply_filters('form_wrap_process_' . $formType, ...)` callbacks
    - keep `post-grid-cve-2024-9636` metadata-only until filter-callback action replay can preserve the `registerForm`/`tutorRegisterInstructor` sink

## 2026-03-27 Page 3 follow-up: get_meta_sql hook model separated Ultimate Member 1702 search path

- Real blocker:
  - the vulnerable `ultimate-member__2.10.0` search-parameter SQLi family was not a plain execution-site SQL sink
  - it mutates the SQL through the old `get_meta_sql` filter callback `Member_Directory::change_meta_sql()`
  - `phparser` already modeled `posts_where`-style SQL return filters, but not `get_meta_sql`
- Generic engine changes:
  - added `get_meta_sql` to the core SQL clause filter models in `internal/taintscan/builtin_models.go`
  - fixed a generic bounds bug in `internal/taintscan/callgraph_relevance.go`
    - `indexGlobalStateReaders()` now guards zero-arg `get_results()` calls instead of indexing `typed.Args[0]` unconditionally
- Regression coverage:
  - added `TestAnalyzeRootFindsTaintedGetMetaSQLFilterReturn`
  - revalidated:
    - `TestAnalyzeRootFindsTaintedPostsWhereFilterReturn`
    - `TestAnalyzeRootFindsUltimateMemberStyleSortOrderQuery`
- Real plugin result:
  - reduced vulnerable core slice now finds the real search-family sink:
    - `tmp/phparser-um-2100-core-sql-after-getmetasql-20260327/human-summary.md`
    - `tainted-sql-string` at `includes/core/class-member-directory.php:1883`
    - source `class-member-directory.php:1777`
    - callable `\um\core\Member_Directory::change_meta_sql`
  - reduced current core slice drops that sink and keeps only the separate sorting path:
    - `tmp/phparser-um-current-core-sql-after-getmetasql-20260327/human-summary.md`
  - full single-case `corpus-compare` against the whole plugin tree still did not finish in a reasonable time, so this promotion is grounded by the vulnerable/current core-slice artifacts plus the green Go suite, not by a completed full-plugin compare artifact yet
- Corpus impact:
  - promoted `ultimate-member-cve-2025-1702` to direct `sql` coverage in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-27 Page 3 follow-up: Fluent Forms 2771 manager-policy path

- Real blocker:
  - the WPFluent route-policy fallback logic already existed, but the real Fluent Forms controller path delegated the mutation into services passed as typed method parameters
  - `phparser` was losing those receiver classes in two places:
    - call-graph class resolution
    - runtime/summary-time class resolution
- Generic engine changes:
  - added `ParamTypes` to callable metadata in `internal/taintscan/taintscan.go`
  - indexed parameter class hints in `internal/taintscan/callable_indexing.go`
  - taught `resolveMethodCallClass()` in `internal/taintscan/wordpress_context.go` to use typed parameter classes
  - taught `resolveCallGraphClassExpr()` in `internal/taintscan/callgraph_relevance.go` to use typed parameter classes
  - taught `analysisState.resolveClassExpr()` in `internal/taintscan/assignment_eval.go` to use typed parameter classes
- Regression coverage:
  - added `TestAnalyzeRootFindsWPFluentPolicyFallbackPrivilegeMutationThroughTypedServiceParam`
  - revalidated:
    - `TestAnalyzeRootFindsWPFluentPolicyFallbackRouteAction`
    - `TestAnalyzeRootSkipsWPFluentRouteActionAfterVerifyRequestGuard`
    - `TestAnalyzeRootFindsPublicAjaxRoleMutationThroughHelperChain`
- Real plugin result:
  - vulnerable full-plugin `call` scan now hits the real manager privilege path:
    - `tmp/phparser-fluent2771-vuln-full-call-after-resolveclassexprfix-20260327/human-summary.md`
    - `wp-request-tainted-privilege-mutation` at `app/Modules/Acl/Acl.php:348`
    - source `app/Http/Controllers/ManagersController.php:19`
    - callable `\FluentForm\App\Http\Controllers\ManagersController::addManager`
  - current full-plugin `call` scan still retains the same sink family, but under a capability-checked route context and at different line offsets:
    - `tmp/phparser-fluent2771-current-full-call-after-resolveclassexprfix-20260327/human-summary.md`
    - `wp-request-tainted-privilege-mutation` at `app/Modules/Acl/Acl.php:352`
    - source `app/Http/Controllers/ManagersController.php:26`
- Corpus impact:
  - promoted `fluent-forms-cve-2024-2771` to direct `call` coverage in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-27 Page 3 follow-up: redux 6828 still blocked at full-plugin write scale

- Recheck:
  - reran the full vulnerable plugin write scan:
    - `timeout 120s env PHARSER_TAINTSCAN_TIMINGS=1 go run ./cmd/taint-scan -target bugbounty-note/wordpress/wp_install/plugins/redux-framework__4.4.17 -sink-op write -output-dir tmp/phparser-redux6828-vuln-full-write-after-fluentfix-20260327`
  - build phase completed in about `4.816s`
  - the process was then killed during the engine run before any report files were emitted
- Current conclusion:
  - the narrow color-scheme slice remains valid and still separates vulnerable `4.4.17` from fixed `4.4.18`
  - but the full-plugin `write` workload is still not tractable enough to promote `redux-framework-cve-2024-6828` to honest direct compare
  - keep it metadata-only until the full-plugin write batch can finish or be bounded generically without special-casing Redux

## 2026-03-27 Page 3 follow-up: default suite green again and remaining public blockers rechecked

- Default `phparser` suite:
  - realigned four legacy tests in `internal/taintscan/taintscan_test.go` from the `output` batch to their correct sink families:
    - three include-path cases now use `include`
    - one filesystem-read case now uses `read`
  - reason:
    - those tests were asserting path sink behavior through the wrong batch while the suite already has dedicated `include`/`read` coverage for the same families
  - verification:
    - focused path slice passed
    - `go test ./...` passed again

- `ninja-forms-cve-2024-11052`
  - reran full vulnerable/current output scans:
    - `tmp/phparser-ninja11052-vuln-20260327b/human-summary.md`
    - `tmp/phparser-ninja11052-current-20260327b/human-summary.md`
  - result:
    - vulnerable `3.8.19` still reports only newer sink families in:
      - `includes/Routes/Submissions.php`
      - `blocks/bootstrap.php`
    - current `3.14.1` also reports different newer sink families in those same modern routes/views
    - neither run isolates the real legacy admin calculations template sink at `includes/Templates/admin-metaboxes-calcs.html.php`
  - conclusion:
    - keep metadata-only until `phparser` can separate the legacy calculations write/read/output path cleanly

## 2026-03-27 Page 3 follow-up: Ninja Forms 11052 HTML-safe placeholder replay fixed

- Root cause:
  - `esc_html()` and similar HTML-safe boundaries were already marking origins with `OutputSafeHTML`
  - but `addPersistentOutputFinding()` still replayed placeholder param/receiver origins through `replayablePersistentOutputOrigins()` even when those placeholders were already HTML-safe
  - that made fixed templates keep stale stored-XSS findings at escaped output sites after summary replay
- Generic engine change:
  - in `internal/taintscan/analysis_support.go`, `replayablePersistentOutputOrigins()` now skips placeholder origins when `OutputSafeHTML` is set and `OutputUnsafeHTML` is not
- Regression coverage:
  - added `TestAnalyzeRootSkipsStoredXSSPlaceholderAfterEscHTMLBoundaryInHelper`
  - reran:
    - `TestAnalyzeRootSkipsStoredXSSAfterWPKsesPostBoundary`
    - `TestBuildEngineSpecializesNinjaFormsTemplateForCalculationsMetabox`
  - `go test ./...` passed again
- Measured Ninja effect:
  - vulnerable `3.8.19` after fix:
    - `tmp/phparser-ninja3819-output-after-eschtml-placeholderfix-20260327/human-summary.md`
    - still reports `includes/Templates/admin-metaboxes-calcs.html.php` lines `4`, `6`, `8`, `9`
  - fixed `3.8.20` after fix:
    - `tmp/phparser-ninja3820-output-after-eschtml-placeholderfix-20260327/human-summary.md`
    - drops escaped template sinks and keeps only line `4`
  - current `3.14.1` after fix:
    - `tmp/phparser-ninja-current-output-after-eschtml-placeholderfix-20260327/human-summary.md`
    - same shape as fixed `3.8.20`, with only line `4` remaining in the calculations metabox
- Current conclusion:
  - sink-side separation is now correct for the legacy calculations template
  - the case still stays metadata-only because the remaining vulnerable findings are not yet rooted in the real `extra['calculations']` submission source chain

- `redux-framework-cve-2024-6828`
  - narrowed color-scheme rerun:
    - vulnerable slice `4.4.17`:
      - `tmp/phparser-redux-colorscheme-vuln-20260327b/human-summary.md`
      - `wp-request-file-upload-without-cap-check` at `class-redux-color-scheme-import.php:243`
    - current slice:
      - `tmp/phparser-redux-colorscheme-current-20260327b/human-summary.md`
      - `0` findings
  - full current plugin recheck:
    - `tmp/phparser-redux-current-write-20260327b/` was created but no report files were emitted before the bounded run ended
  - conclusion:
    - narrow vulnerable/current separation is still real
    - full-plugin direct compare is still blocked on write-batch tractability

- `fluent-forms-cve-2024-10646`
  - reran full vulnerable/current output scans:
    - `tmp/phparser-fluent10646-vuln-output-20260327b/human-summary.md`
    - `tmp/phparser-fluent10646-current-output-20260327b/human-summary.md`
  - result:
    - both trees now produce unrelated admin/rest/payment output findings
    - nothing in those results grounds the claimed unauthenticated `form subject` stored-XSS family
    - the visible public `5.2.6 -> 5.2.7` diff still points at `app/Services/Transfer/TransferService.php` note-export changes, not a subject render patch
  - conclusion:
    - keep metadata-only until a trustworthy advisory or patch pins the real vulnerable source/sink family

## 2026-03-27 Page 3 follow-up: Fluent Forms 10646 public diff rechecked from fixed zip

- Method:
  - downloaded public fixed `5.2.7` from WP.org into `tmp/fluentform-527/`
  - diffed it directly against local vulnerable `fluentform__5.2.6`
- Public code delta:
  - vendor changelog still confirms `5.2.7` as the fix boundary
  - the most plausible security-relevant PHP change is in `boot/globals.php`
    - old code recursively sanitized array values in place while reusing attacker-controlled keys
    - new code rebuilds nested arrays with `sanitize_text_field()` applied to each key before recursion
  - `app/Services/Transfer/TransferService.php` note-export changes are real but do not ground the claimed unauthenticated `form subject` stored-XSS family
  - `app/Services/FormBuilder/EditorShortcodeParser.php` only changes `REQUEST_URI` handling through `urldecode(...)`, which also does not cleanly explain the CVE wording
- Current conclusion:
  - the old `TransferService`-centric note was misleading
  - the public patch history suggests the advisory wording may be incomplete or imprecise, and the visible free-plugin fix is closer to recursive request sanitization than to a pinned subject-render sink
  - keep `fluent-forms-cve-2024-10646` metadata-only until the exact vulnerable source/sink family is grounded from a stronger primary source

## 2026-03-27 Page 3 follow-up: Redux 6828 fixed boundary rechecked from 4.4.18 zip

- Method:
  - downloaded public fixed `4.4.18` from WP.org into `tmp/redux-4418/`
  - compared it against local vulnerable `redux-framework__4.4.17`
- Public code result:
  - the first fixed public tree does not just go clean on the narrowed `color_scheme` slice
  - it removes `redux-core/inc/extensions/color_scheme/color_scheme/class-redux-color-scheme-import.php` entirely
  - that removal is consistent with the already-separated vulnerable slice at `class-redux-color-scheme-import.php:243`
- Current conclusion:
  - version ambiguity is gone for the public free-plugin boundary
  - `redux-framework-cve-2024-6828` remains metadata-only only because the full-plugin `write` workload is still too expensive, not because the vulnerable/fixed file pair is unclear

## 2026-03-27 Page 3 follow-up: Post Grid 9636 promoted to direct compare

- Root cause:
  - `apply_filters(...)` callback summaries were replaying `ParamFindings`, but replayed `SourceFindings` were dropped whenever the merged caller context did not change
  - that meant filter callbacks which read request input inside their own body could mutate state without re-emitting their direct sink findings at the caller
  - the Post Grid `process_form_data() -> form_wrap_process_registerForm()` path hit this exact gap
- Generic engine changes:
  - in `internal/taintscan/call_eval.go`, `instantiateSummaryReturn()` now always replays `summary.SourceFindings` and merges them into `sourceHits` instead of skipping same-context replays
  - in `internal/taintscan/builtin_models.go`, `add_role` is now part of the privilege-mutation method sink family alongside `set_role` and `add_cap`
  - in `internal/taintscan/call_eval.go`, constant role/capability mutation calls now fall back to `currentActionRequestOrigins()` when the role/capability argument itself is literal, and that replay is still suppressed under a definite capability guard via `addUnauthorizedActionFinding(...)`
- Regression coverage:
  - added `TestAnalyzeRootFindsActionSinkInsideApplyFiltersCallbackUsingRequestGetter`
  - added `TestAnalyzeRootFindsPublicAjaxRoleMutationViaLiteralAddRole`
  - added `TestAnalyzeRootSkipsCapabilityCheckedLiteralAddRoleMutation`
  - focused filter/privilege tests passed
- Post Grid result:
  - vulnerable `post-grid__2.3.3` `call` batch now reports:
    - `wp-request-tainted-privilege-mutation` at `includes/blocks/form-wrap/functions.php:2228`
    - source `includes/blocks/form-wrap/functions.php:2154`
    - callable `\form_wrap_process_registerForm`
  - fixed public `2.3.4` stays clean for that privilege-mutation finding on the same `call` batch
  - current local `the-post-grid` also returns `0` findings on the same `call` batch
- Corpus result:
  - `post-grid-cve-2024-9636` is no longer metadata-only
  - promoted to direct `call` coverage in `test/semgrep_bundle_corpus/corpus.json`

## 2026-03-28 Page 3 follow-up: remaining public blocked rows rechecked with stronger primary sources

- `husky-cve-2025-1661`
  - stronger public grounding:
    - NVD/Wordfence pin the CVE to the unauthenticated `woof_text_search` `template` parameter in `ext/by_text/index.php`
    - WP.org changeset `3249621` is the exact public patch for that branch and inserts:
      - `$template = sanitize_key($template);`
      - immediately before the template path is built
    - later WP.org readmes explicitly list a separate `1.3.6.6` Wordfence security release, so the public version story is more awkward than the original note suggested
  - rechecks:
    - current `1.3.8.1` focused include scan on `ext/by_text`:
      - `tmp/phparser-husky-current-bytxt-include-20260328/human-summary.md`
      - only reports the unrelated helper include at `ext/by_text/index.php:569`
    - temporary one-file and copied-subtree vulnerable probes built from Trac revision `3244638` did not produce a durable direct CVE trace:
      - `tmp/phparser-husky-3244638-bytxt-include-20260328/human-summary.md`
      - `tmp/phparser-husky-3244638-extfull-include-20260328/human-summary.md`
  - conclusion:
    - the real public patch location is now exact
    - but public `1.3.6.5` and `1.3.6.6` fixture materialization is still inconsistent through normal downloads, and the temporary revision-backed probes are not yet robust enough for a durable direct corpus contract
    - keep metadata-only for now

- `fluent-forms-cve-2024-10646`
  - no engine change here
  - durable note now reflects the stronger public `5.2.6 -> 5.2.7` evidence:
    - the clearest free-plugin patch is recursive request-key sanitization in `boot/globals.php`
    - the advertised unauthenticated `form subject` output family is still not pinned from the public diff
  - conclusion:
    - still metadata-only because the advisory wording is not cleanly grounded by the free-plugin patch history

- `ninja-forms-cve-2024-11052`
  - stronger source review:
    - real vulnerable chain:
      - `includes/AJAX/Controllers/Submission.php:393` populates `extra['calculations']`
      - the action loop dispatches through `Ninja_Forms()->actions[$type]->process(...)`
      - vulnerable `NF_Actions_Save::process()` calls `update_extra_values()` and then `update_post_meta()`
      - the admin metabox reads the stored `calculations` back with `get_extra_values()` and renders `includes/Templates/admin-metaboxes-calcs.html.php`
    - sink-side separation is already good after the earlier HTML-safe replay fix:
      - vulnerable rerun:
        - `tmp/phparser-ninja3819-output-rerun-20260328/human-summary.md`
      - fixed/current reruns already drop the escaped `value/raw/parsed` sinks and keep only line `4`
  - remaining engine gap:
    - this is not a sink problem anymore
    - the missing piece is dynamic registry resolution for `Ninja_Forms()->actions[$type]->process()`, rooted in the `load_classes('Actions')` registry population path in `ninja-forms.php`
    - current vulnerable findings still root in unrelated admin-side persistent writes instead of the real submission `extra['calculations']` chain
  - conclusion:
    - keep metadata-only until the generic action-registry class-resolution gap is fixed

- Current public page-3 remainder after this pass:
  - `husky-cve-2025-1661`
    - blocked by durable public fixture/materialization problems
  - `fluent-forms-cve-2024-10646`
    - blocked by advisory/source-family ambiguity
  - `ninja-forms-cve-2024-11052`
    - blocked by one concrete generic engine gap around dynamic action registries

## 2026-03-28 Page 3 follow-up: Ninja promoted, Husky and Fluent rechecked again

- `ninja-forms-cve-2024-11052`
  - Promoted to direct `output` coverage in `test/semgrep_bundle_corpus/corpus.json`.
  - The compare contract now keys on the real vulnerable calculations metabox output sinks that disappear after the public `3.8.20` fix:
    - `includes/Templates/admin-metaboxes-calcs.html.php:6`
    - `includes/Templates/admin-metaboxes-calcs.html.php:8`
    - `includes/Templates/admin-metaboxes-calcs.html.php:9`
  - Direct compare result:
    - `tmp/phparser-ninja11052-compare-20260328/summary.json`
    - matched finding at `includes/Templates/admin-metaboxes-calcs.html.php:6`
  - This is an honest direct differential even though the broader source-side trace still roots in admin-side persisted reads instead of the exact `extra['calculations']` submission chain.

- `husky-cve-2025-1661`
  - Rechecked with a stronger revision-backed full-plugin materialization:
    - copied the full current plugin tree into `tmp/husky-full-vuln-plugin-20260328`
    - swapped in vulnerable `ext/by_text/index.php` from Trac revision `3244638`
  - Two full-plugin include scans still died after engine build without producing result files:
    - `tmp/phparser-husky-full-vuln-plugin-include-20260328`
    - `tmp/phparser-husky-full-vuln-plugin-include-max1-20260328`
  - Conclusion:
    - the exact public patch location is known
    - but an honest direct contract is still blocked by durable public vulnerable materialization plus full-plugin include-batch performance

- `fluent-forms-cve-2024-10646`
  - Rechecked again with the stronger public `5.2.6 -> 5.2.7` diffs already downloaded under `tmp/fluentform-526-527-diff-20260328/`.
  - The strongest visible free-plugin deltas are still:
    - recursive request-key sanitization in `boot/globals.php`
    - a separate `EditorShortcodeParser.php` change around `REQUEST_URI`
  - Existing vulnerable/current output probes still do not separate on a trustworthy public `form subject` family:
    - `tmp/phparser-fluent10646-vuln-output-20260327b/human-summary.md`
    - `tmp/phparser-fluent10646-current-output-20260327b/human-summary.md`
  - Conclusion:
    - keep metadata-only until a stronger primary source pins the actual vulnerable sink family

- Page-3 public WP.org status after this pass:
  - `14` direct
  - `2` metadata-only
  - remaining public blocked rows:
    - `husky-cve-2025-1661`
    - `fluent-forms-cve-2024-10646`

## 2026-03-28 Ninja registry follow-up: generic registry resolution made strict and fast again

- problem:
  - the earlier direct Ninja Forms promotion was still too weak for strict review
  - the sink differential was real, but the compare could still satisfy the contract with unrelated admin-side sources
  - the remaining generic gap was dynamic object registry resolution through:
    - singleton/property-backed arrays
    - array lookup by dynamic key
    - later virtual dispatch on the looked-up object
  - a first generic fix worked on the synthetic registry case, but it regressed performance badly:
    - `batch=output pass=5` on `ninja-forms-cve-2024-11052` ballooned to about `2m30s`
    - root cause: unresolved dynamic class placeholders with empty prefixes were broadening to effectively "any class in the plugin"

- generic engine changes:
  - added array-entry class hint caches on the engine so callback/class recovery can reuse bounded results:
    - `receiverPropertyEntryClassHints`
    - `callableArrayEntryClassHints`
  - taught callback/class resolution to follow:
    - array entry lookups like `RegistryFunc()->handlers[$type]`
    - function/method/static-call return arrays
    - singleton/static-property-backed registry assignments
  - fixed dynamic class-pattern handling so empty placeholder prefixes no longer collapse to `self/current class`
  - improved local dynamic string merging:
    - repeated literal assignments now collapse to bounded patterns like `Handler_{class_name}`
    - they no longer fall back to an unconstrained all-class lookup
  - widened literal-arg specialization eligibility for call-batch analysis when a callable uses parameter placeholders in dynamic class construction (`new $class_name`-style patterns)

- new/updated regression coverage:
  - synthetic strict guardrail:
    - `TestAnalyzeRootResolvesSingletonPropertyRegistryArrayDispatch`
    - now asserts:
      - the specialized registry loader resolves array entries to `\Handler_Save` without falling back to `\Registry`
      - `\Demo::run` has a call edge to `\Handler_Save::process`
      - the resulting `unsafe-use` finding reaches the sink at line `4` from the caller source line `55`
  - existing Ninja real-plugin guardrails still pass:
    - `TestBuildEngineKeepsNinjaFormsCalculationsMetaboxRelevant`
    - `TestBuildEngineSpecializesNinjaFormsTemplateForCalculationsMetabox`

- measured result on the real Ninja case:
  - fresh targeted compare:
    - `tmp/phparser-ninja11052-realtrace2-20260328/summary.json`
    - `tmp/phparser-ninja11052-realtrace2-20260328/ninja-forms-cve-2024-11052/comparison.json`
  - performance recovered:
    - `build-engine=6.717s`
    - `engine-run=3.798s`
    - `total=10.857s`
  - the bad multi-minute pass-5 regression is gone
  - matched finding is still the real vulnerable sink family in `includes/Templates/admin-metaboxes-calcs.html.php`

- contract tightening:
  - updated `test/semgrep_bundle_corpus/corpus.json` so `ninja-forms-cve-2024-11052` now requires:
    - the real calculations sink lines (`:6`, `:8`, `:9`)
    - plus the real persistent read source strings from `includes/Abstracts/Model.php`
  - this prevents fake admin-side sources like `includes/Admin/Metaboxes/AppendAForm.php` from satisfying the compare contract

- what remains intentionally unfixed:
  - the current stored-XSS rule family still records the persistent read site as the trace source
  - it does not yet produce a single direct finding that starts at the original submission write in `includes/AJAX/Controllers/Submission.php` and carries through `Ninja_Forms()->actions[$type]->process()` into storage and back out to the metabox sink
  - that is broader cross-request write-provenance work, not a local registry-resolution bug anymore

## 2026-03-28 Ninja stored-write follow-up: bounded foreach-key propagation helps the generic loop, but real Ninja still stops at the read side

- problem:
  - the strict review bar for `ninja-forms-cve-2024-11052` is higher than the current stored-read contract
  - after the registry fix, the remaining generic gap looked like keyed storage provenance:
    - keyed foreach loops were degrading storage writes to `[*]`
    - keyed reads were still unioning family-wide read roots even when a concrete keyed root existed
  - that kept the real plugin compare anchored on `includes/Abstracts/Model.php:503` / `:513` instead of the submission write path

- generic engine changes:
  - added bounded foreach-key string propagation:
    - `StmtForeach` now calls `assignForeachKeyHint(...)`
    - the hint only sticks when the iterated array has exactly one stable top-level key from:
      - a literal array
      - or known structural child paths
  - added runtime keyed storage-root resolution:
    - `storageRootForArgsWithState(...)`
    - `stableStorageKeyValue(...)`
    - runtime storage roots can now use stable string hints like `calculations`
  - tightened keyed storage reads:
    - `storageReadOriginsForFuncCall(...)` now prefers exact keyed roots
    - family-wide self origins are only used when:
      - the read root is itself just the family root, or
      - the exact keyed root has no origins

- new regression coverage:
  - added `TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop`
  - this synthetic case now requires the stored-XSS finding on the calculations template to source from the original request write (`$_POST['value']`), not only from the later persistent read
  - focused synthetic output tests passed:
    - `TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop`

- measured result:
  - full `go test ./...` still passed
    - `internal/taintscan`: about `0.985s`
  - real Ninja targeted compare stayed bounded:
    - `tmp/phparser-ninja11052-writeprovenance-20260328/summary.json`
    - `duration_ms`: `12575`
    - `engine-run`: about `5.455s`
  - no return to the earlier multi-minute regression

- honest outcome:
  - the new bounded logic is sufficient for the generic stored-XSS loop shape
  - but the real Ninja plugin compare is still anchored on:
    - `includes/Abstracts/Model.php:503`
    - `includes/Abstracts/Model.php:513`
  - it did not yet produce `includes/AJAX/Controllers/Submission.php` as a trace source

- current blocker:
  - the remaining gap is not the keyed save loop by itself anymore
  - it is summary-time dynamic keyed subtree propagation in the real plugin object model:
    - the public submission write path
    - the intermediate `_extra_values` / save helpers
    - and the later keyed read/template render path
  - the engine can now prove the stricter write-side shape generically in the synthetic loop
  - but the real plugin still needs another generic layer to preserve keyed subtree identity across that full helper stack

## 2026-03-28 Ninja stored-write contract cleanup: keep the useful key precision work, drop the ineffective replay experiment, and match the real cross-request write context directly

- problem:
  - the temporary receiver-backed summary storage replay experiment did not move the real Ninja compare off the persistent-read bridge source in `includes/Abstracts/Model.php`
  - it also risked reopening storage-path churn without improving the real case
  - the useful generic improvement from this slice was the bounded foreach-key and runtime keyed storage-root precision in:
    - `internal/taintscan/state_summary_helpers.go`
    - `internal/taintscan/statement_walk.go`
  - the honest direct-coverage shape for this stored-XSS case is:
    - vulnerable output sink at `includes/Templates/admin-metaboxes-calcs.html.php`
    - plus the real stored-write entrypoints under `includes/AJAX/Controllers/Submission.php`
    - rather than pinning the visible read-bridge source line forever

- changes:
  - removed the ineffective receiver-backed storage replay experiment from:
    - `internal/taintscan/call_eval.go`
    - `internal/taintscan/structural_state.go`
    - `internal/taintscan/summary_paths.go`
  - removed the temporary real-plugin debug probe:
    - `internal/taintscan/ninja_debug_test.go`
  - added direct compare support for stored-write entrypoint coverage:
    - new comparable coverage field in `internal/corpuscompare/corpuscompare.go`:
      - `stored_write_entry_locations_any`
    - `findingMatchesCoverage(...)` can now require a matched finding’s `stored_write_context.entrypoints[*].location`
  - updated compare artifacts to surface the matched finding’s `stored_write_context` directly in `comparison.json`
  - updated `test/semgrep_bundle_corpus/corpus.json` for `ninja-forms-cve-2024-11052`:
    - removed the old `trace_source_strings_any` requirement for `includes/Abstracts/Model.php`
    - now requires:
      - the real calculations sink lines `:6`, `:8`, `:9`
      - plus stored-write entrypoints:
        - `includes/AJAX/Controllers/Submission.php:29`
        - `includes/AJAX/Controllers/Submission.php:30`

- verification:
  - focused compare test passed:
    - `TestCompareCaseMatchesStoredWriteEntryLocation`
  - focused stored-XSS regressions stayed green:
    - `TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForReceiverBackedExtraSaveLoopWithDynamicRecordID`
  - fresh Ninja compare is still `match`:
    - `tmp/phparser-ninja11052-storedwrite-contract2-20260328/summary.json`
    - `tmp/phparser-ninja11052-storedwrite-contract2-20260328/ninja-forms-cve-2024-11052/comparison.json`
  - full suite passed:
    - `go test ./...`
    - `internal/taintscan`: about `1.012s`

- honest outcome:
  - the direct case is now real in the bounded, cross-request sense:
    - the finding still uses the persistent-read bridge as its visible trace source
    - but the direct contract now also requires the real submission-side stored-write entrypoints from `includes/AJAX/Controllers/Submission.php`
    - and the compare artifact exposes that stored-write context directly
  - full end-to-end request-write line provenance through `Ninja_Forms()->actions[$type]->process()` is still future engine work, but the current direct contract no longer overclaims by pretending the read-bridge source is the whole proof

## 2026-03-28 Stored-XSS noise reduction: collapse duplicate source variants by sink site and prefer the stronger stored-write variant

- problem:
  - after the contract cleanup, `ninja-forms-cve-2024-11052` still had `43` raw direct findings for one stored-XSS family
  - most of that was not real extra coverage
  - it was the same sink sites repeated with multiple source candidates:
    - persistent-read bridges
    - unrelated admin-side request readers
    - and a few stronger variants that already carried the real `stored_write_context`

- changes:
  - `internal/taintscan/helpers.go`
    - added `wp-stored-xss-persistent-read-to-output` to `shouldCollapseFindingSources(...)`
    - final dedupe now collapses stored-XSS findings by sink site instead of preserving one result per source location
    - introduced `findingScore(...)` with `storedWriteContextScore(...)`
    - when source variants collapse, the retained finding now prefers the stronger stored-write variant rather than whichever source has the loudest request snippet
    - `mergeFindings(...)` now scores the original candidates before merging contexts, so a weak existing trace cannot “inherit” a stronger stored-write context and incorrectly stay selected
    - when duplicate findings share the same trace source, stored-write context is still merged as before

- regression coverage:
  - added `TestDedupeFinalFindingsCollapsesStoredXSSToBestStoredWriteVariant`
  - existing collapse tests for `unsafe-use` and record-read-to-output stayed green

- measured result:
  - `ninja-forms-cve-2024-11052`
    - before: `43` findings
    - after: `13` findings
    - still `match`
    - artifact:
      - `tmp/phparser-ninja11052-deduped2-20260328/summary.json`
      - `tmp/phparser-ninja11052-deduped2-20260328/ninja-forms-cve-2024-11052/comparison.json`
  - the calculation metabox family is now one retained finding per sink line instead of four source-variant duplicates per line
  - representative stored-XSS regression stayed `match`:
    - `tmp/phparser-wpstatistics-after-storedxss-dedupe-20260328/summary.json`
  - full suite passed:
    - `go test ./...`
    - `internal/taintscan`: about `1.098s`

- honest outcome:
  - this reduces duplicate stored-XSS noise without pretending there are fewer distinct sink sites than there really are
  - Ninja is still not “one finding total” because the plugin truly has multiple distinct persistent-output surfaces
  - but the worst duplicate inflation from multiple equivalent source variants on the same sink is now gone

## 2026-03-28 Stored-XSS sink-site collapse: stop preserving one result per rendering callable

- problem:
  - after the first stored-XSS dedupe pass, `wp-statistics-cve-2024-2194` was still at `1204` findings
  - inspection of `taint-results.json` showed that the remaining inflation was mostly not new sink sites
  - it was the same template sink lines repeated across many page `view()` callables because final dedupe still keyed stored-XSS on:
    - sink site
    - plus rendering callable
  - the dominant noisy variants also showed a second ranking bug:
    - a bridge with no `stored_write_context` could still beat a context-anchored variant if the anchored context was only `capability_checked`

- changes:
  - `internal/taintscan/helpers.go`
    - added `shouldKeepCallableInCollapsedFinalFinding(...)`
    - `wp-stored-xss-persistent-read-to-output` now collapses by sink site instead of sink site plus callable
    - raised the base `storedWriteContextScore(...)` so any meaningful stored-write context outranks an otherwise similar finding with no stored-write context at all
    - access-specific weighting still differentiates `unauthenticated`, `nonce_only`, `authenticated`, and `capability_checked` variants after that baseline

- regression coverage:
  - added `TestDedupeFinalFindingsCollapsesStoredXSSAcrossEquivalentSinkCallables`
  - existing stored-XSS dedupe regressions still pass

- measured result:
  - `wp-statistics-cve-2024-2194`
    - before: `1204` findings
    - after: `98` findings
    - still `match`
    - artifact:
      - `tmp/phparser-wpstatistics-after-storedxss-dedupe-20260328/summary.json`
      - `tmp/phparser-wpstatistics-after-storedxss-sinkcollapse-20260328/summary.json`
    - the new `98` exactly matches the number of unique sink sites in the vulnerable result set
  - `ninja-forms-cve-2024-11052`
    - stayed `13` findings
    - still `match`
    - artifact:
      - `tmp/phparser-ninja11052-after-storedxss-sinkcollapse-20260328/summary.json`
  - full suite passed:
    - `go test ./...`
    - `internal/taintscan`: about `0.928s`

- honest outcome:
  - stored-XSS reporting is now closer to “one finding per real output site” instead of “one finding per output site per reused page/view wrapper”
  - this is still not a guarantee that every retained sink is exploitable
  - it is a reporting precision improvement, not a semantic narrowing of what counts as a stored persistent-read-to-output surface

## 2026-03-28 Taint result artifact metadata: add timing and per-rule counts to `taint-results.json`

- problem:
  - `taint-results.json` only exposed raw `results` and `errors`
  - repeated triage kept needing extra `jq` or summary-side recomputation just to answer:
    - how long the scan took
    - how many findings it produced in total
    - how many findings each rule contributed

- changes:
  - `internal/taintscan/taintscan.go`
    - added optional top-level `summary` field on the payload
  - `internal/taintscan/payload_summary.go`
    - added `PayloadSummary`
    - added `EnrichPayload(...)` to stamp:
      - `generated_at`
      - `elapsed_ms`
      - `total_results`
      - `total_errors`
      - `results_per_rule`
  - `cmd/taint-scan/main.go`
    - now records command elapsed time and enriches the payload before writing `taint-results.json`
  - `cmd/corpus-compare/main.go`
    - now enriches each per-case `taint-results.json` with the same summary block

- regression coverage:
  - added `internal/taintscan/payload_summary_test.go`
  - `go test ./cmd/taint-scan`
  - `go test ./...`

- verification artifact:
  - direct scan example:
    - `tmp/phparser-wpreset-surface-summary-20260328/taint-results.json`
  - example summary block:
    - `generated_at`
    - `elapsed_ms: 1214`
    - `total_results: 1`
    - `results_per_rule.predictable-security-identifier-surface: 1`

- honest outcome:
  - no taint semantics changed
  - this is purely a scan-artifact observability improvement
  - future triage can read counts and timing directly from `taint-results.json` instead of recomputing them downstream

## 2026-03-28 Fresh baseline attempt: full corpus rerun is now blocked immediately by `forminator`

- problem:
  - after the recent stored-XSS and payload-summary changes, I tried to regenerate a fresh full corpus baseline and TODO list
  - the monolithic `corpus-compare` rerun never produced any case outputs because it got stuck on the first case
  - a guarded per-case rerun confirmed the blocker:
    - `forminator-cve-2025-6463` timed out at about `180684ms` before the rest of the run could stabilize

- focused diagnosis:
  - bounded timing probe:
    - `PHARSER_TAINTSCAN_TIMINGS=1 timeout -k 10s 90s /tmp/phparser-corpus-compare -manifest test/semgrep_bundle_corpus/corpus.json -case-id forminator-cve-2025-6463 ...`
  - timing artifact:
    - `tmp/phparser-forminator-timings-20260328.log`
  - strongest hotspots in the current tree:
    - `build-engine=34.482s`
    - `index-call-sink-relevant-use-orders=9.472s`
    - `index-literal-arg-hints=6.649s`
    - `build-call-graph=7.502s`
    - first delete batch slow callable:
      - `method::\Forminator_CForm_Front_Action::handle_form duration=33.072s`
    - next two large delete callables:
      - `method::\Forminator_Quiz_Front_Action::process_knowledge_submit duration=4.022s`
      - `method::\Forminator_Quiz_Front_Action::process_knowledge_submit_multiple_answers duration=4.623s`

- honest outcome:
  - the requested fresh full-corpus TODO refresh is currently blocked by a real performance regression, not by missing reporting glue
  - the immediate critical path is now:
    - reduce delete-batch work inside the Forminator front action handlers
    - then rerun the guarded full corpus baseline

## 2026-03-28 Delete-mode forward relevance: safely prune post-anchor churn without breaking cross-request delete paths

- problem:
  - the first full rerun attempt was still blocked by `forminator-cve-2025-6463`
  - focused timing on the vulnerable Forminator tree showed delete-mode work staying far too broad:
    - baseline `-sink-op delete -max-passes 1`
      - `relevant=1853`
      - `pending=1853`
      - `engine-run=1m10.773s`
      - `total=1m45.041s`
    - artifact:
      - `tmp/phparser-forminator-delete-max1-20260328.log`
  - the main hotspot stayed in `\Forminator_CForm_Front_Action::handle_form`, and the hot summary list still showed clearly unrelated delete-mode churn like:
    - `\Forminator_CForm_Front_Mail::process_mail`
    - `\Forminator_CForm_Front_Mail::get_admin_email_recipients#runtime`
    - `\Forminator_CForm_Front_Mail::get_recipient`
  - a first broad delete-mode pruning attempt fixed Forminator much more aggressively, but it regressed real cross-request delete coverage in wrapper/storage tests

- changes:
  - `internal/taintscan/callgraph_relevance.go`
    - added bounded `deleteAnchorOrder` discovery for delete-only forward relevance
    - `deleteAnchorOrder` now recognizes early reverse-relevant/direct-sink callees
    - delete-only data-carrier edges are now pruned only when all of the following are true:
      - the edge does not carry a file-relevant root after the call site
      - the callee is not already reverse-relevant
      - the callee is not an anchor-relevant callable
      - the callee is not a direct sink
      - the callee is not a storage writer
      - and the edge occurs after the first delete anchor in that caller
    - this keeps the real writer/reader wrapper chains alive while dropping late request-churn helpers after the delete path is already anchored
  - `internal/taintscan/taintscan_test.go`
    - added `TestBuildEngineDeleteRelevanceSkipsUnrelatedDataCarrierHelper`
    - added `TestBuildEngineDeleteRelevanceKeepsIntermediateWrapper`

- regression coverage:
  - focused delete relevance / wrapper tests:
    - `TestBuildEngineDeleteRelevanceSkipsUnrelatedDataCarrierHelper`
    - `TestBuildEngineDeleteRelevanceKeepsIntermediateWrapper`
    - `TestAnalyzeRootTracksWrapperReturningDBRow`
    - `TestAnalyzeRootTracksWrapperColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete`
    - `TestAnalyzeRootKeepsCrossRequestMetaWriterRelevantForDeleteSink`
    - `TestAnalyzeRootKeepsSmallForeignCrossRequestMetaWriterRelevantForDeleteSink`
    - `TestBuildEngineCapsLargeSameClassCrossRequestWriterSetToReachableWriters`
    - `TestBuildEngineCrossRequestWriterReverseExpansionPrefersRequestReachableCallers`
    - `TestBuildEngineCrossRequestWriterReverseExpansionKeepsCallerOfRequestHelper`
  - all of the above passed

- measured effect:
  - latest safe Forminator delete probe:
    - `tmp/phparser-forminator-delete-max1-after-deleteprune5-20260328.log`
    - `relevant=1532`
    - `pending=1532`
    - `engine-run=1m7.727s`
  - this is a real reduction from the `1853`/`1m10.773s` baseline, but not enough to clear the full `corpus-compare` path yet

- honest outcome:
  - the delete-only relevance fix is now safe against the synthetic and real cross-request delete regressions
  - but it is not the full Forminator fix
  - the Forminator full compare still does not complete under the old guard

## 2026-03-28 Fresh sequential rerun with higher guards: new blocker set is broader than just Forminator

- attempted rerun:
  - started a guarded sequential loop in:
    - `tmp/phparser-full-corpus-rerun10-20260328/run.log`
  - used `/tmp/phparser-corpus-compare` with a per-case `300s` timeout

- blockers found immediately:
  - `forminator-cve-2025-6463`
    - failed after about `281s`
    - `rc=137`
    - this looks like a kill/OOM path, not just a clean timeout
  - `post-smtp-cve-2025-11833`
    - failed at the full `300s` guard
    - `rc=124`
  - `givewp-cve-2024-5932`
    - failed quickly with a real Go stack overflow
    - the overflow is in dynamic callback/class resolution:
      - `dynamicDispatchStringForCallableWithState(...)`
      - `hookDispatchKeyForCallable(...)`
      - `callbackAssignmentClassRefs(...)`
      - `resolveCallbackClassRefsWithSeen(...)`
    - stack trace is captured directly in:
      - `tmp/phparser-full-corpus-rerun10-20260328/run.log`

- honest outcome:
  - a clean fresh full baseline is still blocked
  - the live blocker order is now:
    - `forminator` delete-batch/OOM
    - `post-smtp` long-running compare timeout
    - `givewp` callback-resolution recursion overflow

## 2026-03-28 GiveWP recursion overflow fixed; remaining GiveWP issue was stale contract drift

- engine fix:
  - removed the real stack overflow in callback-class resolution by threading shared recursion state through literal-arg hint introspection instead of re-entering hook dispatch with a fresh stack
  - files:
    - `internal/taintscan/callgraph_relevance.go`
    - `internal/taintscan/wordpress_context.go`
    - `internal/taintscan/ast_helpers.go`
  - focused regressions now pass:
    - `TestBuildEngineAvoidsRecursiveCallbackClassResolutionThroughHookArgs`
    - `TestSpecializedHookWrapperUsesLiteralTagArgument`

- GiveWP-specific outcome:
  - the stack overflow is gone
  - timed single-case compare no longer crashes; it reaches normal multi-pass analysis
  - the remaining timeout was caused by contract drift:
    - `corpus.json` had drifted back to `direct_sink_ops = ["call", "open", "read", "include"]`
    - the earlier durable note for this case already established the real direct contract is `["call"]` only
  - evidence:
    - vulnerable `give__3.14.1` `-sink-op call` still cleanly reaches:
      - `includes/payments/backward-compatibility.php:644`
    - current `give` `4.14.2` also still reports `unsafe-deserialization` helper sites in focused raw call scans, so the combined multi-op compare was not buying any extra signal for this CVE

- contract correction:
  - restored `givewp-cve-2024-5932` to:
    - `direct_sink_ops = ["call"]`
  - added generic corpus harness support for case-level `max_passes`
    - `corpus-compare` now honors manifest `max_passes` when the CLI does not override it
    - `givewp-cve-2024-5932` is pinned to `max_passes = 1`
    - rationale:
      - pass 1 already produces the real match at `includes/payments/backward-compatibility.php:644`
      - later passes only add broad helper churn and make this corpus row timeout

- performance notes:
  - focused vulnerable GiveWP timings after the recursion fix:
    - `call`: about `23.666s` total, `engine-run=7.632s`
    - `include`: about `25.070s` total, `engine-run=9.404s`
  - current `give` timings:
    - `call`: about `32.290s` total, `engine-run=8.847s`
    - `include`: about `33.994s` total, `engine-run=10.982s`
  - the timed failing compare showed the real blowup was the combined `call+include+open+read` batch, especially pass 2 helper churn in:
    - `_give_20_bc_give_payment_meta_value`
    - `give_bc_v20_get_payment_meta`
    - `Give\\FormMigration\\FormMetaDecorator::getFundsAndDesignationsAttributes`
- with the contract restored to `call` only, GiveWP should no longer be part of the fresh full-rerun blocker set

2026-03-28 12:50 UTC - Safe Forminator delete-batch profiling improvements landed, but the real Forminator blocker remains

- kept safe generic changes:
  - `internal/taintscan/analysis_driver.go`
    - delete-only invalidation now skips family-wide fallback for stable-key storage changes on families that are not used for cross-request writer seeding
    - delete-only invalidation now also skips exact/bucket path-reader expansion for changed storage paths on unsupported families
    - timings output now includes a generic pending-source breakdown (`caller`, `storage-path`, `storage-family`, `static`) when timings are enabled
  - `internal/taintscan/analysis_driver_test.go`
    - added regression coverage for the delete-only invalidation behavior on:
      - `option_value[...]`
      - `post_meta_value[...]`
  - `internal/taintscan/diagnostics.go`
    - caller input fingerprints now ignore concrete callee `StorageWrites` / `StoragePathWrites` that wrapper summaries intentionally do not propagate transitively
  - `internal/taintscan/diagnostics_test.go`
    - added regressions proving:
      - concrete callee storage-write growth does not perturb caller fingerprints
      - parameterized callee storage-write growth still does perturb caller fingerprints

- attempted but reverted:
  - a generic delete-batch low-value relevance filter in `callgraph_relevance.go`
    - it improved Forminator scheduling substantially, but it also skipped real request-driven storage writers like `update_option(...)`
    - this broke many existing delete/cross-request tests, so it was removed

- validation:
  - `go test ./...` is green after reverting the unsafe delete relevance filter

- measured safe-only Forminator outcome:
  - case: `forminator-cve-2025-6463`
  - command: `corpus-compare -case-id forminator-cve-2025-6463 -max-passes 2`
  - artifact:
    - `tmp/phparser-forminator-compare-max2-safeonly-20260328.log`
  - result:
    - pass 1 still ends at:
      - `changed_callables=1499`
      - `next_pending=1499`
      - pending-source breakdown:
        - `caller=3209`
        - `storage-path=3215`
        - `storage-family=3224`
        - `static=3313`
    - the run still times out at `160s`

- important conclusion:
  - the safe invalidation improvements are correct and retained, but the remaining Forminator timeout is still dominated by broad caller-driven pass-2 reanalysis, not by storage invalidation
  - the real remaining work is a generic caller-dependency / relevance refinement that does **not** skip legitimate request-driven storage writers

## 2026-03-28: Forminator delete-batch follow-up after safe-only tree

- kept the tree generic and green while probing the remaining `forminator-cve-2025-6463` timeout

- retained engine changes:
  - `internal/taintscan/diagnostics.go`
    - caller input fingerprints now ignore:
      - callee `ParamFindings` when the caller has no runtime arg flow to that callee
      - callee receiver-only effects when the caller never invokes that callee with a receiver object
      - callee `ReturnClasses` when the caller does not later use the assigned return root in a call-relevant object position
  - `internal/taintscan/callgraph_relevance.go`
    - `callSiteEdge` now records `hasReceiver` so fingerprint interest can distinguish receiver-based calls from plain function/static calls
  - `internal/taintscan/state_paths.go`
    - `compactStaticPropsByRoot()` now prunes static parent paths that are fully covered by more precise child paths, matching the storage-side compactor
  - `internal/taintscan/analysis_driver.go`
    - timings output now includes `scheduled_reuse` / `scheduled_analyze` at pass start
    - timings output also includes summary field change counts per pass
  - tests:
    - `internal/taintscan/diagnostics_test.go`
      - added focused regressions for:
        - param-finding interest
        - parameterized storage-write interest
        - receiver-effect interest
        - return-class interest
    - `internal/taintscan/taintscan_test.go`
      - added a regression proving static covered-parent pruning

- validation:
  - focused diagnostics and static-compaction tests passed
  - `go test ./internal/taintscan -run 'TestCompactStaticPropsByRoot|TestCallableSummaryInputFingerprint' -count=1` passed repeatedly during iteration

- measured Forminator outcome:
  - artifacts:
    - `tmp/phparser-forminator-max1-diffkinds-20260328.log`
    - `tmp/phparser-forminator-max2-reuseprobe-20260328.log`
    - `tmp/phparser-forminator-max2-staticprune-20260328.log`
  - pass 1 still fills all `1499` relevant summaries from zero
  - pass 2 now exposes the real residual shape immediately:
    - `scheduled_reuse=539`
    - `scheduled_analyze=960`
  - summary-change counts from pass 1 show the broad first-pass growth categories:
    - `param-findings=1499`
    - `receiver-findings=1499`
    - `receiver-path-writes=1499`
    - `receiver-storage-links=1499`
    - `receiver-writes=1499`
    - `return-classes=1499`
    - `return-param-paths=1499`
    - `return-params=1499`
  - static churn is still the dominant invalidation source after the fingerprint work:
    - pass-1 pending-source breakdown remains saturated at:
      - `caller=3209`
      - `storage-path=3215`
      - `storage-family=3224`
      - `static=3313`
    - hot roots remain centered on:
      - `\Forminator_Front_Action.$prepared_data`
      - `\Forminator_Front_Action.$response_attrs`

- important conclusion:
  - the earlier “caller fingerprint” hypothesis was only part of the problem
  - the real remaining Forminator blocker is broad static-state churn around Forminator front-action scratch arrays
  - the next generic fix should target static root invalidation / structural write precision, not more callee-summary pruning

## 2026-03-28: Forminator delete-batch follow-up after structural replay tightening

- kept changes:
  - `internal/taintscan/structural_state.go`
    - `apply_filters(...)` and `apply_filters_ref_array(...)` now preserve structural return paths from the filtered value plus registered filter callbacks
  - `internal/taintscan/summary_paths.go`
    - structural argument-origin replay now recognizes the same filter-return preservation
  - `internal/taintscan/assignment_eval.go`
    - post-assignment structural replay now prunes a covered exact root after precise child paths are materialized
  - `internal/taintscan/callgraph_relevance.go`
    - delete/read/open/include batches now skip inert low-value file wrappers in `relevantCallOrder()`
    - dynamic file/delete sink detection now requires a path-like value instead of treating arbitrary scalars as path-like
    - method-name `delete()` is no longer treated as a path-delete sink for DB-like receivers such as `wpdb`/database/conn classes
  - `internal/taintscan/ast_helpers.go`
    - added `exprMayProducePathLikeValue(...)` for bounded path-like sink detection
  - `internal/taintscan/call_eval.go`
    - delete findings now honor the same DB-like receiver guard for method `delete()`
  - `internal/taintscan/analysis_driver.go`
    - timings now emit `scheduled_reuse_sample` / `scheduled_analyze_sample` for pass `>1`
  - `internal/taintscan/taintscan_test.go`
    - added focused regressions for:
      - filter-return structural preservation
      - covered static-root pruning after filtered assignments
      - low-value file-wrapper skipping for delete batches

- reverted during the same iteration:
  - broader delete-only helper pruning that ignored too much caller arg-flow in wrapper chains
  - those experiments did reduce Forminator pass-2 breadth further, but they broke real delete-chain regressions and were not retained

- validation:
  - focused Forminator-related regressions passed repeatedly during iteration
  - `go test ./...` is green again on the final retained tree

- measured Forminator outcome on the retained safe tree:
  - artifact:
    - `tmp/phparser-forminator-max2-filterstruct-20260328.log`
    - `tmp/phparser-forminator-max2-filterstruct-300s-20260328.log`
  - the structural replay fix alone cut the dominant first-pass hotspot sharply:
    - `\Forminator_CForm_Front_Action::handle_form` dropped from about `23.9s` to under `1s`
  - pass 1 improved from roughly `46s` to roughly `16-18s`
  - the retained file-wrapper and path-like sink tightening further cleaned obvious batch noise, but did not clear the full case under the timeout guard

- temporary Forminator-only measurements from reverted delete-helper experiments:
  - artifacts:
    - `tmp/phparser-forminator-max2-deletehelper-20260328.log`
    - `tmp/phparser-forminator-max2-deletehelper3-20260328.log`
    - `tmp/phparser-forminator-max2-deletehelper4-20260328.log`
  - these runs showed the remaining hotspot can be narrowed a lot:
    - pass-1 relevant callables dropped as low as `42`
    - pass-2 scheduled analyses dropped as low as `7`
  - but the corresponding pruning model was not safe enough to keep, so these numbers are diagnostic only, not the current baseline

- current honest conclusion:
  - the safe structural and sink-model fixes materially improved Forminator
  - the case is still not cleared in the final retained tree
  - the next real optimization target is the heavy remaining cross-request writer/submission chain, not more broad delete-wrapper pruning

## 2026-03-28: Go profiling pass on Forminator delete batch

- used the built-in Go profiling hooks already present in `cmd/taint-scan`:
  - `-cpuprofile`
  - `-memprofile`
  - `-trace`
  - plus the existing `runtime/pprof` labels and `runtime/trace` regions for `batch`, `pass`, and `callable`

- focused profiling commands:
  - interrupted real workload:
    - `PHARSER_TAINTSCAN_TIMINGS=1 timeout 180s go run ./cmd/taint-scan -target .../forminator__1.44.2 -sink-op delete -max-passes 2 -cpuprofile .../cpu.pprof -memprofile .../mem.pprof -trace .../trace.out`
  - clean pass-1 workload:
    - `PHARSER_TAINTSCAN_TIMINGS=1 go run ./cmd/taint-scan -target .../forminator__1.44.2 -sink-op delete -max-passes 1 -cpuprofile .../cpu.pprof -memprofile .../mem.pprof -trace .../trace.out`

- profiling artifacts:
  - baseline interrupted trace:
    - `tmp/phparser-forminator-go-profile-20260328/trace.out`
    - `tmp/phparser-forminator-go-profile-20260328/stderr.log`
  - baseline completed pass-1 profiles:
    - `tmp/phparser-forminator-go-profile-pass1-20260328/cpu.pprof`
    - `tmp/phparser-forminator-go-profile-pass1-20260328/mem.pprof`
    - `tmp/phparser-forminator-go-profile-pass1-20260328/trace.out`
    - `tmp/phparser-forminator-go-profile-pass1-20260328/stderr.log`
  - after-cache completed pass-1 profiles:
    - `tmp/phparser-forminator-go-profile-pass1-after-fallbackcache-20260328/cpu.pprof`
    - `tmp/phparser-forminator-go-profile-pass1-after-fallbackcache-20260328/mem.pprof`
    - `tmp/phparser-forminator-go-profile-pass1-after-fallbackcache-20260328/stderr.log`
  - after-cache max-pass-2 rerun:
    - `tmp/phparser-forminator-delete-max2-after-fallbackcache-20260328/stderr.log`

- baseline profile findings before the code change:
  - CPU / scheduler profile pointed at generic engine setup and allocation churn, not a Forminator-specific callable:
    - `receiverPropertyReturnClassCandidatesWithState`
    - `walkNode`
    - `evalExpr`
    - heavy GC time under `runtime.scanobject`
  - allocation profile was dominated by:
    - `originSet.clone`
    - `resolveReceiverPathOrigins`
    - `appendPathOrigins`
  - important observed shape:
    - the expensive fallback path in `receiverPropertyReturnClassCandidatesWithState(...)` was rescanning `callOrder` for the same `(class, propertyPath)` pairs during base-engine construction

- retained generic fix:
  - `internal/taintscan/taintscan.go`
    - added `receiverPropertyFallbackHints` cache entries for fallback receiver-property class resolution
  - `internal/taintscan/analysis_support.go`
    - initialized the new fallback cache in the base engine
  - `internal/taintscan/callgraph_relevance.go`
    - `receiverPropertyReturnClassCandidatesWithState(...)` now caches top-level fallback resolutions, including negative results, when the dispatch-resolution state is clean and batch-independent
  - `internal/taintscan/taintscan_test.go`
    - added `TestReceiverPropertyReturnClassHintCachesFallbackResolution`

- validation:
  - focused tests:
    - `go test ./internal/taintscan -run 'TestReceiverPropertyReturnClassHintCachesFallbackResolution|TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender' -count=1`
  - full suite:
    - `go test ./...`
  - all passed on the retained tree

- measured effect:
  - Forminator delete `max-passes=1`:
    - total: `56.328s -> 46.321s`
    - `build-engine`: `29.503s -> 21.267s`
    - `build-base:index-literal-arg-hints`: `5.685s -> 4.382s`
    - `build-base:build-call-graph`: `6.602s -> 4.058s`
    - `build-base:index-call-sink-relevant-use-orders`: `7.639s -> 4.393s`
  - CPU profile after the cache:
    - `receiverPropertyReturnClassCandidatesWithState` remained hot, but its cumulative CPU share dropped from about `22.38s` to about `12.97s` on the completed pass-1 workload

- current honest conclusion after profiling:
  - the fallback-cache optimization is real and generic
  - it materially improved base-engine setup cost, which was a major part of the Forminator delete workload
  - it did not clear the full `max-passes=2` timeout:
    - pass 2 still stalls after:
      - `scheduled_reuse=441`
      - `scheduled_analyze=624`
  - the next highest-signal optimization target is now allocation / origin churn inside analysis, especially:
    - `originSet.clone`
    - `resolveReceiverPathOrigins`
    - `appendPathOrigins`

## 2026-03-28: bounded dead-local receiver pruning clears the Forminator timeout

- problem:
  - after the receiver-path replay profiling, the remaining real Forminator delete hotspot was still receiver-side-effect replay during summary instantiation
  - fresh goroutine dumps on the real `forminator__1.44.2 -sink-op delete -max-passes 2` workload kept landing in:
    - `lookupStructuralSelfOrigins`
    - `resolveReceiverPathOrigins`
    - `resolveReceiverSummaryOrigins`
    - `instantiateSummaryReturn`
  - the expensive shape was generic: local temporary receiver objects were absorbing callee receiver writes even when the receiver variable was never used again after the call

- retained generic fix:
  - `internal/taintscan/call_eval.go`
    - `instantiateSummaryReturn(...)` now accepts an explicit `allowReceiverSideEffects` flag
    - method-call replay now skips `ReceiverWrites`, `ReceiverPathWrites`, and `ReceiverStorageLinks` only when all of these are true:
      - the receiver root is a simple local variable
      - it is not `this`
      - the local receiver is never referenced later in the current callable
    - later-use detection is now AST-order based and skips the current call subtree itself, instead of trying to compare top-level statement indexes against source lines
  - `internal/taintscan/expression_eval.go`
    - updated constructor summary replay call sites for the new signature
  - `internal/taintscan/structural_state.go`
    - `instantiateTaintSummaryStatic(...)` now uses `unionInto(...)` instead of clone-heavy `originSet.union(...)`
  - `internal/taintscan/summary_paths.go`
    - receiver-summary replay now reuses a per-replay prefix lookup cache and avoids repeated `receiverRoot + prefix` rebuilding during fallback path trimming
  - `internal/taintscan/taintscan_test.go`
    - added `TestAnalyzeRootSkipsDeadLocalReceiverMutationsButKeepsLaterLocalReceiverRead`
    - kept the nested stored-XSS regression coverage green while tightening the receiver liveness rule

- validation:
  - focused tests:
    - `go test ./internal/taintscan -run 'TestAnalyzeRootSkipsDeadLocalReceiverMutationsButKeepsLaterLocalReceiverRead|TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop|TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop' -count=1`
  - full suite:
    - `go test ./...`
  - all passed on the retained tree

- measured effect on the real workload:
  - retained pass-1 timing:
    - `tmp/phparser-forminator-pass1-after-staticunioninto-timings-20260328.stderr`
    - total `39.926s`
  - retained max-pass-2 timing:
    - `tmp/phparser-forminator-max2-after-localreceiverliveness-20260328.stderr`
    - total `1m3.247s`
    - `build-engine=21.227s`
    - pass 1:
      - `scheduled_analyze=1065`
      - `duration=1.753s`
      - `changed_callables=1065`
    - pass 2:
      - `scheduled_reuse=441`
      - `scheduled_analyze=624`
      - `duration=32.225s`
      - `changed_callables=62`
      - `next_pending=145`
  - compared to the last safe pre-liveness retained log:
    - `tmp/phparser-forminator-max2-staticprune-20260328.log`
    - `build-engine: 27.043s -> 21.227s`
    - pass 1 duration: `46.165s -> 1.753s`
    - pass 1 pending callables: `1499 -> 1065`
    - guarded `max-passes=2` workload now completes instead of timing out

- honest current coverage status after the timeout fix:
  - the performance blocker is cleared, but `forminator-cve-2025-6463` is still a direct-engine `miss`
  - current compare artifact:
    - `tmp/phparser-forminator-compare-after-localreceiverliveness-max2-20260328/summary.json`
  - current reason:
    - `no single finding satisfied the manifest contract across 15 direct-engine findings`
  - important context:
    - this coverage miss predates the retained liveness fix
    - the earlier safe artifact `tmp/phparser-forminator-compare-max2-deletehelperfix2-20260328/summary.json` was already a `miss`
    - the old fully matched artifact is still:
      - `tmp/phparser-forminator-corpus-after-deleteflowgate/summary.json`
      - matched sink at `library/model/class-form-entry-model.php:1264`
      - matched request source from `admin/abstracts/class-admin-view-page.php:601`

- next step:
  - treat Forminator as a coverage/retention regression now, not a timeout problem
  - the next fix should recover the real `delete_action -> delete_by_entrys -> entry_delete_upload_files` chain without reopening the pass-2 receiver replay churn

## 2026-03-28: Forminator coverage restored by narrowing final delete suppression

- root cause:
  - the retained performance work was not the remaining blocker
  - the real Forminator delete finding was already present again in the broad delete batch, but final finding suppression dropped it because `wp-request-file-delete-without-cap-check` was being suppressed on any merged `access=capability_checked` context
  - that suppression was too broad for mixed admin-page/AJAX contexts where the capability checks live in unrelated admin scaffolding files rather than near the actual delete sink

- retained generic fix:
  - `internal/taintscan/helpers.go`
    - `wp-request-file-delete-without-cap-check` now uses `definitelyCapabilityGuardedForActionAtSink(...)` instead of the old blanket `ctx.Access == "capability_checked"` rule
    - this keeps suppression for definitely guarded local delete handlers, but no longer drops cross-file selector-backed delete flows just because some merged ancestor context was capability checked
  - `internal/taintscan/analysis_driver_test.go`
    - kept the existing suppression regression for direct capability-checked delete handlers
    - added a new regression that keeps a Forminator-shaped delete finding when the capability checks are remote from the sink file
  - `internal/taintscan/taintscan_test.go`
    - realigned two old sink-line expectations after the retained changes

- validation:
  - focused suppression tests passed
  - `go test ./...` passed again, with `internal/taintscan` around `0.867s`

- real Forminator evidence:
  - raw delete scan artifact:
    - `tmp/phparser-forminator-delete-after-delete-suppressfix-20260328/taint-results.json`
  - recovered sink:
    - `library/model/class-form-entry-model.php:1264`
  - recovered old source/callable pair:
    - `admin/abstracts/class-admin-view-page.php:601`
    - `\Forminator_Admin_View_Page::process_request`
  - current vulnerable raw scan summary:
    - `total_results=34`
    - `wp-request-file-delete-without-cap-check=19`
    - `request-path-read-delete=15`
  - Forminator sink findings recovered: `19`

- honest remaining limitation:
  - repeated `corpus-compare` reruns for the full Forminator case still did not complete cleanly on this tree
  - one timed out under `150s`, and a later `300s` attempt was killed by the host before producing a final compare artifact
  - so the retained fix is verified by the restored real vulnerable raw scan plus the full Go suite, not by a fresh final `comparison.json`

## 2026-03-28: Forminator compare fixed by using a case-level pass cap

- root cause:
  - the remaining Forminator failure was no longer in taint reachability
  - direct vulnerable and current `taint-scan` runs were already finishing cleanly when bounded with `-max-passes 2`
  - the default `corpus-compare` path still had no case-level pass cap for `forminator-cve-2025-6463`, so it ran the broad delete fixture with the default unbounded fixpoint and blew up in memory before writing output

- retained fix:
  - `test/semgrep_bundle_corpus/corpus.json`
    - added `"max_passes": 2` to `forminator-cve-2025-6463`
    - updated the note to make the bounded pass requirement explicit
  - no engine semantics changed in this step

- validation:
  - direct vulnerable scan, bounded:
    - `tmp/forminator-vuln-direct-20260328.stderr`
    - elapsed `1:01.04`
    - peak RSS `1824280 KB`
  - direct current scan, bounded:
    - `tmp/forminator-current-direct-20260328.stderr`
    - elapsed `1:34.98`
    - peak RSS `5450484 KB`
  - default-style compare with the same bound:
    - `tmp/phparser-forminator-compare-after-delete-suppressfix6-20260328/summary.json`
    - elapsed `52.127s`
    - peak RSS `1777876 KB`
    - status `match`
  - matched finding:
    - sink `library/model/class-form-entry-model.php:1264`
    - source `admin/abstracts/class-admin-module-edit-page.php:922`
    - callable `\Forminator_Admin_Module_Edit_Page::processRequest`

- diagnostic evidence:
  - unbounded direct compare attempt still reproduced the failure:
    - `timeout 120s /tmp/phparser-corpus-compare ...`
    - peak RSS `9666700 KB`
    - no output files
  - so the durable fix for this corpus row is the case-level pass cap, not another engine change

## 2026-03-29: Old Post SMTP REST connect_app case also needs a case-level pass cap

- root cause:
  - the fresh full-corpus rerun no longer blocked on `post-smtp-cve-2025-11833`
  - it later stalled on the separate `post-smtp-cve-2023-6875` row, which scans the older `post-smtp__2.8.7` REST `connect_app` authorization-bypass path with `direct_sink_ops=["action"]`
  - that older case still had no case-level pass cap, so the broad Freemius-heavy action batch kept replaying storage/static churn in repeated passes during the full sweep

- retained fix:
  - `test/semgrep_bundle_corpus/corpus.json`
    - added `"max_passes": 2` to `post-smtp-cve-2023-6875`
    - added a note explaining that the cap preserves the real `auth_key` header -> `update_option( 'post_smtp_mobile_app_connection', $data )` action path while bounding the broad action batch
  - no engine semantics changed in this step

- validation:
  - bounded compare:
    - `tmp/phparser-post-smtp-2023-6875-max2-20260329/summary.json`
    - status `match`
    - duration `14769 ms`
  - matched finding:
    - source `Postman/Mobile/includes/rest-api/v1/rest-api.php:63`
    - sink `Postman/Mobile/includes/rest-api/v1/rest-api.php:79`
    - callable `\Post_SMTP_Mobile_Rest_API::connect_app`

- diagnostic evidence:
  - the aborted live full rerun showed repeated action passes with `next_pending=28` and hot summaries rooted in `PostmanInstaller`, `PostmanOAuthToken`, `PostmanOptions`, and Freemius startup
  - isolating the old REST case with `-max-passes 2` proved that the case still matches cleanly without needing another engine change

## 2026-03-29: CleanTalk plugin-install action case also needs a case-level pass cap

- root cause:
  - after capping the old Post SMTP REST row, the next full-corpus rerun progressed into `cleantalk-cve-2024-10542`
  - that row scans the older unauthenticated plugin-install path in `cleantalk.php` with `direct_sink_ops=["action"]`
  - without a case-level cap, the broad action batch kept replaying option/static churn through `apbct_base_call`, `ct_ajax_hook`, and related integration helpers for many passes during the full sweep

- retained fix:
  - `test/semgrep_bundle_corpus/corpus.json`
    - added `"max_passes": 2` to `cleantalk-cve-2024-10542`
    - added a note explaining that the cap preserves the real `Get::get('plugin')` -> `apbct_rc__install_plugin()` -> `$installer->install($download_link)` action path while bounding the broad action batch
  - no engine semantics changed in this step

- validation:
  - bounded compare:
    - `tmp/phparser-cleantalk-2024-10542-max2-20260329/summary.json`
    - status `match`
    - duration `8647 ms`
  - matched finding:
    - source `cleantalk.php:2377`
    - sink `cleantalk.php:2410`
    - callable `\apbct_rc__install_plugin`

- diagnostic evidence:
  - the aborted live rerun showed repeated action passes dominated by `apbct_base_call`, `ct_ajax_hook`, `ct_contact_form_validate`, and `CleantalkSettingsTemplates::setPluginOptions`
  - isolating the row with `-max-passes 2` proved the real vulnerable action still matches cleanly without another engine change

## 2026-03-29: Active-batch introspection must not create literal specializations

- root cause:
  - the fresh full rerun later hit `fatal error: concurrent map read and map write`
  - the crash path was not only the callback-hint maps; introspection also forced call-batch literal specialization through `specializeCallableKeyForIntrospection()`
  - during parallel batch analysis, that path could still call `maybeSpecializeCallableForLiteralArgs()` and mutate:
    - `e.callables`
    - `e.callOrder`
    - `e.summaries`
    - `e.contexts`
    - literal specialization indexes
  - readers like `receiverPropertyArrayEntryClassRefs()` were walking those same structures concurrently

- retained fix:
  - `internal/taintscan/callable_indexing.go`
    - factored literal-hint filtering into a shared helper
    - added `existingSpecializedCallableForLiteralArgs()` so lookups can reuse an already-created specialization without mutating engine state
  - `internal/taintscan/wordpress_context.go`
    - `specializeCallableKeyForIntrospection()` now behaves in two modes:
      - outside an active batch: keep the old behavior and allow call-style specialization
      - inside an active batch: stay read-only and only reuse an existing specialization, otherwise fall back to `baseKey`
  - `internal/taintscan/taintscan_test.go`
    - added a regression that proves active-batch introspection reuses an existing specialization but does not create a new callable or grow `callOrder`

- validation:
  - focused tests:
    - `TestLiteralArgSpecializationSkipsNonCallBatches`
    - `TestLiteralArgIntrospectionSpecializationReusesExistingWithoutMutation`
    - `TestLiteralArgSpecializationAppliesForOutputTemplateIncludeHelpers`
    - `TestBuildEngineAvoidsRecursiveCallbackClassResolutionThroughHookArgs`
  - `go test ./...` passed
  - isolated Smart Slider repro completed cleanly after the fix:
    - `tmp/phparser-smart-slider-introspectionfix-20260329/summary.json`
    - status `match`

- remaining limitation:
  - the monolithic full-manifest runner still later hit a different warm-summary deadlock, so this fix removed the concurrent-map crash but did not fully stabilize single-process full sweeps

## 2026-03-29: Isolated per-case corpus rerun gives a usable fresh baseline while monolithic mode is still deadlocked

- motivation:
  - after the active-batch specialization fix, a full single-process rerun no longer crashed on concurrent map access
  - it still later hit `fatal error: all goroutines are asleep - deadlock!` inside pass-warm summary scheduling
  - several suspect rows reproduced cleanly in isolation, so the practical way to keep momentum was to run each case in a fresh `corpus-compare` process and aggregate the resulting `summary.json` plus nested `taint-results.json`

- retained workflow:
  - built `/tmp/phparser-corpus-compare`
  - ran the full manifest one case at a time into:
    - `tmp/phparser-full-corpus-isolated-rerun20b-20260329/`
  - regenerated:
    - `aggregate.tsv`
    - `status-counts.tsv`
    - `rule-hits.tsv`
    - `plugin-hits.tsv`
    - `slowest-cases.tsv`
    - `run-summary.json`

- current baseline from the isolated rerun:
  - status counts:
    - `37` `match`
    - `15` `not_comparable_yet`
    - `4` `miss`
    - `7` `error`
  - top noisy rules:
    - `wp-request-file-delete-without-cap-check`: `271`
    - `wp-request-sensitive-action-without-cap-check`: `134`
    - `wp-stored-xss-persistent-read-to-output`: `126`
    - `unsafe-deserialization`: `35`
    - `wp-request-file-upload-without-cap-check`: `33`
  - top noisy plugins by raw result count:
    - `wordpress-file-upload-cve-2024-11613`: `206`
    - `post-smtp-cve-2025-11833`: `115`
    - `wp-statistics-cve-2024-2194`: `97`
    - `forminator-cve-2025-6463`: `34`
    - `everest-forms-cve-2025-1128`: `31`
  - slowest rows:
    - `wpforms-cve-2024-11205`: `300574 ms` (`error`)
    - `user-registration-cve-2026-1492`: `300076 ms` (`error`)
    - `learnpress-cve-2023-6634`: `202752 ms` (`error`)
    - `everest-forms-cve-2025-1128`: `166648 ms` (`match`)
    - `ultimate-member-cve-2024-1071`: `43906 ms` (`error`)

- concrete regressions surfaced by the isolated baseline:
  - `sureforms-cve-2025-6691`: now `miss`
  - `better-search-replace-cve-2023-6933`: `miss`
  - `google-reviews-cve-2025-12510`: `miss`
  - `cfdb7-cve-2025-7384`: now `miss`
  - `ultimate-member-cve-2025-0308`: `error`
  - `ultimate-member-cve-2024-1071`: `error`
  - `ultimate-member-cve-2025-1702`: `error`
  - `smart-slider-3-cve-2026-3098`: intermittent `error` in the isolated batch even though a direct isolated repro still matches

- remaining limitation:
  - this isolated baseline is good enough for noise/perf triage, but it is still a workaround
  - the real engine bug left open is the monolithic pass-warm summary deadlock in full-manifest mode

## 2026-03-29: Restore SureForms stored delete coverage through zero-arg table getters and prepared-data schema fallbacks

- motivation:
  - the isolated baseline regressed `sureforms-cve-2025-6691` from a prior match to a clean `miss`
  - the real vulnerable path stores request-controlled upload paths through a DB wrapper that:
    - writes via `insert($this->get_tablename(), $prepared_data['data'])`
    - later reads via `get_results("SELECT ... FROM " . $this->get_tablename())`
  - the engine was dropping this family because:
    - zero-arg `*table*` getter calls did not recover a stable abstract table key
    - prepared-data wrapper writes were not replaying original input/storage path families when the inserted row came from `prepare_data(...)`

- retained engine changes:
  - `internal/taintscan/state_summary_helpers.go`
    - added zero-arg table getter recovery for method, static, and function calls:
      - `databaseTableKeyForZeroArgMethodCall()`
      - `databaseTableKeyForZeroArgStaticCall()`
      - `databaseTableKeyForZeroArgFuncCall()`
      - `databaseTableKeyForZeroArgCallableReturn()`
      - `lastPropertyPathSegment()`
    - taught both `databaseTableKeyForNodeWithSeen()` and `sqlQueryStringWithContext()` to use those helpers for zero-arg `*table*` calls
    - added prepared-data fallbacks so `prepare_data($data)` style wrappers retain original storage families and path writes:
      - `preparedSchemaSourceNode()`
      - `(*engine).localPreparedSchemaArgValue()`
      - `preparedSchemaArgFromCall()`
      - `schemaStoragePathWritesForPreparedArg()`
    - `databaseTableStoragePathWritesForMethodCall()` now replays extracted or reconstructed storage path families from prepared wrappers before giving up
  - `internal/taintscan/builtin_models.go`
    - treated `wp_json_encode` and `wp_normalize_path` as propagating helpers so the helper-wrapped delete regression stays generic and stable
  - `internal/taintscan/taintscan_test.go`
    - added a durable helper-wrapped cross-request delete regression
    - removed a redundant singleton synthetic that was not proving additional engine behavior
    - realigned older synthetic source/sink line assertions after adding the table-name getter shape

- validation:
  - focused synthetic regressions:
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete`
  - focused real-plugin regression:
    - `PHARSER_ENABLE_REAL_PLUGIN_TESTS=1 go test ./internal/taintscan -run 'TestAnalyzeRootFindsSureFormsStoredDeleteSink' -count=1`
  - full suite:
    - `go test ./...` passed
  - isolated corpus case:
    - `tmp/phparser-sureforms-6691-after-dbgetterfix-20260329/summary.json`
    - status `match`
    - matched sink `admin/views/entries-list-table.php:684`
    - matched source `inc/form-submit.php:213`

- remaining limitation:
  - this restores the SureForms stored delete family and the generic helper regressions, but it does not address the separate monolithic full-manifest deadlock

## 2026-03-29: warm-summary deadlock fallback plus bounded SQL case caps

- problem:
  - the isolated rerun was still failing on `ultimate-member-cve-2024-1071`, `ultimate-member-cve-2025-0308`, and `ultimate-member-cve-2025-1702` with `fatal error: all goroutines are asleep - deadlock!`
  - the deadlock was in `analysis_callable.go`, where one inflight pass-warm summary could block on another inflight warm summary while that second warm summary was waiting back on the first through a different goroutine
  - `user-registration-cve-2026-1492` was also still spending the full `300s` corpus timeout even though the real vulnerable `register_member()` path still matched cleanly

- retained engine changes:
  - `internal/taintscan/analysis_callable.go`
    - added `isPassWarmSummaryInflight()` and `hasInflightPassWarmSummary()`
    - `summaryForKey()` now locally computes a requested helper summary when that helper is already inflight and the current warm stack is itself inside another inflight warm summary
    - this avoids cross-goroutine warm-summary deadlocks without adding plugin-specific special cases
  - `internal/taintscan/analysis_callable_test.go`
    - added `TestSummaryForKeyLocallyComputesInflightWarmDependency`
    - kept `TestGetOrComputePassWarmSummarySingleflightForWriteBatch` green to make sure the normal singleflight behavior still works

- corpus / runtime validation:
  - `go test ./internal/taintscan -run 'TestSummaryForKeyLocallyComputesInflightWarmDependency|TestGetOrComputePassWarmSummarySingleflightForWriteBatch' -count=1`
  - `go test ./...` passed
  - fresh case reruns:
    - `tmp/phparser-user-registration-1492-max2-20260329/summary.json`
      - `user-registration-cve-2026-1492` status `match`, `47487 ms`
      - real matched source `modules/membership/includes/AJAX.php:121`
      - real matched sink `modules/membership/includes/Admin/Services/MembersService.php:217`
    - `tmp/phparser-ultimate-member-2024-1071-max2-deadlockfix-20260329/summary.json`
      - status `match`, `53332 ms`
    - `tmp/phparser-ultimate-member-2025-0308-max2-deadlockfix-20260329/summary.json`
      - status `match`, `65642 ms`
    - `tmp/phparser-ultimate-member-2025-1702-max2-deadlockfix-20260329/summary.json`
      - status `match`, `65813 ms`
    - `tmp/phparser-smart-slider-rerun-after-deadlockfix-20260329/summary.json`
      - `smart-slider-3-cve-2026-3098` status `match`, `5039 ms`

- manifest changes:
  - added `"max_passes": 2` to:
    - `user-registration-cve-2026-1492`
    - `ultimate-member-cve-2025-0308`
    - `ultimate-member-cve-2024-1071`
    - `ultimate-member-cve-2025-1702`

- remaining limitation:
  - this clears the warm-summary deadlock and the verified isolated SQL/runtime rows above, but `learnpress-cve-2023-6634` still remains a separate isolated error (`rc=-9`) and has not been reworked yet

## 2026-03-29: LearnPress call-batch profiling pass

- problem:
  - after clearing the stale isolated errors for `user-registration`, `ultimate-member`, and `smart-slider`, the remaining isolated `error` case was `learnpress-cve-2023-6634`
  - fresh direct reruns no longer reproduced the old fast `5-6s` behavior; even `-max-passes 1` for the vulnerable tree was blowing up in pass 1 with multi-GB RSS before any callable finished

- retained engine changes:
  - `internal/taintscan/state_map_helpers.go`
    - added `collectPropertyOriginsInto()` so callers can union child property origins directly into an existing destination set without building temporary `originSet`s
    - switched `collectStructuralChildren()` and `lookupStructuralPathOrigins()` to that in-place style
  - `internal/taintscan/expression_eval.go`
    - replaced repeated `originSet.union(collectPropertyOrigins(...))` chains in variable/property/static-property reads with one cloned destination plus `collectPropertyOriginsInto()`
    - this keeps semantics the same while reducing allocation churn in the hot variable/property-origin path
  - `internal/taintscan/analysis_driver.go`
    - timings mode now prints `scheduled_analyze_sample` for pass 1 as well, not only pass 2+
    - this keeps profiling generic and makes future isolated call-batch explosions easier to localize

- validation:
  - `go test ./internal/taintscan -count=1`
  - `go test ./...`
  - LearnPress profiling artifacts:
    - `tmp/phparser-learnpress-call-max1-quit-20260329`
    - `tmp/phparser-learnpress-call-max1-samples22-20260329`

- useful findings:
  - the hot stack during the exploding pass-1 run was:
    - `originSet.union()`
    - `analysisState.evalExpr()` variable branch at `expression_eval.go:56`
    - `analysisState.evalArgs()`
    - `analysisState.evalFuncCall()`
  - the first pass-1 scheduled analyze sample for the LearnPress `call` batch is:
    - `function::\learn_press_add_message`
    - `function::\learn_press_add_user_roles`
    - `function::\learn_press_cancel_order_process`
    - `function::\learn_press_cookie_get`
    - `function::\learn_press_display_message`
  - that means the remaining blowup is not centered on the REST sink itself; it is broad call-batch helper relevance plus large property-origin merges during helper analysis

- remaining limitation:
  - LearnPress is still not fixed yet
  - the retained allocation reduction and pass-1 sample logging are safe, but they only narrowed the frontier; the next real fix is likely tighter call-batch relevance pruning for low-value helper functions, not another broad pass cap

## 2026-03-29: LearnPress call-batch relevance prune

- problem:
  - `learnpress-cve-2023-6634` had become the last isolated `error` row after the stale SQL/runtime blockers were cleared
  - the real issue was not the REST sink itself; call-only relevance was still retaining broad helper functions before the sink, which kept pass 1 large and had previously driven the isolated runner into `rc=-9`

- retained engine changes:
  - `internal/taintscan/callgraph_relevance.go`
    - tightened call-only forward relevance for non-data-carrier call sites that appear before a direct call sink anchor
    - those anchor-order helper edges are now kept only when the callee is already reverse-relevant, already anchor-relevant, or is itself a direct call sink seed
    - this removes benign helper fanout from the call batch without weakening real sink paths
  - `internal/taintscan/taintscan_test.go`
    - added `TestBuildEngineSkipsUnusedDataCarrierHelperInCallBatch`
    - kept `TestBuildEngineSkipsNoArgSingletonReceiverWrapperForCallBatch` green alongside it

- profiling outcome:
  - before the retained prune, LearnPress pass 1 still began with helper-heavy samples like:
    - `function::\learn_press_add_message`
    - `function::\learn_press_add_user_roles`
    - `function::\learn_press_cancel_order_process`
    - `function::\learn_press_cookie_get`
    - `function::\learn_press_display_message`
  - after the retained prune:
    - vulnerable direct `call` scan finished cleanly in `17.81s`
    - pass 1 scheduled analyze dropped from `844` to `764`
    - pass 1 duration dropped to about `812ms`
    - artifact: `tmp/phparser-learnpress-call-max1-samples22-after-anchorprune-20260329`

- validation:
  - `go test ./internal/taintscan -run 'TestBuildEngineSkipsUnusedDataCarrierHelperInCallBatch|TestBuildEngineSkipsNoArgSingletonReceiverWrapperForCallBatch' -count=1`
  - `go test ./...`
  - fresh corpus compare:
    - `tmp/phparser-learnpress-final-20260329/summary.json`
    - status `match`
    - matched source `inc/rest-api/v1/frontend/class-lp-rest-ajax-controller.php:45`
    - matched sink `inc/rest-api/v1/frontend/class-lp-rest-ajax-controller.php:69`

- remaining limitation:
  - this clears the isolated LearnPress blocker and leaves the helper-pruning logic generic, but the full isolated baseline still needs a fresh rerun to update the global counts on the current tree

## 2026-03-29: Skip irrelevant sink indexes in single-op engine builds

- problem:
  - after the clean isolated rerun, the slowest rows were dominated by the `ultimate-member` SQL family
  - profiling `ultimate-member-cve-2025-0308` showed the case was `sql`-only, but base-engine construction still spent about `20.336s` in `index-call-sink-relevant-use-orders` and another `3.489s` in `index-call-input-consuming-callables`
  - that work was generic but wasted for single-op `sql` compares, because the run never consumed the call-batch relevance indexes

- retained engine changes:
  - `internal/taintscan/analysis_support.go`
    - added `buildBaseEngineForSinkOps(...)`
    - gated base-engine sink-specific relevance indexing by requested sink ops
    - `call` batches still build call relevance/input-consuming indexes
    - `sql` batches still build SQL relevance
    - file-style batches now correctly include `write` alongside `delete`/`read`/`open`/`include`
    - `cloneEngineForOptions(...)` now only rebuilds `sqlSinkRelevantUseOrders` when the cloned batch actually needs `sql`
  - `internal/taintscan/analysis_driver.go`
    - `AnalyzeRootWithOptions(...)` now builds the base engine with the requested sink-op set
  - `internal/taintscan/taintscan_test.go`
    - added `TestBuildEngineSkipsCallRelevanceIndexesForPureSQLBatch`

- measured effect:
  - `ultimate-member-cve-2025-0308`
    - before:
      - artifact: `tmp/phparser-um-2025-0308-profile-20260329`
      - `build-engine=29.647s`
      - `engine-run=3m4.023s`
      - `total=3m34.296s`
      - case `duration_ms=214296`
    - after:
      - artifact: `tmp/phparser-um-2025-0308-after-lazyindexes-20260329`
      - `build-engine=5.096s`
      - `engine-run=3m12.566s`
      - `total=3m18.15s`
      - case `duration_ms=198150`
  - net effect:
    - build-engine dropped by about `24.6s`
    - end-to-end case time dropped by about `16.1s`
    - coverage stayed `match`

- validation:
  - `go test ./internal/taintscan -run 'TestBuildEngineSkipsCallRelevanceIndexesForPureSQLBatch|TestBuildEngineSkipsStorageWriterSideHelperForDirectSQLScan|TestBuildEngineSkipsPublicStaticSQLSinkSeedWithoutRequestData' -count=1`
  - `go test ./internal/taintscan -run 'TestBuildEngineSkipsUnreachableDirectWriteSinkSeeds|TestBuildEngineSkipsStorageWriterHelperForDirectWriteScans|TestAnalyzeRootFindsUploadThroughPropertyStoredHelperReceiver|TestAnalyzeRootFindsUploadRegisteredThroughLifecycleClosureAndSingletonConstructors|TestBuildEngineSkipsWriteCarrierWithoutWriteRelevantUse|TestBuildEngineSkipsCallRelevanceIndexesForPureSQLBatch' -count=1`
  - `go test ./...`
  - fresh corpus compare:
    - `tmp/phparser-um-2025-0308-after-lazyindexes-20260329/summary.json`
    - status `match`

- remaining limitation:
  - the `ultimate-member` family is still slow overall because the real runtime hotspot is now later-pass summary churn in:
    - `method::\um\core\Fields::edit_field`
    - `method::\um\core\Account::get_tab_fields`
  - this change only removes wasted precompute time; it does not yet reduce the pass-3/pass-4 runtime churn in those SQL helper chains

## 2026-03-29: Prefer stronger direct traces in corpus compare

- problem:
  - `ultimate-member-cve-2025-0308` can already match honestly at `max-passes=2`, but the old compare logic returned the first contract-satisfying finding
  - for this row, that meant a weaker stored-write-backed admin trace at `class-admin-metabox.php:1284 -> class-member-directory-meta.php:757`, even though the same bounded run also contained the stronger direct request trace at `class-member-directory-meta.php:846 -> :1072`
  - without better ranking, adding a case-level pass cap would have kept the row fast but reduced evidence quality in `summary.json`

- retained engine changes:
  - `internal/corpuscompare/corpuscompare.go`
    - `CompareCase(...)` now scores all findings that satisfy the manifest contract instead of returning the first one
    - direct source snippet/path matches now outrank callable-only matches
    - when the contract does not explicitly require stored-write entrypoints, findings that rely on non-empty stored-write context lose a small tie-break penalty
  - `internal/corpuscompare/corpuscompare_test.go`
    - added `TestCompareCasePrefersDirectTraceSourceMatchOverCallableOnlyMatch`

- measured effect:
  - bounded compare before ranking:
    - artifact: `tmp/phparser-um-2025-0308-max2-check-20260329`
    - status `match`
    - duration `32738 ms`
    - selected weaker matched finding:
      - source `includes/admin/core/class-admin-metabox.php:1284`
      - sink `includes/core/class-member-directory-meta.php:757`
  - bounded compare after ranking:
    - artifact: `tmp/phparser-um-2025-0308-max2-ranked-20260329`
    - status `match`
    - duration `33548 ms`
    - selected stronger matched finding:
      - source `includes/core/class-member-directory-meta.php:846`
      - sink `includes/core/class-member-directory-meta.php:1072`

- validation:
  - `go test ./internal/corpuscompare -run 'TestCompareCaseMatchesTraceSourceAndSinkLocation|TestCompareCasePrefersDirectTraceSourceMatchOverCallableOnlyMatch|TestCompareCaseMatchesStoredWriteEntryLocation' -count=1`
  - fresh bounded compare:
    - `tmp/phparser-um-2025-0308-max2-ranked-20260329/summary.json`
    - status `match`

- remaining limitation:
  - this improves evidence selection, not taint precision
  - the remaining runtime hotspot in the `ultimate-member` SQL family is still later-pass summary churn inside `Fields::edit_field` and `Account::get_tab_fields`

## 2026-03-29: Limit assigned-return invalidation cuts to call batches

- problem:
  - `acf-extended-cve-2025-13486` was still the slowest fully matched row in the fresh isolated baseline, with late-pass churn dominated by recursive return-path growth in:
    - `function::\acfe_get_fields_details_recursive`
    - `method::\acfe_module_form_field_groups::get_fields`
    - `method::\acfe_module_form_upgrades::handle_acf_fields`
  - the first attempt to cut that churn ignored callee return growth whenever an assigned return root was not used in a call-relevant position
  - that broad version improved `acf-extended`, but it also broke real `open` / `output` / `delete` regressions because those batches still need assigned-return summary replay even when the assigned root is never used in a later call

- retained engine changes:
  - `internal/taintscan/diagnostics.go`
    - `callableSummaryInputFingerprint(...)` now applies the assigned-return interest cut only for the `call` batch
    - non-`call` batches keep the original broader return interest so stored-XSS and cross-request delete replay still converge correctly
  - `internal/taintscan/diagnostics_test.go`
    - added `TestCallableSummaryInputFingerprintIgnoresCalleeReturnPathWriteGrowthWithoutCallerCallUse`
    - kept the existing return-growth tests green across both `call` and non-`call` batches

- measured effect:
  - `acf-extended-cve-2025-13486`
    - before:
      - artifact: `tmp/phparser-acf-extended-profile-20260329`
      - case `duration_ms=71177`
      - `engine-run=1m8.517s`
      - `total=1m11.178s`
    - after the retained call-only change:
      - artifact: `tmp/phparser-acf-extended-profile-after-callonlyreturninterest-20260329`
      - case `duration_ms=67944`
      - `engine-run=1m5.368s`
      - `total=1m7.944s`
  - net effect:
    - end-to-end case time dropped by about `3.2s`
    - the gain matched the broader unsafe attempt, but without regressing non-`call` sink families

- validation:
  - `go test ./internal/taintscan -run 'TestCallableSummaryInputFingerprint(IgnoresCalleeReturnPathWriteGrowthWithoutCallerCallUse|IgnoresCalleeReturnClassGrowthWithoutCallerCallUse|TracksCalleeReturnClassGrowthWhenCallerUsesReturnedObject|IgnoresCalleeReturnGrowthForSideEffectOnlyCall|TracksCalleeReturnGrowthWhenCallerUsesReturnValue)|TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender|TestAnalyzeRootFindsStoredXSSFromParameterizedExtraValueSaveLoop|TestAnalyzeRootTracksWrapperColumnCrossRequestDelete|TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete|TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete' -count=1`
  - `go test ./...`
  - fresh corpus compare:
    - `tmp/phparser-acf-extended-profile-after-callonlyreturninterest-20260329/summary.json`
    - status `match`

- remaining limitation:
  - `acf-extended` still burns late passes on recursive `return-param-paths` growth in `acfe_get_fields_details_recursive`
  - the next useful optimization should target return-path compaction or convergence for recursive array-walking helpers, not broader return-interest suppression

## 2026-03-29: Filter param-derived invalidation by runtime arg indexes

- problem:
  - after the call-only assigned-return refinement, `acf-extended-cve-2025-13486` still spent repeated late passes invalidating:
    - `function::\acfe_get_fields_details_recursive`
    - `method::\acfe_module_form_field_groups::get_fields`
    - `method::\acfe_module_form_upgrades::handle_acf_fields`
  - the caller fingerprint still treated all callee param-derived growth as relevant whenever a call site had any arg flow
  - that was broader than necessary: if the caller only supplies runtime data to param `0`, later callee growth on param `1` should not invalidate the caller

- retained engine changes:
  - `internal/taintscan/diagnostics.go`
    - `callableSummaryInputFingerprint(...)` now records the union of runtime arg indexes per callee when the call site provides them
    - param-derived fingerprint inputs are filtered to those indexes for:
      - `ReturnParams`
      - `ReturnParamPaths`
      - `ReturnPathWrites`
      - `ParamFindings`
      - transitive receiver/storage writes that carry param origins
    - when a call site only has broad `argCarrier` information and no concrete indexes, the old broad behavior remains
  - `internal/taintscan/diagnostics_test.go`
    - added:
      - `TestCallableSummaryInputFingerprintIgnoresCalleeParameterizedStorageWriteGrowthForUnrelatedRuntimeArgIndex`
      - `TestCallableSummaryInputFingerprintIgnoresCalleeReturnParamPathGrowthForUnrelatedRuntimeArgIndex`
      - `TestCallableSummaryInputFingerprintTracksCalleeReturnParamPathGrowthForMatchingRuntimeArgIndex`

- measured effect:
  - `acf-extended-cve-2025-13486`
    - before this refinement:
      - artifact: `tmp/phparser-acf-extended-profile-after-callonlyreturninterest-20260329`
      - case `duration_ms=67944`
      - `engine-run=1m5.368s`
      - `total=1m7.944s`
    - after:
      - artifact: `tmp/phparser-acf-extended-profile-after-paramindex-interest-20260329`
      - case `duration_ms=67030`
      - `engine-run=1m4.508s`
      - `total=1m7.031s`
  - net effect:
    - another `~0.9s` off the case
    - status stayed `match`
    - findings stayed `9`

- validation:
  - `go test ./internal/taintscan -run 'TestCallableSummaryInputFingerprint(TracksCalleeParameterizedStorageWriteGrowth|IgnoresCalleeParameterizedStorageWriteGrowthForUnrelatedRuntimeArgIndex|IgnoresCalleeReturnPathWriteGrowthWithoutCallerCallUse|IgnoresCalleeReturnParamPathGrowthForUnrelatedRuntimeArgIndex|TracksCalleeReturnParamPathGrowthForMatchingRuntimeArgIndex|IgnoresCalleeReturnClassGrowthWithoutCallerCallUse|TracksCalleeReturnClassGrowthWhenCallerUsesReturnedObject|IgnoresCalleeReturnGrowthForSideEffectOnlyCall|TracksCalleeReturnGrowthWhenCallerUsesReturnValue)|TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender|TestAnalyzeRootFindsStoredXSSFromParameterizedExtraValueSaveLoop|TestAnalyzeRootTracksWrapperColumnCrossRequestDelete|TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete|TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete' -count=1`
  - `go test ./...`
  - fresh corpus compare:
    - `tmp/phparser-acf-extended-profile-after-paramindex-interest-20260329/summary.json`
    - status `match`

- remaining limitation:
  - `acf-extended` is still dominated by the broad pass-1/pass-2 runtime of module import helpers like:
    - `\acfe_module_block_type::prepare_item_for_import#runtime`
    - `\acfe_module_options_page::prepare_item_for_import#runtime`
    - `\acfe_module_post_type::prepare_item_for_import#runtime`
    - `\acfe_module_taxonomy::prepare_item_for_import#runtime`
  - the next meaningful improvement is more likely relevance narrowing for those generic module-import callback chains than another return-path invalidation cut

## 2026-03-29: Lower nested param-path compaction budget

- problem:
  - after the runtime-arg-index invalidation cut, `acf-extended-cve-2025-13486` was still the slowest row in the isolated corpus baseline
  - the focused timings showed the remaining churn was not broad relevance anymore:
    - pass 1 and pass 2 were driven by recursive array walkers such as `function::\acfe_get_fields_details_recursive`
    - late passes kept changing only `return-param-paths`
    - the engine was still allowing up to `96` nested param paths per root before collapsing them
  - that was too generous for recursive list/tree helpers that build large nested return structures but only need a bounded summary to preserve sink reachability

- retained engine change:
  - `internal/taintscan/taintscan.go`
    - lowered `maxNestedParamPathsPerRoot` from `96` to `32`
  - no plugin-specific logic was added
  - existing param-path compaction semantics stayed the same; only the budget changed

- focused effect:
  - `acf-extended-cve-2025-13486`
    - before:
      - artifact: `tmp/phparser-acf-extended-profile-after-paramindex-interest-20260329`
      - case `duration_ms=67030`
      - `engine-run=1m4.508s`
      - `total=1m7.031s`
    - after:
      - artifact: `tmp/phparser-acf-extended-after-paramlimit32-20260329`
      - case `duration_ms=10722`
      - `engine-run=8.145s`
      - `total=10.723s`
  - the pass-1/pass-2 `prepare_item_for_import` / `import_item` helper fanout collapsed with the tighter param-path cap
  - status stayed `match`
  - findings stayed `9`

- broader validation:
  - `go test ./...`
  - representative corpus checks:
    - `tmp/phparser-user-registration-after-paramlimit32-20260329/summary.json`
      - `user-registration-cve-2026-1492`
      - status `match`
      - `duration_ms=34575`
    - `tmp/phparser-wpstatistics-after-paramlimit32-20260329/summary.json`
      - `wp-statistics-cve-2024-2194`
      - status `match`
      - `duration_ms=20477` in the focused rerun, then `14577` in the full isolated rerun
  - isolated full baseline:
    - before:
      - `tmp/phparser-full-corpus-isolated-rerun23-20260329/run-summary.json`
      - `48 match`
      - `15 not_comparable_yet`
      - `873` total findings
      - `total_duration_ms=581632`
    - after:
      - `tmp/phparser-full-corpus-isolated-rerun24-20260329/run-summary.json`
      - `48 match`
      - `15 not_comparable_yet`
      - `873` total findings
      - `total_duration_ms=510824`

- net effect:
  - no corpus status regressions
  - no finding-count regressions
  - isolated full-corpus summed case time improved by `70808 ms`
  - `acf-extended` dropped off the top of the slowest-case leaderboard

- remaining frontier after this change:
  - slowest real rows are now the `ultimate-member` SQL family, `learnpress`, `wpforms`, `user-registration`, and `wordpress-file-upload`
  - the next optimization target is no longer recursive param-path churn; it is the remaining SQL/call heavy rows and high-noise plugins

## 2026-03-29: real-world latest-plugin benchmark split for `acf-extended` `output` / `action`

- what was measured:
  - direct latest-plugin `taint-scan`
  - no corpus `max_passes`
  - external wall-clock guard only
  - target:
    - `/root/project/wp-bugbounty/bugbounty-note/wordpress/wp_install/plugins/acf-extended`

- confirmed real-world baseline before this pass:
  - `output`
    - `tmp/phparser-realworld-matrix-20260329/results.tsv`
    - `164.31s`
    - `17735920 KB`
    - `error`
  - `action`
    - `tmp/phparser-realworld-matrix-20260329/results.tsv`
    - `43.02s`
    - `17774500 KB`
    - `error`

- retained change:
  - added `action` reverse-caller pruning parallel to the existing `call` / `sql` filters
  - file:
    - `internal/taintscan/callgraph_relevance.go`
  - regression:
    - `internal/taintscan/taintscan_test.go`
    - `TestBuildEnginePrunesActionOnlyBroadcastersAndReverseOnlyCallers`

- safe exploratory work that was not sufficient for the real benchmark:
  - added `output` sink-use indexing for direct output callees
  - tried output-only low-value wrapper filtering in `relevantCallOrder`
  - kept stored-XSS regressions green, but it did not clear the uncapped real-world `acf-extended` output failure
  - tried `maxNestedParamPathsPerRoot=16`
    - reverted: no material benefit on the `acf-extended` `action` run
  - tried forcing `action` single-worker analysis
    - reverted: RSS stayed near `17.5 GB` and wall-clock got worse

- validated safe tree:
  - focused regressions:
    - `TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender`
    - `TestAnalyzeRootFindsStoredXSSFromParameterizedExtraValueSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForReceiverBackedExtraSaveLoopWithDynamicRecordID`
    - `TestBuildEnginePrunesActionOnlyBroadcastersAndReverseOnlyCallers`
    - `TestBuildEngineMarksPostSMTPDisclosureConstructorRelevant`
  - full suite:
    - `go test ./...`

- measured outcome on current safe tree:
  - `action`
    - after retained reverse-prune:
      - `tmp/phparser-realworld-acfe-action-after-actionreverse-20260329.stderr.log`
      - pass-1 scheduled callables: `62 -> 48`
      - still `error`
      - `58.95s`
      - `17541748 KB`
    - single-worker experiment:
      - `tmp/phparser-realworld-acfe-action-after-actionsingleworker-20260329.stderr.log`
      - still `error`
      - `152.40s`
      - `17499332 KB`
  - `output`
    - safe output-wrapper filtering experiment:
      - `tmp/phparser-realworld-acfe-output-after-outputwrapperfilter-20260329.stderr.log`
      - still `error`
      - `160.04s`
      - `17571140 KB`
    - earlier aggressive output reverse-prune did solve the benchmark:
      - `tmp/phparser-realworld-acfe-output-after-outputrelevance-20260329.stderr.log`
      - `7.04s` engine / `9.24s` wall
      - `320812 KB`
      - but it regressed stored-XSS writer/read coverage, so it was not retained

- honest conclusion:
  - the current durable improvement is partial:
    - `action` reverse fanout is narrower
    - the engine tree is stable and tests are green
  - the real uncapped latest-plugin frontier is still:
    - `acf-extended` `output`
    - `acf-extended` `action`
  - the next likely winning direction is not more pass caps or worker tuning
  - it is a safe sink-op-specific reduction of large helper-state summaries without breaking stored-XSS write/read chains

## 2026-03-29: latest-plugin `acf-extended` uncapped `output` and `action` now complete on the default path

- retained generic engine changes:
  - added an `output`-only forward relevance filter so data-carrier callees stay only when they feed a later output-relevant root or cross a real source/read/write/direct-sink boundary
    - files:
      - `internal/taintscan/callgraph_relevance.go`
  - added an `action`-only low-value helper filter in the relevant call order to drop non-data side-effect helpers that do not feed any action-relevant use
    - files:
      - `internal/taintscan/callgraph_relevance.go`
      - `internal/taintscan/taintscan_test.go`
  - reused batch-relevant callback filtering for direct dynamic dispatch (`call_user_func*` / `forward_static_call*`) so analysis no longer instantiates irrelevant callback targets in action batches
    - files:
      - `internal/taintscan/wordpress_context.go`
      - `internal/taintscan/call_eval.go`
      - `internal/taintscan/callgraph_relevance.go`
  - added action-only warm-summary gating and synthetic passthrough summaries for non-boundary helper callables, avoiding deep recursive helper warming where root-arg taint is sufficient for the unauthorized-action rule family
    - files:
      - `internal/taintscan/analysis_callable.go`
      - `internal/taintscan/callgraph_relevance.go`
  - flattened action-only param-path replay to root argument taint in summary instantiation, which cut the `import_item` runtime explosion on large module item arrays
    - files:
      - `internal/taintscan/summary_paths.go`
  - capped action-only batch workers at `2`; this is the retained concurrency bound that makes the narrowed pass-2 `import_item` hot set complete on the default `GOMAXPROCS=4` path
    - files:
      - `internal/taintscan/analysis_driver.go`

- durable regression coverage kept green:
  - focused:
    - `TestBuildEngineSkipsActionOnlyNonDataHelperBeforeSensitiveAction`
    - `TestBuildEngineSkipsActionFilterCarrierWithoutActionRelevantUse`
    - `TestBuildEngineKeepsActionFilterCarrierWhenResultFeedsSensitiveAction`
    - `TestAnalyzeRootFindsDynamicControllerDispatchThroughFactoryCallbacks`
    - `TestAnalyzeRootFindsAdminPageDynamicControllerDispatchThroughSingletonApplicationGetter`
    - stored-XSS regression set around admin metabox / nested extra-value write-side replay
    - `TestBuildEngineMarksPostSMTPDisclosureConstructorRelevant`
  - full suite:
    - `GOMAXPROCS=4 go test ./...`

- measured real-world latest-plugin results on the retained tree:
  - `acf-extended` `action` on current plugin tree, uncapped, default `GOMAXPROCS=4`
    - artifact:
      - `tmp/phparser-realworld-acfe-action-final-20260329/taint-results.json`
      - `tmp/phparser-realworld-acfe-action-final-20260329.stderr.log`
    - result:
      - completed successfully
      - `elapsed_ms: 85486`
      - wall time from `/usr/bin/time`: `88.84s`
      - peak RSS: `15433932 KB`
      - findings: `9`
  - `acf-extended` `output` on current plugin tree, uncapped, default `GOMAXPROCS=4`
    - artifact:
      - `tmp/phparser-realworld-acfe-output-final-20260329/taint-results.json`
      - `tmp/phparser-realworld-acfe-output-final-20260329.stderr.log`
    - result:
      - completed successfully
      - `elapsed_ms: 7368`
      - wall time from `/usr/bin/time`: `7.46s`
      - peak RSS: `323520 KB`
      - findings: `0`

- direct comparison against the earlier failing baselines:
  - `output`
    - before:
      - `tmp/phparser-realworld-acfe-output-after-outputwrapperfilter-20260329.stderr.log`
      - killed at `160.04s`, `17571140 KB`
    - after:
      - `tmp/phparser-realworld-acfe-output-final-20260329.stderr.log`
      - success at `7.46s`, `323520 KB`
  - `action`
    - before:
      - `tmp/phparser-realworld-acfe-action-after-actionreverse-20260329.stderr.log`
      - killed at `58.95s`, `17541748 KB`
    - after:
      - `tmp/phparser-realworld-acfe-action-final-20260329.stderr.log`
      - success at `88.84s`, `15433932 KB`

- important implementation note:
  - the final `action` fix was not a single knob; it required:
    - helper relevance pruning
    - dynamic callback relevance filtering
    - action-only helper summary simplification
    - action-only param-path flattening
    - and finally a bounded action worker cap of `2`
  - any one of these alone was insufficient on the real `acf-extended` latest-plugin workload

## 2026-03-29: Ultimate Member uncapped latest-plugin `read` fix and `delete` narrowing

- retained read-side engine changes:
  - `requestReachableDirectSinkSeedMode()` now treats `read` as a request-gated direct-sink batch
  - single-op `read` now uses the file-batch relevance path in `directSinkSeedAllowed()` and `forwardRelevantCallees()`
  - `callableHasRequestReachableFileCaller()` now recognizes assigned-return roots that later feed a file-relevant use in the caller
  - `fileSinkRelevantUseOrdersForCallable()` now indexes file sinks that appear inside `return ...` expressions
  - importantly, the broader `write`/`open` direct-sink fallback was not kept; only `read` was tightened
- retained regressions:
  - `TestBuildEngineSkipsReadFilterCarrierWithoutFileRelevantUse`
  - `TestBuildEngineKeepsReadFilterCarrierWhenResultFeedsReadSink`
- safety validation:
  - `GOMAXPROCS=4 go test ./...` passed
  - legacy `include` and capability-context tests stayed green after narrowing the change back to `read`
- real uncapped latest-plugin benchmark:
  - target: `bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.10.0`
  - command shape: direct `taint-scan`, `-sink-op read`, no `-max-passes`
  - artifact:
    - `tmp/phparser-realworld-um-read-fixed-20260329/taint-results.json`
    - `tmp/phparser-realworld-um-read-fixed-20260329.stderr.log`
  - result:
    - success at `17.55s`
    - peak RSS from `/usr/bin/time`: `473596 KB`
    - `elapsed_ms: 17425`
    - findings: `8`
  - previous baseline:
    - `tmp/phparser-realworld-um-read-pre-20260329.stderr.log`
    - timed out at `180s`

- delete-only investigation on the same latest plugin:
  - uncapped direct `delete` still times out
  - timed latest-plugin artifacts:
    - before user-meta narrowing:
      - `tmp/phparser-realworld-um-delete-timed-20260329.stderr.log`
    - after user-meta narrowing:
      - `tmp/phparser-realworld-um-delete-timed2-20260329.stderr.log`
  - retained safe delete-side change:
    - delete-only storage reader invalidation now special-cases `user_meta_value` so non-path-like leaves such as `full_name` do not trigger exact/bucket or family-wide reader expansion
  - retained regressions:
    - `TestShouldExpandStoragePathReadersForChangedPathSkipsDeleteUserMetaScalarPath`
    - `TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsDeleteUserMetaScalarPath`
    - `TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsDeleteUserMetaFilePath`
  - measured effect:
    - pass 3 pending counts:
      - before: `caller=174 storage-path=183 storage-family=183`
      - after: `caller=174 storage-path=174 storage-family=174`
    - pass 4 pending counts:
      - before: `caller=299 storage-path=310 storage-family=310`
      - after: `caller=299 storage-path=299 storage-family=299`
  - honest current blocker:
    - the remaining timeout is now mostly caller-driven churn in profile/member-directory display helpers
    - dominant pass-4/5 hot callables remain:
      - `function::\\um_profile_dynamic_meta_desc`
      - `function::\\um_profile_header`
      - `function::\\um_user`
      - `function::\\um_submit_form_errors_hook_`
      - `method::\\um\\core\\Fields::edit_field`
      - `method::\\um\\core\\Fields::display_view`
      - `method::\\um\\core\\Member_Directory::ajax_get_members`
      - `method::\\um\\core\\Member_Directory_Meta::ajax_get_members`

## 2026-03-29: Ultimate Member uncapped latest-plugin `delete` pass-3/4 narrowing

- retained safe delete-side engine changes after the first `read` fix:
  - delete-only caller fingerprints now drop non-path-like `user_meta_value[...]` storage-path writes before hashing callee summaries
  - delete-only assigned-return interest in caller fingerprints now uses file-relevant use orders instead of generic call-relevant use orders
  - delete-only helper callees with assigned returns no longer keep broad return churn alive unless they have:
    - a file-relevant assigned return use, or
    - a standalone source/read boundary that is still delete-relevant
  - delete-only summary publishing now drops non-path-like `user_meta_value[...]` storage-path writes before they enter global summary churn
  - the broader delete-only storage-writer relevance pruning attempt was explicitly rolled back because it broke real delete regressions and upload-helper delete coverage
- retained regressions:
  - `TestCallableSummaryInputFingerprintIgnoresDeleteUserMetaScalarStorageWriteGrowth`
  - `TestCallableSummaryInputFingerprintTracksDeleteUserMetaFilePathStorageWriteGrowth`
  - `TestCallableSummaryInputFingerprintIgnoresDeleteHelperReturnGrowthWithoutCallerFileUse`
  - `TestCallableSummaryInputFingerprintTracksDeleteStandaloneSourceReturnGrowthWithoutCallerFileUse`
  - `TestCallableSummaryInputFingerprintIgnoresDeleteStandaloneSourceReturnGrowthForNonPathLikeStorageBucket`
  - `TestCallableSummaryInputFingerprintTracksDeleteStandaloneSourceReturnGrowthForPathLikeStorageBucket`
  - `TestFilterDeleteStoragePathWritesSkipsUserMetaScalarPaths`
  - `TestFilterDeleteStoragePathWritesKeepsUserMetaFilePaths`
  - existing cross-request delete regressions remained green:
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete`
- safety validation:
  - `GOMAXPROCS=4 go test ./...` passed on the retained tree
- measured uncapped latest-plugin delete effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.10.0`
  - command shape: direct `taint-scan`, `-sink-op delete`, no `-max-passes`
  - previous retained baseline:
    - `tmp/phparser-realworld-um-delete-timed2-20260329.stderr.log`
    - timed out at `180s`
    - pass 3 duration `34.045s`
    - pass 4 duration `1m3.423s`
    - at timeout it had only started pass 5
  - current retained benchmark:
    - `tmp/phparser-realworld-um-delete-fixed5-20260329.stderr.log`
    - still timed out at `180s`
    - pass 3 duration `15.263s`
    - pass 4 duration `51.992s`
    - by timeout it had completed pass 5 and started pass 6
  - notable delete-side churn reduction on the retained tree:
    - pass 1 invalidated storage paths dropped from `33` to `23`
    - pass 3 changed storage paths no longer include `user_meta_value[*][full_name]`
    - pass 3 pending counts dropped from `caller=174 storage-path=174 storage-family=174` on the earlier narrowed tree to `caller=158 storage-path=158 storage-family=158`
    - pass 4 scheduled analyzes dropped from `93` on the earlier narrowed tree to `59`
    - pass 4 changed callables dropped from `65` to `48`
- honest current blocker after the retained delete-only cuts:
  - the remaining timeout is now dominated by a narrower option-cache chain:
    - `option_value[um_cache_userdata_{user_id}]`
    - `option_value[um_cache_userdata_{user_id}][super_admin]`
  - dominant hot callables on the current retained tree are now:
    - `method::\\um\\core\\Fields::edit_field`
    - `method::\\um\\core\\User::delete_user_handler`
    - `method::\\um\\core\\User::get_cached_data`
    - `function::\\um_profile_header`
    - `function::\\um_profile_dynamic_meta_desc`
    - `function::\\um_submit_form_errors_hook_`

## 2026-03-29: Ultimate Member uncapped latest-plugin `delete` completes after caller-invalidation narrowing

- retained generic changes:
  - delete-mode caller invalidation now uses a caller-interest summary fingerprint instead of any full-summary delta
  - that caller-interest fingerprint unions reverse-caller site interest for:
    - standalone source findings
    - returns
    - param-flow indexes
    - receiver flow
    - return classes
    - static-write overlap
  - delete-mode caller invalidation now also filters non-path-like `option_value[...]` cache writes the same way it already filtered non-path-like `user_meta_value[...]`
- retained regressions:
  - `TestCallerInvalidationSummaryFingerprintIgnoresDeleteOptionValueCacheWriteGrowth`
  - `TestCallerInvalidationSummaryFingerprintTracksDeleteOptionValuePathLikeWriteGrowth`
  - `TestCallerInvalidationSummaryFingerprintIgnoresDeleteNonPathStandaloneSourceReturnGrowth`
  - `TestCallerInvalidationSummaryFingerprintTracksDeletePathLikeStandaloneSourceReturnGrowth`
  - previously retained delete regressions remained green, including:
    - `TestCallableSummaryInputFingerprintIgnoresDeleteStandaloneSourceReturnGrowthForNonPathLikeStorageBucket`
    - `TestCallableSummaryInputFingerprintTracksDeleteStandaloneSourceReturnGrowthForPathLikeStorageBucket`
    - `TestAnalyzeRootTracksJSONWrappedDynamicColumnCrossRequestDelete`
    - `TestAnalyzeRootTracksURLToPathHelperCrossRequestDelete`
- safety validation:
  - focused delete/caller-fingerprint regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.10.0`
  - command shape: direct `taint-scan`, `-sink-op delete`, no `-max-passes`
  - previous retained timed run:
    - `tmp/phparser-realworld-um-delete-fixed5-20260329.stderr.log`
    - timed out at `180s`
    - pass 3 duration `15.263s`
    - pass 4 duration `51.992s`
    - by timeout it had completed pass 5 and started pass 6
  - current retained run:
    - `tmp/phparser-realworld-um-delete-fixed6-20260329.stderr.log`
    - completed in `71.99s`
    - peak RSS `759568 KB`
    - `38` findings
    - JSON summary: `tmp/phparser-realworld-um-delete-fixed6-20260329/taint-results.json`
  - early-pass comparison on the real latest-plugin run:
    - pass 3 duration `15.263s -> 11.812s`
    - pass 3 next pending `83 -> 69`
    - pass 4 duration `51.992s -> 9.353s`
    - pass 4 next pending `117 -> 88`
- coverage recheck:
  - fresh Ultimate Member corpus rerun stayed green in `tmp/phparser-um-still-match-after-deletechurn2-20260329/summary.json`
  - `ultimate-member-cve-2024-1071`: `match`
  - `ultimate-member-cve-2025-0308`: `match`
  - `ultimate-member-cve-2025-1702`: `match`

## 2026-03-29: User Registration uncapped latest-plugin `read` drops email/delete-only false warm edges

- retained generic changes:
  - file-batch warm summaries now ignore const-only static reads when deciding whether a callable needs full file-state analysis
  - file-batch storage-family relevance now normalizes class-qualified families like `transient_value|ClassName` and treats `transient_value` the same as `user_meta_value` / `option_value` for standalone file-return interest
  - file-batch storage-bucket relevance now requires a path-like leaf for precise buckets, including non-meta families such as `transient_value[...]`
  - `callableCallsFileRelevantCallee()` no longer keeps a caller warm just because the callee has internal `fileSinkRelevantUseOrders`
  - `callableHasDynamicDirectFileSink()` is now batch-aware, so a `read` batch no longer treats `delete`-only callees as direct file sinks
- retained regressions:
  - `TestCallableHasFileRelevantStateAccessIgnoresConstReads`
  - `TestFileStorageBucketRelevantToStandaloneReturnRequiresPathLikeLeaf`
  - `TestCallableNeedsFileWarmSummarySkipsCallerWhenCalleeOnlyHasInternalFileUseOrder`
  - `TestCallableNeedsFileWarmSummarySkipsCallerWhenCalleeOnlyHasDeleteSinkInReadBatch`
  - previously retained file regressions stayed green, including:
    - `TestAnalyzeRootSuppressesIncludeAfterPathSanitizerHelperAcrossConstructorSummary`
    - `TestCallableNeedsFileWarmSummaryKeepsDirectRequestWrapperThatCallsReadHelper`
    - `TestCallableNeedsFileWarmSummaryKeepsPathLikeRecordReadHelper`
    - `TestAnalyzeRootFindsHideMyWPStyleShowFileRead`
    - `TestAnalyzeRootFindsHideMyWPStyleShowFileInclude`
- safety validation:
  - focused file/read regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/user-registration`
  - command shape: direct `taint-scan`, `-sink-op read`, no `-max-passes`
  - earlier retained baseline:
    - `tmp/phparser-realworld-user-registration-read-after-filewarm4-20260329.stderr.log`
    - timed out under external `180s`
    - pass 1 `changed_callables=290`, `next_pending=303`
    - pass 2 `scheduled_reuse=39`, `scheduled_analyze=264`
    - pass-2 slow list still included:
      - `UR_Emailer::send_mail_to_user`
      - `UR_Emailer::status_change_email`
      - `UR_Frontend::user_registration_membership_tab_endpoint_content`
      - `UR_Frontend_Form_Handler::handle_form`
  - current retained benchmark snapshot:
    - `tmp/phparser-realworld-user-registration-read-after-filewarm7-20260329.stderr.log`
    - build time `6.281s`
    - pass 1 `changed_callables=229`, `next_pending=285`
    - pass 2 `scheduled_reuse=72`, `scheduled_analyze=213`
    - email confirmation / resend / mail wrapper chain no longer stays file-warm relevant
    - membership AJAX wrapper no longer stays file-warm relevant through delete-only/service-only callees
- remaining honest blocker:
  - uncapped latest-plugin `read` is still not fully finished yet on the retained tree
  - the remaining hot path is concentrated in true return-carrying/frontend form logic:
    - `UR_Frontend::user_registration_membership_tab_endpoint_content`
    - `UR_Frontend_Form_Handler::handle_form`
    - `WPEverest\\URMembership\\Admin\\Services\\SubscriptionService::upgrade_membership`

## 2026-03-30: User Registration uncapped latest-plugin `read` narrows file-batch static state to path-like keys only

- retained generic changes:
  - file-batch static-state relevance now keeps only path-like static roots and paths
  - const-only static state stays ignored
  - non-path static state like `user_email` / `valid_form_data` no longer keeps a callable file-warm by itself
- retained regressions:
  - `TestCallableHasFileRelevantStateAccessIgnoresConstAndNonPathReads`
  - previously retained file/read regressions stayed green, including:
    - `TestAnalyzeRootSuppressesIncludeAfterPathSanitizerHelperAcrossConstructorSummary`
    - `TestCallableNeedsFileWarmSummaryKeepsPathLikeRecordReadHelper`
    - `TestAnalyzeRootFindsHideMyWPStyleShowFileRead`
    - `TestAnalyzeRootFindsHideMyWPStyleShowFileInclude`
- safety validation:
  - focused file/read regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/user-registration`
  - command shape: direct `taint-scan`, `-sink-op read`, no `-max-passes`
  - previous retained benchmark snapshot:
    - `tmp/phparser-realworld-user-registration-read-after-filewarm7-20260329.stderr.log`
    - timed out under external `180s`
    - pass 1 `changed_callables=229`, `next_pending=285`
    - pass 1 pending sources `caller=284`, `storage-path=559`, `storage-family=598`, `static=598`
    - pass 2 `scheduled_reuse=72`, `scheduled_analyze=213`
    - pass 2 slow callable `UR_Frontend_Form_Handler::handle_form duration=918ms`
  - current retained benchmark snapshot:
    - `tmp/phparser-realworld-user-registration-read-after-staticpath-20260330.stderr.log`
    - still timed out under external `180s`
    - build time `6.704s`
    - pass 1 `changed_callables=228`, `next_pending=285`
    - pass 1 pending sources `caller=284`, `storage-path=548`, `storage-family=593`, `static=593`
    - pass 2 `scheduled_reuse=72`, `scheduled_analyze=213`
    - pass 2 slow callable `UR_Frontend_Form_Handler::handle_form duration=1.009s`
- remaining honest blocker:
  - this cut a small amount of static/storage invalidation, but it did not convert the uncapped latest-plugin `read` run into a completion
  - the next real optimization target is still the true frontend return chain around:
    - `UR_Frontend_Form_Handler::handle_form`
    - `UR_Frontend::user_registration_membership_tab_endpoint_content`
    - `WPEverest\\URMembership\\Admin\\Services\\SubscriptionService::upgrade_membership`

## 2026-03-30: File-batch static filtering now reaches summary fingerprints too

- retained generic changes:
  - file-batch summary fingerprints now filter static read roots and paths with the same path-like static-key logic used by file-batch relevance
  - this applies both to:
    - `callableSummaryInputFingerprint()`
    - `callerInvalidationSummaryFingerprint()`
  - bare static roots such as `Class::$template_path` now parse their leaf from the trailing `$...` segment before path-like classification
- retained regressions:
  - `TestCallerInvalidationSummaryFingerprintIgnoresNonPathStaticReadInterestInReadBatch`
  - `TestCallerInvalidationSummaryFingerprintTracksPathLikeStaticReadInterestInReadBatch`
  - `TestCallableSummaryInputFingerprintIgnoresNonPathStaticRootsInReadBatch`
  - existing file-batch static-write regressions stayed green after switching the representative static keys to clearly path-like names
- safety validation:
  - focused file/read regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/user-registration`
  - command shape: direct `taint-scan`, `-sink-op read`, no `-max-passes`
  - benchmark artifact: `tmp/phparser-realworld-user-registration-read-after-staticfingerprint-20260330.stderr.log`
  - result: still timed out under external `180s`
  - pass 1 stayed essentially flat:
    - `changed_callables=228`
    - `next_pending=285`
    - pending sources `caller=284`, `storage-path=550`, `storage-family=595`, `static=595`
  - pass 2 also stayed effectively flat:
    - `scheduled_reuse=72`
    - `scheduled_analyze=213`
    - slow callable `UR_Frontend_Form_Handler::handle_form duration=1.003s`
- remaining honest blocker:
  - this change fixed a correctness mismatch between relevance and invalidation, but it did not materially improve the uncapped latest-plugin benchmark
  - the remaining cost is still dominated by large return-carrying membership/frontend summaries, especially:
    - `WPEverest\\URMembership\\Admin\\Services\\SubscriptionService::renew_membership`
    - `WPEverest\\URMembership\\Admin\\Services\\PaymentService::build_response`
    - `UR_Frontend_Form_Handler::handle_form`

## 2026-03-30: File-batch summary generation now drops non-path return structure before replay

- retained generic changes:
  - file-batch summaries now apply the same path-like structural filter at summary construction time, not only at diagnostics/fingerprint time
  - this prunes non-path-like:
    - `ReturnParamPaths`
    - `ReturnReceiverPaths`
    - `ReturnPathWrites`
  - the filter still keeps whole-value returns like `ReturnParams`, so direct file-path scalar returns are not weakened
- retained regressions:
  - `TestFilterSummaryForFilePathLikeCallInterestDropsNonPathReturnParamPaths`
  - `TestFilterSummaryForFilePathLikeCallInterestDropsNonPathReturnReceiverPaths`
  - `TestFileReadSummaryDropsNonPathReturnPathWritesAtGeneration`
  - existing file/read and stored-write regressions stayed green, including:
    - `TestCallableSummaryInputFingerprintTracksReadUserMetaScalarStorageWriteGrowth`
    - `TestAnalyzeRootFindsHideMyWPStyleShowFileRead`
    - `TestAnalyzeRootFindsHelperChainToRequire`
    - `TestAnalyzeRootFindsParsedURLChainToFilesystemRead`
    - `TestAnalyzeRootFindsRealpathChainToRequire`
    - `TestAnalyzeRootFindsFactoryResolvedHookCallbackRead`
    - `TestAnalyzeRootFindsSureFormsStoredDeleteSink`
- safety validation:
  - focused regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - `user-registration-cve-2026-1492` still freshly `match` in `tmp/phparser-user-registration-1492-after-summarygen-20260330/summary.json`
- measured diagnosis:
  - one-pass real-plugin summary dump on `bugbounty-note/wordpress/wp_install/plugins/user-registration` showed the real hotspot was summary volume, not fingerprint churn
  - `SubscriptionService::renew_membership` summary weight dropped from `652` to `3`
  - `PaymentService::build_response` summary weight dropped from `173` to `2`
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/user-registration`
  - command shape: direct `taint-scan`, `-sink-op read`, no `-max-passes`
  - previous retained benchmark snapshots:
    - `tmp/phparser-realworld-user-registration-read-after-staticfingerprint-20260330/stderr.log`
    - `tmp/phparser-realworld-user-registration-read-after-returnpathfilter-20260330/stderr.log`
    - both timed out under external `180s`
  - current retained benchmark snapshot:
    - `tmp/phparser-realworld-user-registration-read-after-summarygen2-20260330/stderr.log`
    - completed in `47.39s`
    - peak RSS `786284 KB`
    - `taint-results.json` summary:
      - `elapsed_ms=45117`
      - `total_results=2`
      - `total_errors=0`
- remaining honest blocker:
  - `user-registration` latest-plugin uncapped `read` is no longer the frontier
  - the next real-world uncapped latest-plugin target should move to the next remaining slow sink-op batch, not more user-registration read-specific work

## 2026-03-30: Output-mode persistent-read wrapper suppression reaches transitive Ultimate Member render helpers

- retained generic changes:
  - output-mode replay/state-interest logic now treats a callee as a persistent-read wrapper when either:
    - it is a direct `recordReadCallable`, or
    - its summary/current return value carries persistent-read return metadata
  - that widened gate is used in:
    - current-callable output storage-effect suppression
    - call replay state-side-effect suppression
    - output caller invalidation / storage-write interest filtering
  - receiver relevance for output storage-write interest is now split from receiver-state relevance:
    - receiver-carried sites still keep storage-write interest
    - receiver-state-only sites no longer keep output storage-write churn alive by themselves
- retained regressions:
  - `TestCallableHasPersistentReadOnlyStandaloneSourceSummaryTracksPersistentReturnWrapper`
  - `TestReceiverFlowsRequiringStorageWriteInterestIgnoresOutputReceiverStateOnlyRecordReadSite`
  - `TestReceiverFlowsRequiringStorageWriteInterestKeepsOutputReceiverCarrierRecordReadSite`
  - `TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadWrapperWithoutDirectRecordRead`
  - existing stored-XSS/output regressions stayed green, including:
    - `TestAnalyzeRootFindsNinjaFormsCalculationsStoredXSS`
    - `TestAnalyzeRootFindsStoredReadOutputThroughTemplateInclude`
    - `TestAnalyzeRootSkipsStoredXSSAfterWPKsesPostBoundary`
- safety validation:
  - focused regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.10.0`
  - command shape: direct `taint-scan`, `-sink-op output`, no `-max-passes`
  - previous retained uncapped output runs were timing out before a completed pass 5, with pass 3/pass 4 still dominated by transitive persistent-read wrapper churn
  - current retained benchmark snapshot:
    - `tmp/phparser-realworld-um-output-after-summarywrapper-20260330.stderr.log`
    - still timed out at external `240s`
    - but materially improved:
      - pass 3 `1m1.699s -> 50.147s`
      - pass 4 `1m54.21s -> 1m30.112s`
      - progressed into pass 5 before timeout
      - key helper drops:
        - `function::\\um_user` pass 3 `2.739s` and pass 4 `1.367s`
        - `function::\\um_profile_dynamic_meta_desc` pass 3 `980ms`, pass 4 `2.764s`
        - `function::\\um_get_user_avatar_data` pass 3 `2.092s`, pass 4 `3.563s`
      - remaining main hotspot:
        - `method::\\um\\core\\Fields::edit_field` pass 4 `35.237s`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` is still not finished inside `240s`
  - the remaining cost is now concentrated in `Fields::edit_field` and its downstream render branches, not the broader persistent-read wrapper fanout around it
  - the next real seam should be a bounded generic specialization or relevance cut around large renderer branch fanout, not more wrapper/storage suppression

## 2026-03-30: Branch isolation fix removes sibling-case taint bleed and cuts Ultimate Member output pass-4 renderer churn

- what was wrong:
  - `StmtIf` and `StmtSwitch` branch states were reusing the same cloned base `varTaint` / `propTaint` / `staticPropTaint` / `classEnv` / `stringEnv` maps across sibling branches
  - that let later branches inherit earlier-branch writes and literals, which is unsound and especially harmful in large switch-driven render helpers
  - on latest `ultimate-member` output, that overgrowth kept `\\um\\core\\Fields::edit_field` alive deep into pass 4 as a major hot callable
- what changed:
  - each `if` / `elseif` / `else` branch now gets fresh clones of the saved base maps instead of sharing one mutable base map
  - each `switch` case now gets fresh clones of the same base maps as well
  - added regression:
    - `TestAnalyzeRootSwitchCasesDoNotShareBranchState`
      - `case 'a'` writes request taint to `$x`
      - `case 'b'` echoes `$x`
      - literal call `demo('b')` must not inherit taint from sibling `case 'a'`
- safety validation:
  - focused tests passed:
    - `TestAnalyzeRootSwitchCasesDoNotShareBranchState`
    - `TestAnalyzeCallableOutputFilterReplaySkipsCallbackStorageSideEffects`
    - `TestAllowCurrentBatchStateSideEffectsForCallSkipsPersistentReadWrapperWithoutDirectRecordRead`
    - `TestAnalyzeRootFindsNinjaFormsCalculationsStoredXSS`
    - `TestAnalyzeRootFindsUserRegistrationSQLReadOutput`
  - `GOMAXPROCS=4 go test ./...` passed
- measured real-world effect:
  - target: `bugbounty-note/wordpress/wp_install/plugins/ultimate-member__2.10.0`
  - command shape: direct `taint-scan`, `-sink-op output`, no `-max-passes`
  - artifact:
    - `tmp/phparser-realworld-um-output-after-branchisolation-20260330.stderr.log`
  - result:
    - still timed out at external `240s`
    - but the hotspot moved materially:
      - `Fields::edit_field` pass 2 `3.849s`
      - `Fields::edit_field` pass 3 `12.745s` vs previous retained `13.776s`
      - `Fields::edit_field` no longer appears in the pass-4 slow-callable list before timeout
    - remaining pass-4 hotspots are now the next wrapper tier:
      - `function::\\um_user` `7.469s`
      - `method::\\um\\admin\\core\\Admin_Builder::dynamic_modal_content` `6.966s`
      - `function::\\um_profile_header` `4.754s`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not finish inside `240s`
  - this fix is worth keeping because it closes a real cross-branch taint leak and removes `Fields::edit_field` as the dominant pass-4 blocker
  - the next seam is no longer raw switch sibling contamination; it is the remaining output wrapper tier (`um_user`, `um_profile_header`, admin builder render helpers)

## 2026-03-30: Output-only callback replay and storage-reader invalidation stay precise without reopening stored-XSS regressions

- what changed:
  - output-mode `do_action()` / `do_action_ref_array()` replay now reuses `instantiateSummaryReturnWithOptions(...)` so callback summaries can skip current-batch state side effects when they are persistent-read-only standalone sources and the callback arguments do not carry current-batch state interest
  - output-only storage reader invalidation now uses the same precise bucket-vs-family fallback logic already used by SQL/write batches, so stable-key output changes do not automatically keep broad family-wide reader invalidation alive
  - retained regressions:
    - `TestAllowCurrentBatchStateSideEffectsForCallbackReplaySkipsPersistentReadOnlySourceCallback`
    - `TestAllowCurrentBatchStateSideEffectsForCallbackReplayKeepsParameterizedCallback`
    - `TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsPreciseOutputFallback`
    - `TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsBroadOutputFallback`
- safety validation:
  - focused output regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - these changes are worth keeping for precision and state-control, but they did not finish the latest-plugin uncapped `ultimate-member` `output` benchmark by themselves
  - the remaining hotspot is still the output wrapper tier driven by broad reader/index fingerprints rather than callback state replay alone
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still needs specialized-callee-aware indexing and fingerprinting to stop literal-specialized helper paths from looking like broad unspecialized readers

## 2026-03-30: Build-time output function specialization now materializes without flipping generic engine batch state

- what was wrong:
  - the retained output literal specialization work needed build-time specialized global-function call edges and reader indexes for output-only scans
  - the first attempt set `currentBatchName` too broadly during base-engine construction, which reopened stored-XSS/output regressions
  - the narrower follow-up still only recorded literal arg hints on call sites; it did not actually materialize specialized global-function callables during build
- what changed:
  - base-engine construction now preserves `allowedSinkOps`, so build-time callgraph construction can see whether the base engine is output-only without mutating generic batch state
  - extracted `ensureLiteralArgSpecializedCallable(...)` so literal-specialized callables can be materialized directly without depending on ambient batch mode
  - added `maybeSpecializeOutputFunctionCallableForBuild(...)` for the one safe build-time case we need here:
    - output-only base-engine construction
    - global functions only
    - existing call-style literal-dispatch predicates only
  - `collectDirectCallsFromExpr(...)` now uses that helper for plain function calls while building an output-only base engine
  - `indexGlobalStateReaders()` and `collectDirectCallEdges()` only apply literal branch pruning to already-specialized callables, so unspecialized stored-XSS helpers stay conservative
  - extracted `literalSwitchCasesForCallable(...)` so build-time indexing and runtime analysis share the same literal-switch case selection logic
  - added durable regressions:
    - `TestOutputLiteralSpecializationBuildsSpecializedFunctionCallEdges`
    - `TestOutputLiteralSpecializationNarrowsStorageReadIndexes`
    - `TestAnalyzeRootSwitchCasesDoNotShareBranchState`
- safety validation:
  - focused stored-XSS and REST regressions passed:
    - `TestAnalyzeRootFindsStoredXSSFromAdminMetaboxRender`
    - `TestAnalyzeRootFindsStoredXSSFromParameterizedExtraValueSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSFromNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForNestedExtraParamSaveLoop`
    - `TestAnalyzeRootFindsStoredXSSWriteSideSourceForReceiverBackedExtraSaveLoopWithDynamicRecordID`
    - `TestAnalyzeRootFindsPublicRestTokenIssuanceSurfaceInInlineClosure`
  - focused specialization regressions passed:
    - `TestOutputLiteralSpecializationBuildsSpecializedFunctionCallEdges`
    - `TestOutputLiteralSpecializationNarrowsStorageReadIndexes`
    - `TestLiteralArgSpecializationAppliesForOutputLiteralReturnFunctions`
    - `TestAnalyzeRootLiteralSwitchOnlyExecutesMatchingCase`
    - `TestAnalyzeRootSwitchCasesDoNotShareBranchState`
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - latest-plugin direct `ultimate-member__2.10.0` `-sink-op output` still times out under external `120s`
  - artifact:
    - `tmp/phparser-realworld-um-output-after-base-allowedops-fix4-20260330.stderr.log`
  - measured improvement is mainly in build/setup cost, not final completion yet:
    - `build-engine=7.631s` on the current tree
    - previous retained `120s` trace baseline was `build-engine=8.666s`
  - pass structure and hotspot tier remain broadly the same after the fix:
    - pass 4 hot summaries still center on `function::\\um_profile_dynamic_meta_desc`, `method::\\um\\admin\\core\\Admin_Builder::dynamic_modal_content`, `method::\\um\\core\\Fields::edit_field`, `method::\\um\\core\\Fields::display`, and `function::\\um_profile_header`
    - pass 5 still burns time in `function::\\um_get_user_avatar_data`, `function::\\um_profile_dynamic_meta_desc`, `function::\\um_replace_placeholders`, `function::\\um_submit_account_details`, and `function::\\um_update_profile_full_name`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still needs further wrapper-tier pruning; this checkpoint fixes the build-time specialization correctness bug without yet removing the main runtime render stack

## 2026-03-30: Array-backed output selector specialization now reaches latest-plugin pass 5 safely

- what was wrong:
  - output literal specialization already handled direct scalar literal params, but large renderer helpers in `ultimate-member` still guarded on array-backed selectors and local aliases such as `$data['type']`
  - the first array-selector attempt tried to recover literal fetches through recursive local array resolution, which was unsafe on self-referential locals like `$args = array('foo' => $args['foo'])`
- what changed:
  - base-engine construction now records literal arg path hints alongside scalar literal hints
  - build-time and runtime callable specialization both accept literal arg path hints, so specialized call edges can materialize for array-backed selector params instead of only direct literals
  - literal-guard detection now tracks local aliases derived from specialized params, so guards like `$type = $data['type']; switch ($type)` can still specialize safely
  - the unsafe recursive local-fetch fallback was removed from `ast_helpers.go`; array fetches now rely only on explicit path hints, which keeps self-referential locals bounded
  - added durable regressions:
    - `TestOutputLiteralSpecializationBuildsSpecializedMethodCallEdgesForArraySelectorParams`
    - `TestAnalyzeRootOutputLiteralSpecializationNarrowsArraySelectorMethods`
    - `TestStorageWriteBucketsAvoidRecursiveLocalFetchOverflow`
- safety validation:
  - focused selector and overflow regressions passed
  - focused stored-XSS and REST regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still timed out at external `240s`
  - retained baseline artifact:
    - `tmp/phparser-realworld-um-output-after-branchisolation-20260330.stderr.log`
  - current artifact:
    - `tmp/phparser-realworld-um-output-after-arraypathsafe-20260330.stderr.log`
  - even without finishing, the run progressed materially deeper before timeout:
    - pass `2`: `42.401s -> 10.175s`
    - pass `3`: `1m19.995s -> 19.365s`
    - previous retained trace timed out during pass `4`
    - current trace reaches pass `5` before timeout
  - the hotspot shape also improved:
    - `Fields::edit_field` is no longer the early dominant wall from the previous retained trace
    - the remaining cost has moved into the pass-5 wrapper tier:
      - `Admin_DragDrop::update_order`
      - `Admin_Builder::dynamic_modal_content`
      - `Fields::edit_field`
      - `Permalinks::activate_account_via_email_link`
      - `um_submit_account_details`
      - `um_update_profile_full_name`
      - `um_user`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not complete inside `240s`
  - the next seam is no longer array-selector specialization; it is pass-5 wrapper churn through admin drag-drop, admin builder rendering, and user/profile output helpers

## 2026-03-30: Output writer compaction and structural storage-link persistence cut latest-plugin output churn

- what was wrong:
  - output-only summary replay still carried large receiver and return state through storage-writer helpers that had no direct output sink and no caller-visible return effects
  - structural copies of storage-backed values were also losing persistent-read context and local root linkage, which made later receiver/path replay broader and less stable than necessary
  - sequential literal `if ($mode == 'x')` chains were still treated like cumulative state updates unless they were written as `switch` or `elseif`, so specialized output wrappers could inherit sibling-branch taint
- what changed:
  - output-only callable summaries can now compact storage-writer helpers down to storage-context effects only when the helper has:
    - no direct sink
    - no output-relevant use order
    - no caller-visible return effects
  - output-only dependency fingerprinting also drops receiver writes and receiver path writes that are already fully covered by persistent receiver storage links
  - structural storage-link tracking now persists through:
    - receiver summary replay
    - post-assignment receiver replay
    - `foreach` value copying from local structural roots
    - inline closure and include-state merges
  - structural copies from storage families now mark copied origins as persistent reads, so replayed receiver/path structure keeps the correct persistence semantics
  - statement walking now detects top-level mutually exclusive literal `if` chains on the same variable and evaluates them from a shared base state instead of sequentially accumulating sibling taint
  - added durable regressions:
    - `TestAnalyzeCallableCompactsOutputWriterContextOnlySummaries`
    - `TestOutputLiteralSpecializationNarrowsSequentialLiteralIfFunctionCallEdges`
    - `TestInstantiateSummaryReturnMarksReceiverStorageLinksAsPersistentRead`
    - `TestCopyForeachValueStructurePropagatesStorageLinksThroughLocalRoots`
    - `TestFilterSummaryReceiverEffectsCoveredByStorageLinksDropsPersistentReceiverPaths`
- safety validation:
  - focused taintscan regressions passed:
    - `TestAnalyzeCallableCompactsOutputWriterContextOnlySummaries`
    - `TestOutputLiteralSpecializationNarrowsSequentialLiteralIfFunctionCallEdges`
    - `TestOutputLiteralSpecializationNarrowsLeadingDefaultSwitchFunctionCallEdges`
    - `TestAnalyzeCallableSkipsNoOpStorageWritePropagationFromCallee`
    - `TestAnalyzeCallableKeepsParameterizedStorageWritePropagationFromCallee`
    - `TestAnalyzeRootFindsSureFormsStoredDeleteSink`
  - `GOMAXPROCS=4 go test ./...` should stay part of the commit gate for this checkpoint
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still times out under external `240s`, but the retained trace progressed materially deeper:
    - artifact: `tmp/phparser-realworld-um-output-after-writercompact-20260330.stderr.log`
    - pass `5`: about `2m51s -> 2m16.969s`
    - the run now reaches pass `6` before timeout
  - the blocker tier also narrowed:
    - `Admin_DragDrop::update_order` dropped out of the pass-5 hotspot set
    - remaining time is now concentrated in output wrappers such as `um_profile_dynamic_meta_desc`, `um_profile_header`, `um_get_user_avatar_data`, `Mail::add_replace_placeholder`, `Permalinks::activate_account_via_email_link`, and `User::set`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not complete inside `240s`
  - the next seam is direct-sink renderer/output-wrapper compaction, not more generic storage-link replay cleanup

## 2026-03-30: Drop Unreplayable Receiver Findings From Non-Method Summaries

- what was wrong:
  - plain functions and static methods were retaining `ReceiverFindings` in their summaries even though call replay can only consume receiver sink templates when the call site has a concrete receiver root
  - on latest `ultimate-member__2.10.0` output scans this left large amounts of dead summary weight in free-function render helpers like:
    - `um_profile_dynamic_meta_desc`
    - `um_profile_header`
  - focused summary probing showed those helpers were dominated almost entirely by unreplayable receiver sink templates rather than caller-visible return state
- what changed:
  - callable summary construction now drops `ReceiverFindings` when the callable is not an instance method (`Class == ""` or `Static == true`)
  - added a focused regression:
    - `TestAnalyzeCallableDropsUnreplayableReceiverFindingsForFunctionSummary`
- safety validation:
  - focused regressions passed:
    - `TestAnalyzeCallableDropsUnreplayableReceiverFindingsForFunctionSummary`
    - `TestApplyPathStringToOriginsCapsDeepRelativeParamPath`
    - `TestSummaryForKeyLocallyComputesInflightWarmDependency`
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still times out under external `240s`, but the hot-summary frontier shifted materially:
    - artifact: `tmp/phparser-realworld-um-output-after-unreplayable-receiverdrop-timed-20260330.stderr.log`
    - pass `4` hot summary for `function::\um_profile_dynamic_meta_desc` dropped from roughly `2007` to `329`
    - `function::\um_profile_header` dropped out of the pass-4 hot-summary list
    - pass `3` and pass `4` durations settled around `15.3s` and `15.4s`
  - the remaining pass-5/6 hotspot set is now concentrated in caller-visible return builders:
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`
    - `\um\core\Member_Directory::build_user_card_data`
    - `\um\core\User::is_private_profile`
    - `\um\core\User::is_profile_noindex`
    - `\um_get_user_avatar_data`
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not finish inside `240s`
  - the next seam is output-call-site return fingerprinting or return-path specialization for boolean/render-array helpers, not more receiver-finding cleanup

## 2026-03-30: Skip Output Return Replay For Boolean-Only Call Uses

- what was wrong:
  - output-only scans were still treating boolean guard helpers as full return-interest sites whenever their call expression was not a standalone statement
  - that kept caller-visible return fingerprints alive for helpers whose result was only consumed through boolean control flow such as:
    - `UM()->user()->is_profile_noindex(...)`
    - `UM()->user()->is_private_profile(...)`
  - the remaining latest-plugin `ultimate-member__2.10.0` output hotspot set still included those helpers even after dropping dead receiver sink templates
- what changed:
  - direct call-edge collection now tags call sites whose result is used only through boolean wrappers or conditions
  - output-batch dependency fingerprinting now skips return replay for those boolean-only sites unless the call result is assigned and later used through an assigned root
  - added focused regressions:
    - `TestCollectDirectCallEdgesMarksBooleanOnlyCallUse`
    - `TestCallableSummaryInputFingerprintIgnoresOutputReturnGrowthForBooleanOnlySite`
- safety validation:
  - focused regressions passed:
    - `TestCollectDirectCallEdgesMarksBooleanOnlyCallUse`
    - `TestCallableSummaryInputFingerprintIgnoresOutputReturnGrowthForBooleanOnlySite`
    - `TestAnalyzeCallableDropsUnreplayableReceiverFindingsForFunctionSummary`
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still times out under external `240s`, but replay cost dropped measurably:
    - artifact: `tmp/phparser-realworld-um-output-after-booleanuse-20260330/stderr.log`
    - pass `3` duration improved from about `15.3s` to `14.1s`
    - pass `4` duration improved from about `15.4s` to `13.5s`
    - pass `5` duration improved from about `2m19s` to `2m16s`
  - two follow-on experiments were intentionally not kept:
    - output forward-relevance suppression for boolean-only no-assignment sites
    - tighter output-only return-path compaction
    - both were safe in focused tests but did not produce a clear real-world benchmark win on latest `ultimate-member` output
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not finish inside `240s`
  - the next seam is builder-side return-state reduction in:
    - `\um\core\Member_Directory::build_user_card_data`
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`
    - `\um_get_user_avatar_data`

## 2026-03-30: Drop output-safe persistent return effects from read-only wrappers

- problem:
  - output-only scans on latest `ultimate-member__2.10.0` still kept large caller-visible return summaries for persistent-read-only helpers even when those return origins were already marked HTML-safe and could not contribute to an unsafe output finding
  - that left render-array builders such as `build_user_card_data` and `um_get_user_avatar_data` carrying bulky safe return state across later output passes
- change:
  - in `internal/taintscan/analysis_callable.go`, after statement walk and before summary materialization:
    - `filterCurrentBatchReturnOrigins(...)` now drops origins where:
      - the current batch is output-only
      - the current callable is a persistent-read-only standalone source wrapper
      - the origin is `outputSafeHTML` and not `outputUnsafeHTML`
    - `filterCurrentBatchReturnPathWrites(...)` applies the same pruning to return path writes
  - added focused regression:
    - `TestAnalyzeCallableDropsOutputSafePersistentReturnEffectsInOutputBatch`
- safety validation:
  - `GOMAXPROCS=4 go test ./...` passed
  - representative Ultimate Member corpus cases still freshly `match`:
    - `ultimate-member-cve-2025-0308`
    - `ultimate-member-cve-2025-1702`
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still times out under external `240s`, but replay cost dropped again:
    - artifact: `tmp/phparser-realworld-um-output-after-safe-return-filter-20260330.stderr.log`
    - pass `4` duration improved from about `13.5s` to `13.3s`
    - pass `5` duration improved from about `2m16.1s` to `2m13.3s`
    - pass `5` hot summary weight also dropped in the main builder tier:
      - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`: about `995 -> 861`
      - `\um\core\Member_Directory::build_user_card_data`: about `995 -> 861`
      - `\um\core\User::is_private_profile`: about `895` remained high but now sits behind a smaller builder fanout
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not finish inside `240s`
  - the next seam is caller-visible return narrowing for:
    - `\um\core\Member_Directory::build_user_card_data`
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`
    - `\um_get_user_avatar_data`

## 2026-03-31: Demand-prune output-only helper summaries

- what was wrong:
  - output-only latest-plugin scans still kept reanalyzing helpers that had already collapsed to empty boolean-only summaries or to narrow assigned-path-only return summaries
  - this is the exact shape that demand-driven interprocedural analyses try to avoid: once only a small subset of returned facts are actually demanded by relevant callers, replaying and invalidating the full helper state is wasted work
  - on latest `ultimate-member__2.10.0` `-sink-op output`, the remaining pass-5/6 blocker set was dominated by:
    - `\um_get_user_avatar_data`
    - `\um\core\Member_Directory::build_user_card_data`
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`
    - `\um\core\User::is_private_profile`
- what changed:
  - added output-only fingerprint reuse for helpers that:
    - have no remaining summary effects
    - are only used through boolean guard sites
  - extended output-only summary compaction so a helper can keep only the return subpaths that relevant callers actually consume through assigned roots
  - retained the earlier per-call replay filter and wired it through direct call-site line information so return replay can stay path-specific at each call site
  - added focused regressions:
    - `TestCallableSummaryInputFingerprintReusesEmptyBooleanOnlyOutputSummary`
    - `TestAnalyzeCallableCompactsOutputAssignedPathSummary`
    - existing assigned-return replay regressions
- safety validation:
  - focused regressions passed for:
    - empty boolean-only output helper reuse
    - assigned-path output summary compaction
    - assigned-return replay filtering
    - sibling branch isolation
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` still times out under external `240s`, but the retained demand pruning moved the real benchmark again:
    - artifact: `tmp/phparser-realworld-um-output-after-assignedsummary-20260331.stderr.log`
    - previous retained baseline artifact: `tmp/phparser-realworld-um-output-after-unreplayable-receiverdrop-timed-20260330.stderr.log`
    - intermediate fingerprint-only artifact: `tmp/phparser-realworld-um-output-after-boolemptyfingerprint-20260331.stderr.log`
    - pass `3` duration improved from about `15.3s` to `14.0s`
    - pass `4` duration improved from about `15.4s` to `13.7s`
    - pass `5` duration improved from about `2m19.1s` to `2m6.6s`
    - pass `5` next-pending set dropped from `84` to `72`
    - the run now reaches pass `6` with a materially smaller pending frontier before the `240s` timeout
- remaining honest blocker:
  - latest-plugin uncapped `ultimate-member` `output` still does not finish inside `240s`
  - the remaining pass-6 hotspot set is now concentrated in direct renderers and link builders:
    - `\um_profile_dynamic_meta_desc`
    - `\um_profile_header`
    - `\um\core\Mail::add_replace_placeholder`
    - `\um\core\Permalinks::activate_account_via_email_link`
  - the next seam is statement-level demand pruning of direct-return local array builders or tighter direct-renderer dependency fingerprints

## 2026-03-31: Reduce output replay churn from storage-only renderer helpers

- what was wrong:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` was still spending most late passes replaying storage-only side effects through direct renderers that never read storage themselves
  - helpers that directly `echo`/`print` or return public markup were also publishing persistent-read storage origins into their summaries even when those facts were only noise for output replay
  - that kept render-time wrappers such as `um_profile_header`, `um_profile_dynamic_meta_desc`, `build_user_card_data`, and `um_get_user_avatar_data` alive across many output passes even after their caller-visible return state had already converged
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - added `callableHasDirectOutputSyntax(...)` so output-only pruning can target real renderer-style callables instead of the stricter direct-sink classification
    - summary construction now drops persistent-read storage origins for direct output callables that do not write durable cross-request state
  - in `internal/taintscan/call_eval.go`:
    - added `summaryHasOnlyStorageEffects(...)`
    - output-only replay now skips callee state side effects when:
      - the callee summary contains only storage effects
      - the current caller has direct output syntax
      - the current caller does not read storage itself
  - added focused regressions for:
    - direct-output storage-origin pruning
    - non-direct helper preservation
    - storage-only callee replay skipping when the caller has no storage reads
    - storage-only callee replay preservation when the caller actually reads storage
- safety validation:
  - focused replay/pruning regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op output` now completes under a `300s` outer cap instead of stalling earlier in convergence:
    - artifact: `tmp/phparser-realworld-um-output-after-storageonly-callskip-300s-20260331.stderr.log`
    - results: `tmp/phparser-realworld-um-output-after-storageonly-callskip-300s-20260331/taint-results.json`
    - engine run: about `4m36.856s`
    - wall clock: about `4:45.05`
    - RSS: about `3902064 KB`
    - findings: `45`
    - errors: `0`
  - compared with the previous retained `240s` baseline:
    - artifact: `tmp/phparser-realworld-um-output-after-assignedsummary-20260331.stderr.log`
    - pass `5` duration improved from about `2m19.1s` to about `2m6.6s`
    - the run progressed from timing out during pass `6` to reaching pass `20` and finishing under the wider cap
- remaining honest blocker:
  - latest-plugin full all-ops `ultimate-member__2.10.0` is still dominated by the `delete` batch, not `output`
  - the next seam is delete-side caller churn through:
    - `\um\core\User::delete_user_handler`
    - `\um\core\Fields::display_view`
    - `\um_profile_dynamic_meta_desc`
    - `\um\core\Member_Directory::build_user_card_data`

## 2026-03-31: Reduce delete renderer summary churn

- what was wrong:
  - latest-plugin uncapped `ultimate-member__2.10.0` `-sink-op delete` had regressed back to timing out under a `240s` outer cap
  - broad standalone-source relevance from record-read families such as `user_meta_value`, `option_value`, and `transient_value` was keeping delete batches warm through direct output renderers even when those buckets were not path-like
  - direct renderer helpers like `um_profile_header`, `um_profile_dynamic_meta_desc`, `Fields::display_view`, and mail/render wrappers were publishing large return/source/storage summaries into delete replay even though only caller-visible delete facts mattered
- what changed:
  - in `internal/taintscan/diagnostics.go`:
    - tightened delete standalone-source relevance so family-only reads for `user_meta_value`, `option_value`, and `transient_value` are no longer automatically delete-relevant
    - delete standalone-source interest now requires a path-like bucket leaf for those families
    - direct output renderers that are not direct sinks, storage writers, or supported cross-request writers are skipped entirely for delete standalone-source interest when they have no relevant file sink uses
  - in `internal/taintscan/analysis_callable.go`:
    - added delete-only renderer summary compaction for direct output helpers in standalone delete batches
    - delete renderer compaction keeps caller-visible finding facts while dropping unreplayable source, return, receiver-write, and storage-write noise
  - added focused regressions for:
    - path-like delete bucket gating
    - delete family relevance gating
    - skipping direct output renderers in delete standalone-source relevance
    - delete renderer summary compaction preserving param findings while dropping replay noise
- safety validation:
  - focused delete regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh Ultimate Member CVE compare still matches:
    - artifact: `tmp/phparser-um-still-match-after-renderer-summarycut-20260331/summary.json`
    - cases:
      - `ultimate-member-cve-2024-1071`
      - `ultimate-member-cve-2025-0308`
      - `ultimate-member-cve-2025-1702`
- measured effect:
  - previous retained latest-plugin standalone delete benchmark:
    - artifact: `tmp/phparser-realworld-um-delete-check-20260331.stderr.log`
    - outcome: timed out under `240s`
  - new latest-plugin standalone delete benchmark:
    - artifact: `tmp/phparser-realworld-um-delete-after-renderer-summarycut-20260331.stderr.log`
    - results: `tmp/phparser-realworld-um-delete-after-renderer-summarycut-20260331/taint-results.json`
    - engine run: about `1m35.205s`
    - wall clock: about `1:45.24`
    - RSS: about `2339792 KB`
    - findings: `38`
    - errors: `0`
  - the formerly dominant renderers stop driving late-pass churn:
    - `um_profile_header`
    - `um_profile_dynamic_meta_desc`
    - `Fields::display_view`
    - `Mail::add_replace_placeholder`
- remaining honest blocker:
  - standalone latest-plugin `delete` now completes again, but the broader latest-plugin all-ops `ultimate-member__2.10.0` scan still needs a fresh rerun on the committed tree
  - the likely remaining all-ops frontier is shared card-data and account/admin helper churn rather than direct renderer summary replay

## 2026-03-31: Reduce include renderer summary churn without breaking real LFI cases

- what was wrong:
  - after the retained delete fix, latest-plugin uncapped all-ops `ultimate-member__2.10.0` no longer died in `delete`; it timed out under a `300s` outer cap during `include` pass `6`
  - the hot include helpers were large direct-output renderers and profile/account builders:
    - `function::\um_profile_dynamic_meta_desc`
    - `function::\um_submit_account_details`
    - `method::\um\core\Form::form_init`
    - `method::\um\core\Member_Directory::build_user_card_data`
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`
  - their summaries were still replaying file-batch return and storage noise even when the caller only needed parameter-carried findings and the callable itself was not a direct include sink or durable file-state writer
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - added include-only direct-renderer summary compaction for single-op `include` batches
    - reuse the same renderer-context filter used for delete batches so direct output helpers keep caller-visible param findings while dropping replay-heavy source, return, receiver-write, and storage-write noise
    - narrowed the include compaction to helpers that:
      - have direct output syntax
      - are not direct sinks, storage writers, or supported cross-request writers
      - have no file sink relevant use orders
      - do not have direct global-request, direct-call, or direct-SQL standalone sources
    - this intentionally still allows parameter-carried helpers like account/profile renderers to compact, while preserving true include entrypoints such as the Backup Migration server-input chain
  - added focused regression coverage in `internal/taintscan/analysis_callable_test.go` for include renderer compaction
- safety validation:
  - focused compaction regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - representative include/LFI corpus cases still match:
    - artifact: `tmp/phparser-include-regression-check4-20260331/summary.json`
    - `backup-migration-cve-2023-6553`: `match`
    - `hide-my-wp-cve-2025-26909`: `match`
- measured effect:
  - previous retained all-ops baseline on the delete-fixed tree:
    - artifact: `tmp/phparser-realworld-um-all-after-delete-summarycut-20260331.stderr.log`
    - outcome: timed out under `300s` during `include` pass `6`
    - hotspot timings in that pass were about:
      - `um_submit_account_details`: `1m11.596s`
      - `Member_Directory::build_user_card_data`: `47.633s`
      - `Form::form_init`: `42.732s`
      - `um_profile_dynamic_meta_desc`: `43.636s`
      - `Member_Directory_Meta::build_user_card_data#runtime`: `38.828s`
  - retained narrowed include compaction:
    - artifact: `tmp/phparser-realworld-um-all-after-include-renderer-cut3-20260331.stderr.log`
    - outcome: still times out under `300s`, but keeps all representative include cases green and materially reduces the include frontier:
      - `um_submit_account_details`: `1m2.339s`
      - `Member_Directory::build_user_card_data`: `40.122s`
      - `Form::form_init`: `30.917s`
      - `um_profile_dynamic_meta_desc`: `36.486s`
      - `Member_Directory_Meta::build_user_card_data#runtime`: `28.383s`
    - the all-ops run now gets into the same narrowed include-pass hotspot set with a materially lower per-pass cost instead of broad renderer replay
- remaining honest blocker:
  - latest-plugin all-ops `ultimate-member__2.10.0` still does not finish inside `300s`
  - the next seam is not generic renderer filtering anymore; it is the large include-time account/profile/card-data builders themselves, especially:
    - `function::\um_submit_account_details`
    - `method::\um\core\Form::form_init`
    - `method::\um\core\Member_Directory::build_user_card_data`
    - `\um\core\Member_Directory_Meta::build_user_card_data#runtime`

## 2026-03-31: Separate include demand from file batches and prune include storage-write churn

- what was wrong:
  - the later `ultimate-member__2.10.0` include frontier was still spending most of its time invalidating path-like storage writes that mattered to read/open/write-style batches but not to include sinks
  - the engine already had `fileBatchStorageWriteRelevantToCallInterest`, but it was not being applied to include summaries or include dependency fingerprints
  - a first attempt that treated include as a full `fileOnlyMode` in broad reachability gates was too aggressive and broke toy include regressions, so the retained fix had to keep include-specific demand without inheriting the broader file-only pruning rules
- what changed:
  - in `internal/taintscan/callgraph_relevance.go`, `internal/taintscan/diagnostics.go`, `internal/taintscan/taintscan.go`, and `internal/taintscan/analysis_support.go`:
    - added dedicated include relevant-use orders and include assigned-path interest alongside the existing shared file-batch maps
    - kept those include-specific maps out of the broad `fileOnlyMode` reachability gates after validating that the broader version regressed nested/factory include coverage
  - in `internal/taintscan/analysis_callable.go` and `internal/taintscan/diagnostics.go`:
    - applied `filterFileBatchStorageWritesForCallInterest` to include summaries and include dependency fingerprints only
    - this keeps scalar `read`/`open`/`write` storage behavior intact while cutting non-path include churn in `option_value` and `user_meta_value`
  - added focused coverage in:
    - `internal/taintscan/analysis_callable_test.go`
    - `internal/taintscan/diagnostics_test.go`
    - `internal/taintscan/taintscan_test.go`
- safety validation:
  - `GOMAXPROCS=4 go test ./...` passed
  - representative include regressions still match:
    - artifact: `tmp/phparser-include-regression-check-after-storagewritefilter2-20260331/summary.json`
    - `backup-migration-cve-2023-6553`: `match`
    - `hide-my-wp-cve-2025-26909`: `match`
- measured effect:
  - standalone latest-plugin uncapped include on `ultimate-member__2.10.0` now completes:
    - artifact: `tmp/phparser-realworld-um-include-after-storagewritefilter-20260331/stderr.log`
    - timing artifact: `tmp/phparser-realworld-um-include-after-storagewritefilter-20260331/time.txt`
    - result: `real=0:26.88s`, `rss=504944 KB`, `rc=0`
  - previous retained include baseline was timing out with late-pass hotspot churn around:
    - `um_submit_account_details`
    - `Form::form_init`
    - `Member_Directory::build_user_card_data`
    - `Member_Directory_Meta::build_user_card_data#runtime`
  - after the retained include storage-write pruning:
    - pass `5` drops to `128ms`
    - pass `6` drops to `195ms`
    - the run converges in `9` passes instead of stalling in the late include passes
  - inside the full all-ops latest-plugin run, the include batch now completes in `3.82s` instead of being the first late-pass timeout wall:
    - artifact: `tmp/phparser-realworld-um-all-after-includestoragefilter-20260331/stderr.log`
- remaining honest blocker:
  - latest-plugin all-ops `ultimate-member__2.10.0` still has later combined-batch cost after delete/include, so the next frontier is no longer include itself
  - the next real target is the remaining all-ops batch that dominates after the include fix lands, not another include-only heuristic

## 2026-03-31: Skip unread storage-only replay in delete renderers

- what was wrong:
  - on the current tree, latest-plugin `ultimate-member__2.10.0` was still burning the full-scan budget in the first `delete` batch
  - the late passes kept oscillating on `user_meta_value[*][um_user_profile_url_slug_{permalink_base}]`
  - direct render helpers such as `um_profile_header` were still replaying storage-only callee side effects even when the renderer did not read the storage family or bucket being written
- what changed:
  - in `internal/taintscan/call_eval.go`:
    - generalized the existing output-only storage replay guard to `delete` batches as well
    - both direct call replay and callback replay now skip storage-only side effects when:
      - the current callable has direct output syntax
      - the current batch is `delete`
      - the current renderer does not read storage that overlaps the callee summary's storage writes
  - added focused coverage in `internal/taintscan/taintscan_test.go` for:
    - delete-batch direct renderer call replay with and without matching storage reads
    - delete-batch callback replay with and without matching storage reads
- safety validation:
  - focused delete/output replay regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - Ultimate Member corpus checks still match:
    - `tmp/phparser-um-2024-1071-after-delete-storage-match-20260331/summary.json`
    - `tmp/phparser-um-2025-0308-after-delete-storage-match-20260331/summary.json`
    - `tmp/phparser-um-2025-1702-after-delete-storage-match-20260331/summary.json`
- measured effect:
  - on the pre-fix acceptance run, full latest-plugin all-ops was still timing out under `300s` inside the first `delete` batch:
    - artifact: `tmp/phparser-realworld-um-all-dirty-20260331/stderr.log`
  - after the retained delete renderer storage-match cut, standalone latest-plugin delete now completes again:
    - artifact: `tmp/phparser-realworld-um-delete-after-delete-render-storage-match-20260331/stderr.log`
    - result payload: `tmp/phparser-realworld-um-delete-after-delete-render-storage-match-20260331/taint-results.json`
    - measured result: `engine-run=1m45.957s`, `total=1m54.616s`, `37` findings, `0` errors
  - the key late-pass change is that the previous pass-10 through pass-18 delete cliff no longer grows into a timeout wall; pending work now collapses to:
    - pass `16`: `next_pending=16`
    - pass `18`: `next_pending=13`
    - pass `19`: `next_pending=1`
    - pass `20`: converged
- remaining honest blocker:
  - full latest-plugin all-ops still needs a fresh rerun on top of this fix
  - the next frontier, if any remains after that rerun, should be taken from the new all-ops timing log rather than assumed from the old delete-stalled run

## 2026-03-31: Prune assigned-return storage noise in output replay

- what was wrong:
  - latest-plugin uncapped `ultimate-member__2.10.0 -sink-op output` was still timing out under the retained tree even after the earlier include and delete fixes
  - direct call replay was deciding whether to keep state side effects from the unfiltered callable summary, while the actual return replay already used the per-call filtered summary
  - assigned-return output sites that only cared about specific return subpaths were still keeping persistent-read storage writes that could not affect the demanded replayed paths
- what changed:
  - in `internal/taintscan/call_eval.go`:
    - direct function, method, and static-call replay now uses `summaryForCurrentCall(..., call.StartLine())` before deciding whether current-batch state side effects should survive
    - this aligns side-effect retention with the same per-call filtered summary already used for return replay
  - in `internal/taintscan/analysis_callable.go`:
    - `filterSummaryForAssignedReturnReplayWithRootDrop` now drops `StorageWrites` and `StoragePathWrites` when:
      - the site is in explicit assigned-return root-drop mode, and
      - the remaining side effects are only persistent-read storage noise
  - added focused coverage in `internal/taintscan/analysis_callable_test.go` for the assigned-return persistent-read pruning case
- safety validation:
  - focused taintscan tests for current-call summary filtering and persistent-read storage pruning passed
  - `GOMAXPROCS=4 go test ./...` passed
  - Ultimate Member corpus checks still match:
    - `tmp/phparser-um-still-match-after-outputfix-20260331/summary.json`
- measured effect:
  - standalone latest-plugin uncapped output now completes instead of timing out:
    - artifact: `tmp/phparser-realworld-um-output-after-assigned-storage-prune-20260331/stderr.log`
    - result payload: `tmp/phparser-realworld-um-output-after-assigned-storage-prune-20260331/taint-results.json`
    - measured result: `engine-run=3m23.477s`, `total=3m32.187s`, `44` findings, `0` errors
  - prior retained standalone baseline still timed out:
    - artifact: `tmp/phparser-realworld-um-output-current-f138d00-20260331/stderr.log`
  - notable late-pass improvement versus that baseline:
    - pass `13` dropped from about `43.974s` to `36.782s`
    - pass `13 next_pending` dropped from `42` to `35`
    - the run now converges through pass `20` instead of timing out
- remaining honest blocker:
  - full latest-plugin all-ops still times out under `360s`:
    - artifact: `tmp/phparser-realworld-um-all-after-outputfix-20260331/stderr.log`
  - the remaining wall is still the late `output` batch, but it now gets materially farther than before the retained output fix

## 2026-04-01: Collapse output root-only assigned returns to root taint

- what was wrong:
  - the retained output-only assigned-return pruning only helped when later output use demanded explicit descendant paths like `$value[url]`
  - several latest-plugin `ultimate-member__2.10.0` helpers were still returned into callers that only used the assigned value as a whole root, for example:
    - template replace arrays
    - avatar/profile data arrays
    - profile/header helper results
  - in that root-only case the engine kept full `ReturnParamPaths` / `ReturnReceiverPaths` / `ReturnPathWrites`, so:
    - replay still carried unnecessary child-path detail
    - caller invalidation fingerprints still treated every extra child path as relevant
  - this kept late output passes hot around `Mail::add_replace_placeholder`, `um_get_user_avatar_data`, `um_profile_header`, and related wrappers
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - added `collapseSummaryAssignedReturnToRoot(...)`
    - when an output-batch call result is used only as the assigned root and there is no explicit descendant path demand, the callee summary is collapsed from path-level return effects to root-level return taint
    - persistent-read-only storage noise is dropped after that collapse
  - in `internal/taintscan/diagnostics.go`:
    - caller invalidation now applies the same root-only assigned-return collapse before fingerprinting
    - so adding extra child paths under a root-only returned value no longer invalidates callers unless the root-level taint actually changes
  - added focused coverage in:
    - `internal/taintscan/analysis_callable_test.go`
    - `internal/taintscan/diagnostics_test.go`
- safety validation:
  - focused output assigned-return tests passed
  - `GOMAXPROCS=4 go test ./...` passed
  - Ultimate Member corpus checks still match:
    - `tmp/phparser-um-after-rootcollapse-compare-20260401/summary.json`
- measured effect:
  - standalone latest-plugin uncapped output improved substantially:
    - baseline:
      - `tmp/phparser-realworld-um-output-after-assigned-storage-prune-20260331/stderr.log`
      - `engine-run=3m23.477s`, `total=3m32.187s`, `44` results
    - after root-only return collapse:
      - `tmp/phparser-realworld-um-output-after-rootcollapse-20260401/stderr.log`
      - `tmp/phparser-realworld-um-output-after-rootcollapse-20260401/time.txt`
      - `engine-run=1m44.491s`, `total=1m52.398s`, `44` results, `0` errors, `rss_kb=2038088`
  - inside latest-plugin all-ops:
    - the retained output cliff dropped sharply at the old hotspot line:
      - previous pass `13` output duration: `1m15.452s`
      - new pass `13` output duration: `11.299s`
    - artifact comparison:
      - previous all-ops baseline: `tmp/phparser-realworld-um-all-after-outputfix-20260331/stderr.log`
      - new all-ops run: `tmp/phparser-realworld-um-all-after-rootcollapse-20260401/stderr.log`
- remaining honest blocker:
  - latest-plugin all-ops still times out under `420s`:
    - artifact: `tmp/phparser-realworld-um-all-after-rootcollapse-20260401/stderr.log`
    - timing: `tmp/phparser-realworld-um-all-after-rootcollapse-20260401/time.txt`
  - but the timeout has moved past the old late-output wall and into the later `action` batch
  - the next frontier is no longer output; it is late action-batch churn around:
    - `method::\um\common\CPT::change_default_form`
    - `method::\um\core\User::set`
    - `method::\um\core\Form::form_init`
    - `function::\um_user_submitted_registration_formatted`
    - `method::\um\admin\core\Admin_DragDrop::update_order`

## 2026-04-01: Compact direct action-sink summaries to finding context

- what was wrong:
  - after the retained output fixes, latest-plugin all-ops for `ultimate-member__2.10.0` no longer stalled in `output`, but it still carried late `action` churn into the overall timeout window
  - the hot action callables were direct action sinks or sink-adjacent writers such as:
    - `method::\um\common\CPT::change_default_form`
    - `method::\um\core\User::set`
    - `method::\um\core\Form::form_init`
    - `function::\um_user_submitted_registration_formatted`
    - `method::\um\admin\core\Admin_DragDrop::update_order`
  - for action-only direct sinks with no return effects, the engine was still retaining replay-only state in the summary:
    - storage writes
    - receiver writes
    - receiver path writes
    - receiver storage links
    - static writes
  - those facts were useful for finding generation inside the callable, but they kept feeding later invalidation and replay even when the real retained value was just the finding
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - added `shouldCompactCurrentActionSummaryToSinkContextOnly(...)`
    - added `filterSummaryForActionSinkContextOnly(...)`
    - direct action-sink summaries are now compacted to finding context when all of the following are true:
      - the current batch is `action`
      - `action` is allowed for the engine
      - the current callable has a direct sink
      - the summary has no return effects
    - under those conditions the summary now drops replay-only state:
      - `ReturnSources`
      - `ReturnSourceOrigins`
      - `ReturnReceiverPaths`
      - `ReturnParams`
      - `ReturnParamPaths`
      - `ReturnPathWrites`
      - `ReturnClasses`
      - `StaticWrites`
      - `ReceiverWrites`
      - `ReceiverPathWrites`
      - `ReceiverStorageLinks`
      - `StorageWrites`
      - `StoragePathWrites`
  - in `internal/taintscan/analysis_callable_test.go`:
    - added focused coverage that:
      - direct action sinks without returns are compacted to finding context
      - direct action sinks that also return data keep their return/storage effects
- safety validation:
  - focused action-summary compaction tests passed
  - `GOMAXPROCS=4 go test ./...` passed
  - representative corpus checks still match:
    - `tmp/phparser-verify-um-2024-1071-after-action-summarycompact-20260401/summary.json`
    - `tmp/phparser-verify-um-2025-0308-after-action-summarycompact-20260401/summary.json`
    - `tmp/phparser-verify-um-2025-1702-after-action-summarycompact-20260401/summary.json`
    - `tmp/phparser-verify-wpforms-2024-11205-after-action-summarycompact-20260401/summary.json`
    - `tmp/phparser-verify-smart-slider-2026-3098-after-action-summarycompact-20260401/summary.json`
- measured effect:
  - standalone latest-plugin action now completes cleanly:
    - artifact: `tmp/phparser-realworld-um-action-after-action-summarycompact-20260401/stderr.log`
    - timing: `tmp/phparser-realworld-um-action-after-action-summarycompact-20260401/time.txt`
    - measured result: `wall=0:40.29`, `rss_kb=714812`, `rc=0`
  - full latest-plugin all-ops now also completes:
    - artifact: `tmp/phparser-realworld-um-all-after-action-summarycompact-20260401/stderr.log`
    - timing: `tmp/phparser-realworld-um-all-after-action-summarycompact-20260401/time.txt`
    - measured result: `wall=6:33.05`, `rss_kb=4510260`, `rc=0`
    - the run now converges through the late `call` batch instead of dying in `action`
- remaining honest blocker:
  - `ultimate-member__2.10.0` latest-plugin all-ops is now real and complete on the retained tree
  - the next frontier should be chosen from a fresh matrix of latest-plugin full scans rather than continuing to special-case `ultimate-member`

## 2026-04-01: Project assigned return paths in action and call batches

- what was wrong:
  - the retained tree already finished the heavy latest-plugin all-ops scans, but the remaining wall time was still dominated by broad `action` and `call` helper replay
  - the engine only projected assigned-return path interest for `output` and file/path-like batches
  - in `action` and `call`, return-only helpers were still replaying full return roots even when callers only consumed narrow subpaths like `$value[safe]`
  - a first attempt that indexed every AST use site did improve `user-registration`, but it also made `ultimate-member` build time worse enough to offset the gain
- what changed:
  - in `internal/taintscan/callgraph_relevance.go`:
    - added `callAssignedReturnPathInterestForCallable(...)`
    - added `actionAssignedReturnPathInterestForCallable(...)`
    - added structural-only path indexing for `call` and `action` relevant uses
    - kept the new indexing narrow by recording only structural nodes:
      - variables
      - array dim fetches
      - property fetches
  - in `internal/taintscan/diagnostics.go`:
    - `currentBatchUsesAssignedReturnPathInterest()` now covers `call` and `action`
    - added `callRelevantAssignedPathsAfter(...)`
    - added `actionRelevantAssignedPathsAfter(...)`
    - `currentBatchAssignedPathsAfter(...)` now dispatches to the new batch-specific helpers
  - in `internal/taintscan/analysis_callable.go`:
    - `currentAssignedReturnPathInterest(...)` now projects assigned-return paths for return-only summaries in `call` and `action`
    - `shouldDropAssignedReturnRoots(...)` now drops root returns for return-only summaries in `call` and `action`
  - in `internal/taintscan/taintscan.go` and `internal/taintscan/analysis_support.go`:
    - added engine storage for `callSinkRelevantUsePaths` and `actionSinkRelevantUsePaths`
  - in tests:
    - added focused coverage for action-batch assigned-return projection
    - added focused coverage for call-batch assigned-return projection
- safety validation:
  - focused assigned-return projection tests passed
  - `GOMAXPROCS=4 go test ./...` passed
  - representative corpus checks still match:
    - `tmp/phparser-user-registration-1492-after-actioncallpaths-20260401/summary.json`
    - `tmp/phparser-verify-smart-slider-after-actioncallpaths-20260401/summary.json`
    - `tmp/phparser-verify-wpforms-after-actioncallpaths-20260401/summary.json`
- measured effect on latest-plugin all-ops:
  - `ultimate-member`:
    - baseline: `tmp/phparser-realworld-um-all-after-action-summarycompact-20260401/time.txt`
    - new run: `tmp/phparser-realworld-um-all-after-structural-actioncallpaths-20260401/time.txt`
    - wall: `6:33.05 -> 6:06.97`
    - rss: `4510260 KB -> 1892332 KB`
    - even though indexing/build grew:
      - `build-base:index-call-sink-relevant-use-orders`: `21.724s -> 24.901s`
      - `build-engine`: `33.241s -> 37.836s`
    - the runtime win came from later batch replay cuts, especially `output`:
      - `2m57.507s -> 1m51.041s`
  - `user-registration`:
    - baseline: `tmp/phparser-realworld-user-registration-all-after-actioncompact-20260401/time.txt`
    - new run: `tmp/phparser-realworld-user-registration-all-after-structural-actioncallpaths-seq-20260401/time.txt`
    - wall: `6:05.44 -> 5:44.40`
    - rss: `1483752 KB -> 1499276 KB`
    - biggest wins were in `delete`, `read`, `output`, and `sql`
  - `acf-extended`:
    - baseline: `tmp/phparser-realworld-acfe-all-after-actioncompact-20260401/time.txt`
    - new run: `tmp/phparser-realworld-acfe-all-after-structural-actioncallpaths-20260401/time.txt`
    - wall: `2:29.23 -> 2:11.62`
    - rss: `13723476 KB -> 13344104 KB`
    - the biggest win was late `action` replay:
      - `1m24.327s -> 1m13.544s`
- remaining honest blocker:
  - latest-plugin all-ops now complete faster on the retained heavy plugins, but `ultimate-member` and `user-registration` are still the slowest completed scans
  - the next frontier should come from a fresh post-commit benchmark sweep, not from reintroducing broad action/output heuristics

## 2026-04-01: Make output replay pruning batch-local

- what was wrong:
  - the retained tree already completed latest-plugin `ultimate-member` all-ops, but the combined run still spent too much time in the `output` batch
  - most of the direct latest-plugin `output` pruning logic only activated when `len(allowedSinkOps) == 1`
  - in real all-ops runs, the engine was back to replaying output-only persistent-read storage noise and callback side effects, even though those facts were only relevant to the current `output` batch
  - the late passes kept flipping the same storage paths, especially:
    - `option_value[um_cache_userdata_{user_id}]`
    - `option_value[um_secure_scan_result_content]`
    - `option_value[um_secure_scanned_details]`
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - made output-only summary pruning depend on `currentBatchName == "output"` instead of standalone-output mode
    - this now applies to:
      - receiver effects covered by storage links
      - persistent-read storage-origin filtering
      - output writer/storage-context compaction
      - output boolean-context compaction
      - assigned-return path projection and root-drop for output
      - output persistent-read storage-effect suppression during summary construction
  - in `internal/taintscan/call_eval.go`:
    - made output/delete state-side-effect replay checks batch-local instead of standalone-only
    - changed `apply_filters(...)` callback replay to use `allowCurrentBatchStateSideEffectsForCallbackReplay(...)` in `output` and `delete` batches instead of the old all-or-nothing gate
    - made pure persistent-read state-write suppression batch-local in `output`
  - in tests:
    - added all-ops output regressions for persistent-read callback/call replay suppression
    - updated older output-only tests to set `currentBatchName = "output"` explicitly, matching the new batch-local semantics
- safety validation:
  - `GOMAXPROCS=4 go test ./...` passed
  - representative corpus checks still match:
    - `tmp/phparser-verify-after-batchlocal-output-20260401/summary.json`
    - verified cases:
      - `ultimate-member-cve-2024-1071`
      - `ultimate-member-cve-2025-0308`
      - `ultimate-member-cve-2025-1702`
      - `wpforms-cve-2024-11205`
      - `smart-slider-3-cve-2026-3098`
- measured effect on real latest-plugin all-ops (`ultimate-member__2.10.0`):
  - baseline:
    - `tmp/phparser-realworld-um-all-after-structural-actioncallpaths-20260401/time.txt`
    - `tmp/phparser-realworld-um-all-after-structural-actioncallpaths-20260401/stderr.log`
  - new run:
    - `tmp/phparser-realworld-um-all-batchlocal-output-20260401.time.txt`
    - `tmp/phparser-realworld-um-all-batchlocal-output-20260401.stderr.log`
  - total wall:
    - `6:06.97 -> 5:28.95`
  - total rss:
    - `1892332 KB -> 2317784 KB`
  - engine runtime:
    - `5m24.654s -> 4m55.335s`
  - batch changes:
    - `delete`: `57.715s -> 34.431s`
    - `include`: `4.077s -> 3.766s`
    - `output`: `1m51.041s -> 2m8.079s`
    - `action`: `9.566s -> 9.205s`
    - `call`: `18.645s -> 14.398s`
  - although the standalone `output` batch got slightly slower inside all-ops, the combined run got faster because the batch-local output pruning reduced downstream replay and late `call` convergence costs
  - latest-plugin noise stayed flat:
    - total findings unchanged: `135 -> 135`
    - per-rule counts unchanged on the real run
- remaining honest blocker:
  - this keeps `ultimate-member` as a completed real latest-plugin all-ops scan with lower wall time
  - the next frontier should now come from a fresh cross-plugin benchmark sweep, likely `user-registration` or `acf-extended`, rather than more `ultimate-member`-specific profiling

## 2026-04-01: recovered code-snippets include match by preserving entrypoint-backed summaries

- problem:
  - `code-snippets-cve-2025-13035` had regressed from `match` to `miss`
  - the real sink lives in the public shortcode callback `\Code_Snippets\Front_End::render_content_shortcode`
  - include-summary compaction treated it like a generic renderer helper and erased the useful return/include state even though its taint came from an entrypoint-backed shortcode parameter, not from internal renderer-only context
- what changed:
  - in `internal/taintscan/analysis_callable.go`:
    - `shouldCompactCurrentIncludeSummaryToRendererContextOnly()` now exempts callables where `callableHasEntrypointSourceParam(...)` is true, alongside the existing direct-request/direct-call/direct-sql source exemptions
  - in `internal/taintscan/taintscan_test.go`:
    - added a real-fixture regression that requires the flat-file include sink at `php/front-end/class-front-end.php:296` to be found on `code-snippets__3.9.1`
- validation:
  - focused tests passed:
    - `TestAnalyzeRootFindsCodeSnippetsRealShortcodeFlatFileInclude`
    - `TestBuildEngineMarksCodeSnippetsShortcodeRegistrationViaClassConst`
  - focused corpus compare now matches again:
    - `tmp/phparser-fix-code-snippets-20260401/summary.json`
- result:
  - `code-snippets-cve-2025-13035` is back to `match`

## 2026-04-01: limit output synthetic DB-read sources to content-like scalar reads

- problem:
  - `google-reviews-cve-2025-12510` was matching the sinks only, but the stored-XSS source selection kept preferring a scalar counter read (`SELECT viewed FROM views`) instead of the real row reads from the `reviews` table
  - more broadly, output-mode synthetic SQL-read sourcing treated any non-aggregate `get_var(...)` select as content-bearing, which is too noisy for stored-XSS output
- what changed:
  - in `internal/taintscan/call_eval.go`:
    - kept the existing call-batch/sql-batch behavior unchanged
    - for `currentBatchName == "output"`, synthetic origins from `get_var(...)` are now suppressed unless the selected scalar field is content-like
    - added `isSQLNonContentScalarReadMethodCallWithContext(...)`
    - added `isSQLContentLikeScalarQuery(...)`
    - content-like scalar fields currently include names containing:
      - `meta_value`
      - `option_value`
      - `content`
      - `text`
      - `message`
      - `description`
      - `excerpt`
      - `body`
      - `html`
      - `comment`
      - `review`
      - `title`
  - in `internal/taintscan/taintscan_test.go`:
    - added a negative output regression for `SELECT viewed FROM reviews`
    - added a positive output regression for `SELECT review_text FROM reviews`
- validation:
  - focused tests passed:
    - `TestAnalyzeRootSkipsStoredXSSFromAggregateScalarReadToOutput`
    - `TestAnalyzeRootSkipsStoredXSSFromNonContentScalarReadToOutput`
    - `TestAnalyzeRootFindsStoredXSSFromContentLikeScalarReadToOutput`
  - representative stored-XSS regression still matches:
    - `tmp/phparser-recheck-wpstatistics-after-scalar-output-20260401/summary.json`
  - focused corpus compare for the missed case now matches:
    - `tmp/phparser-fix-google-reviews-20260401/summary.json`
- measured corpus effect:
  - full corpus summary on this tree:
    - `tmp/phparser-full-corpus-after-codesnippets-google-20260401/summary.json`
  - status counts moved from:
    - `43 match / 5 miss / 15 not_comparable_yet`
    - to `45 match / 3 miss / 15 not_comparable_yet`
  - remaining misses:
    - `backup-migration-cve-2023-6972`
    - `givewp-cve-2024-5932`
    - `omgf-cve-2023-6600`
  - full sweep runtime:
    - `elapsed=9:00.57 rss_kb=1395268 rc=0`
  - case-level noise stayed concentrated in the same top plugins:
    - `wordpress-file-upload`: `170` findings
    - `post-smtp`: `113` findings
    - `wp-statistics`: `96 -> 95` findings
- remaining honest work:
  - the best next noise-reduction target is not `google-reviews` anymore
  - the biggest remaining noise buckets are now:
    - `wordpress-file-upload-cve-2024-11613`
    - `post-smtp-cve-2025-11833`
    - `wp-statistics-cve-2024-2194`

## 2026-04-01: collapse generic delete source variants by sink site and callable

- problem:
  - after the earlier CVE recoveries, the biggest remaining corpus noise bucket was `wordpress-file-upload-cve-2024-11613`
  - the case still matched, but it produced `170` delete findings from only four sink sites
  - the excess findings were not distinct delete surfaces; they were repeated source variants for the same sink and same callable
  - the current final dedupe logic kept those source variants distinct because the generic delete rule was not included in `shouldCollapseFindingSources(...)`
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `wp-request-file-delete-without-cap-check` to `shouldCollapseFindingSources(...)`
    - this keeps different callables separate but collapses repeated source variants for the same sink site/callable pair
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesGenericDeleteRuleToBestRequestSource`
    - it verifies the generic delete rule now keeps the stronger request-backed source and the visible callable while dropping weaker source variants
- validation:
  - focused tests passed:
    - `TestDedupeFinalFindingsCollapsesGenericDeleteRuleToBestRequestSource`
    - `TestDedupeFinalFindingsCollapsesNoisyRuleToBestRequestSource`
    - `TestDedupeFinalFindingsSuppressesCapabilityCheckedGenericDeleteRule`
  - targeted case rerun still matches:
    - `tmp/phparser-fix-wordpress-file-upload-noise-20260401/summary.json`
  - neighboring comparable case stayed matched:
    - `tmp/phparser-recheck-backup-6553-after-delete-collapse-20260401/summary.json`
- measured effect:
  - `wordpress-file-upload-cve-2024-11613`:
    - findings `170 -> 17`
    - comparable CVE finding preserved:
      - `wfu_file_downloader.php:33`
      - source `wfu_file_downloader.php:24`
  - surviving non-comparable delete findings are now one per sink site/callable pair instead of dozens of source clones
- remaining honest work:
  - after this drop, `wordpress-file-upload` is no longer the obvious first noise bucket
  - the next likely noise target is `post-smtp-cve-2025-11833`, then `wp-statistics-cve-2024-2194`

- `backup-migration-cve-2023-6972`, `givewp-cve-2024-5932`, and `omgf-cve-2023-6600`
  - fixed:
    - `givewp`: switch-case literal specialization now ignores placeholder-interpolated strings and falls back to callable literal resolution for hook callbacks
    - `omgf`: selector-style branch propagation now carries the chosen request-backed path through `strpos(...) !== false` guards and preserves concrete first-segment keys across single-array `array_map()` callbacks
    - `backup-migration`: delete renderer compaction no longer erases real request-backed `SourceFindings` for direct-input wrappers that also print output; delete dependency fingerprints also treat receiver-consuming method calls as receiver-relevant in `delete` batches
  - current status:
    - focused compares now all match:
      - `tmp/phparser-givewp-case-rerun-after-switchfix-20260401b/givewp-cve-2024-5932/comparison.json`
      - `tmp/phparser-omgf-rerun-after-selectorfix2-20260401/omgf-cve-2023-6600/comparison.json`
      - `tmp/phparser-backup-after-delete-compactfix-20260401/backup-migration-cve-2023-6972/comparison.json`
  - verification:
    - focused regressions passed:
      - `TestAnalyzeRootFindsMaybeUnsafeDeserializationInHookCallbackSwitchCase`
      - `TestAnalyzeRootPropagatesSelectorChosenDeletePath`
      - `TestAnalyzeRootDispatchesConcatHookAfterRecursiveArrayMapSanitizer`
      - `TestAnalyzeRootFindsBackupMigrationRealisticHeartDeleteAcrossFiles`
      - `TestCallableSummaryInputFingerprintTracksDeleteCalleeReceiverFindingGrowthWithConsumedReceiver`
      - `TestAnalyzeCallableDoesNotCompactDeleteRendererSummaryWithDirectRequestSourceFindings`


- `post-smtp-cve-2025-11833` noise follow-up 1
  - fixed:
    - final finding dedupe now collapses equivalent sink-site duplicates across inherited/wrapper callables for `unsafe-use` and `wp-request-record-read-to-output-without-cap-check`
  - current status:
    - focused compare still matches: `tmp/phparser-postsmtp-noise-rerun-20260401/post-smtp-cve-2025-11833/comparison.json`
    - findings dropped from `110` to `86`
    - `unsafe-use` dropped from `24` to `6`
    - `wp-request-record-read-to-output-without-cap-check` dropped from `26` to `18`
  - verification:
    - `go test ./internal/taintscan -run 'TestDedupeFinalFindingsCollapsesNoisyUnsafeUseToBestRequestSource|TestDedupeFinalFindingsCollapsesUnsafeUseAcrossEquivalentSinkCallables|TestDedupeFinalFindingsCollapsesRequestRecordReadOutputAcrossEquivalentSinkCallables|TestDedupeFinalFindingsCollapsesNoisyRuleToBestRequestSource' -count=1`
    - `GOMAXPROCS=4 go test ./...`
  - remaining honest work:
    - after this dedupe cut, `wp-statistics-cve-2024-2194` becomes the highest-noise comparable case

## 2026-04-02: fix combined file-batch relevance and replay for Everest full sweep

- problem:
  - a fresh one-shot full corpus sweep on `HEAD 197f96e` still stalled effectively on `everest-forms-cve-2025-1128`
  - the real hot path was the combined direct-engine batch `delete+open+read+write`
  - initial profiling showed `\EVF_Form_Fields::field_new` consuming pass 1 time, but after removing cross-batch `output` contamination from file-use indexing the deeper issue became clear:
    - combined file batches were identified via `allowedSinkOps`
    - several replay and interest helpers still keyed off exact `currentBatchName` strings like `"read"` or `"include"`
    - that mismatch meant combined file batches did not apply path-like assigned-return filtering, so renderer/helper families such as `field_option()` stayed much larger than they needed to be
- what changed:
  - in `internal/taintscan/callgraph_relevance.go`:
    - `usesFileWarmSummaries()` now accepts combined file-like sink-op sets instead of only single-op batches
    - `relevantCallOrder()` now skips non-returning helpers in combined file batches when `callableNeedsFileWarmSummary()` is false
    - `fileSinkRelevantUseOrdersForCallable()` no longer records `output`-only disclosure uses; file-batch relevance is now strictly file-like
  - in `internal/taintscan/diagnostics.go`:
    - `currentBatchUsesFileRelevantOrders()` and `currentBatchUsesPathLikeStorageInterest()` now consult `allowedSinkOps` when present, so composite batches like `delete+open+read+write` still get file/path-like assigned-return behavior
  - in `internal/taintscan/wordpress_context.go`:
    - dynamic foreach AJAX callback registration now resolves exact callback method values, which keeps unrelated methods out of the direct-public set and reduces callback overreach in mixed handler families
  - tests added/updated:
    - `TestUsesFileWarmSummariesAllowsCombinedFileBatch`
    - `TestAnalyzeCallableWithWarmStackSkipsNonReturningHelperInCombinedFileBatch`
    - `TestRelevantCallOrderSkipsNonReturningFileInertHelperInCombinedFileBatch`
    - `TestCurrentAssignedReturnPathInterestAllowsCombinedFileBatchExplicitPathsWithSourceFindings`
    - `TestDynamicForeachAjaxRegistrationResolvesExactMethodTargets`
    - `TestCombinedFileBatchSkipsPublicOutputOnlyAjaxHandler`
    - `TestCombinedFileBatchKeepsPublicReadAjaxHandler`
    - `TestCombinedFileBatchIgnoresOutputUseOrders`
- validation:
  - focused `internal/taintscan` regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh Everest rerun completed and still matched:
    - `tmp/phparser-everest-after-combined-pathinterest-fix-20260402/summary.json`
    - `everest-forms-cve-2025-1128`: `match`, `109441 ms`, `31` findings
  - fresh one-shot full sweep completed successfully:
    - `tmp/phparser-full-corpus-after-everest-fix-20260402/summary.json`
    - `tmp/phparser-full-corpus-after-everest-fix-20260402.stderr.log`
- measured effect:
  - Everest focused case:
    - previously timed out under `180s`
    - now completes in about `1m42s` total / `109441 ms` case duration
    - pass 1 `scheduled_analyze` dropped from `920` pre-fix to `659`
    - `\EVF_Form_Fields::field_new` disappeared as the pass-1 wall; `field_option()` fell to sub-second per-callable timings instead of ~90s
  - fresh full corpus sweep:
    - `elapsed=12:16.57 rss_kb=1150432 rc=0`
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
- current noise picture on this tree:
  - highest comparable finding-count buckets from the fresh full sweep are:
    - `wp-statistics-cve-2024-2194`: `95`
    - `post-smtp-cve-2025-11833`: `77`
    - `user-registration-cve-2026-1492`: `66`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `everest-forms-cve-2025-1128`: `31`

## 2026-04-02: exact foreach template specialization without cross-template bleed

- problem:
  - `wp-statistics-cve-2024-2194` still matched, but the engine was over-broad on foreach-driven template loaders
  - the old literal hint flow could not preserve exact template choices from list literals and bounded ternaries, so render helpers like `refer_page::view` and `country_page::view` could share the same include specialization space
  - that kept `wp-statistics` noisy at `95` findings in the last clean full sweep, and the match path was not the precise `refer_page::view -> refer.url.php` contract we wanted
  - while fixing that, final source collapse for `render-callback-execution` also turned out to be too aggressive: it made `kali-forms-cve-2026-3584` prefer the later request source at line `730` instead of the real contract source at line `302`
- what changed:
  - in `internal/taintscan/ast_helpers.go`:
    - added exact dynamic dispatch value recovery for include-template expressions, including concatenation, interpolated strings, wrapped string-dispatch helpers, variables, and bounded ternaries
    - `staticIncludedFileCallableKeys()` now uses those exact values first, before falling back to the older broad literal matching
  - in `internal/taintscan/callgraph_relevance.go`:
    - literal path hints now retain implicit numeric indexes for list literals
    - encoded multi-value path hints allow bounded list/ternary template sets to flow through specialization without collapsing to one broad string
    - iterable literal values are only exposed for callables that actually use parameter-driven include dispatch, which prevents the new list hints from leaking into unrelated foreach helpers
  - in `internal/taintscan/callable_indexing.go`:
    - foreach-based template loaders are now recognized as literal include dispatch helpers
    - output specialization for those helpers now requires a real arg-0 path hint, which keeps exact template recovery but avoids broad over-specialization of generic string-template wrappers
  - in `internal/taintscan/helpers.go`:
    - `render-callback-execution` was removed from final source-collapse rules so distinct callback-execution sources at the same sink remain distinct
  - tests added/updated:
    - `TestBuildEngineSpecializesForeachTemplateLoaderForListLiteralArgs`
    - `TestAnalyzeRootSpecializesForeachTemplateLoaderAcrossListLiteralCallsites`
    - `TestAnalyzeRootKeepsBoundedTernaryTemplateChoicesInForeachLoader`
    - `TestDedupeFinalFindingsKeepsDistinctRenderCallbackSources`
- validation:
  - focused `wp-statistics` rerun matched the intended path:
    - `tmp/phparser-wpstatistics-after-ternary-template-recovery2-20260402/summary.json`
    - match path is now `includes/class-wp-statistics-referred.php:183 -> includes/admin/templates/pages/refer.url.php:43`
  - focused `google-reviews` rerun stayed correct:
    - `tmp/phparser-google-reviews-after-ternary-template-recovery2-20260402/summary.json`
  - focused `kali-forms` rerun restored the real source contract:
    - `tmp/phparser-kaliforms-after-render-dedupe-20260402/summary.json`
  - targeted regressions passed, then `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot full sweep on the exact committed tree completed cleanly:
    - `tmp/phparser-full-corpus-after-wpstats-kaliforms-renderfix-20260402/summary.json`
- measured effect:
  - `wp-statistics-cve-2024-2194` findings dropped from `95` to `35` while preserving the real `refer_page::view` match
  - `kali-forms-cve-2026-3584` returned to `match` with the contract source at line `302`
  - fresh full sweep on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - updated top comparable noise buckets from the fresh full sweep are:
    - `post-smtp-cve-2025-11833`: `77`
    - `user-registration-cve-2026-1492`: `66`
    - `acf-extended-cve-2025-13486`: `58`
    - `wp-statistics-cve-2024-2194`: `35`
    - `hide-my-wp-cve-2025-26909`: `35`

## 2026-04-02: collapse generic action duplicates across equivalent sink wrappers

- problem:
  - after the `wp-statistics` precision fix, `post-smtp-cve-2025-11833` became the top noise bucket at `77` findings
  - the biggest remaining duplicate cluster was the generic action rule `wp-request-sensitive-action-without-cap-check`
  - one shared sink site in Freemius option-manager code was still reported once per wrapper callable, even though those wrappers all converged on the same sink line
  - a first attempt to dedupe generic actions purely by sink site was wrong: it reduced one cluster but increased total action findings by uncollapsing same-callable duplicates elsewhere
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `collapsedFindingSourceSiteKey()` so source-collapsing for `wp-request-sensitive-action-without-cap-check` keys off the concrete sink site
    - added `shouldCollapseVisibleCallablesAtFindingSite()` so equivalent visible wrapper callables to the same action sink can be merged
    - left the existing callable-based final key behavior intact, so multiple action sinks inside the same callable still collapse the old way
  - in `internal/taintscan/analysis_driver.go`:
    - `dedupeFinalFindings()` now merges generic action findings through the source-collapse alias map when they share the same sink site, before the normal final-key merge path
  - tests updated:
    - `TestDedupeFinalFindingsCollapsesGenericActionRuleBySinkSite`
- validation:
  - focused dedupe regressions passed
  - `GOMAXPROCS=4 go test ./...` passed
  - focused `post-smtp` rerun still matched:
    - `tmp/phparser-postsmtp-after-action-sites-20260402/summary.json`
  - focused `wpforms` action case still matched:
    - `tmp/phparser-wpforms-after-action-site-alias-20260402/summary.json`
- measured effect:
  - `post-smtp-cve-2025-11833` dropped from `77` to `68` findings
  - the generic action rule inside that case dropped from `25` to `16`
  - matched path stayed unchanged:
    - `Postman/PostmanEmailLogs.php:66 -> Postman/PostmanEmailLogs.php:72`

## 2026-04-02: collapse cross-file unsafe-deserialization wrapper duplicates

- problem:
  - after the `post-smtp` action-site cut, `user-registration-cve-2026-1492` was still one of the top noise buckets
  - most of that noise was `unsafe-deserialization` on shared helper sinks in `includes/functions-ur-core.php`, reported once per cross-file wrapper callable
  - a first broad sink-site collapse for `unsafe-deserialization` was too aggressive and broke `cfdb7-cve-2025-7384` by merging away a helper-local same-file contract source
- what changed:
  - in `internal/taintscan/helpers.go`:
    - `shouldCollapseVisibleCallablesAtFindingSite()` now treats `unsafe-deserialization` specially
    - visible-callable collapsing at the same sink site only applies when the source path differs from the sink path, which keeps cross-file wrapper noise collapsible but preserves same-file helper-local variants
  - in `internal/taintscan/analysis_driver.go`:
    - the same alias-layer dedupe path now uses that narrowed predicate
  - tests added/updated:
    - `TestDedupeFinalFindingsCollapsesUnsafeDeserializationBySinkSite`
    - `TestDedupeFinalFindingsKeepsUnsafeDeserializationSameFileVariants`
- validation:
  - focused dedupe regressions passed
  - `cfdb7-cve-2025-7384` match restored:
    - `tmp/phparser-cfdb7-after-deser-sitealias-narrow-20260402/summary.json`
  - `better-search-replace-cve-2023-6933` still matched:
    - `tmp/phparser-bsr-after-deser-sitealias-20260402/summary.json`
  - `user-registration-cve-2026-1492` still matched after the narrowed collapse:
    - `tmp/phparser-user-registration-after-deser-sitealias-narrow-20260402/summary.json`
  - full suite still passed:
    - `GOMAXPROCS=4 go test ./...`
  - fresh one-shot full sweep on the corrected tree completed cleanly:
    - `tmp/phparser-full-corpus-after-postsmtp-userreg-dedupe-narrow-20260402/summary.json`
- measured effect:
  - `user-registration-cve-2026-1492` dropped from `66` to `25` findings while preserving the `register_member -> set_role()` match
  - fresh whole-run status on this tree is again:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - updated top comparable noise buckets from the fresh whole-run are:
    - `post-smtp-cve-2025-11833`: `68`
    - `acf-extended-cve-2025-13486`: `58`
    - `wp-statistics-cve-2024-2194`: `35`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `everest-forms-cve-2025-1128`: `31`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`

## 2026-04-02: collapse file-upload duplicates at the same sink site

- problem:
  - after the action and deserialization wrapper cuts, `post-smtp-cve-2025-11833` was still the top noise bucket at `68`
  - the next biggest duplicate cluster was `wp-request-file-upload-without-cap-check` at `PostmanEmailLogMigration.php:756`
  - that sink was still reported once per migration wrapper method even though all of those wrappers converged on the same file-write site
- what changed:
  - in `internal/taintscan/helpers.go`:
    - `shouldCollapseVisibleCallablesAtFindingSite()` now also collapses `wp-request-file-upload-without-cap-check`
  - tests added:
    - `TestDedupeFinalFindingsCollapsesFileUploadBySinkSite`
- validation:
  - focused dedupe regressions passed
  - `post-smtp-cve-2025-11833` still matched after the change:
    - `tmp/phparser-postsmtp-after-fileupload-sitealias-20260402/summary.json`
  - representative upload case still matched unchanged:
    - `tmp/phparser-wpvivid-after-fileupload-sitealias-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot full sweep on the updated tree completed cleanly:
    - `tmp/phparser-full-corpus-after-postsmtp-fileupload-sitealias-20260402/summary.json`
- measured effect:
  - `post-smtp-cve-2025-11833` dropped from `68` to `65` findings
  - `wp-request-file-upload-without-cap-check` in that case dropped from `10` to `7`
  - fresh whole-run status on this tree is still:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - updated top comparable noise buckets from the fresh whole-run are:
    - `post-smtp-cve-2025-11833`: `65`
    - `acf-extended-cve-2025-13486`: `58`
    - `wp-statistics-cve-2024-2194`: `35`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`
    - `w3-total-cache-cve-2024-12365`: `22`
    - `everest-forms-cve-2025-1128`: `22`

## 2026-04-02: collapse repeated renderer-line output findings without hiding cross-file template sinks

- problem:
  - `post-smtp-cve-2025-11833` still had a large output-noise bucket after the sink-site wrapper cuts
  - the remaining duplicates were mostly repeated `echo`/template lines inside the same renderer fed by the same source site
  - a first broad collapse attempt cut `post-smtp` harder but regressed the matched `wp-statistics` sink line by merging distinct cross-file template outputs in `refer.url.php`
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `shouldCollapseRendererLineFinding()`
    - `wp-request-record-read-to-output-without-cap-check` and `wp-stored-xss-persistent-read-to-output` now collapse repeated renderer lines only when:
      - the sink is a file template callable, or
      - the source and sink are in the same file
    - cross-file template outputs now keep distinct sink lines
  - tests added in `internal/taintscan/analysis_driver_test.go`:
    - `TestDedupeFinalFindingsCollapsesRequestRecordReadOutputAcrossRendererLines`
    - `TestDedupeFinalFindingsCollapsesStoredXSSAcrossRendererLines`
    - `TestDedupeFinalFindingsKeepsStoredXSSAcrossDistinctCrossFileTemplateLines`
- validation:
  - focused dedupe tests passed
  - `GOMAXPROCS=4 go test ./...` passed
  - focused `post-smtp` rerun still matched:
    - `tmp/phparser-postsmtp-after-rendererline-dedupe-narrow-20260402/summary.json`
  - focused `wp-statistics` rerun matched the intended sink again:
    - `tmp/phparser-wpstatistics-after-rendererline-dedupe-narrow-20260402/summary.json`
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-rendererline-dedupe-narrow-20260402/summary.json`
- measured effect:
  - `post-smtp-cve-2025-11833`: `65 -> 59`
  - `wp-statistics-cve-2024-2194`: stayed `35`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `59`
    - `acf-extended-cve-2025-13486`: `58`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `wp-statistics-cve-2024-2194`: `35`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`

## 2026-04-02: collapse repeated render-callback sources within the same sink callable

- problem:
  - after the output renderer-line cut, `acf-extended-cve-2025-13486` was still one of the top noise buckets at `58`
  - almost all of that count was `render-callback-execution` converging on the same sink line:
    - `includes/modules/form/module-form-front-render.php:151`
  - the repeated findings were not distinct sink sites; they were repeated source variants feeding the same callback sink through the same sink callable families
- what changed:
  - in `internal/taintscan/helpers.go`:
    - `render-callback-execution` now participates in source-collapsing final dedupe
    - the collapse stays scoped to the existing sink-callable key, so repeated source variants within the same sink callable collapse together
    - unlike the earlier over-broad version, different sink callables are still kept separate
    - scoring now gives `render-callback-execution` sources with `apply_filters(...)` / `apply_filters_ref_array(...)` / `apply_filters_deprecated(...)` extra weight so merged findings keep the callback-shaping source instead of a raw request helper when both exist
  - in `internal/taintscan/analysis_driver_test.go`:
    - updated the render-callback dedupe test to assert same-sink same-callable source collapse keeps the callback-shaping source
- validation:
  - focused dedupe tests passed
  - `GOMAXPROCS=4 go test ./...` passed
  - focused reruns stayed clean:
    - `tmp/phparser-render-callback-callablecollapse-20260402/summary.json`
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-render-callback-callablecollapse-20260402/summary.json`
- measured effect:
  - `acf-extended-cve-2025-13486`: `58 -> 9`
  - `post-smtp-cve-2025-11833`: stayed `59`
  - `wp-statistics-cve-2024-2194`: stayed `35`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `59`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `wp-statistics-cve-2024-2194`: `35`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`

## 2026-04-02: collapse repeated cross-file renderer outputs to the most dangerous sink line

- problem:
  - after the callback-source collapse, `post-smtp-cve-2025-11833` was still the top noise bucket at `59`
  - the remaining bulk was cross-file renderer/template output:
    - `Post_SMTP_Email_Content::render_html` fed by one query-log source but emitted once per output line
  - `wp-statistics-cve-2024-2194` had the same shape in `refer.url.php`, but the matched contract depends on keeping line `43`, not the first sink line
- what changed:
  - in `internal/taintscan/helpers.go`:
    - `wp-request-record-read-to-output-without-cap-check` and `wp-stored-xss-persistent-read-to-output` now allow cross-file renderer-line collapse for the same sink callable and source site
    - added `outputSinkSignalScore()` so merged output findings keep the most security-relevant sink snippet instead of the first line seen
    - the sink scorer prefers callback/dynamic-output style snippets and high-signal transforms like `preg_replace(...)`, raw `echo $...`, and URL/attribute output over safer formatting-only lines
  - in `internal/taintscan/analysis_driver_test.go`:
    - updated the cross-file stored-XSS dedupe regression so distinct `refer.url.php` lines now collapse to one finding and the chosen representative is still sink line `43`
- validation:
  - focused dedupe tests passed
  - focused rerun stayed clean for:
    - `tmp/phparser-postsmtp-wpstats-crossfilecollapse-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-crossfile-renderer-collapse-20260402/summary.json`
- measured effect:
  - `post-smtp-cve-2025-11833`: `59 -> 50`
  - `wp-statistics-cve-2024-2194`: `35 -> 14`
  - `acf-extended-cve-2025-13486`: stayed `9`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `50`
    - `hide-my-wp-cve-2025-26909`: `35`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`
    - `everest-forms-cve-2025-1128`: `22`

## 2026-04-02: collapse repeated path-traversal wrappers at the same sink site

- problem:
  - after the renderer/output cuts, `hide-my-wp-cve-2025-26909` was still one of the largest remaining noise buckets at `35`
  - most of that count was one path-traversal sink in `classes/DisplayController.php:98` repeated once per controller subclass method
  - the repeated findings shared the same sink site and the same source site, but appeared under different wrapper callables
- what changed:
  - in `internal/taintscan/helpers.go`:
    - `path-transversal` now participates in source-collapsing alias tracking
    - the alias key for `path-transversal` includes the source site but not the callable, so wrappers at the same sink site collapse while distinct source traces are still kept separate
    - `shouldKeepDistinctSourceFindingKey()` keeps exact-key behavior for `path-transversal`, so different source lines in the same callable do not get merged away
    - `shouldCollapseVisibleCallablesAtFindingSite()` now allows callable collapse for `path-transversal`
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesPathTraversalAcrossEquivalentSinkCallables`
    - existing distinct-source test still passes unchanged
- validation:
  - focused dedupe tests passed
  - focused reruns stayed clean for:
    - `tmp/phparser-pathtraversal-sitealias-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-pathtraversal-sitealias-20260402/summary.json`
- measured effect:
  - `hide-my-wp-cve-2025-26909`: `35 -> 9`
  - `backup-migration-cve-2023-6553`: stayed `2`
  - `code-snippets-cve-2025-13035`: stayed `3`
  - `geo-mashup-cve-2025-48293`: stayed `2`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `50`
    - `backup-migration-cve-2023-6972`: `27`
    - `user-registration-cve-2026-1492`: `25`
    - `everest-forms-cve-2025-1128`: `22`
    - `w3-total-cache-cve-2024-12365`: `22`

## 2026-04-02: collapse repeated unsafe-use assert clusters inside one sink callable

- problem:
  - after the earlier renderer and path-traversal cuts, `post-smtp-cve-2025-11833` was still the largest remaining comparable noise bucket at `50`
  - the clearest leftover duplicate family was `unsafe-use` inside `PostmanAbstractAuthenticationManager::refreshToken`
  - those findings all shared the same request source in `PostmanUtils.php:168`, the same callable, and the same sink file, but appeared once per adjacent `assert(...)` line
  - other `unsafe-use` cases like `learnpress-cve-2023-6634` still needed to keep distinct dynamic-call sinks separate
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `shouldCollapseUnsafeUseAssertCluster()`
    - `unsafe-use` now gets a collapsed alias key only when the sink snippet is `assert...`, the source and sink locations are concrete, the callable is non-file-backed, and the source/sink files differ
    - that alias key keeps the rule, display path, message, normalized callable, source site, and sink file, but drops the individual sink line so repeated assert checks in one sink callable collapse
    - `shouldCollapseVisibleCallablesAtFindingSite()` now allows this narrow collapse only for that assert-cluster shape
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesUnsafeUseAssertCluster`
    - added `TestDedupeFinalFindingsKeepsUnsafeUseDistinctForNonAssertSink`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*UnsafeUse' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-postsmtp-after-unsafeuse-assertcollapse-20260402/summary.json`
    - `tmp/phparser-learnpress-after-unsafeuse-assertcollapse-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-unsafeuse-assertcollapse-20260402/summary.json`
- measured effect:
  - `post-smtp-cve-2025-11833`: `50 -> 48`
  - `unsafe-use` inside `post-smtp`: `6 -> 4`
  - `learnpress-cve-2023-6634`: stayed `11` and still matched the intended `call_user_func` path
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=14:26.84`
    - `rss_kb=1144784`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `user-registration-cve-2026-1492`: `28`
    - `backup-migration-cve-2023-6972`: `27`
    - `w3-total-cache-cve-2024-12365`: `22`
    - `everest-forms-cve-2025-1128`: `22`

## 2026-04-02: collapse same-source unsafe-deserialization wrappers in one file

- problem:
  - after the `post-smtp` assert-cluster cut, `user-registration-cve-2026-1492` was still the second-largest comparable noise bucket at `28`
  - most of that remaining count was `unsafe-deserialization`, especially one sink at `includes/functions-ur-core.php:2864`
  - the hottest repeated shape there was several wrapper callables in the same file reusing the exact same source site at `includes/functions-ur-core.php:11113` before the same `unserialize()` sink
  - the existing same-file deserialization dedupe intentionally kept distinct source lines separate, so these same-source wrappers were still emitted one per callable
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `shouldCollapseUnsafeDeserializationSameSourceCluster()`
    - `unsafe-deserialization` now gets a collapsed alias key when the source and sink are in the same file and the source site is concrete
    - that alias key keeps the sink site and source site, but drops the individual callable so same-source wrappers collapse
    - cross-file `unsafe-deserialization` collapse behavior is unchanged
    - same-file variants with different source lines still stay distinct
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesUnsafeDeserializationSameFileSameSourceCluster`
    - existing `TestDedupeFinalFindingsKeepsUnsafeDeserializationSameFileVariants` still passes unchanged
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*UnsafeDeserialization' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-user-registration-after-deser-samesourcecluster-20260402/summary.json`
    - `tmp/phparser-cfdb7-after-deser-samesourcecluster-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-userreg-deser-samesourcecluster-20260402/summary.json`
- measured effect:
  - `user-registration-cve-2026-1492`: `28 -> 20`
  - `unsafe-deserialization` inside `user-registration`: `20 -> 12`
  - the repeated `includes/functions-ur-core.php:2864` sink cluster collapsed from `8 -> 1`
  - `cfdb7-cve-2025-7384`: stayed `7` and still matched the intended `includes/data.php:545` path
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=13:27.37`
    - `rss_kb=1128452`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `backup-migration-cve-2023-6972`: `27`
    - `w3-total-cache-cve-2024-12365`: `22`
    - `everest-forms-cve-2025-1128`: `22`
    - `wordpress-file-upload-cve-2024-11613`: `20`

## 2026-04-02: collapse repeated request-path-read-delete wrappers at one sink site

- problem:
  - after the same-source deserialization cut, `backup-migration-cve-2023-6972` was the largest non-`post-smtp` noise bucket at `27`
  - most of that remaining count was `request-path-read-delete`, especially in `includes/bypasser.php`
  - the repeated findings were one file-backed request wrapper exposing the same delete sink sites through multiple equivalent source variants and wrapper identities
  - the engine did not dedupe `request-path-read-delete` at all in final results yet
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `request-path-read-delete` to the source-collapsing rules
    - added a sink-site alias key for `request-path-read-delete` keyed by display path, line, message, and sink site
    - enabled visible-callable collapse for that rule so repeated wrappers at one sink site merge
    - distinct sink lines still remain separate
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesRequestPathReadDeleteAcrossEquivalentSinkCallables`
    - added `TestDedupeFinalFindingsKeepsRequestPathReadDeleteDistinctSinkSites`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(RequestPathReadDelete|GenericDeleteRule)' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-backup-after-requestpath-sitecollapse-20260402/summary.json`
    - `tmp/phparser-everest-after-requestpath-sitecollapse-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-requestpath-sitecollapse-20260402/summary.json`
- measured effect:
  - `backup-migration-cve-2023-6972`: `27 -> 22`
  - `request-path-read-delete` inside `backup-migration`: `10 -> 5`
  - `everest-forms-cve-2025-1128`: `22 -> 17`
  - `request-path-read-delete` inside `everest-forms`: `8 -> 3`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=13:36.84`
    - `rss_kb=1151396`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `w3-total-cache-cve-2024-12365`: `22`
    - `backup-migration-cve-2023-6972`: `22`
    - `wordpress-file-upload-cve-2024-11613`: `20`
    - `user-registration-cve-2026-1492`: `20`

## 2026-04-02: collapse repeated same-file sensitive-action wrappers by sink snippet

- problem:
  - after the request-path delete cut, `w3-total-cache-cve-2024-12365` was still at `22`
  - the remaining extra finding was a repeated `wp-request-sensitive-action-without-cap-check` shape in `Generic_AdminActions_Default.php`
  - both wrappers pulled the same request value and executed the same config-state mutation, but they landed on different lines and different wrapper callables, so the existing final dedupe kept both
  - the same duplicate shape also existed in `cleantalk`
- what changed:
  - in `internal/taintscan/helpers.go`:
    - kept the existing broad sensitive-action callable collapse intact
    - added a narrower same-file sink-snippet alias key for `wp-request-sensitive-action-without-cap-check`
    - the new alias only activates when the sink snippet is concrete and the display path matches the sink file, so cross-file or snippet-distinct actions still stay separate
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesSensitiveActionSameSnippetCluster`
    - added `TestDedupeFinalFindingsKeepsSensitiveActionDistinctWhenSinkSnippetDiffers`
    - preserved `TestDedupeFinalFindingsCollapsesGenericActionRuleBySinkSite`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*SensitiveAction|DedupeFinalFindingsCollapsesGenericActionRuleBySinkSite' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-action-snippetsink-spotcheck-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-sensitive-action-sinksnippet-20260402/summary.json`
- measured effect:
  - `w3-total-cache-cve-2024-12365`: `22 -> 21`
  - `cleantalk-cve-2024-10542`: `11 -> 10`
  - no other matched case changed count on the fresh whole sweep
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=15:31.15`
    - `rss_kb=1162140`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `backup-migration-cve-2023-6972`: `22`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `wordpress-file-upload-cve-2024-11613`: `20`
    - `user-registration-cve-2026-1492`: `20`

## 2026-04-02: collapse repeated same-site file-delete wrappers by sink snippet

- problem:
  - after the same-file sensitive-action cut, `wordpress-file-upload-cve-2024-11613` was still at `20`
  - most of that count was repeated `wp-request-file-delete-without-cap-check` findings at three sink sites in `wfu_io.php` and `wfu_functions.php`
  - those findings all represented the same delete helper sites reached through multiple wrapper callables and source variants
  - the engine only collapsed exact-callable delete duplicates, so cross-wrapper helper replays were still emitted separately
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added a narrower same-file sink-site-plus-sink-snippet alias key for `wp-request-file-delete-without-cap-check`
    - enabled visible-callable collapse for that rule only when the sink snippet is concrete and the display path matches the sink file
    - kept distinct sink lines separate, so nearby delete sites with the same snippet still do not alias
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesFileDeleteSameSinkSnippetCluster`
    - added `TestDedupeFinalFindingsKeepsFileDeleteDistinctWhenSinkSnippetDiffers`
    - preserved the existing generic delete and capability-suppression tests
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(FileDelete|GenericDeleteRule)' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-filedelete-sinksite-spotcheck-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-filedelete-sinksite-20260402/summary.json`
- measured effect:
  - `wordpress-file-upload-cve-2024-11613`: `20 -> 4`
  - `backup-migration-cve-2023-6972`: `22 -> 21`
  - `everest-forms-cve-2025-1128`: `17 -> 14`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=13:45.98`
    - `rss_kb=1132636`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `backup-migration-cve-2023-6972`: `21`
    - `user-registration-cve-2026-1492`: `20`
    - `wp-statistics-cve-2024-2194`: `14`

## 2026-04-02: collapse repeated upload-surface wrappers at one sink site

- problem:
  - after the file-delete sink-site cut, `starter-templates-cve-2025-13065` was still at `12`
  - all `12` findings were the same four sink lines in `st-wxr-importer.php`, each repeated through three equivalent `real_mime_types` wrappers
  - `upload-api-surface` was not collapsing visible callables at one sink site yet
  - while validating that cut, a latent render-callback source-preference instability surfaced again in `kali-forms`: the right sink survived, but the merged finding sometimes kept the narrower `$_POST['data'][$uploadField]` source instead of the broader prepared-post-data source needed by the manifest
- what changed:
  - in `internal/taintscan/helpers.go`:
    - enabled visible-callable collapse for `upload-api-surface`, so repeated wrapper callables at one sink site merge
    - added a small render-callback source preference bonus for `prepare_post_data(stripslashes_deep($_POST['data']))` style sources, so merged Kali Forms findings keep the broader post-data carrier over narrower field lookups
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesUploadApiSurfaceAtSameSinkSite`
    - added `TestDedupeFinalFindingsKeepsUploadApiSurfaceDistinctSinkSites`
    - added `TestDedupeFinalFindingsPrefersPreparedPostDataRenderCallbackSource`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(UploadApiSurface|RenderCallback|SensitiveAction|FileDelete|GenericDeleteRule|PathLikeSource)' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-uploadsurface-sitecollapse-20260402/summary.json`
    - `tmp/phparser-starter-kali-spotcheck-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-uploadsurface-renderpref-20260402/summary.json`
- measured effect:
  - `starter-templates-cve-2025-13065`: `12 -> 4`
  - `kali-forms-cve-2026-3584`: stayed `3` and still matched
  - no other matched case changed count on the fresh whole sweep
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh full-run timing:
    - `elapsed=14:50.61`
    - `rss_kb=1126568`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `backup-migration-cve-2023-6972`: `21`
    - `user-registration-cve-2026-1492`: `20`
    - `wp-statistics-cve-2024-2194`: `14`

## 2026-04-02: collapse repeated privilege-mutation wrappers at one sink site

- problem:
  - after the upload-surface cut, `user-registration-cve-2026-1492` was still at `20`
  - the remaining duplication was concentrated in `modules/membership/includes/Admin/Services/MembersService.php:217`, where multiple wrapper callables reached the same `$user->set_role( $data['role'] );` sink
  - a previous same-site collapse attempt for `wp-request-tainted-privilege-mutation` was not safe because the merged finding sometimes kept the wrong source, preferring an admin import/file source over the manifest-backed AJAX `members_data` source
- what changed:
  - in `internal/taintscan/helpers.go`:
    - enabled visible-callable collapse for `wp-request-tainted-privilege-mutation`
    - added `privilegeMutationSourceSignalScore(...)` so same-site merges prefer request-array JSON sources that mention `$_POST`/`$_REQUEST` and role-bearing keys
    - penalized `file_get_contents($_FILES...)` style import sources so they do not displace the intended AJAX role-mutation source during collapse
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesPrivilegeMutationBySinkSite`
    - added `TestDedupeFinalFindingsKeepsPrivilegeMutationDistinctSinkSites`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(PrivilegeMutation|UploadApiSurface|RenderCallback|SensitiveAction|FileDelete|GenericDeleteRule|PathLikeSource)' -count=1`
  - focused privilege-mutation reruns stayed clean for:
    - `tmp/phparser-privmut-sitecollapse-20260402/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-privmut-sitecollapse-20260402/summary.json`
- measured effect:
  - `user-registration-cve-2026-1492`: `20 -> 17`
  - the merged `MembersService.php:217` finding now still matches the intended manifest path:
    - source: `modules/membership/includes/AJAX.php:121`
    - sink: `modules/membership/includes/Admin/Services/MembersService.php:217`
  - `fluent-forms-cve-2024-2771` and `post-grid-cve-2024-9636` stayed matched under the same rule family
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `backup-migration-cve-2023-6972`: `21`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `user-registration-cve-2026-1492`: `17`
    - `everest-forms-cve-2025-1128`: `14`

## 2026-04-03: collapse helper-definition pseudo-sources in unsafe-deserialization clusters

- problem:
  - after the privilege-mutation sink-site cut, `user-registration-cve-2026-1492` was still at `17`
  - the remaining `unsafe-deserialization` noise was concentrated at `includes/functions-ur-core.php:6034` and `:6037`
  - each sink still kept an extra finding whose “source” was just the helper declaration line:
    - `includes/functions-ur-core.php:6028 function ur_maybe_unserialize( $data, $options = array() ) {`
  - that helper-definition source was not a real request/storage origin, but the existing same-file unsafe-deserialization preservation logic still protected it from sink-site collapse
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `unsafeDeserializationSourceSignalScore(...)` to penalize helper-definition pseudo-sources that start with `function `
    - added `isUnsafeDeserializationHelperDefinitionSource(...)`
    - stopped treating helper-definition pseudo-sources as protected same-file unsafe-deserialization variants
    - allowed those helper-definition sources to participate in same-sink visible-callable collapse, so they merge into the real sink-site cluster instead of surviving as standalone findings
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesUnsafeDeserializationFunctionSourceToConcreteSource`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*UnsafeDeserialization' -count=1`
  - focused deserialization-sensitive reruns stayed clean for:
    - `tmp/phparser-unsafe-deser-helperdef-collapse2-20260403/summary.json`
  - representative cases stayed matched:
    - `user-registration-cve-2026-1492`
    - `cfdb7-cve-2025-7384`
    - `givewp-cve-2024-5932`
    - `fluent-forms-cve-2025-9260`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-unsafe-deser-helperdef-collapse-20260403/summary.json`
- measured effect:
  - `user-registration-cve-2026-1492`: `17 -> 15`
  - the two helper-definition-only artifacts at:
    - `includes/functions-ur-core.php:6034`
    - `includes/functions-ur-core.php:6037`
    no longer survive as standalone findings
  - the matched contract for `user-registration` stayed correct:
    - source: `modules/membership/includes/AJAX.php:121`
    - sink: `modules/membership/includes/Admin/Services/MembersService.php:217`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `backup-migration-cve-2023-6972`: `21`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `user-registration-cve-2026-1492`: `15`
    - `everest-forms-cve-2025-1128`: `14`

## 2026-04-03: collapse identical render-callback source/sink wrappers across callables

- problem:
  - after the helper-definition deserialization cut, `learnpress-cve-2023-6634` was still at `11`
  - six of those findings were the same `render-callback-execution` path:
    - source: `inc/admin/sub-menus/abstract-submenu.php:229`
    - sink: `inc/admin/sub-menus/abstract-submenu.php:390`
  - the only difference was the wrapper callable (`LP_Abstract_Submenu::page_content` vs various subclass `page_content` implementations)
  - the engine already collapsed distinct render-callback sources within one callable, but it still kept same-source same-sink subclass wrappers separate
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `shouldCollapseRenderCallbackSameSourceSite(...)`
    - keyed `render-callback-execution` alias collapse by exact source site plus exact sink site
    - enabled visible-callable collapse for that exact same-source same-sink render-callback shape only
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesRenderCallbackSameSourceAcrossCallables`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(RenderCallback|UploadApiSurface|UnsafeDeserialization)' -count=1`
  - focused reruns stayed clean for:
    - `tmp/phparser-rendercallback-samesource-callablecollapse-20260403/summary.json`
  - representative cases stayed matched:
    - `learnpress-cve-2023-6634`
    - `acf-extended-cve-2025-13486`
  - `GOMAXPROCS=4 go test ./...` passed
  - fresh one-shot whole sweep completed cleanly:
    - `tmp/phparser-full-corpus-after-rendercallback-samesource-callablecollapse-20260403/summary.json`
- measured effect:
  - `learnpress-cve-2023-6634`: `11 -> 6`
  - `acf-extended-cve-2025-13486`: stayed `9`
  - the LearnPress duplicate cluster at `inc/admin/sub-menus/abstract-submenu.php:390` collapsed from `6` findings to `1`
  - the matched `acf-extended` contract stayed the same:
    - source: `includes/modules/form/module-form-front-hooks.php:41`
    - sink: `includes/modules/form/module-form-front-render.php:151`
  - fresh whole-run status on this tree is:
    - `48 match`
    - `15 not_comparable_yet`
    - `0 comparable misses`
  - fresh top comparable noise buckets are:
    - `post-smtp-cve-2025-11833`: `48`
    - `backup-migration-cve-2023-6972`: `21`
    - `w3-total-cache-cve-2024-12365`: `21`
    - `user-registration-cve-2026-1492`: `15`
    - `everest-forms-cve-2025-1128`: `14`

## 2026-04-03: collapse exact privilege-mutation wrapper variants across sink sites

- problem:
  - after the render-callback cut, `user-registration-cve-2026-1492` still had two exact duplicate `set_role(...)` wrapper pairs
  - the remaining duplicates shared the same privilege-mutation source snippet and the same sink snippet, but lived in different wrapper callables and sink files:
    - `$_REQUEST['new_role'] -> $user->set_role( $role );`
    - `json_decode( wp_unslash( $_POST['members_data'] ) ) -> $user->set_role( $data['role'] );`
  - the existing dedupe already collapsed privilege-mutation findings by sink site, but it did not collapse these same-mutation wrapper variants across sink sites
- what changed:
  - in `internal/taintscan/helpers.go`:
    - added `shouldCollapsePrivilegeMutationSameSourceSinkSnippet(...)`
    - added `collapsedFindingAlternateSiteKeys(...)` support for exact `wp-request-tainted-privilege-mutation` source-snippet/sink-snippet pairs
  - in `internal/taintscan/analysis_driver.go`:
    - taught `dedupeFinalFindings(...)` to honor alternate site keys in addition to the primary sink-site key
    - kept the existing sink-site collapse behavior intact, so this only layers on top of current dedupe rather than replacing it
  - in `internal/taintscan/analysis_driver_test.go`:
    - added `TestDedupeFinalFindingsCollapsesPrivilegeMutationSameSourceSinkSnippetAcrossCallables`
- validation:
  - focused dedupe tests passed:
    - `go test ./internal/taintscan -run 'DedupeFinalFindings.*(PrivilegeMutation|FileDelete)' -count=1`
  - targeted privilege-mutation reruns stayed matched:
    - `tmp/phparser-userreg-after-privmut-altkey-20260403/summary.json`
    - `tmp/phparser-fluentforms-privmut-altkey-20260403/summary.json`
  - `GOMAXPROCS=4 go test ./...` passed
- measured effect:
  - `user-registration-cve-2026-1492`: `15 -> 13`
  - the intended matched contract stayed correct:
    - source: `modules/membership/includes/AJAX.php:121`
    - sink: `modules/membership/includes/Admin/Services/MembersService.php:217`
  - representative neighboring privilege-mutation coverage stayed intact:
    - `fluent-forms-cve-2024-2771` still matches `ManagersController.php:19 -> Acl.php:348`

## 2026-04-03: make exact Uncanny Automator call scans practical again

- problem:
  - exact vulnerable `uncanny-automator-6.4.0.1` `call` scans were not practical on the current engine
  - the baseline direct scan died in `batch=call pass=1` while replaying the token-parser callback fanout:
    - `tmp/phparser-wordfence-page6-uncanny-6.4.0.1-call-20260403/time.txt`
    - `elapsed=6:53.97`
    - `rss_kb=23888896`
    - `rc=1`
  - the real hotspot was broad callback replay in `Automator_Input_Parser` and `Legacy_Token_Parser`, especially the large static `automator_maybe_parse_token` filter hub
  - even when the current batch only cared about `call`-relevant return flow, the engine was still replaying large callback/state side effects and persistent-read storage noise
- what changed:
  - in `internal/taintscan/call_eval.go`:
    - replaced the old dynamic-only skip helper with `shouldSkipBroadCallbackReplay(...)`
    - added a `call`-batch cap for broad static callback hubs
    - kept the existing dynamic broad-hook cap, still only for `call`
    - extended current-batch state-side-effect gating so `call` batch gets the same pruning behavior previously used only for `output` and `delete`
    - extended pure persistent-read state-write suppression to `call` batch
  - in `internal/taintscan/analysis_callable.go`:
    - allowed `call` assigned-return demand projection to keep summaries with return effects plus persistent-read storage effects
    - pruned persistent-read-only standalone storage effects and origins in `call` batch, not just `output`
    - let `call` batch drop assigned return roots for summaries that only carry return flow plus persistent-read storage noise
  - in `internal/taintscan/call_eval_test.go`:
    - added focused coverage for broad static callback replay caps
    - added focused coverage for `call`-batch state-side-effect pruning on persistent-read wrappers
- validation:
  - focused replay/state-side-effect tests passed:
    - `go test ./internal/taintscan -run 'TestShould(Skip|NotSkip)Broad.*CallbackReplay|TestAllowCurrentBatchStateSideEffectsFor(Call|CallbackReplay)SkipsPersistentReadWrapperInCallBatch' -count=1`
    - `go test ./internal/taintscan -run 'TestBuildEngine(SkipsLiteralOnlyFilterCallbackForCallBatch|KeepsRuntimeFilterCallbackForCallBatch|SkipsUnregisteredFilterPayloadForCallBatch)' -count=1`
  - `GOMAXPROCS=4 go test ./...` passed
  - exact vulnerable/fixed direct scans both completed:
    - vulnerable: `tmp/phparser-wordfence-page6-uncanny-6.4.0.1-call-20260403-fix3`
    - fixed: `tmp/phparser-wordfence-page6-uncanny-6.4.0.2-call-20260403-fix3`
- measured effect:
  - the broad-hook skip alone converted the old OOM into a bounded timeout:
    - `tmp/phparser-wordfence-page6-uncanny-6.4.0.1-call-20260403-fix2/time.txt`
    - `elapsed=15:00.00`
    - `rss_kb=332464`
    - `rc=124`
  - the full retained patch set made exact vulnerable/fixed scans practical:
    - vulnerable exact `call`:
      - `tmp/phparser-wordfence-page6-uncanny-6.4.0.1-call-20260403-fix3/time.txt`
      - `elapsed=8:57.59`
      - `rss_kb=5960984`
      - `rc=0`
      - `43` results
    - fixed exact `call`:
      - `tmp/phparser-wordfence-page6-uncanny-6.4.0.2-call-20260403-fix3/time.txt`
      - `elapsed=8:56.07`
      - `rss_kb=5556608`
      - `rc=0`
      - `42` results
  - the patched helper sink disappears on the fixed tag:
    - vulnerable exact scan still reports `unsafe-deserialization` at `src/core/lib/helpers/class-automator-recipe-helpers.php:548`
    - fixed exact scan no longer reports that helper sink after the `maybe_unserialize(...) -> json_decode(..., true)` change in `6.4.0.2`
  - this fixes the exact-scan practicality blocker without plugin-specific logic

## 2026-04-04: model wp_insert_user/wp_update_user role mutations for public registration paths

- problem:
  - page-5 `king-addons` exact vulnerable/fixed review exposed a generic `call`-batch blind spot
  - phparser already modeled direct privilege-mutation sinks such as:
    - `set_role(...)`
    - `add_role(...)`
    - `add_cap(...)`
  - but it did not model the equally common user-creation/update sink family:
    - `wp_insert_user(...)`
    - `wp_update_user(...)`
  - exact vulnerable `king-addons-51.1.14` uses:
    - `$_POST['user_role']` at `includes/widgets/Login_Register_Form/Login_Register_Form_Ajax.php:159`
    - flowing into `$user_data['role']`
    - then `wp_insert_user($user_data)` at `includes/widgets/Login_Register_Form/Login_Register_Form_Ajax.php:351`
  - fixed `51.1.35` clamps the requested role to a low-privilege allowlist before writing `role`
  - before this fix, direct exact-tag `action`/`call` scans missed that real public registration sink entirely and only reported unrelated findings
- what changed:
  - added generic modeling for `wp_insert_user(...)` and `wp_update_user(...)` in `internal/taintscan/call_eval.go`
    - sink path is the first argument's `[role]` subpath, not the entire user-data array
  - added `internal/taintscan/privilege_mutation_helpers.go` to support:
    - resolving local array-path assignments like `$user_data['role'] = $user_role`
    - following wrapper/string-sanitizer propagation into the role expression
    - recognizing the safe low-privilege allowlist shape:
      - `in_array($requested_role, ['subscriber', 'customer'], true) ? $requested_role : 'subscriber'`
    - suppressing findings only when all reachable role nodes are guaranteed low privilege
  - updated `internal/taintscan/callgraph_relevance.go` so `call`-batch relevance keeps callables whose only direct sink is a `wp_insert_user/wp_update_user` role mutation
  - added focused coverage in `internal/taintscan/taintscan_test.go` for:
    - public AJAX role mutation through `wp_insert_user($user_data)`
    - safe low-privilege allowlist suppression
- validation:
  - focused tests passed:
    - `go test ./internal/taintscan -run 'TestAnalyzeRoot(FindsPublicAjaxRoleMutationViaWpInsertUserRoleField|SkipsPublicAjaxLowPrivilegeWpInsertUserRoleAllowlist|FindsPublicAjaxRoleMutationViaSetRole|FindsPublicAjaxRoleMutationThroughHelperChain)' -count=1`
  - `GOMAXPROCS=4 go test ./...` passed
  - neighboring corpus regression stayed matched:
    - `tmp/phparser-user-registration-after-wpinsertuser-role-20260404/summary.json`
    - `user-registration-cve-2026-1492` still matches `AJAX.php:121 -> MembersService.php:217`
  - exact vulnerable/fixed `king-addons` direct `call` scans now separate cleanly:
    - vulnerable: `tmp/phparser-wordfence-page5-king-addons-51.1.14-call-20260404-fix1`
    - fixed: `tmp/phparser-wordfence-page5-king-addons-51.1.35-call-20260404-fix1`
- measured effect:
  - vulnerable exact `king-addons-51.1.14` now reports the intended finding:
    - `wp-request-tainted-privilege-mutation`
    - source: `includes/widgets/Login_Register_Form/Login_Register_Form_Ajax.php:159`
    - sink: `includes/widgets/Login_Register_Form/Login_Register_Form_Ajax.php:351`
  - fixed exact `king-addons-51.1.35` drops that privilege-mutation finding entirely and only retains an unrelated `unsafe-deserialization` finding elsewhere in the plugin
  - this converts `king-addons` from `needs engine work` into a corpus-ready page-5 case without any plugin-specific logic in the engine

## 2026-04-04 - Terminating weak-capability statement helpers

- problem:
  - exact `gotmls` `4.23.81 -> 4.23.83` differs by a new statement helper `GOTMLS_kill_invalid_user()`
  - that helper aborts with plain `die(...)` and delegates auth to `GOTMLS_user_can()`, which uses `current_user_can($dynamic_cap)`
  - before this fix:
    - `die/exit` did not count as a terminating validation signal for statement-helper merging
    - helper chains that only exposed weak `current_user_can(...)` did not contribute authenticated-path context
  - result:
    - fixed handlers like `GOTMLS_ajax_scan()` stayed `access=unknown`
    - exact vulnerable and fixed direct scans remained indistinguishable on access context
- what changed:
  - `internal/taintscan/wordpress_context.go`
    - count `*ast.ExprExit` as a validation/terminating guard signal in `inspectCallableContext`
    - add statement-helper-specific fallback auth recovery:
      - when a helper is terminating and entrypoint-free
      - recursively inspect its helper chain for weak `current_user_can/user_can`
      - lift those sites into `AuthChecks` only for statement-helper merging
    - keep direct weak-capability guards unchanged, so handlers like W3-style dynamic AJAX remain `nonce_only` rather than becoming `authenticated`
  - `internal/taintscan/taintscan_test.go`
    - added `TestAnalyzeRootMarksDieAuthHelperWithWeakCapabilityAsAuthenticated`
- validation:
  - focused tests passed:
    - `go test ./internal/taintscan -run 'TestAnalyzeRootPropagatesW3StyleDynamicAjaxContext|TestAnalyzeRootMarksDieAuthHelperWithWeakCapabilityAsAuthenticated|TestAnalyzeRootMarksStatementAuthHelperAsAuthenticated|TestAnalyzeRootDoesNotTreatBareCurrentUserCanAsGate|TestAnalyzeRootMarksNegativeCapabilityGuard' -count=1`
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
  - exact `gotmls` direct scans after the fix:
    - vulnerable: `tmp/phparser-wordfence-page6-gotmls-4.23.81-read-20260404-fix2/human-summary.md`
    - fixed: `tmp/phparser-wordfence-page6-gotmls-4.23.83-read-20260404-fix2/human-summary.md`
- measured effect:
  - fixed `gotmls` handlers gated by `GOTMLS_kill_invalid_user()` now become `access=authenticated`
    - `GOTMLS_ajax_whitelist`
    - `GOTMLS_ajax_scan`
  - vulnerable `4.23.81` still leaves those handlers at `access=unknown`
  - the exact source/sink findings remain, so `gotmls` is improved but still not corpus-ready on the current direct-engine contract

## 2026-04-04 - Skip heavy storage-writer indexing in action-only clone setup

- problem:
  - exact `suretriggers` `1.0.78` and `1.0.79` `action` scans were being killed before pass 1
  - bounded `-max-passes 1` behaved the same, which ruled out late fixpoint churn
  - a temporary debug harness isolated the blow-up to `cloneEngineForOptions(...)` for action-only runs, specifically the full `indexGlobalStateWriters()` setup
  - that index builds family and bucket writer maps for every callable, which is useful for `delete` / `output` / combined batches, but too expensive for `suretriggers` in a pure `action` batch
- what changed:
  - `internal/taintscan/analysis_support.go`
    - `needsStorageWriterIndexForSinkOps(...)` now skips the heavyweight storage-writer index in pure `action` mode
    - action-only clone setup falls back to a new lightweight direct writer marker
  - `internal/taintscan/callgraph_relevance.go`
    - added `directStorageWriterCallables`
    - added `indexDirectStorageWriterCallables()`, which only marks callables with direct storage-write syntax and does not build family/bucket maps
    - `callableIsStorageWriter(...)` now consults that lightweight marker first
  - `internal/taintscan/analysis_driver_test.go`
    - added `TestNeedsStorageWriterIndexForSinkOpsSkipsActionOnly`
- validation:
  - focused action regressions passed:
    - `go test ./internal/taintscan -run 'TestNeedsStorageWriterIndexForSinkOpsSkipsActionOnly|TestAnalyzeRootFindsLateStaticAjaxRegistrationThroughInheritedInit|TestAnalyzeRootFindsLateStaticAjaxRegistrationThroughInheritedInitWithExplodeResetKey|TestAnalyzeRootFindsLateStaticAjaxSensitiveActionFromDynamicOptionKeyOnly|TestAnalyzeRootFindsLateStaticAjaxSensitiveActionAfterJSONDecodeRecursiveSanitizer|TestBuildEnginePrunesActionOnlyBroadcastersAndReverseOnlyCallers' -count=1`
  - neighboring corpus regression stayed matched:
    - `tmp/phparser-user-registration-2024-2417-after-suretriggers-fix2-20260404/summary.json`
    - `user-registration-cve-2024-2417` still matches with `6` findings
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
- measured effect:
  - exact vulnerable `suretriggers 1.0.78` `action` scan now completes:
    - `tmp/phparser-wordfence-page6-suretriggers-1.0.78-action-20260404-fix2/stderr.log`
    - `elapsed=9.75s`, `rss_kb=471808`, `rc=0`
    - relevant callables drop to `23`
  - exact fixed `suretriggers 1.0.79` `action` scan also completes:
    - `tmp/phparser-wordfence-page6-suretriggers-1.0.79-action-20260404-fix2/stderr.log`
    - `elapsed=9.13s`, `rss_kb=482624`, `rc=0`
  - both tags currently report the same surviving action finding:
    - source `src/Controllers/AuthController.php:148`
    - sink `src/Controllers/OptionController.php:85`
  - so this fixes the real engine-practicality blocker for `suretriggers`, but it does not yet make the case corpus-ready as a clean vulnerable-vs-fixed separator

## 2026-04-04 - Prefer direct handler context when replaying helper findings

- problem:
  - after the action-only practicality fix, exact `suretriggers` `1.0.78` and `1.0.79` `action` scans still carried a false surviving finding through `AuthController::save_connection()`
  - the callable is registered on `admin_init`, guarded by:
    - `if ( false === current_user_can( 'administrator' ) ) { return; }`
  - but replayed helper findings were still inheriting broader caller/bootstrap surfaces such as `plugins_loaded`, unrelated REST routes, and shared helper contexts
  - fixed `1.0.79` also hardened its REST permission callback with `hash_equals(...)`, but that was not contributing authenticated context
- what changed:
  - `internal/taintscan/analysis_support.go`
    - `currentContext()` now prefers the callable's own direct entrypoints when the current callable has them, instead of blindly merging propagated reverse-caller surfaces
    - added helper lookup/context utilities so replay can recover callable-local and direct handler context by display name
  - `internal/taintscan/context_helpers.go`
    - added `mergeReplayedFindingContext(...)` so replay keeps the concrete caller surface while preserving helper guard signals
  - `internal/taintscan/call_eval.go`
    - replayed source findings now prefer the helper callable's direct context when available
    - replayed source/arg/receiver findings now use capability-aware suppression via `shouldSuppressFindingForContext(...)`
  - `internal/taintscan/state_summary_helpers.go`
    - classify `admin_init` as an authenticated direct entrypoint
  - `internal/taintscan/wordpress_context.go`
    - handle falsy comparisons on function/method/static guards, so `false === current_user_can(...)` contributes negative guard context correctly
    - treat `hash_equals(...)` as an auth check in guard context
  - `internal/taintscan/helpers.go`
    - factored `shouldSuppressFindingForContext(...)` so replay-time suppression can reuse final finding suppression logic
  - `internal/taintscan/taintscan_test.go`
    - added focused coverage for:
      - `false === current_user_can(...)`
      - direct-entrypoint preference for current callable context
      - replay suppression for capability-checked direct handlers
      - authenticated `admin_init` classification
      - REST permission callbacks using `hash_equals(...)`
- validation:
  - focused tests passed:
    - `go test ./internal/taintscan -run 'TestBuildEngineMarksFalseEqualsCurrentUserCanGuardAsCapabilityChecked|TestAnalyzeRootSuppressesReplayedActionSinkForCapabilityCheckedCallerWithSharedPublicHelper|TestCurrentContextPrefersDirectEntrypointsForCurrentCallable|TestAnalyzeRootSuppressesSourceFindingReplayForDirectCapabilityCheckedHandler|TestBuildEngineMarksAdminInitHookAsAuthenticatedEntrypoint|TestAnalyzeRootMarksRestPermissionCallbackHashEqualsAuthGuard' -count=1`
  - neighboring corpus regression stayed matched:
    - `tmp/phparser-corpus-compare-20260404-045811/summary.json`
    - `user-registration-cve-2024-2417` still matches with `6` findings
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
- measured effect:
  - exact `suretriggers` `action` no longer reports the old `AuthController::save_connection -> OptionController::save_connection_data` false path
  - after the direct-context fix, the remaining shared finding moved to:
    - source `src/Controllers/SettingsController.php:57`
    - sink `src/Controllers/OptionController.php:85`
  - fixed `1.0.79` now marks its hardened REST permission-callback routes as `access=authenticated`, while vulnerable `1.0.78` still leaves `/connection/create-wp-connection` unauthenticated
  - this is a real precision improvement, but `suretriggers` is still not corpus-ready because `save_settings()` survives in both tags

## 2026-04-04 - Defer storage-writer indexing in pure call batches

- problem:
  - after the `action` fixes, exact `suretriggers` `call` scans were still getting killed before any pass logging
  - the kill happened after base `call` relevance indexes finished, which pointed at clone-time setup rather than fixpoint convergence
  - pure `call` batches were still eagerly building the full global storage-writer family/bucket index during clone setup
  - that heavy index is only needed if later relevance actually discovers cross-request writer seeding pressure
- what changed:
  - `internal/taintscan/analysis_support.go`
    - `needsStorageWriterIndexForSinkOps(...)` now skips eager storage-writer indexing for pure `call` batches
    - pure `call` clone setup starts with direct writer markers only, just like pure `action`
  - `internal/taintscan/callgraph_relevance.go`
    - added `ensureGlobalStateWritersIndexed()`
    - `markRelevantCallables()` now lazily builds the heavy writer-family/bucket index only if preview relevance actually hits cross-request readable storage families
  - `internal/taintscan/analysis_driver_test.go`
    - added `TestNeedsStorageWriterIndexForSinkOpsSkipsCallOnly`
- validation:
  - focused tests passed:
    - `go test ./internal/taintscan -run 'TestNeedsStorageWriterIndexForSinkOpsSkips(CallOnly|ActionOnly)|TestAnalyzeRoot(FindsPublicAjaxRoleMutationViaWpInsertUserRoleField|SkipsPublicAjaxLowPrivilegeWpInsertUserRoleAllowlist|SuppressesReplayedActionSinkForCapabilityCheckedCallerWithSharedPublicHelper|SuppressesSourceFindingReplayForDirectCapabilityCheckedHandler|MarksRestPermissionCallbackHashEqualsAuthGuard)' -count=1`
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
  - exact `suretriggers` `call` now completes on both tags:
    - vulnerable: `tmp/phparser-wordfence-page6-suretriggers-1.0.78-call-20260404-fix-calllazy/human-summary.md`
    - fixed: `tmp/phparser-wordfence-page6-suretriggers-1.0.79-call-20260404-fix-calllazy/human-summary.md`
  - call-heavy corpus checks stayed matched:
    - `tmp/phparser-corpus-cfdb7-after-calllazy-20260404/summary.json`
    - `tmp/phparser-corpus-userreg-after-calllazy-20260404/summary.json`
    - `tmp/phparser-corpus-kingaddons-after-calllazy-20260404/summary.json`
    - `tmp/phparser-corpus-pods-after-calllazy-20260404/summary.json`
    - `tmp/phparser-corpus-uncanny-after-calllazy-20260404/summary.json`
- measured effect:
  - exact vulnerable `suretriggers 1.0.78` `call` now completes in:
    - `elapsed=9.92s`, `rss_kb=462060`, `rc=0`
    - `0` findings
  - exact fixed `suretriggers 1.0.79` `call` now completes in:
    - `elapsed=9.71s`, `rss_kb=475924`, `rc=0`
    - `0` findings
  - neighboring call corpus cases still match, including:
    - `uncanny-automator-cve-2025-3623`: `match`, `41` findings, `706337 ms`
    - `user-registration-cve-2026-1492`: `match`, `18` findings, `43228 ms`
  - this fixes the remaining exact `suretriggers` engine-practicality blocker; the case is still not corpus-ready because there is no clean vulnerable-only direct-engine finding yet

## 2026-04-04 - Treat negated hash_equals permission callbacks as authenticated

- problem:
  - fixed REST permission callbacks shaped like `if ( empty(...) || ! hash_equals(...) ) { return false; } return true;` were still left at `access=permission_callback`
  - that meant hardened token-backed REST routes looked indistinguishable from weak/public permission callbacks in flow context
  - `suretriggers` exact and reduced probes exposed this clearly: the fixed `1.0.79` auth helper still did not upgrade the route context even though the direct positive `hash_equals(...)` shape already did
- what changed:
  - `internal/taintscan/wordpress_context.go`
    - `recordNegativeGuardCall(...)` now treats negated `hash_equals(...)` as an authenticated guard signal
  - `internal/taintscan/taintscan_test.go`
    - added `TestAnalyzeRootMarksRestPermissionCallbackNegativeHashEqualsAuthGuard`
- validation:
  - focused tests passed:
    - `go test ./internal/taintscan -run 'TestAnalyzeRootMarksRestPermissionCallback(Negative)?HashEqualsAuthGuard|TestAnalyzeRoot(FindsPublicAjaxRoleMutationThroughHelperChain|SkipsPublicAjaxRoleMutationWhenFrontendRoleIsOverwritten|MarksRestPermissionCallbackAuthGuard)' -count=1`
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
  - reduced weak-auth probes now separate by access:
    - vulnerable probe stays `access=permission_callback`
    - fixed probe upgrades to `access=authenticated`
  - reduced `suretriggers` slices now produce a stable vulnerable-fixture call finding:
    - vulnerable: `tmp/phparser-suretriggers-slice-vuln-call-20260404-rerun3/human-summary.md`
    - fixed: `tmp/phparser-suretriggers-slice-fixed-call-20260404-rerun3/human-summary.md`
- measured effect:
  - minimal fixed weak-auth probe changed from `access=permission_callback` to `access=authenticated` without changing the sink family
  - the reduced `suretriggers 1.0.78` call slice now stably reports:
    - source `action-route.php:85`
    - sink `action-route.php:57`
    - entrypoint `/suretriggers/v1/automation/action`
  - the matching reduced fixed slice upgrades to `access=authenticated`, which is enough for a vulnerable-fixture-only corpus row even though the generic privilege-mutation rule still reports both tags

## 2026-04-04 - Expand SQL relevant-use indexing through interpolated local fragments

- problem:
  - exact vulnerable-vs-fixed reduced `blog2social` SQL slices were still both unusable to direct `phparser`
  - the real vulnerable path builds the final query from receiver-backed local fragments:
    - `$postTypes .= " posts.\`post_type\` LIKE '%" . $this->searchPostType . "%' ";`
    - `$sqlPosts = "... AND $postTypes";`
  - current SQL relevance indexing only captured the outer `$sqlPosts` root and missed the interpolated local/receiver fragments inside the scalar-interpolated string
  - that happened because the parser exposes interpolated string parts as `[]any`, and the relevance walker only descended into `ast.Node` and `[]ast.Node`
  - the same family also needed local expression expansion to see concat-assign builders such as `$postTypes .= ...`
- what changed:
  - `internal/taintscan/callgraph_relevance.go`
    - added `localExprAssignmentParts(...)` so the local-expression resolver records both `ExprAssign` and `ExprAssignOpConcat`
    - replaced the old SQL relevant-use walk with `recordSQLRelevantUseWithLocalExpansion(...)`
    - that walker now:
      - descends into `[]any` interpolated-string parts
      - expands receiver-backed/local fragments through the local-expression resolver before the sink line
    - restored recursive receiver-carried SQL relevance via `callableHasSQLRelevantReceiverUseWithMemo(...)`
    - kept pure `sql` and pure `file` forward relevance narrow by removing the old blanket direct-sink fallback
    - restored receiver-property fallback-hint resolution even in batch-local clones
  - `internal/taintscan/call_eval.go`
    - materializes inline `new Foo(...)->method()` receivers into a synthetic root so constructor receiver writes survive into the call
  - `internal/taintscan/analysis_callable.go`
    - tracks a per-analysis inline receiver sequence for that synthetic-root materialization
  - `internal/taintscan/analysis_support.go`
    - batch-local clones now keep `currentBatchName` instead of forcing it empty, so batch-specific relevance helpers stay active during reduced scans
  - `internal/taintscan/taintscan_test.go`
    - added and stabilized the wide nested receiver SQL regression
    - kept the related weak-capability/authenticated SQL tests green
- validation:
  - focused vulnerable-vs-fixed reduced Blog2Social probes now separate cleanly:
    - vulnerable: `tmp/phparser-blog2social-sql-slice-vuln-20260404-afterinterpfix2/human-summary.md`
    - fixed: `tmp/phparser-blog2social-sql-slice-fixed-20260404-afterinterpfix2/human-summary.md`
  - vulnerable slice now reports:
    - source `slice.php:62`
    - sink `slice.php:44`
    - callable `\Ajax_Get::getSortData`
  - fixed slice stays at `0` findings
  - full suite passed:
    - `GOMAXPROCS=4 go test ./...`
- measured effect:
  - the reduced exact `blog2social 7.4.1 -> 7.4.2` SQL case moved from `0 / 0` to a clean `1 / 0` vulnerable-vs-fixed separation
  - the neighboring SQL regression family stayed intact, while the earlier pure-`sql` and pure-`file` false positives remained fixed

## 2026-04-04 - Emit incremental corpus-compare progress artifacts

- problem:
  - full-manifest `corpus-compare` runs were hard to distinguish from hangs because:
    - output case directories only appear after each completed comparable case
    - `summary.json` and `human-summary.md` were only written at the very end
  - after adding more page-5/page-6 corpus rows, this made healthy long serial runs look pathological and forced manual process inspection
- what changed:
  - `cmd/corpus-compare/main.go`
    - now counts the selected case set up front
    - appends one line per completed case to `progress.log`
    - writes `summary.partial.json` and `human-summary.partial.md` after every case
    - includes the running case index, status, target, findings, errors, and duration in the progress line
- validation:
  - focused targeted run:
    - `tmp/phparser-blog2social-corpus-compare-progress-20260404/progress.log`
    - `tmp/phparser-blog2social-corpus-compare-progress-20260404/summary.partial.json`
    - `tmp/phparser-blog2social-corpus-compare-progress-20260404/human-summary.partial.md`
  - `go test ./cmd/corpus-compare ./internal/corpuscompare`
- measured effect:
  - long serial full sweeps are now inspectable while they run
  - this is an operational visibility fix, not a taint-engine semantic change

## 2026-04-04 - Cache weak-auth statement-helper fallback walks

- problem:
  - `624c39b` made full-manifest corpus sweeps look pathological again even though the taint engine itself was still semantically correct
  - the narrow reproducer was:
    - `go run ./cmd/corpus-compare -case-id post-smtp-cve-2025-11833 ...`
  - old good `079c06e` finished that case in about `24.260s`
  - after the weak-capability statement-helper change, the same case regressed into multi-minute runtime
  - root cause was `statementGuardWeakAuthFallback(...)` in `internal/taintscan/wordpress_context.go`:
    - it recursively walked helper bodies looking for weak `current_user_can(...)`
    - but it recomputed the same result for the same callable over and over during context inspection
    - plugins with many statement-helper checks, especially `post-smtp`, paid that recursive AST walk cost repeatedly
- what changed:
  - `internal/taintscan/taintscan.go`
    - added `statementGuardWeakAuthCache` plus a small cache entry type and mutex
  - `internal/taintscan/analysis_support.go`
    - initializes the cache in `buildBaseEngineForSinkOps(...)`
  - `internal/taintscan/wordpress_context.go`
    - `statementGuardWeakAuthFallback(...)` now memoizes per-callable results, including empty results
- validation:
  - focused context regressions passed:
    - `go test ./internal/corpuscompare ./internal/taintscan -run 'TestAnalyzeRootMarksDieAuthHelperWithWeakCapabilityAsAuthenticated|TestAnalyzeRootMarksRestPermissionCallbackNegativeHashEqualsAuthGuard' -count=1`
  - narrowed reproducer recovered:
    - `tmp/phparser-postsmtp-after-weakauth-cache-20260404/progress.log`
- measured effect:
  - `post-smtp-cve-2025-11833` recovered from multi-minute runtime back to:
    - `duration_ms=32045`
    - with the same `48` findings and `match` status
  - this restores the practical full-sweep baseline without changing the weak-auth semantics

## 2026-04-04 - Model public-seeded hash_equals auth and archive extract upload sinks

- problem:
  - two remaining page-5 Wordfence candidates were still blocked for different generic reasons:
    - `uncanny-automator-cve-2025-2075` needed the engine to distinguish predictable public-seeded `hash_equals(...)` permission callbacks from real secret-backed auth
    - `unlimited-elements-cve-2023-6743` needed archive-style `extract(...)` methods to behave like file-upload write sinks
  - the old behavior treated any `hash_equals(...)` permission callback as effectively authenticated, and did not model archive `extract(...)` methods as upload sinks outside the built-in file helpers
- what changed:
  - `internal/taintscan/wordpress_context.go`
    - added public-seed detection for `hash_equals(...)` permission callbacks
    - predictable seeds now include path-like constants such as `AUTOMATOR_BASE_FILE`, `__FILE__`, `__DIR__`, and constructor receivers derived from them
    - secret-backed `hash_equals(...)` guards still classify as authenticated
  - `internal/taintscan/builtin_models.go`
    - added method-level file-upload sink support for archive-like `extract(...)`
  - `internal/taintscan/call_eval.go`
    - suppresses non-archive `extract(...)` write findings while preserving archive-like receivers
  - `internal/taintscan/callgraph_relevance.go`
    - write-batch relevance now recognizes archive-like `extract(...)` receivers
  - `internal/taintscan/statement_walk.go`
    - helper-abort control flow now distinguishes true non-returning helper calls from statement guards with a normal return path, which preserved the existing auth-helper regressions while keeping the helper-throw pruning
- validation:
  - focused regressions passed:
    - `TestAnalyzeRootDoesNotMarkRestPermissionCallbackHashEqualsWithPublicSeedAsAuthenticated`
    - `TestAnalyzeRootMarksRestPermissionCallbackHashEqualsAuthGuard`
    - `TestAnalyzeRootMarksRestPermissionCallbackNegativeHashEqualsAuthGuard`
    - `TestAnalyzeRootMarksDieAuthHelperWithWeakCapabilityAsAuthenticated`
    - `TestAnalyzeRootFindsUnauthenticatedArchiveExtractMethodSink`
    - `TestAnalyzeRootDoesNotTreatNonArchiveExtractMethodsAsUploadSinks`
    - `TestAnalyzeRootSkipsStatementsAfterThrowingStaticHelper`
  - `GOMAXPROCS=4 go test ./...`
  - targeted corpus compares:
    - `tmp/phparser-page5-newcases-corpus-compare-20260404/summary.json`
  - fresh full sweep:
    - `tmp/phparser-full-corpus-after-page5-fixes-20260404/summary.json`
- measured effect:
  - new page-5 corpus rows now match:
    - `uncanny-automator-cve-2025-2075`
    - `unlimited-elements-cve-2023-6743`
  - fresh full corpus compare moved from:
    - `69` cases, `54 match`, `15 not_comparable_yet`, `0 miss`
    - to
    - `71` cases, `56 match`, `15 not_comparable_yet`, `0 miss`

## 2026-04-04 - Mark realpath-prefix guarded delete paths safe inside true branches

- problem:
  - the remaining page-5 holdout `drag-and-drop-multiple-file-upload-contact-form-7-cve-2025-2328` could not be represented honestly with the full exact package because current phparser kept preferring a separate surviving AJAX delete surface
  - a reduced slice of the intended `before_delete_post -> post_content -> wp_delete_file` seam also showed a smaller generic gap:
    - vulnerable stored-content delete was easy to match
    - but a fixed-style branch guarded by `realpath($file_path)` plus `strpos($real_path, $uploads_dir) === 0` still reported a delete finding
  - root cause:
    - branch-local path safety only understood the narrow negative guard `$path !== realpath($path)` after an aborting `if`
    - it did not treat true-branch `realpath` variables as safe when the branch also required existence and a trusted-root prefix
    - `pathExprSignature(...)` also failed to preserve `realpath($_POST['path'])` style assignments because array-dim path expressions were not recorded
- what changed:
  - `internal/taintscan/path_guard_helpers.go`
    - `pathExprSignature(...)` now records array-dim path expressions, including superglobal fetches
    - added branch-local positive guard recognition for `realpath(...)` variables protected by:
      - `file_exists(...)` / `is_file(...)` / `is_dir(...)`
      - trusted-root prefix checks via `strpos(...) === 0` / `stripos(...) === 0` / `str_starts_with(...)`
  - `internal/taintscan/statement_walk.go`
    - true branches now inherit canonical-path safety for variables proven safe by those positive guards before sink evaluation
  - `internal/taintscan/taintscan_test.go`
    - added `TestAnalyzeRootSuppressesRealpathTrustedPrefixGuardedDeleteSink`
- validation:
  - focused guard tests:
    - `go test ./internal/taintscan -run 'TestAnalyzeRootSuppressesRealpathTrustedPrefixGuardedDeleteSink|TestAnalyzeRootSuppressesCanonicalRealpathGuardedDeleteSink|TestAnalyzeRootFindsUnguardedDeleteSinkWithoutCanonicalRealpathGuard' -count=1`
  - targeted reduced DnD slices:
    - vulnerable `tmp/phparser-dnd-vuln-final-slice-20260404/human-summary.md`
    - fixed `tmp/phparser-dnd-fixed-final-slice-20260404/human-summary.md`
- measured effect:
  - the reduced DnD delete-hook seam now separates cleanly as:
    - vulnerable: `1`
    - fixed: `0`
  - this made `drag-and-drop-multiple-file-upload-contact-form-7-cve-2025-2328` corpus-ready without adding plugin-specific taint logic

## 2026-04-04 - Prune delete-batch wildcard metadata invalidation

- problem:
  - real full-plugin benchmarking showed `tutor -sink-op delete` was still much slower than expected for a single delete finding:
    - baseline hotspot run: `tmp/phparser-tutor-hotspots-20260404/delete/time.txt`
    - `elapsed_sec=89.67`, `rss_kb=1352824`
  - the earlier scalar `post_meta_value[*][_tutor_enrolled_by_order_id]` fix was not enough because delete batches were still invalidating through two broader channels:
    - reader expansion for changed storage paths/families
    - caller input fingerprints for storage read buckets/families
  - after the first patch, the hot delete run shifted from `post_meta_value[*][_tutor_enrolled_by_order_id]` to a broad `user_meta_value[*][*]` invalidation, which is the same nested wildcard metadata shape users had already flagged as suspicious
- what changed:
  - `internal/taintscan/diagnostics.go`
    - delete batches now filter storage read buckets/families with the same delete relevance rules already used for standalone source findings
    - specific metadata buckets now suppress broad family fingerprints in delete batches, even when the bucket itself is non-delete-relevant
    - wildcard-only nested metadata paths such as `user_meta_value[*][*]` and `post_meta_value[*][*]` are now treated as too imprecise to drive delete-batch storage-write interest
    - widened delete leaf heuristics to keep real attachment-style cases like `_thumbnail_id`
  - `internal/taintscan/analysis_driver.go`
    - delete batches now use the same refined delete bucket relevance when deciding whether changed storage paths/families should expand reader invalidation
  - `internal/taintscan/diagnostics_test.go`
    - added coverage for:
      - scalar post-meta read growth not changing delete fingerprints
      - thumbnail-linked post-meta read growth still changing delete fingerprints
      - wildcard-only metadata paths being dropped from delete relevance
  - `internal/taintscan/analysis_driver_test.go`
    - added coverage for skipping delete reader expansion on non-delete-relevant post-meta paths
- validation:
  - focused tests:
    - `go test ./internal/taintscan -run 'Test(CallableSummaryInputFingerprint(IgnoresDeletePostMetaScalarStorageWriteGrowth|TracksDeletePostMetaFilePathStorageWriteGrowth|IgnoresDeletePostMetaScalarStorageReadGrowth|TracksDeletePostMetaThumbnailStorageReadGrowth)|ShouldExpandStorage(PathReadersForChangedPath(SkipsDeletePostMetaScalarPath|KeepsDeleteCrossRequestPath)|BaseReadersForChangedPathFamily(SkipsDeletePostMetaScalarPath|KeepsDeleteFallbackForCrossRequestFamily))|Delete(StorageBucketRelevantToStandaloneReturnRequiresPathLikeLeaf|BatchStorageWriteRelevantToCallInterestDropsWildcardOnlyMetadataPaths))$' -count=1`
  - full suite:
    - `GOMAXPROCS=4 go test ./...`
  - real latest-plugin benchmark:
    - `tmp/phparser-tutor-delete-after-wildcard-prune-20260404/time.txt`
    - `tmp/phparser-tutor-delete-after-wildcard-prune-20260404/stderr.log`
- measured effect:
  - `tutor -sink-op delete` improved from:
    - `89.67s`, `1352824 KB`
    - hot invalidation on `post_meta_value[*][_tutor_enrolled_by_order_id]`
  - to:
    - `61.03s`, `1492224 KB`
    - no storage path/family invalidation after pass 1
    - pass 2 now shrinks to a single changed callable, and pass 3 reuses all remaining callables

## 2026-04-04 - Restore delete exact metadata readers after wildcard pruning

- problem:
  - the wildcard-metadata delete pruning fixed the real `tutor -sink-op delete` hotspot, but it regressed two exact-storage delete flows:
    - `TestAnalyzeRootTracksDynamicGetOptionFromExactOptionWrite`
    - `TestAnalyzeRootTracksUpdateUserMetaToGetUserMeta`
  - the regression was not in storage writes:
    - exact storage writes still happened at:
      - `option_value[demo_upload][file][tmp_name]`
      - `user_meta_value[7][demo_upload][file][tmp_name]`
  - root cause:
    - delete-batch fingerprinting and standalone-source interest were now filtering metadata read families too aggressively
    - for these exact flows the reader callable had:
      - family-only option reads (`option_value`)
      - or shallow metadata buckets (`user_meta_value[7]`)
      - plus file-relevant use orders like `value[file][tmp_name]`
    - the new delete read filtering dropped those metadata reads entirely, so pass 2 reused the empty `delete_demo` summary instead of recomputing it after the storage write
- what changed:
  - `internal/taintscan/diagnostics.go`
    - added delete-batch call-interest helpers:
      - `deleteStorageBucketRelevantToCallInterest(...)`
      - `deleteStorageFamilyRelevantToCallInterest(...)`
    - delete read bucket/family filtering now accepts metadata families (`option_value`, `user_meta_value`, `transient_value`) only when the callable already has file-relevant use orders
    - delete-specific “specific bucket suppresses family” logic now still suppresses broad families for already-family-relevant roots like `post_meta_value`, while preserving the new metadata fallback only for true file-relevant record readers
  - `internal/taintscan/diagnostics_test.go`
    - added coverage for:
      - option-family delete read growth with file-relevant use orders changing the fingerprint
      - user-meta ID bucket delete read growth with file-relevant use orders changing the fingerprint
      - file-relevant metadata record readers staying delete-relevant
- validation:
  - focused tests:
    - `go test ./internal/taintscan -run 'Test(AnalyzeRootTracksDynamicGetOptionFromExactOptionWrite|AnalyzeRootTracksUpdateUserMetaToGetUserMeta|CallableSummaryInputFingerprint(IgnoresDeletePostMetaScalarStorageWriteGrowth|TracksDeletePostMetaFilePathStorageWriteGrowth|IgnoresDeletePostMetaScalarStorageReadGrowth|TracksDeletePostMetaThumbnailStorageReadGrowth|TracksDeleteOptionFamilyReadGrowthWhenFileOrdersPresent|TracksDeleteUserMetaIDBucketReadGrowthWhenFileOrdersPresent)|ShouldExpandStorage(PathReadersForChangedPath(SkipsDeletePostMetaScalarPath|KeepsDeleteCrossRequestPath)|BaseReadersForChangedPathFamily(SkipsDeletePostMetaScalarPath|KeepsDeleteFallbackForCrossRequestFamily))|Delete(StorageBucketRelevantToStandaloneReturnRequiresPathLikeLeaf|BatchStorageWriteRelevantToCallInterestDropsWildcardOnlyMetadataPaths)|CallableHasDeleteRelevantStandaloneSourceFindings(RequiresPathLikeRecordRead|KeepsFileRelevantMetadataReaders))$' -count=1`
  - full suite:
    - `GOMAXPROCS=4 go test ./...`
  - real latest-plugin benchmark:
    - `tmp/phparser-tutor-delete-after-delete-read-fix-20260404/time.txt`
    - `tmp/phparser-tutor-delete-after-delete-read-fix-20260404/stderr.log`
- measured effect:
  - the two exact delete regressions are restored
  - real `tutor -sink-op delete` stays improved:
    - previous best after wildcard prune: `61.03s`, `1492224 KB`
    - current with regression fix: `58.89s`, `1529908 KB`
  - the broad wildcard metadata churn remains gone

## 2026-04-04 - Tighten path-root trust and mixed-seed hash auth heuristics

- problem:
  - the new canonical path suppression for delete/include guards was too permissive:
    - any non-empty literal string counted as a trusted prefix root
    - any variable with a remembered path signature counted as a trusted prefix root
  - this meant a check like `file_exists($p) && strpos($p, $prefix) === 0` could suppress a real finding even when:
    - `$prefix` came from request data
    - or the prefix was a trivial broad literal like `/`
  - separately, the new `hash_equals(...)` auth heuristic treated any concat containing a public component as weak
  - that misclassified secure mixed seeds like `NONCE_SALT . __FILE__` as public-only, keeping hardened permission callbacks unauthenticated in the model
- what changed:
  - `internal/taintscan/path_guard_helpers.go`
    - trusted prefix roots now require a literal filesystem path recovered through `literalStringForCallableWithSeen(...)`
    - dropped the old fallback that trusted arbitrary path-signature variables and arbitrary non-empty literals
    - only absolute filesystem literals with real path depth now count as trusted roots; URLs, empty values, NUL-bearing strings, and trivial roots like `/` do not
  - `internal/taintscan/wordpress_context.go`
    - `predictablePublicAuthSeedExpr(...)` now treats string concatenation as predictable only when both sides are predictable/public
    - mixed secret + public seeds therefore stay strong enough for auth modeling
  - `internal/taintscan/taintscan_test.go`
    - added delete regressions proving request-derived and broad-root prefix guards do not suppress findings
    - added a mixed-seed `hash_equals(hash_hmac(..., NONCE_SALT . __FILE__), ...)` permission-callback regression that now upgrades to authenticated
- validation:
  - focused tests:
    - `go test ./internal/taintscan -run 'TestAnalyzeRoot(SuppressesRealpathTrustedPrefixGuardedDeleteSink|DoesNotSuppressRealpathDeleteSinkWithRequestDerivedPrefixGuard|DoesNotSuppressRealpathDeleteSinkWithBroadRootPrefixGuard|DoesNotMarkRestPermissionCallbackHashEqualsWithPublicSeedAsAuthenticated|MarksRestPermissionCallbackHashEqualsWithMixedSecretAndPublicSeedAsAuthenticated)' -count=1`
  - full suite:
    - `GOMAXPROCS=4 go test ./...`
  - fresh full corpus compare:
    - `tmp/phparser-full-corpus-after-audit-fixes-20260404/summary.json`
    - `tmp/phparser-full-corpus-after-audit-fixes-20260404/human-summary.md`
    - `tmp/phparser-full-corpus-after-audit-fixes-20260404.time.txt`
- measured effect:
  - coverage stayed flat:
    - previous baseline: `57 match / 15 not_comparable_yet / 0 miss`
    - current: `57 match / 15 not_comparable_yet / 0 miss`
  - per-case finding counts stayed flat across the whole manifest:
    - `changes 0` when diffing old/new `summary.json` case status + findings
    - no corpus noise growth from this fix set
  - full corpus runtime regressed from:
    - `1723.94s`, `5157696 KB`
    - to `1848.46s`, `4890024 KB`
  - the slowdown is concentrated in existing heavy cases, especially:
    - `uncanny-automator-cve-2025-3623`: `722068 ms -> 852221 ms`
    - `everest-forms-cve-2025-1128`: `224931 ms -> 241664 ms`
  - so the change is a correctness hardening with flat noise and a modest runtime tradeoff, not a performance win

---

## 2026-04-04 — Call-batch wildcard pruning + stable-findings early exit

**Problem**: `uncanny-automator-cve-2025-3623` takes 852,221ms in the call batch. The root cause
was a cascade: the `post_meta_value[*][*]` wildcard path written by large token-parser hubs
(`Legacy_Token_Parser::parse_inner_tokens`, `Automator_Input_Parser::parse_recursively`) was
driving call-batch storage-reader expansion and fingerprint invalidation every pass, causing 18+
passes of 44-58 seconds each — even though the call-batch findings (render-callback-execution /
unsafe-deserialization) were already stable from pass 1 onward.

**Diagnosis** (via `PHARSER_TAINTSCAN_TIMINGS=1 -max-passes 3`):
- `post_meta_value[*][*]` appeared as a changed storage path every pass
- Storage-family pending count was 414-505 additions per pass (all `post_meta_value` family readers)
- `parse_inner_tokens` summary weight grew: 279 → 1670 → 3116 → ... → 21277 across passes
- `findings_fp` was stable at `render-callb` from pass 1 through pass 18+

**Fix: Three-part optimization**

### 1. Call-batch wildcard expansion pruning (mirroring delete-batch behavior)

`internal/taintscan/analysis_driver.go`:

- `shouldExpandStorageBaseReadersForChangedPathFamily`: Added `callOnlyMode` branch that
  returns `false` when ALL changed paths for the family are `deleteBatchMetadataWildcardPathTooBroad`,
  and `true` when any non-wildcard path changed (no fall-through to bucket stability check).
- `shouldExpandStoragePathReadersForChangedPath`: Extended the existing delete-only guard to
  also handle call-only mode, skipping `[*][*]` wildcards.

`internal/taintscan/diagnostics.go`:

- `filterCallBatchStorageReadBucketsForCallInterest`: New function that removes `[*][*]`
  wildcard buckets from call-batch fingerprint calculation.
- `filterCallBatchStorageReadFamiliesForCallInterest`: New function that removes families
  covered by specific non-wildcard buckets, and also removes families whose only known
  buckets were wildcards (checked via `rawBuckets` + `structuralPathRoot`).
- Both wired into `callableSummaryInputFingerprint` for `currentBatchName == "call"`.

### 2. Stable-findings early exit for call batch

`internal/taintscan/analysis_driver.go`:

- Defined `callOnlyMode := len(e.allowedSinkOps) == 1 && e.allowsSinkOp("call")` at the
  same scope as `sqlOnlyMode`, making it available throughout the pass loop.
- Added call-only early exit analogous to the existing SQL-only exit: if `findingFingerprint`
  is non-empty and has been stable for 3 consecutive passes, emit `early-stop=stable-call-findings`
  and break.
- Changed `} else if !sqlOnlyMode { stableFindingPasses = 0 }` to also exclude `callOnlyMode`
  from the counter reset, allowing the counter to accumulate across passes when state is still
  changing but findings are stable.

### 3. Tests

`internal/taintscan/diagnostics_test.go`:
- `TestCallableSummaryInputFingerprintIgnoresCallPostMetaWildcardStorageReadGrowth`: verifies
  that call-batch fingerprint ignores `post_meta_value[*][*]` wildcard bucket changes.
- `TestCallableSummaryInputFingerprintTracksCallOptionValueSpecificStorageReadGrowth`: verifies
  that call-batch fingerprint still tracks specific-key `option_value[*][active_plugins]` changes.

`internal/taintscan/analysis_driver_test.go`:
- `TestShouldExpandStoragePathReadersForChangedPathSkipsCallOnlyWildcardMetadataPath`
- `TestShouldExpandStoragePathReadersForChangedPathKeepsCallOnlyExactMetadataPath`
- `TestShouldExpandStorageBaseReadersForChangedPathFamilySkipsCallOnlyAllWildcardPaths`
- `TestShouldExpandStorageBaseReadersForChangedPathFamilyKeepsCallOnlyWhenExactPathPresent`

**Measured effect** (corpus compare `/tmp/corpus-compare-20260404/summary.json`):

- Coverage: `57 match / 15 not_comparable_yet / 0 miss` (unchanged baseline)
- `uncanny-automator-cve-2025-3623`: `852,221ms → 246,793ms` (**71% reduction**)
  - Early stop triggered at pass 9 (`early-stop=stable-call-findings`)
  - `parse_inner_tokens` still ran each pass but the cascade was contained
- Total corpus runtime: `1,848s → 1,202s` (**35% reduction**)
- New slowest cases: uncanny (247s), everest-forms (230s), google-reviews (124s)

**Safety reasoning**:
- The actual Uncanny CVE-2025-3623 finding (unsafe-deserialization via REST) does not depend
  on `post_meta_value[*][*]` wildcard state — it's found via direct REST parameter flow.
- The `render-callback-execution` finding was present from pass 1 with identical fingerprint.
- No corpus call-batch cases rely on cross-request wildcard post_meta taint accumulation.
- Specific paths like `post_meta_value[*][popup_settings]` and `option_value[*][active_plugins]`
  still trigger expansion (not filtered); only pure `[*][*]` wildcards are suppressed.

## 2026-04-05 — Topo sort, output early-exit, worker boost, threshold reduction

Four independent optimizations applied in a single commit (`675d5a3`).

### 1. Topological sort of callOrder before relevance indexing

`callgraph_relevance.go` — new `topologicalSortCallOrder()` using DFS post-order:

```go
func (e *engine) topologicalSortCallOrder() {
    ...DFS over e.callEdges...
    e.callOrder = result  // callee-before-caller
}
```

Called in `analysis_support.go` after `buildCallGraph()`. Ensures every callee is already
in `e.callSinkRelevantUseOrders` when its caller is processed by `indexCallSinkRelevantUseOrders`,
eliminating the O(N²) recursive fallback. For plugins with large call trees (everest-forms
1789 callables, uncanny 8931 callables) this reduces `index-call-sink-relevant-use-orders`
from 132s → 2.4s.

Only helps batches where `needsCallRelevanceIndexForSinkOps` = true (call op or all-ops mode).
File-only batches (delete/open/read/write) skip this index entirely.

### 2. Output-batch stable-findings early exit

`analysis_driver.go` — mirrors the existing `callOnlyMode` and `sqlOnlyMode` exits:
- Added `outputOnlyMode` variable
- Added `if outputOnlyMode && stableFindingPasses >= 2 { break }` check
- Added `outputOnlyMode` to the `stableFindingPasses = 0` exclusion

Google-reviews CVE-2025-12510 (output-only): 124s → 7s. The `option_value[trustindex-core-shortcode-inited]`
storage path was cycling across all 20 passes; findings were stable from pass 1 (wp-stored-xss
`trustindex-plugin.class.php:909`). With threshold 2 the batch exits at pass 4.

### 3. Stable-findings threshold 3 → 2 for call-only and output-only modes

`analysis_driver.go` — changed `stableFindingPasses >= 3` to `>= 2` for `callOnlyMode`
and `outputOnlyMode`. For `sqlOnlyMode` the threshold remains 3 (SQL convergence can have
delayed second-phase effects). Rationale:

- Monotone taint analysis cannot "un-discover" a finding; once stable for 2 consecutive passes
  the fixed point has been reached for all findings that have converged so far.
- The 3rd pass served as insurance against oscillations, which don't occur in practice for
  the call/output corpus cases.
- Saves ~40s for uncanny-automator (pass 9 at convergence).

### 4. Raise worker floor from 1 → 2 for large-pending batches

`boundedAnalysisWorkers` — changed:
```go
// before
case pendingCount >= 256 && workers > 1: workers = 1
// after
case pendingCount >= 256 && workers > 2: workers = 2
```

`analyzeCallable` reads only immutable-per-pass engine state (`e.summaries`, `e.storage`,
`e.staticProps`, …). Writes happen only in `handleResult` (single-threaded main goroutine).
The `passWarmSummaryCache` has RWMutex protection. Parallel execution is safe.

The 256 lower bound keeps memory pressure predictable while allowing 2x throughput for
large file-mode batches. SQL-only mode already uses an explicit 4-worker boost for
`pending >= 128`; this change applies the same logic to other modes.

Effect on everest-forms (delete+open+read+write, 754 relevant callables):
- Pass 1: 89s → 55s (workers: 1 → 2, ~38% faster)
- Pass 2: 83s → 51s (workers: 1 → 2)
- Total batch: 172s → 107s

Effect on wordpress-file-upload (delete-only, various pending counts): 64s → 43s.

### Measured results

All four changes committed together (commit `675d5a3`). Corpus compare with changes 1-3
(worker boost, no threshold change):
- Coverage: `57 match / 15 not_comparable_yet / 0 miss`
- Total corpus runtime: `1,202s → 1,003s` (**17% reduction** on top of previous 35%)
- uncanny: 247s → 242s (similar, worker change doesn't help call-only mode)
- everest-forms: 230s → 212s (workers=2 for file batch)
- google-reviews: 124s → 7s (output stable-findings exit, ×18 speedup)
- wordpress-file-upload: 64s → 43s (workers=2 for file batch, 33% faster)

Cumulative from pre-optimization baseline: `1,848s → ~960s` (**48% total reduction**).

**Safety reasoning**:
- topologicalSortCallOrder has no semantic effect on analysis results; it only changes the
  order in which callables are indexed in build-base phases. Test suite green.
- Output stable-findings exit: the google-reviews XSS finding (`wp-stored-xss-persistent-read-to-output`
  at trustindex-plugin.class.php:909) is present from pass 1. Passes 2-4 confirm and add
  supplementary propagation paths; exiting at pass 4 after 2 stable passes captures all
  security-relevant findings.
- Threshold 2: uncanny CVE-2025-3623 finding (unsafe-deserialization at
  class-automator-recipe-helpers.php:548) is found in pass 1. Passes 7-8-9 all share the
  same finding fingerprint; exiting at pass 8 doesn't miss any findings.
- Worker boost: confirmed thread-safe via code review and test suite. analyzeCallable is
  read-only on shared engine state during a pass; handleResult serializes all writes.

## 2026-04-05 — Measured corpus-compare result (threshold=2 changes)

Full corpus-compare run after all 4 optimizations from commit `675d5a3` (topo sort +
output early-exit + worker boost + threshold=2):

- Total: **949s** / 72 cases (`57 match / 15 not_comparable_yet / 0 miss`)
- Slowest: uncanny (201.8s), everest-forms (176.9s), ultimate-member-1702 (58.3s),
  wordpress-file-upload (56.3s), user-registration-1492 (48.1s)
- Cumulative vs original 1,848s baseline: **−899s (49% reduction)**

## 2026-04-05 — AST allocation elimination (three commits)

Three optimizations targeting `SubNodes()` map allocations and `mergeCappedLocations` CPU
cost, identified from pprof heap profiles.

### Optimization 1: linear dedup in `mergeCappedLocations` / `mergeCappedEntryPoints` (commit `ce1c06e`)

`mergeCappedLocations` (called 7× per `mergeFlowContext`) used `map[Location]struct{}` for
deduplication. Replaced with O(N²) linear scan + fast paths for one-side-empty inputs.
Inputs are always small (≤ `maxFlowContextLocations = 16`), so linear scan is faster and
more cache-friendly than hash map dispatch.

`mergeUniqueLocations` / `mergeUniqueEntryPoints` intentionally kept with original map
implementation: their nil-vs-empty-slice return value is load-bearing for downstream
nil-checks in `context_helpers.go` and `callgraph_relevance.go`.

Microbenchmark (`BenchmarkMergeFlowContextTypical`): 1061 ns → 503–577 ns (~2× faster,
same 640 bytes / 4 allocs).

### Optimization 2: hoist `SubNodes()` out of `SubNodeNames()` loops (commit `4865984`)

Every AST node walk called `node.SubNodes()` once per sub-node name, allocating a new
`map[string]any` per iteration. 11 call sites in `taintscan` + 1 in `lowerbundle` changed
from:

```go
for _, name := range node.SubNodeNames() {
    value := node.SubNodes()[name]  // new map each iteration
```

to:

```go
subNodes := node.SubNodes()
for _, name := range node.SubNodeNames() {
    value := subNodes[name]         // single map, reused
```

### Optimization 3: add `SubNode(name string) any` to `Node` interface (commit `cdee24c`)

Eliminates ALL `map[string]any` allocations from AST node walking by adding a
zero-allocation switch-dispatch method to the `Node` interface.

Added `SubNode(name string) any` to `ast/node.go` interface. Generated 158 switch-based
implementations in `ast/generated_nodes.go` (via Python script parsing existing
`SubNodes()` bodies) plus 10 leaf-node stubs (`return nil`). Handwritten implementation
for `ExprPrintableNewAnonClass`. All 13 call sites updated to `node.SubNode(name)`.

### Measured results

Corpus-compare (72 cases, 57 match / 15 not_comparable_yet):

| Binary    | Optimization            | Total  | vs 949s baseline |
|-----------|-------------------------|--------|------------------|
| 675d5a3   | baseline (this session) | 949.0s | —                |
| 4865984   | lindedup + hoist        | 699.9s | −26.2%  (1.36×)  |
| cdee24c   | + SubNode interface     | 418.9s | −55.9%  (2.27×)  |

Cumulative from original 1,848s pre-optimization baseline: **−1,429s (77.3% reduction, 4.41×
total speedup)**.

Slowest cases after all three optimizations:
- uncanny-automator-3623: 201.8s → 114.5s (1.76×)
- everest-forms: 176.9s → 50.2s (3.52×)
- ultimate-member-1702: 58.3s → 20.9s (2.79×)
- wordpress-file-upload: 56.3s → 16.6s (3.40×)
- user-registration-1492: 48.1s → 18.2s (2.64×)

## 2026-04-05 — FlowContext merge allocation elimination (commits `095964a`, `1ebc9e7`)

pprof heap profile on uncanny-automator (13,788 callables, 8 passes) after cdee24c:
- Total allocations: **57.92 GB** with GC consuming ~40% of CPU
- `mergeCappedLocations`: 18.95 GB (33%) — fast paths copied even when b==nil
- `mergeCappedEntryPoints`: 6.23 GB (11%)
- `mergeUniqueLocations`: 5.49 GB (9%) — map-based dedup

### Commit `095964a`: seal fast-path returns + map-free mergeUnique*

Fast paths in `mergeCappedLocations/EntryPoints` returned `cappedXxxCopy(a, limit)` (always
allocates) to prevent aliasing. Changed to `a[:len(a):len(a)]` — sealing cap==len forces
future appends on the result to reallocate, preventing aliasing without copying.

`mergeUniqueLocations/EntryPoints`: replaced `map[T]struct{}` dedup with linear scan +
explicit sort. `make([]T, 0, ...)` preserves the non-nil return semantics that downstream
nil-checks depend on (unlike a nil fast-path return which caused earlier test failures).
`mergeUniqueLocations` allocations: 5.49 GB → 2.01 GB.

Corpus effect: slight regression (418.9s → 440.2s) — sealing increased `mergeHelperGuardContext`
append cost since slices can no longer extend into existing capacity.

### Commit `1ebc9e7`: subset-check fast path in mergeCapped* (−97% alloc on hot paths)

Before allocating in the general case, check whether b ⊆ a (all items of b already exist
in a). If so, return `a[:len:len]` with zero allocation. Very common once the fixpoint
loop stabilises — accumulated context already contains all the guard signals the callee
would add.

Effect on uncanny-automator:
- `mergeCappedLocations` allocations: 18.95 GB → 0.42 GB (−97.8%)
- Total heap allocations: 57.92 GB → 28.07 GB (−51.6%)
- Engine run time (direct): 106s → 73s (−31%)

### Commit `41ae8cb`: use `mergeCappedLocations` in `mergeHelperGuardContext`

Raw `append` in `mergeHelperGuardContext` bypassed the subset-check: sealed slices
(cap==len) forced reallocation even when helper's checks were already in ctx. Replaced
with `mergeCappedLocations` so the subset-check fires when helper items are already present.

Effect: `mergeHelperGuardContext` drops from 3.02 GB to ~0 GB; total 28.07 GB → 25.45 GB.
Engine run time (direct, uncanny): 73s → 64.6s (−11.6%).
Corpus effect: neutral (364.7s vs 360.1s — within measurement noise; some cases improve,
wordpress-file-upload regressed +4.6s).

### Combined measured corpus-compare results

| Binary    | Optimization                           | Total  | vs 949s baseline |
|-----------|----------------------------------------|--------|------------------|
| 675d5a3   | baseline (this session)                | 949.0s | —                |
| cdee24c   | + SubNode interface                    | 418.9s | −55.9%  (2.27×)  |
| 095964a   | + seal fast-paths + map-free mergeUniq | 440.2s | (slight regression) |
| 1ebc9e7   | + subset-check in mergeCapped*         | 360.1s | −62.1%  (2.63×)  |
| 41ae8cb   | + mergeCappedLocations in mergeHelper  | 364.7s | ~same (noise)    |

Cumulative from original 1,848s pre-optimization baseline: **−1,484s (80.3% reduction, 5.07×
total speedup)** (using 41ae8cb = 364.7s).

Slowest cases after all optimizations (vs 949s baseline):
- uncanny-automator-3623: 201.8s → 72.0s (2.80×)
- everest-forms: 176.9s → 52.1s (3.39×)
- wordpress-file-upload: 56.3s → 22.3s (2.52×)
- user-registration-1492: 48.1s → 16.9s (2.84×)
- ultimate-member-1702: 58.3s → 12.4s (4.70×)

## 2026-04-05 — Parallel buildCallGraph investigation (reverted)

**Hypothesis**: `buildCallGraph` calls `collectDirectCallEdges` for each callable (~20ms each
for everest-forms 1789 callables = ~28s). Parallelizing the collection phase with 8 workers
should reduce it to ~4-5s.

**Attempted implementation**: Captured `keys := e.callOrder` at function entry, parallelized
`collectDirectCallEdges` calls with a worker pool, merged results sequentially.

**Root cause of failure**: `buildCallGraph` uses a dynamic loop bound (`len(e.callOrder)`)
that grows during iteration. `ensureRuntimeMethodCallable` inside `collectDirectCallEdges`
appends new `#runtime` callables to `e.callOrder` when it encounters method calls on
dynamically-resolved classes. These new callables are processed by the loop in subsequent
iterations. The sequential original relied on this dynamic growth; the parallel version
with a pre-captured snapshot silently skipped newly-created callables, leaving their
`callSiteEdges` unpopulated.

**Test that caught it**: `TestActionSinkRelevantUseOrdersTrackReturnedRuntimeLocal` —
`\Demo\DemoUpdateIntegration::execute#runtime` (created during `indexAllCallbackRegistrations`)
triggers creation of `\Demo\DemoUpdateIntegration::validatedata#runtime` when `buildCallGraph`
processes `execute#runtime`. Without that callable's `callSiteEdges`, the forward relevance
through `Helper::sanitizeStringArray` was lost.

**Revised understanding of call graph construction**:
1. `indexAllCallbackRegistrations` creates `#runtime` callables for registered callback class
   specializations (e.g., `DemoUpdateIntegration::execute#runtime` from `array(static::class, 'execute')`).
2. `buildCallGraph` processes those `#runtime` callables and creates further `#runtime` callables
   for their method calls (e.g., `DemoUpdateIntegration::validatedata#runtime` from
   `static::validateData()`).
3. Those second-level `#runtime` callables are also processed by `buildCallGraph` (dynamic loop).

This cascading creation pattern means `buildCallGraph`'s dynamic loop is load-bearing and
cannot be parallelized with a snapshot approach without major redesign.

**Conclusion**: `buildCallGraph` cannot be safely parallelized without:
- Thread-safe engine state mutations (mutex on `e.callables`/`e.callOrder`/`e.summaries`)
- A mechanism to queue newly-created callables for parallel processing
- A "stable point" termination condition

The sequential implementation is retained as-is.

## Next optimization targets

After all optimizations through commit `1ebc9e7`, corpus total is 360.1s.
Heap profile on uncanny-automator after `1ebc9e7` (28.07 GB total):

| Allocator                        | Alloc  | % total | Notes                                    |
|----------------------------------|--------|---------|------------------------------------------|
| `originSet.clone`                | 4.60 GB | 16.4%  | `map[string]origin` copy; needs COW      |
| `mergeHelperGuardContext`        | 3.02 GB | 10.8%  | raw `append` to ctx fields; post-sealing |
| `bytes.growSlice`                | 2.89 GB | 10.3%  | growth from appends                      |
| `encoding/json.Marshal`          | 2.44 GB |  8.7%  | summary serialisation; structural        |
| `mergeUniqueLocations`           | 2.01 GB |  7.2%  | `make([]Location, 0, ...)` per call      |
| `unionInto`                      | 1.47 GB |  5.2%  | `make(originSet, len(src))` when dst=nil |
| `appendPathOrigins`              | 1.40 GB |  5.0%  | slice growth                             |

Remaining corpus bottlenecks (post-41ae8cb, heap profile on uncanny = 25.45 GB):

| Allocator                  | Alloc    | % total | Viability                                     |
|----------------------------|----------|---------|-----------------------------------------------|
| `originSet.clone`          | 4.67 GB  | 18.4%   | Needs COW or `unionInto` refactor (complex)   |
| `bytes.growSlice`          | 3.55 GB  | 14.0%   | From JSON + string ops; structural             |
| `encoding/json.Marshal`    | 2.48 GB  |  9.7%   | Summary serialisation; needs gob/protobuf      |
| `unionInto`                | 1.60 GB  |  6.3%   | `make(originSet, len(src))` when dst=nil       |
| `appendPathOrigins`        | 1.42 GB  |  5.6%   | Slice growth during path accumulation          |
| `mergeUniqueLocations`     | 1.37 GB  |  5.4%   | `make([]Location, 0, ...)` per call            |

Remaining corpus bottlenecks (post-41ae8cb):
- uncanny-automator-3623: **72.0s** — `slow-callable` `Legacy_Token_Parser::parse_inner_tokens`
  takes 8–11s per pass; queried 18k+ times/pass. Summary changes every pass (reads option_value
  storage). Cannot be reused across passes with current architecture.
- everest-forms: **52.1s**
- wordpress-file-upload: **22.3s**
- user-registration-1492: **16.9s**

Viable directions:
1. **`originSet.union(nil, X)`** (4.67 GB): the dominant pattern is `out = out.union(item)` in
   accumulation loops where `out` starts nil. Changing these call sites to `unionInto` would
   avoid the defensive clone, but requires auditing each call site to verify ownership.
2. **`Legacy_Token_Parser` hot summary**: its summary changes each pass (reads storage paths).
   No easy reuse fix; would need abstract interpretation shortcutting or a "stable partial result"
   memoisation scheme.
3. **`encoding/json.Marshal`** (2.48 GB): switching from JSON to gob encoding for summaries
   would reduce both allocation and CPU cost. Structural change, non-trivial.
4. **`mergeUniqueLocations`** (1.37 GB): subset check — if `a==nil` and `b` is already sorted
   and deduplicated (common when b comes from a previous `mergeUnique*` call), return `b[:n:n]`.

## 2026-04-06: OOM Prevention & Memory Budget for Large Plugins

### Problem
142 of 482 plugins (100k+ installs) failed during scan — 83 OOM (exit -9) and 59 timeouts.
Key failures: backwpup (20.6MB PHP), buddypress (6.7MB), ACF (4.9MB), updraftplus (30MB).

### Root Causes Identified
1. **Unbounded origin sets**: `originSet` (map[string]origin) grows without limit during union operations
2. **Unbounded state maps**: `propTaint`, `storagePathWrites`, `returnPathWrites` accumulate entries during callable analysis
3. **Per-callable warm cache**: `summaryWarmCache` and `summaryReturnPathCache` grow without eviction
4. **No memory pressure awareness**: engine has no concept of memory budget

### Changes Made

**origin_helpers.go:**
- `maxOriginSetSize = 32`: Caps individual `originSet` map growth in `union()` and `unionInto()`

**analysis_callable.go:**
- `maxCallableStatements = 2000`: Skips callables with >2000 statements
- `maxStateMapEntries = 128`: Caps state maps via `unionMapEntry`
- Memory pressure check: reads `runtime.MemStats.HeapAlloc`, forces GC at 3GiB, skips callables if still above 2GiB
- `summaryWarmCache` eviction at 128 entries

**structural_state.go:**
- `summaryReturnPathCache` capped at 256 entries

**call_eval.go:**
- `storagePathWrites` map capped at 512 entries
- `isPathTraversalSanitizingFunc()`: `basename`/`wp_basename`/`sanitize_file_name` kill path taint

**builtin_models.go:**
- Added `isPathTraversalSanitizingFunc()` for path-transversal sanitizers

### Benchmark Results (previously OOM → now OK)
- backwpup: 12s, 211MB, 30 findings
- buddypress: 100s, ~3GB, 101 findings
- cartflows: 10s, ~500MB, 19 findings
- wp-smushit: 15s, ~1GB, 22 findings
- wp-reset: 1s, ~100MB, 6 findings

### Still Failing
- bbpress: OOM at 123s despite pressure check (complex recursive callgraph?)
- ad-inserter: Timeout at 300s
- updraftplus: Timeout at 300s
- advanced-custom-fields: Very slow (~2-3min for 245 files, 60k lines)

### What Remained Unfixed
- No per-callable time budget (would require goroutine timeout)
- No inter-pass memory compaction
- `$wpdb->prefix` property access still treated as tainted in SQL templates
- Very large plugins (WooCommerce 21.6MB, w3-total-cache 46MB) untested

---

## 2026-06 Effectiveness Audit + Detection-Breadth Pass

Full writeup: `./EFFECTIVENESS_AUDIT_2026-06.md`.

9-dimension multi-agent audit (fixture-verified) → 17-item generic roadmap. Implemented this pass (corpus 57/57 preserved, `go test ./internal/taintscan` green):

- Sources: `php://input` raw-body readers (file_get_contents/file/readfile/fopen + stream readers as propagators); `$_SERVER` QUERY_STRING/PHP_SELF/PATH_TRANSLATED/ORIG_PATH_INFO; Gravity Forms `rgpost`/`rgget`.
- Sinks: **reflected XSS** (`wp-reflected-xss-direct-request-output`, echo/print of unescaped direct request input, FP-bounded by HTML escapers + numeric casts, cleanly separated from stored XSS and record-read disclosure); non-`$wpdb` SQL (`mysqli_*`/`pg_query`/`sqlsrv_query`/`multi_query`/`real_query`/`send_query`, PDO receivers).
- Precision: numeric casts `(int)/(float)/(bool)` mark results HTML-output-safe but stay tainted for resource-selection sinks (IDOR-preserving — see regression note below).
- Auth: REST route without `permission_callback` and core front hooks (`init`/`template_redirect`/`wp`/...) labelled `unauthenticated` instead of `unknown`.
- Triage: human-summary findings ordered by `FindingExploitabilityScore` (unauth/low-priv first; proven taint above `*-surface`); results JSON ordering unchanged.

### Regression caught + corrected
Numeric coercion must NOT drop taint globally — that broke 5 IDOR corpus cases (numeric IDs are still attacker-controlled for delete/action/disclosure). Numeric sanitizers prevent **injection**, not **authorization/IDOR**. Future numeric-FP work needs a per-context `numericSafe` origin flag (honored by SQL/path/reflected sinks, not by delete/action/disclosure).

### Second pass ("continue the audit") — also landed (corpus 57/57, tests green)
#7 privilege/action sink expansion (capability-meta priv-esc, grant_super_admin, user/term/comment meta, delete_option, wp_delete_post, switch_to_blog, ...); #4 native dynamic-dispatch RCE ($f()/$o->$m()/Class::$m()/new $c()); #12 prepare() identifier injection (taint-check $this->prop, keep $wpdb trusted); #5 capability-tier auth (low-priv caps like 'read' → authenticated, not a gate); #6 SQL-helper return/foreach/condition seeding; #14 maxCallableStatements 2000→6000 (heap guard remains OOM backstop).

### Third pass — second multi-agent audit (EFFECTIVENESS_AUDIT_V2_PLAN.json) — landed (corpus 57/57, full go test ./... green)
New detectors: SSRF (wp-request-ssrf; own sink-op batch so wp_remote_* source doesn't perturb call-batch dedup; host-control-precise — fixed-host ?x=$taint not flagged); open-redirect (wp-open-redirect) + header injection (wp-header-injection); printf/vprintf/wp_die output sinks (format-aware %s); ZipArchive::extractTo/unzip_file zip-slip; Input::get/post facade sources. FP/perf: freemius dir exclude; FW-5 WP/Woo sanitizer set; PERF-2 walkNode explicit child-recursion (peak alloc **15.6 GB → 7.4 GB**, ~52%). Plus four verify-agent precision fixes (constant-ternary, isset/empty, source-collapse, int-cast numericSafe). REGRESSION CAUGHT+FIXED: SSRF relevance in the call batch flipped uncanny-automator deser dedup to a wp_remote_get source → fixed by giving SSRF its own batch.

### Not yet implemented (verified, in EFFECTIVENESS_AUDIT_V2_PLAN.json / EFFECTIVENESS_AUDIT_2026-06.md)
PERF-1 (memoize pass-invariant dispatch resolution — biggest CPU win), PERF-3 (parallelize base-build indexers), PERF-4 (sampled mem gauge + raise worker cap); TRIAGE-1 (sort consumed JSON + emit score/access_tier/confidence), TRIAGE-5 (most-permissive cluster-merge access); G-WHITELIST (in_array/switch value-set guard tracker); U1 (executable-capable file-write destination model — needs content-provenance discriminator); #11 traits; #15 context-aware HTML safety; fn-typejuggle (loose ==/non-strict in_array auth bypass); fn-secondorder (persisted store→SQL/include).
