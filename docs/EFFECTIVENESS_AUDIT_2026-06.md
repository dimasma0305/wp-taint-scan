# phparser Effectiveness Audit — 2026-06

Goal: audit the native `phparser` taint engine and make it more effective at finding **real, exploitable** WordPress plugin vulnerabilities, without regressing the 72-case vulnerable-plugin corpus and while keeping every change generic (no plugin/CVE-specific logic).

## Method

1. **Baseline** — ran `cmd/corpus-compare` over the full corpus: **57/57 comparable cases matched** (15 cases have no local fixture). Peak ~15.6 GB / 60 s on the largest plugin (everest-forms); several plugins >10 GB.
2. **Multi-agent audit** — 9 specialist auditors (sources, injection sinks, XSS/output, file/upload/path, sanitizers, WP auth/context, interprocedural, false-positive/relevance, performance), each adversarially **verified with minimal PHP fixtures**, synthesized into a 17-item prioritized roadmap. Every item was `confirmed_by_fixture`.
3. **Implementation** — risk-ordered batches, each validated against the corpus (recall must stay 57/57) and `go test ./internal/taintscan`.

## Coverage snapshot (at audit time)

<!-- coverage table from the audit; "Implemented" column reflects this change set -->
| WP vuln class | Was | Now |
|---|---|---|
| Reflected XSS | **MISSING** | **Detected** (`wp-reflected-xss-direct-request-output`) |
| Stored XSS | Partial | Partial (unchanged; reflected/stored now cleanly separated) |
| SQLi | Partial ($wpdb only) | + `mysqli_*`, `pg_query`, `sqlsrv_query`, `multi_query`/`real_query`/`send_query`, PDO receivers |
| LFI/RFI, Path traversal | Partial | Partial (numeric-cast precision improved) |
| Raw request body (php://input) | **MISSING (source bug)** | **Detected** (file_get_contents/fopen+stream readers) |
| Unauth surface labelling | `unknown` for REST-no-permission / core front hooks | `unauthenticated` |
| Triage ordering | path/line only | exploitability-ranked (human summary) |

(The full original coverage table with file:line evidence is in the audit roadmap saved alongside this run.)

## Implemented in this change set (all generic; corpus 57/57 preserved)

### Sources
- **`php://input` raw request body** — `file_get_contents`/`file`/`readfile`/`fopen`/`fgets`/`stream_get_contents` on `'php://input'` are now request sources on every sink-op batch (`call_eval.go` `evalFuncCall`; fixed an `*ast.Arg` unwrap bug). Stream readers (`fread`/`fgets`/`fgetss`/`stream_get_contents`/`stream_get_line`) added as first-arg propagators so `fopen('php://input')` handle taint flows to its reads (`builtin_models.go isPropagatingFunc`). Recovers the dominant modern REST/AJAX JSON-body attack surface.
- **`$_SERVER` keys** — added `QUERY_STRING`, `PHP_SELF`, `PATH_TRANSLATED`, `ORIG_PATH_INFO` (`analysis_support.go superglobalSource`). `PHP_SELF`/`QUERY_STRING` are textbook reflected-XSS vectors.
- **Gravity Forms accessors** — `rgpost`/`rgget`/`rgpost_array`/`rgget_array` added as direct request sources (`builtin_models.go isDirectRequestSourceFunc`).

### Sinks
- **Reflected XSS** (`#1`, headline) — `echo`/`print` of a direct request origin that is not HTML-escaped now emits `wp-reflected-xss-direct-request-output` (`analysis_support.go addReflectedRequestOutputFinding`, wired into the `StmtEcho`/`ExprPrint` handlers; relevance via `callableHasDirectSink` echo gates + `outputSinkRelevantUseOrdersForCallable`). FP-bounded by HTML escapers (`esc_html`/`esc_attr`/`esc_url`/`wp_kses`/`sanitize_text_field`) and numeric casts.
  - Cleanly separated from stored XSS: origins carrying a `storedWriteContext` or `persistentRead` flag go to the stored-XSS path; record-read callables defer to the disclosure rule (no duplicate framing).
  - Respects the engine's literal-arg specialization (does not become a standalone root when the request→echo flow is behind a literal-guard branch), matching how SQL/file sinks behave.
- **Non-`$wpdb` SQL execution** — `mysqli_query`/`mysqli_multi_query`/`mysqli_real_query`/`mysqli_send_query`/`mysqli_prepare` (link-first arg index), `pg_query`/`pg_send_query`/`sqlsrv_query`, and methods `multi_query`/`real_query`/`send_query`; DB-receiver recognition extended to `pdo`/`mysqli` (`builtin_models.go`, `call_eval.go`).

### Precision / sanitizers
- **Numeric casts** `(int)`/`(float)`/`(bool)` mark their result **HTML-output-safe** (suppresses reflected-XSS FPs on the canonical `(int)$_GET['id']` idiom) while **keeping the taint** for resource-selection sinks (delete/action/disclosure), where a numeric value is still attacker-controlled (IDOR / missing-authorization). SQL safety is handled by the existing `sqlExecutionOrigins` re-walk. (`expression_eval.go`, `call_eval.go sqlExecutionOrigins`).

### Auth / entrypoint labelling
- **REST route without `permission_callback`** → `unauthenticated` (was `unknown`), so the auth-aware rules fire and it scores as the public surface it is (`state_summary_helpers.go restPermissionAccess`).
- **Core front hooks** (`init`/`wp_loaded`/`template_redirect`/`parse_request`/`wp`/`plugins_loaded`) → `unauthenticated` (`state_summary_helpers.go classifyHookEntryPoint`).

### Triage
- **Exploitability ranking** — the human summary now lists findings most-exploitable-first (unauthenticated/low-priv above admin-gated; proven taint above heuristic `*-surface`), via `FindingExploitabilityScore` (`helpers.go`), used in `cmd/taint-scan` `buildHumanSummary`. The machine-readable `taint-results.json` keeps its stable path/line ordering (no test/contract impact).

## A regression caught and fixed (recorded for future work)

First cut made numeric coercion **drop taint globally**, which broke 5 IDOR-style corpus cases (forminator file-deletion, wpforms action, ninja-forms disclosure, google-reviews) — there a numeric ID is still attacker-controlled. Corrected model: **numeric coercion is injection-safe (HTML/SQL/path metacharacters) but stays tainted for resource-selection sinks.** Also reverted an over-reach (`intval`/`floatval` marking results HTML-safe) that suppressed a stored-XSS case via container-field collapse, and separated reflected vs. stored origins by `storedWriteContext`.

Lesson: **numeric sanitizers prevent injection, not authorization/IDOR.** Any future numeric-sanitizer work must remain per-sink-context (a `numericSafe` origin flag honored by SQL/path/reflected sinks but not by delete/action/disclosure would let us also kill the remaining `$id=(int)$_GET; query($id)` SQL FP and the `echo intval($_GET)` reflected FP without regression).

## Implemented — second pass ("continue the audit")

All fixture-verified; corpus stayed **57/57** after each batch; `go test ./internal/taintscan` green.

### Privilege / sensitive-action sinks (#7)
- `update_user_meta`/`add_user_meta` (and `update_metadata`/`add_metadata` with `'user'`) writing a `*capabilities` / `*user_level` key → routed to `wp-request-tainted-privilege-mutation` (not cap-gated) via `capabilityMetaPrivilegeValueArgIndex` (`privilege_mutation_helpers.go`), checked before the generic action sink in `evalFuncCall`.
- `grant_super_admin` added to `privilegeMutationFuncArgPath` (arg 0 = attacker-chosen user id).
- `actionSinkModelByFunc` extended: user/term/comment meta {0,1,2}, `wp_create_user`/`wp_insert_attachment` {0,1,2}, `delete_option`/`delete_site_option`/`delete_network_option`, `wp_delete_post`/`wp_trash_post`/`wp_delete_attachment`/`wp_delete_user`/`wp_delete_comment`/`wp_delete_term`/`switch_to_blog` {0}. Relevance picked up automatically via the action-sink enumeration; the privilege path added to the `call`-batch relevance enumeration.

### Native dynamic-dispatch RCE (#4)
- `$f(...)`, `$arr['cb'](...)`, `$obj->$m(...)`, `Class::$m(...)`, `new $c(...)` with a request-tainted callable/class name → `unsafe-use` (gated on the `call` sink op + absence of a capability check, mirroring the `call_user_func` model). New `emitDynamicCallNameFinding`/`isDynamicCallNameExpr` (`call_eval.go`), wired into `evalFuncCall`/`evalMethodCall`/`evalStaticCall`/`ExprNew`, with matching relevance in `callableHasDirectSink`.

### prepare() identifier injection (#12)
- `isSafePreparedTemplateReceiver` no longer trusts `$this` — only `$wpdb` (framework constants). A `prepare()` template interpolating a `$this->prop` is now taint-checked at the call site, so `$this->table = $_GET['t']; $wpdb->prepare("... {$this->table} ...")` fires `tainted-sql-string` while `{$wpdb->prefix}` stays safe.

### Capability-tier auth (#5)
- New `capabilityCheckIsPrivileged` / `ctxHasPrivilegedCapabilityCheck` (`context_helpers.go`) reusing `capabilityToMinRole` + `roleHierarchy`. `deriveAccess` and `definitelyCapabilityGuarded` now require a **privileged** capability (above subscriber tier); a low-priv `current_user_can('read')` gate yields `authenticated` (still reported) instead of `capability_checked` (suppressed). Surfaces the subscriber/customer-exploitable missing-authorization class. (4 `WeakCapability*` unit tests updated to expect the now-correct `authenticated` label — finding counts unchanged.)

### SQL helper return/foreach/condition seeding (#6)
- `sqlSinkRelevantUseOrdersForCallable` now scans every statement's value expressions (return, foreach iterable, if/while/switch conditions, echo) for raw-SQL execution sinks — not just bare expression statements — so `return $wpdb->get_results("...".$tainted)` and `foreach ($wpdb->query(...))` seed SQL relevance across call boundaries. Clause-filter return seeding (posts_where etc.) preserved.

### Mega-handler coverage (#14)
- `maxCallableStatements` raised 2000 → 6000; the 3 GiB heap-pressure guard + per-callable state/origin caps remain the OOM backstop. Recovers request→sink detection in giant procedural admin-ajax/settings handlers (a `$_GET`→`$wpdb->query` SQLi that vanished at 2100 statements now fires).

## Real-plugin validation + precision hardening (third pass)

The corpus proves the engine hits the **real CVE sink** in 57 real vulnerable plugins, but only for the rules each case pins — and **no corpus case requires the new reflected-XSS rule**. So the new detections were, until this pass, validated only on synthetic fixtures. Running them against real plugin code (a 29-plugin sample of the 809-plugin tree, plus targeted scans) exposed real false positives that fixtures hid, and one clear real true-positive:

- **TRUE POSITIVE (real bug, real plugin):** `wp-google-map-plugin` `core/class.controller.php:146` — `$this->entityObj->$operation()` with `$operation = $_POST['operation']`, unauthenticated. Exactly the #4 dynamic-dispatch arbitrary-method-invocation primitive, found in real code.
- **False positives found & fixed:**
  - Output escapers missing from `isHTMLOutputSafeFunc`: `echo esc_url(...)`, `esc_js`, `json_encode`/`wp_json_encode`, `http_build_query`, and the attribute-flag helpers `selected/checked/disabled/wp_readonly` (which return a fixed token, never their args) were all flagged as reflected XSS. **Fix:** expanded the output-safe set with URL/JS/JSON escapers + attribute-flag helpers. **Bare `wp_kses` is deliberately kept unsafe** (a caller allowlist can still permit XSS — guarded by 3 stored-XSS unit tests).
  - `echo intval($_GET[...])` / `echo absint(...)` flagged as reflected XSS. **Fix:** a dedicated `numericSafe` origin flag (set by intval/absint/floatval/array_map-thereof) that the **reflected** path drops but the **stored-XSS** path ignores — so the FP is killed without re-suppressing the ninja-forms stored XSS (where container-field collapse makes a numeric helper falsely cover a string sibling). Explicit `(int)/(float)/(bool)` casts already mark output-safe.

Effect on the worst sample plugin: reflected findings **41 → 21** (unique sink lines 18 → 7); the egregious FPs gone, the remainder either real (a `$_POST`→logger debug XSS) or low-priority `capability_checked` framework code (ranked down by #8). Reflected XSS is still the highest-volume new rule (~43% of sample findings) and ~80% of those are `capability_checked` admin self-XSS — the exploitability ranking surfaces the unauth/nonce-only ones first.

**Residual known FPs (documented, not yet fixed):** guard-unaware over-approximation (e.g. a dynamic call constrained by an `in_array($x, $allowlist)` whitelist the engine doesn't model; a `request → DB → escaped read` flow), and `echo get_the_title($request_id)` (stored title, attribution to the request id). These need value-set/guard tracking (related to #15).

## Second multi-agent audit + implementation (pass 2)

A second 8-dimension audit (`EFFECTIVENESS_AUDIT_V2_PLAN.json`) grounded in the 430-finding real-plugin dataset produced a 27-item plan (perf, systematic FP, missing classes, guards, interprocedural, triage, upload, framework). Landed this pass (corpus 57/57, `go test ./internal/taintscan` green, fixture-verified):

- **#2 Freemius exclude** — `defaultExcludedDirs()` adds `freemius` (bundled SDK: ~5k files/plugin, out of scope, large noise + parse-time source).
- **#10 FW-5 sanitizers** — `isHTMLOutputSafeFunc` += `esc_xml`/`tag_escape`/`sanitize_hex_color(_no_hash)`/`sanitize_mime_type`/`wp_filter_nohtml_kses`/`antispambot`/`number_format(_i18n)` and WooCommerce `wc_clean`/`wc_sanitize_*` (XSS-context only; cuts the highest-volume rule's FPs).
- **#14 FW-2 facade sources** — `isRequestGetterStaticCall` += `Input::get/post/query`, `Request::post/query` (Laravel/wpfluent idiom; restores Tutor LMS-class recall).
- **#13 FW-4 output sinks** — `printf`/`vprintf`/`wp_die` modeled as reflected/stored-XSS output sinks (`directOutputFuncArgIndexes`); `printf` is **format-aware** (`%s` only, so `printf("...%d", $_GET['n'])` is not an FP); `wp_die` keeps its guard role *and* gains output-sink modeling.
- **#15 archive-extraction** — `ZipArchive::extractTo` (arg0, archive-receiver gated) and `unzip_file($file,$to)` destination → zip-slip/RCE.
- **#12 SSRF** (`wp-request-ssrf`) — request URL into `wp_remote_*`/`wp_safe_remote_*` (piggybacked on the `call` op; no new batch). **Host-control precision**: `requestControlsURLHost` fires only when the tainted part can influence the URL host — a fixed `http://host/?x=$taint` query-param flow is NOT flagged. Confirmed real TP: clearfy `components/cache/includes/todo_cdn.php`.
- **#19 open-redirect + header injection** (`wp-open-redirect`, `wp-header-injection`) — `wp_redirect`/`header()` with request taint (on the `action` op). `wp_safe_redirect` correctly excluded (host-validates by design).
- **#3 PERF-2** — `walkNode` (`ast_helpers.go`) given explicit child-recursion for the hot fall-through node types (ExprTernary/ExprArray/StmtForeach/StmtSwitch/StmtCase/Isset/Empty/BooleanNot/New/Return/Echo/AssignOpConcat/common BinaryOps), removing the `SubNodeNames()`/`SubNode()` per-node slice allocation that dominated profiling (~70–80% of per-batch allocations). Order/coverage identical.

Also picked up four precision fixes landed by the audit's verification agents (kept, corpus-validated): constant-ternary condition is no longer taint (a ternary's value is its branch, not its condition); `isset`/`empty` boolean-taint suppression; reflected/stored-XSS source-collapse; int-cast `numericSafe` at SQL sinks. Together these cut a 28-plugin real sample 430→259 (~40%).

### Still open (top of the 27-item plan, for follow-up)
PERF-1 (memoize pass-invariant dispatch resolution — the biggest CPU win), PERF-3 (parallelize base-build indexers), PERF-4 (sampled mem gauge + raise worker cap); TRIAGE-1 (sort consumed JSON + emit score/access_tier/confidence) and TRIAGE-5 (most-permissive cluster-merge access); G-WHITELIST (value-set guard tracker for `in_array`/switch allowlists); U1 (executable-capable file-write destination model — ~94% of file-upload FPs, needs content-provenance discriminator to keep 57/57); ipc-1 (PHP traits); fn-typejuggle (loose `==`/non-strict `in_array` auth bypass); fn-secondorder (persisted-store→SQL/include).

## Validation

- Corpus recall: **57/57** comparable cases (no regression) after each batch.
- `go test ./internal/taintscan`: green.
- Minimal-fixture confirmations for every new detection and FP boundary.
- Real-plugin spot-checks: new detections produce real true positives (dynamic-dispatch RCE in wp-google-map; SSRF in clearfy); high-frequency real-world FPs identified and fixed (escapers, numeric coercion, SSRF fixed-host).

## Remaining prioritized roadmap (verified, not yet implemented)

Done so far: **#1, #2, #3, #4, #5, #6, #7, #8, #9, #10, #12, #14, #17(partial)**. Still open, highest value first:

- **#13 Perf cliffs** — move per-callable `runtime.ReadMemStats` to a pass boundary; share batch-independent structures read-only across the 9 sink-op batches (currently ~9× redundant recompute; peak ~15 GB on the largest plugins blocks parallel mass scanning). Largest scale win; semantics-preserving but touches hot paths.
- **#11 PHP traits** — collect trait method bodies and merge `use Trait` into the class (modern OOP plugins hide handlers/DB/file helpers in traits; entirely unmodeled).
- **#15 Context-aware HTML safety** — body vs attribute vs JS vs URL escaper sets (`sanitize_text_field` is not attribute/JS-safe; pairs with reflected XSS for attribute-context detection). Also enables a per-context `numericSafe` origin flag that would let numeric coercion kill SQL/path/reflected FPs without dropping IDOR taint, and safe `printf`/`_e` output-sink modeling.
- **#16 Upload type-validation bypass** — `upload_mimes`/`image_sideload_extensions` filter weakening and `test_type => false` in `wp_handle_upload`.
- **#17 (remainder)** — `get_comment_meta` stored-read source and `sanitize_sql_orderby`/`floatval`/`boolval` sanitizers were deferred (the latter caused the ninja-forms stored-XSS suppression — needs the per-context `numericSafe` flag from #15 first).

Refuted / deprioritized by verification (do not pursue blindly): preg_replace `/e` (removed in PHP 7), phar:// deserialization (partially covered by path sinks), the low-priv relevance-prune over-suppression claim (not reproducible).
