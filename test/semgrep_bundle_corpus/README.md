# Semgrep Bundle Corpus

This directory holds a reusable regression corpus for
`.agents/skills/authoring-semgrep-rules/scripts/run_semgrep_php_lowered_bundle.py`.

The corpus is based on 20 notable WordPress plugin CVE targets supplied for
bundle-script testing. It stores:

- `corpus.json`: the plugin/case manifest
- `fixtures/`: durable synthetic PHP smoke targets for lowerer/regression tests
- `plugins/`: test fixtures copied or downloaded for the corpus
- `artifacts/`: fixture-local helper files only
- `download_corpus_plugins.py`: populate `plugins/`
- `run_bundle_corpus.py`: execute the lowered-bundle scan across the corpus
- `update_test_report.py`: regenerate `test/report.md` from a corpus `summary.json`

## Important behavior

- WordPress.org cases are copied from `bugbounty-note/wordpress/wp_install/plugins`
  first when available.
- Corpus scans prefer the installed plugin copy under
  `bugbounty-note/wordpress/wp_install/plugins/` so Semgrep does not trip over
  the repo's `test/`-path exclusions.
- Durable synthetic smoke targets should live in
  `test/semgrep_bundle_corpus/fixtures/` instead of `tmp/`. The
  `give_like_return_hook/` fixture is the canonical regression for helper
  returns plus hook dispatch plus persistence bridging.
- Cases can pin one or more Semgrep configs in `corpus.json`, so each CVE is
  tested against the relevant rule family instead of the entire default ruleset.
- Cases with `install_version` are pinned to that vulnerable version and are
  downloaded directly from WordPress.org version archives into case-specific
  fixture directories.
- If a non-pinned WordPress.org case is missing locally, the downloader can fetch
  the latest public release into `test/semgrep_bundle_corpus/plugins/`.
- Premium or closed plugins are tracked in the manifest but marked as manual
  fixtures. Drop them into `plugins/<slug>/` if you want them included.
- You can mirror the pinned corpus fixtures into
  `bugbounty-note/wordpress/wp_install/plugins` with `--also-install-local`.
- Scan outputs are written outside both `test/` and `artifacts/` under
  `tmp/semgrep-bundle-corpus/`. `test/` is excluded by the Semgrep rules in
  this repo, and `artifacts/` is ignored by the nested `artifacts/.gitignore`.

## Commands

Populate the corpus fixture directory:

```bash
python3 test/semgrep_bundle_corpus/download_corpus_plugins.py
```

Install the pinned vulnerable fixtures into both the corpus tree and the local
WordPress plugin tree:

```bash
python3 test/semgrep_bundle_corpus/download_corpus_plugins.py --refresh --also-install-local
```

Run the full default ruleset against the corpus:

```bash
python3 test/semgrep_bundle_corpus/run_bundle_corpus.py
```

Run only one case:

```bash
python3 test/semgrep_bundle_corpus/run_bundle_corpus.py --case-id wp-reset-cve-2023-6799
```

Download missing WordPress.org fixtures during the run:

```bash
python3 test/semgrep_bundle_corpus/run_bundle_corpus.py --download-missing
```

Outputs land under `tmp/semgrep-bundle-corpus/<timestamp>/`.

The durable human-readable tracker lives at `test/report.md`. Generate or refresh
it after a corpus run with:

```bash
python3 test/semgrep_bundle_corpus/update_test_report.py \
  --summary tmp/semgrep-bundle-corpus/<timestamp>/summary.json \
  --output test/report.md
```

Coverage checks can now assert both:

- vulnerable files/functions made it into the lowered bundle
- Semgrep produced a real request-source to sink `dataflow_trace` for selected cases

Preferred strict trace fields in `corpus.json`:

- `trace_source_strings_any`
- `trace_sink_strings_any`
- `trace_sink_locations_any`
- `bridge_read_locations_any` for lowered bridge cases where the trace sink stays synthetic
