#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from corpus_lib import (
    CORPUS_PLUGINS_DIR,
    MANIFEST_PATH,
    WP_INSTALL_PLUGINS_DIR,
    CorpusError,
    case_matches,
    case_fixture_dir,
    copy_plugin_tree,
    copy_local_plugin,
    detect_plugin_version,
    download_wporg_plugin,
    load_manifest,
    resolve_plugin_dir,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Populate test/semgrep_bundle_corpus/plugins from local WordPress plugins or WordPress.org."
    )
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--plugins-dir", default=str(CORPUS_PLUGINS_DIR))
    parser.add_argument("--local-plugins-dir", default=str(WP_INSTALL_PLUGINS_DIR))
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--slug", action="append", default=[])
    parser.add_argument("--no-download-missing", action="store_true")
    parser.add_argument("--also-install-local", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest_path = Path(args.manifest).resolve()
    plugins_dir = Path(args.plugins_dir).resolve()
    local_plugins_dir = Path(args.local_plugins_dir).resolve()
    selected_case_ids = {value.strip() for value in args.case_id if value.strip()}
    selected_slugs = {value.strip() for value in args.slug if value.strip()}
    allow_download = not args.no_download_missing

    summary: list[dict[str, str]] = []
    for case in load_manifest(manifest_path):
        if not case_matches(case, selected_case_ids, selected_slugs):
            continue
        slug = str(case["slug"])
        case_id = str(case["case_id"])
        fixture_dir = case_fixture_dir(case)
        source_type = str(case.get("source_type", ""))
        install_version = str(case.get("install_version", "")).strip()
        record = {
            "case_id": case_id,
            "slug": slug,
            "fixture_dir": fixture_dir,
            "source_type": source_type,
            "status": "",
            "plugin_dir": "",
            "plugin_version": "",
            "local_plugin_dir": "",
            "note": "",
        }

        existing = resolve_plugin_dir(case, [plugins_dir])
        existing_version = detect_plugin_version(existing) if existing is not None else ""
        if existing is not None and (not install_version or existing_version == install_version):
            record["status"] = "present"
            record["plugin_dir"] = str(existing)
            record["plugin_version"] = existing_version
            if args.also_install_local:
                local_copy = copy_plugin_tree(existing, local_plugins_dir, fixture_dir, refresh=args.refresh)
                record["local_plugin_dir"] = str(local_copy)
            summary.append(record)
            continue

        local_match = resolve_plugin_dir(case, [local_plugins_dir]) if not install_version else None
        if local_match is not None and not install_version:
            copied = copy_local_plugin(local_match, plugins_dir, fixture_dir, refresh=args.refresh)
            record["status"] = "copied_from_local"
            record["plugin_dir"] = str(copied)
            record["plugin_version"] = detect_plugin_version(copied)
            if args.also_install_local:
                record["local_plugin_dir"] = str(local_match)
            summary.append(record)
            continue

        if not source_type.startswith("wporg"):
            record["status"] = "manual_fixture_required"
            record["note"] = str(case.get("notes", "")).strip() or source_type
            summary.append(record)
            continue

        if not allow_download:
            record["status"] = "missing"
            record["note"] = "download disabled"
            summary.append(record)
            continue

        try:
            downloaded, metadata = download_wporg_plugin(
                slug,
                plugins_dir,
                refresh=args.refresh,
                version=install_version,
                destination_name=fixture_dir,
                plugin_name=str(case.get("plugin_name", "")).strip(),
            )
        except CorpusError as exc:
            record["status"] = "download_error"
            record["note"] = str(exc)
            summary.append(record)
            continue

        record["status"] = "downloaded"
        record["plugin_dir"] = str(downloaded)
        record["plugin_version"] = detect_plugin_version(downloaded)
        record["note"] = str(metadata.get("version", ""))
        if args.also_install_local:
            local_copy = copy_plugin_tree(downloaded, local_plugins_dir, fixture_dir, refresh=args.refresh)
            record["local_plugin_dir"] = str(local_copy)
        summary.append(record)

    payload = {
        "manifest": str(manifest_path),
        "plugins_dir": str(plugins_dir),
        "results": summary,
        "counts": {
            "present": sum(1 for item in summary if item["status"] == "present"),
            "copied_from_local": sum(1 for item in summary if item["status"] == "copied_from_local"),
            "downloaded": sum(1 for item in summary if item["status"] == "downloaded"),
            "manual_fixture_required": sum(1 for item in summary if item["status"] == "manual_fixture_required"),
            "download_error": sum(1 for item in summary if item["status"] == "download_error"),
            "missing": sum(1 for item in summary if item["status"] == "missing"),
        },
    }
    write_json(plugins_dir.parent / "download-summary.json", payload)
    for item in summary:
        note = f" note={item['note']}" if item["note"] else ""
        plugin_dir = f" dir={item['plugin_dir']}" if item["plugin_dir"] else ""
        version = f" version={item['plugin_version']}" if item["plugin_version"] else ""
        local_dir = f" local_dir={item['local_plugin_dir']}" if item["local_plugin_dir"] else ""
        print(f"{item['case_id']}: {item['status']}{plugin_dir}{local_dir}{version}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
