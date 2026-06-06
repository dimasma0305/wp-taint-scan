#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


TEST_ROOT = Path(__file__).resolve().parent
REPO_ROOT = TEST_ROOT.parents[1]
MANIFEST_PATH = TEST_ROOT / "corpus.json"
CORPUS_PLUGINS_DIR = TEST_ROOT / "plugins"
CORPUS_ARTIFACTS_DIR = REPO_ROOT / "tmp" / "semgrep-bundle-corpus"
WP_INSTALL_PLUGINS_DIR = REPO_ROOT / "bugbounty-note" / "wordpress" / "wp_install" / "plugins"
LOWERED_RUNNER = (
    REPO_ROOT
    / ".agents"
    / "skills"
    / "authoring-semgrep-rules"
    / "scripts"
    / "run_semgrep_php_lowered_bundle.py"
)
DEFAULT_CONFIGS = [
    REPO_ROOT / "bugbounty-note" / "semgrep" / "sqli.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "file-upload.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "path-transversal.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "backdoor.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "privilege-escalation.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "xss.yaml",
    REPO_ROOT / "bugbounty-note" / "semgrep" / "unsafe-use.yaml",
]


class CorpusError(RuntimeError):
    pass


PLUGIN_VERSION_RE = re.compile(r"^\s*\*\s+Version\s+(.+)$", re.M)
PLUGIN_HEADER_VERSION_RE = re.compile(r"^\s*Version:\s*(.+)$", re.M)
README_STABLE_TAG_RE = re.compile(r"^\s*Stable tag:\s*(.+)$", re.M | re.I)


def load_manifest(path: Path = MANIFEST_PATH) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not isinstance(cases, list):
        raise CorpusError(f"invalid manifest: {path}")
    return cases


def case_matches(case: dict[str, Any], selected_case_ids: set[str], selected_slugs: set[str]) -> bool:
    if selected_case_ids and str(case.get("case_id", "")) not in selected_case_ids:
        return False
    if selected_slugs and str(case.get("slug", "")) not in selected_slugs:
        return False
    return True


def case_fixture_dir(case: dict[str, Any]) -> str:
    value = str(case.get("fixture_dir", "")).strip()
    return value or str(case.get("slug", "")).strip()


def case_slug_candidates(case: dict[str, Any]) -> list[str]:
    values = [case_fixture_dir(case), str(case.get("slug", "")).strip()]
    values.extend(str(item).strip() for item in case.get("local_candidates", []) if str(item).strip())
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def resolve_plugin_dir(case: dict[str, Any], roots: list[Path]) -> Path | None:
    for root in roots:
        for candidate in case_slug_candidates(case):
            plugin_dir = root / candidate
            if plugin_dir.is_dir():
                return plugin_dir
    return None


def detect_plugin_version(plugin_dir: Path) -> str:
    info_path = plugin_dir / "wordpress_plugin_info.json"
    if info_path.exists():
        try:
            payload = json.loads(info_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        for key in ("requested_version", "version"):
            value = str(payload.get(key, "")).strip()
            if value:
                return value

    for candidate in plugin_dir.glob("*.php"):
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        match = PLUGIN_HEADER_VERSION_RE.search(text[:20000])
        if match:
            return match.group(1).strip()

    for name in ("readme.txt", "README.txt", "readme.md", "README.md"):
        candidate = plugin_dir / name
        if not candidate.exists():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        match = README_STABLE_TAG_RE.search(text[:20000])
        if match:
            return match.group(1).strip()

    return ""


def fetch_wporg_plugin_info(slug: str) -> dict[str, Any]:
    params = urllib.parse.urlencode(
        {
            "action": "plugin_information",
            "request[slug]": slug,
            "request[fields][sections]": "0",
            "request[fields][description]": "0",
            "request[fields][banners]": "0",
            "request[fields][reviews]": "0",
        }
    )
    url = f"https://api.wordpress.org/plugins/info/1.2/?{params}"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if isinstance(payload, dict) and payload.get("error"):
        raise CorpusError(f"wp.org lookup failed for {slug}: {payload['error']}")
    if not isinstance(payload, dict) or not payload.get("slug"):
        raise CorpusError(f"invalid wp.org payload for {slug}")
    return payload


def copy_plugin_tree(source_dir: Path, destination_root: Path, destination_name: str, refresh: bool = False) -> Path:
    destination = destination_root / destination_name
    if destination.exists() and refresh:
        shutil.rmtree(destination)
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_dir, destination)
    return destination


def copy_local_plugin(source_dir: Path, corpus_plugins_dir: Path, slug: str, refresh: bool = False) -> Path:
    return copy_plugin_tree(source_dir, corpus_plugins_dir, slug, refresh=refresh)


def download_wporg_plugin(
    slug: str,
    corpus_plugins_dir: Path,
    refresh: bool = False,
    version: str = "",
    destination_name: str = "",
    plugin_name: str = "",
) -> tuple[Path, dict[str, Any]]:
    requested_version = version.strip()
    destination_name = destination_name.strip() or slug
    metadata: dict[str, Any]
    destination = corpus_plugins_dir / destination_name
    if destination.exists():
        detected_version = detect_plugin_version(destination)
        version_ok = not requested_version or detected_version == requested_version
        if refresh or not version_ok:
            shutil.rmtree(destination)
        else:
            return destination, {"slug": slug, "version": detected_version}

    if requested_version:
        metadata = {
            "name": plugin_name or slug,
            "slug": slug,
            "version": requested_version,
        }
        download_link = f"https://downloads.wordpress.org/plugin/{slug}.{requested_version}.zip"
    else:
        metadata = fetch_wporg_plugin_info(slug)
        download_link = str(metadata.get("download_link", "")).strip()
        if not download_link:
            download_link = f"https://downloads.wordpress.org/plugin/{slug}.zip"

    corpus_plugins_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"{slug}-wporg-") as tmpdir:
        tmp_root = Path(tmpdir)
        archive_name = f"{destination_name}.zip"
        archive_path = tmp_root / archive_name
        try:
            urllib.request.urlretrieve(download_link, archive_path)
        except Exception as exc:
            raise CorpusError(f"download failed for {slug} {requested_version or 'latest'}: {exc}") from exc
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(tmp_root / "extract")
        extracted_dirs = [entry for entry in (tmp_root / "extract").iterdir() if entry.is_dir()]
        if len(extracted_dirs) != 1:
            raise CorpusError(f"unexpected archive layout for {slug}: {download_link}")
        shutil.move(str(extracted_dirs[0]), destination)
    info_path = destination / "wordpress_plugin_info.json"
    info_path.write_text(
        json.dumps(
            {
                "name": metadata.get("name", plugin_name or slug),
                "slug": slug,
                "version": metadata.get("version", ""),
                "requested_version": requested_version,
                "download_link": download_link,
                "source": "wporg",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination, metadata


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def utc_stamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
