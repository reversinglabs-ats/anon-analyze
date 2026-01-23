#!/usr/bin/env python3
"""Release automation script for anon-analyze.

Commands:
    prepare VERSION  - Update version, move Unreleased to new section, commit and tag
    publish          - Create GitHub release from CHANGELOG.md for current version
    changelog        - Show unreleased changes and recent commits
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
REPO_URL = "https://github.com/reversinglabs-ats/anon-analyze"


def run(cmd: list[str], capture: bool = False, check: bool = True) -> subprocess.CompletedProcess:
    """Run a shell command."""
    return subprocess.run(cmd, capture_output=capture, text=True, check=check)


def get_current_version() -> str:
    """Get version from pyproject.toml."""
    content = PYPROJECT_PATH.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if not match:
        sys.exit("Could not find version in pyproject.toml")
    return match.group(1)


def extract_release_notes(version: str) -> str:
    """Extract release notes for a specific version from CHANGELOG.md."""
    content = CHANGELOG_PATH.read_text()
    # Match from version header to next version header or end
    pattern = rf"## \[{re.escape(version)}\][^\n]*\n(.*?)(?=\n## \[|$)"
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        sys.exit(f"Could not find version {version} in CHANGELOG.md")
    notes = match.group(1).strip()

    # Append Docker image section
    docker_section = f"""
---

## Docker Image

```bash
docker pull ghcr.io/reversinglabs-ats/anon-analyze:{version}
```

[View on GitHub Container Registry]({REPO_URL}/pkgs/container/anon-analyze)"""

    return notes + docker_section


def cmd_changelog(args: argparse.Namespace) -> None:
    """Show unreleased changes and recent commits."""
    print("=== Unreleased Changes ===\n")

    content = CHANGELOG_PATH.read_text()
    pattern = r"## \[Unreleased\]\n(.*?)(?=\n## \[)"
    match = re.search(pattern, content, re.DOTALL)
    unreleased = match.group(1).strip() if match else "(empty)"
    print(unreleased if unreleased else "(no unreleased changes)")

    print("\n=== Recent Commits ===\n")
    result = run(["git", "log", "--oneline", "-10"], capture=True)
    print(result.stdout)


def cmd_prepare(args: argparse.Namespace) -> None:
    """Prepare a new release."""
    version = args.version.lstrip("v")
    current = get_current_version()

    print(f"Preparing release v{version} (current: v{current})")

    # Check for uncommitted changes
    result = run(["git", "status", "--porcelain"], capture=True)
    if result.stdout.strip():
        sys.exit("Error: Uncommitted changes exist. Commit or stash them first.")

    # Update pyproject.toml version
    pyproject = PYPROJECT_PATH.read_text()
    pyproject = re.sub(
        r'^(version\s*=\s*)"[^"]+"',
        f'\\1"{version}"',
        pyproject,
        flags=re.MULTILINE,
    )
    PYPROJECT_PATH.write_text(pyproject)
    print(f"Updated pyproject.toml version to {version}")

    # Update CHANGELOG.md
    from datetime import date

    today = date.today().isoformat()
    changelog = CHANGELOG_PATH.read_text()

    # Replace [Unreleased] section header with new version
    changelog = re.sub(
        r"## \[Unreleased\]",
        f"## [Unreleased]\n\n## [{version}] - {today}",
        changelog,
    )

    # Update comparison links
    changelog = re.sub(
        rf"\[Unreleased\]: {re.escape(REPO_URL)}/compare/v[\d.]+\.\.\.HEAD",
        f"[Unreleased]: {REPO_URL}/compare/v{version}...HEAD",
        changelog,
    )

    # Add new version link after Unreleased link
    prev_version = current
    new_link = f"[{version}]: {REPO_URL}/compare/v{prev_version}...v{version}"
    changelog = re.sub(
        r"(\[Unreleased\]: [^\n]+\n)",
        f"\\1{new_link}\n",
        changelog,
    )

    CHANGELOG_PATH.write_text(changelog)
    print(f"Updated CHANGELOG.md with version {version}")

    # Git commit and tag
    run(["git", "add", str(PYPROJECT_PATH), str(CHANGELOG_PATH)])
    run(["git", "commit", "-m", f"Release v{version}"])
    run(["git", "tag", "-a", f"v{version}", "-m", f"Release v{version}"])

    print(f"\nRelease v{version} prepared!")
    print("\nNext steps:")
    print("  git push && git push --tags")
    print("  # GitHub Actions will auto-create the release, or run:")
    print("  python scripts/release.py publish")


def cmd_publish(args: argparse.Namespace) -> None:
    """Create GitHub release from CHANGELOG.md."""
    version = args.version or get_current_version()
    print(f"Creating GitHub release for v{version}")

    notes = extract_release_notes(version)
    if not notes:
        sys.exit(f"No release notes found for version {version}")

    # Check if release already exists
    result = run(
        ["gh", "release", "view", f"v{version}"],
        capture=True,
        check=False,
    )
    if result.returncode == 0:
        print(f"Release v{version} already exists. Updating...")
        run(
            [
                "gh",
                "release",
                "edit",
                f"v{version}",
                "--notes",
                notes,
            ]
        )
    else:
        run(
            [
                "gh",
                "release",
                "create",
                f"v{version}",
                "--title",
                f"v{version}",
                "--notes",
                notes,
            ]
        )

    print(f"Release v{version} published!")
    print(f"View at: {REPO_URL}/releases/tag/v{version}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # changelog command
    subparsers.add_parser("changelog", help="Show unreleased changes and recent commits")

    # prepare command
    prepare_parser = subparsers.add_parser("prepare", help="Prepare a new release")
    prepare_parser.add_argument("version", help="Version number (e.g., 1.5.0)")

    # publish command
    publish_parser = subparsers.add_parser("publish", help="Create GitHub release")
    publish_parser.add_argument(
        "--version",
        "-v",
        help="Version to publish (default: current version in pyproject.toml)",
    )

    args = parser.parse_args()

    if args.command == "changelog":
        cmd_changelog(args)
    elif args.command == "prepare":
        cmd_prepare(args)
    elif args.command == "publish":
        cmd_publish(args)


if __name__ == "__main__":
    main()
