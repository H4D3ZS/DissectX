#!/usr/bin/env python3
"""
Version bumping script for DissectX.

Usage:
    python scripts/bump_version.py [major|minor|patch] [--dry-run]

Examples:
    python scripts/bump_version.py patch        # 1.0.0 -> 1.0.1
    python scripts/bump_version.py minor        # 1.0.0 -> 1.1.0
    python scripts/bump_version.py major        # 1.0.0 -> 2.0.0
    python scripts/bump_version.py 1.2.3        # Set to specific version
"""

import argparse
import re
import sys
from pathlib import Path


def get_current_version():
    """Read current version from src/__version__.py"""
    version_file = Path(__file__).parent.parent / "src" / "__version__.py"
    if not version_file.exists():
        return "1.0.0"
    
    content = version_file.read_text()
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    if match:
        return match.group(1)
    return "1.0.0"


def parse_version(version_str):
    """Parse version string into (major, minor, patch) tuple"""
    parts = version_str.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid version format: {version_str}")
    return tuple(int(p) for p in parts)


def bump_version(current, bump_type):
    """Bump version based on type (major, minor, patch)"""
    major, minor, patch = parse_version(current)
    
    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    elif bump_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    else:
        # Assume it's a specific version
        parse_version(bump_type)  # Validate format
        return bump_type


def update_version_file(new_version, dry_run=False):
    """Update src/__version__.py with new version"""
    version_file = Path(__file__).parent.parent / "src" / "__version__.py"
    content = f'''"""Version information for DissectX."""

__version__ = "{new_version}"
__version_info__ = tuple(int(i) for i in __version__.split("."))
'''
    
    if dry_run:
        print(f"Would write to {version_file}:")
        print(content)
    else:
        version_file.write_text(content)
        print(f"Updated {version_file}")


def update_setup_py(new_version, dry_run=False):
    """Update version in setup.py if it's hardcoded"""
    setup_file = Path(__file__).parent.parent / "setup.py"
    if not setup_file.exists():
        return
    
    content = setup_file.read_text()
    # Only update if version is hardcoded (not reading from __version__.py)
    if 'version="' in content and '__version__' not in content:
        new_content = re.sub(
            r'version="[^"]*"',
            f'version="{new_version}"',
            content
        )
        
        if dry_run:
            print(f"Would update {setup_file}")
        else:
            setup_file.write_text(new_content)
            print(f"Updated {setup_file}")


def main():
    parser = argparse.ArgumentParser(description="Bump DissectX version")
    parser.add_argument(
        "bump_type",
        choices=["major", "minor", "patch"],
        nargs="?",
        help="Version component to bump, or specific version (e.g., 1.2.3)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--version",
        help="Set specific version (alternative to bump_type)"
    )
    
    args = parser.parse_args()
    
    # Determine bump type
    bump_type = args.version if args.version else args.bump_type
    if not bump_type:
        parser.error("Must specify bump type or --version")
    
    # Get current version
    current_version = get_current_version()
    print(f"Current version: {current_version}")
    
    # Calculate new version
    try:
        new_version = bump_version(current_version, bump_type)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    print(f"New version: {new_version}")
    
    if args.dry_run:
        print("\n[DRY RUN - No changes made]")
    
    # Update files
    update_version_file(new_version, args.dry_run)
    update_setup_py(new_version, args.dry_run)
    
    if not args.dry_run:
        print(f"\nVersion bumped to {new_version}")
        print("\nNext steps:")
        print(f"  1. Review changes: git diff")
        print(f"  2. Commit: git commit -am 'Bump version to {new_version}'")
        print(f"  3. Tag: git tag -a v{new_version} -m 'Release v{new_version}'")
        print(f"  4. Push: git push && git push --tags")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
