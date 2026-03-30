#!/usr/bin/env bash
set -euo pipefail

# release.sh — Bump version, commit, tag, and push to trigger the release pipeline.
#
# Usage: ./scripts/release.sh <major|minor|patch> [--dry-run] [--yes]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TOML="$REPO_ROOT/Cargo.toml"

DRY_RUN=false
AUTO_YES=false
BUMP_TYPE=""

# ── Parse arguments ──────────────────────────────────────────────────────

usage() {
  echo "Usage: $0 <major|minor|patch> [--dry-run] [--yes]"
  echo ""
  echo "Options:"
  echo "  --dry-run   Print what would happen without making changes"
  echo "  --yes       Skip confirmation prompt"
  exit 1
}

for arg in "$@"; do
  case "$arg" in
    major|minor|patch)
      if [ -n "$BUMP_TYPE" ]; then
        echo "Error: Only one bump type allowed."
        usage
      fi
      BUMP_TYPE="$arg"
      ;;
    --dry-run)
      DRY_RUN=true
      ;;
    --yes)
      AUTO_YES=true
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "Error: Unknown argument '$arg'"
      usage
      ;;
  esac
done

if [ -z "$BUMP_TYPE" ]; then
  echo "Error: Bump type required (major, minor, or patch)."
  usage
fi

# ── Guards ───────────────────────────────────────────────────────────────

# Must be on main or master branch
CURRENT_BRANCH="$(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)"
if [ "$CURRENT_BRANCH" != "main" ] && [ "$CURRENT_BRANCH" != "master" ]; then
  echo "Error: Must be on 'main' or 'master' branch (currently on '$CURRENT_BRANCH')."
  exit 1
fi

# Working directory must be clean
if ! git -C "$REPO_ROOT" diff --quiet || ! git -C "$REPO_ROOT" diff --cached --quiet; then
  echo "Error: Working directory is not clean. Commit or stash your changes first."
  exit 1
fi

# Check for untracked files that matter
if [ -n "$(git -C "$REPO_ROOT" ls-files --others --exclude-standard)" ]; then
  echo "Warning: Untracked files present. They will not be included in the release."
fi

# Git remote must be reachable
if ! git -C "$REPO_ROOT" ls-remote --exit-code origin &>/dev/null; then
  echo "Error: Cannot reach git remote 'origin'. Check your network connection."
  exit 1
fi

# ── Extract current version ──────────────────────────────────────────────

CURRENT_VERSION="$(grep '^version' "$CARGO_TOML" | head -1 | sed 's/.*"\(.*\)".*/\1/')"
if [ -z "$CURRENT_VERSION" ]; then
  echo "Error: Could not extract version from Cargo.toml."
  exit 1
fi

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# ── Compute new version ─────────────────────────────────────────────────

case "$BUMP_TYPE" in
  major)
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
    ;;
  minor)
    MINOR=$((MINOR + 1))
    PATCH=0
    ;;
  patch)
    PATCH=$((PATCH + 1))
    ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH}"

echo "Current version: $CURRENT_VERSION"
echo "New version:     $NEW_VERSION ($BUMP_TYPE bump)"
echo "Tag:             v${NEW_VERSION}"
echo ""

if [ "$DRY_RUN" = true ]; then
  echo "[dry-run] Would update Cargo.toml version from $CURRENT_VERSION to $NEW_VERSION"
  echo "[dry-run] Would run: cargo check --quiet"
  echo "[dry-run] Would run: git add Cargo.toml Cargo.lock"
  echo "[dry-run] Would run: git commit -m 'chore: release v${NEW_VERSION}'"
  echo "[dry-run] Would run: git tag -a v${NEW_VERSION} -m 'Release v${NEW_VERSION}'"
  echo "[dry-run] Would run: git push && git push --tags"
  echo ""
  echo "No changes made."
  exit 0
fi

# ── Confirm ──────────────────────────────────────────────────────────────

if [ "$AUTO_YES" != true ]; then
  printf "Proceed? [y/N] "
  read -r CONFIRM
  if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Aborted."
    exit 0
  fi
fi

# ── Update Cargo.toml ───────────────────────────────────────────────────

# Portable sed: use -i.bak then remove the backup (works on both macOS and GNU sed)
sed -i.bak "s/^version = \"${CURRENT_VERSION}\"/version = \"${NEW_VERSION}\"/" "$CARGO_TOML"
rm -f "${CARGO_TOML}.bak"

echo "Updated Cargo.toml: $CURRENT_VERSION -> $NEW_VERSION"

# ── Regenerate Cargo.lock ────────────────────────────────────────────────

echo "Regenerating Cargo.lock..."
(cd "$REPO_ROOT" && cargo check --quiet)

# ── Git commit and tag ───────────────────────────────────────────────────

git -C "$REPO_ROOT" add Cargo.toml Cargo.lock
git -C "$REPO_ROOT" commit -m "chore: release v${NEW_VERSION}"
git -C "$REPO_ROOT" tag -a "v${NEW_VERSION}" -m "Release v${NEW_VERSION}"

echo ""
echo "Created commit and tag v${NEW_VERSION}."

# ── Push ─────────────────────────────────────────────────────────────────

echo "Pushing to origin..."
git -C "$REPO_ROOT" push origin HEAD:main
git -C "$REPO_ROOT" push origin --tags

echo ""
echo "Done! Tag v${NEW_VERSION} pushed. The release workflow will build and publish binaries."
