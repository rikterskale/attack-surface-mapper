#!/usr/bin/env bash
# .pre-commit-hook/no-pyc.sh
# Prevents committing .pyc files and __pycache__ directories.
# Install: cp pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit

set -euo pipefail

pyc_files=$(git diff --cached --name-only --diff-filter=ACR | grep -E '\.pyc$|__pycache__/' || true)

if [ -n "$pyc_files" ]; then
    echo "ERROR: Refusing to commit Python bytecache files:"
    echo "$pyc_files"
    echo ""
    echo "Remove them with:  git rm --cached <file>"
    echo "Or unstage with:   git reset HEAD <file>"
    exit 1
fi
