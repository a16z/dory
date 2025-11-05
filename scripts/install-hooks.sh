#!/bin/bash
# Installation script for Git hooks

set -e

HOOKS_DIR="hooks"
GIT_HOOKS_DIR=".git/hooks"

echo "Installing Git hooks..."

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run this script from the repository root."
    exit 1
fi

# Check if hooks directory exists
if [ ! -d "$HOOKS_DIR" ]; then
    echo "Error: hooks/ directory not found"
    exit 1
fi

# Install pre-commit hook
if [ -f "$HOOKS_DIR/pre-commit" ]; then
    cp "$HOOKS_DIR/pre-commit" "$GIT_HOOKS_DIR/pre-commit"
    chmod +x "$GIT_HOOKS_DIR/pre-commit"
    echo "✅ Installed pre-commit hook"
else
    echo "⚠️  Warning: hooks/pre-commit not found"
fi

echo "Done! Git hooks are now active."
echo ""
echo "The pre-commit hook will:"
echo "  • Auto-format code with cargo fmt"
echo "  • Run cargo clippy in strict mode"
echo "  • Block commits if clippy warnings exist"
