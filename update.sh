#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Restarting with sudo..."
    exec sudo bash "$0" "$@"
fi

venv="/opt/yukiwall-venv"

if [ ! -d "$venv" ]; then
    echo "No installation found, run install_yukiwall.sh first"
    exit 1
fi

repo_dir="$(dirname "$(realpath "$0")")"

if [ -f "$repo_dir/setup.py" ] || [ -f "$repo_dir/pyproject.toml" ]; then
    echo "Updating yukiwall from local repo..."
    "$venv/bin/pip" install --upgrade "$repo_dir"
else
    echo "Hmm. Something went wrong. Open an issue on GitHub."
fi

echo "yukiwall updated!"