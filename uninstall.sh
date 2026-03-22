#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Restarting with sudo..."
    exec sudo bash "$0" "$@"
fi

venv_path="/opt/yukiwall-venv"
wrapper_path="/usr/local/bin/yukiwall"

if [ -d "$venv_path" ]; then
    rm -rf "$venv_path"
fi

if [ -f "$wrapper_path" ]; then
    rm "$wrapper_path"
fi

if [ -f "/etc/yukiwall.json" ]; then
    rm "/etc/yukiwall.json"
fi

echo "yukiwall removed completely"