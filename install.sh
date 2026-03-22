#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Restarting self with sudo..."
    exec sudo bash "$0" "$@"
fi

apt install -y python3-venv python3-pip nftables

venv_path="/opt/yukiwall-venv"
if [ ! -d "$venv_path" ]; then
    python3 -m venv "$venv_path"
fi

"$venv_path/bin/pip" install --upgrade pip
"$venv_path/bin/pip" install .

wrapper_path="/usr/local/bin/yukiwall"
tee "$wrapper_path" > /dev/null <<EOF
#!/bin/bash
$venv_path/bin/yukiwall "\$@"
EOF

chmod +x "$wrapper_path"

echo "yukiwall installed! Use sudo yukiwall configure/add/remove/list"