import json
import os
import subprocess
import tempfile

CONFIG_PATH = "/etc/yukiwall.json"
NFT_PATH = "/etc/nftables.conf"

def save_config(config):
    import tempfile
    dir_name = os.path.dirname(CONFIG_PATH)
    fd, temp_path = tempfile.mkstemp(dir=dir_name, text=True)
    
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(config, f, indent=4)
        os.replace(temp_path, CONFIG_PATH)
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
    else:
        cfg = {}

    cfg.setdefault("rules", [])
    cfg.setdefault("default_policy", "drop")
    cfg.setdefault("logging", False)

    return cfg

def normalize_port(token):
    token = token.lower().strip()

    valid_protos = {"tcp", "udp", "both"}

    if "/" not in token:
        if token.isdigit():
            return f"tcp/{token}"
        return None

    a, b = token.split("/", 1)

    if a.isdigit() and b in valid_protos:
        return f"{b}/{a}"

    if b.isdigit() and a in valid_protos:
        return f"{a}/{b}"

    return None

def expand_ports(ports):
    result = []
    for p in ports:
        proto, port = p.split("/")

        if proto == "both":
            result.append(f"tcp/{port}")
            result.append(f"udp/{port}")
        elif proto in ("tcp", "udp"):
            result.append(p)

    return result

def generate_nft_config(config):
    rules = config.get("rules", [])
    policy = config.get("default_policy", "drop")

    nft = [
        "#!/usr/sbin/nft -o -f",
        ""
        "table inet yukiwall {",
        "    chain input {",
        "        type filter hook input priority 0;",
        f"        policy {policy};",
        "        ct state established,related accept;",
        "        iif \"lo\" accept;"
    ]

    for r in rules:
        if r["action"] != "block":
            continue
        if r["source"]:
            nft.append(f"        ip saddr {r['source']} drop;")

    for r in rules:
        if r["action"] != "allow" or r["ports"] is not None:
            continue
        if r["source"]:
            nft.append(f"        ip saddr {r['source']} accept;")

    for r in rules:
        if r["action"] != "allow" or not r["ports"]:
            continue

        ports = expand_ports(r["ports"])

        for p in ports:
            proto, port = p.split("/")
            if r["source"]:
                nft.append(
                    f"        ip saddr {r['source']} {proto} dport {port} accept;"
                )
            else:
                nft.append(
                    f"        {proto} dport {port} accept;"
                )

    logging_enabled = config.get("logging", False)

    if logging_enabled and policy == "drop":
        nft.append(
            '        limit rate 3/minute burst 10 packets log prefix "[YW | DROP]: ";'
        )

    nft.append("    }")
    nft.append("}")

    return "\n".join(nft)

def get_systemctl_state(service):
    out = subprocess.run(
        ["systemctl", "show", service, "--property=UnitFileState,ActiveState"],
        capture_output=True,
        text=True,
        check=True
    ).stdout

    state = dict(line.split("=", 1) for line in out.strip().split("\n"))
    return state["UnitFileState"], state["ActiveState"]


def ensure_nftables():
    enabled, active = get_systemctl_state("nftables")

    if enabled != "enabled":
        if active == "active":
            subprocess.run(["systemctl", "enable", "nftables"], check=True)
        else:
            subprocess.run(["systemctl", "enable", "--now", "nftables"], check=True)
    elif active != "active":
        subprocess.run(["systemctl", "start", "nftables"], check=True)


def apply_nft_config(config):
    nft_conf = generate_nft_config(config)

    with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(NFT_PATH), delete=False) as f:
        f.write(nft_conf)
        tmp = f.name

    if os.path.exists(NFT_PATH):
        os.replace(NFT_PATH, NFT_PATH + ".bak")

    os.replace(tmp, NFT_PATH)

    ensure_nftables()

    subprocess.run(["nft", "-f", NFT_PATH], check=True)