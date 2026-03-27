import json
import os
import subprocess
import tempfile
import fcntl
from contextlib import contextmanager

CONFIG_PATH = "/etc/yukiwall.json"
NFT_PATH = "/etc/nftables.conf"
LOCK_PATH = "/run/lock/yukiwall.lock"

@contextmanager
def lock():
    lock_dir = os.path.dirname(LOCK_PATH)
    if not os.path.exists(lock_dir):
        os.makedirs(lock_dir, exist_ok=True)
    lock_file = open(LOCK_PATH, "w")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()

def save_config(config):
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
    cfg.setdefault("logging", {"unm": False, "inv": False})
    cfg.setdefault("invalid_action", "allow")
    logging_cfg = cfg.get("logging")
    if isinstance(logging_cfg, bool):
        cfg["logging"] = {"unm": logging_cfg, "inv": logging_cfg}
    return cfg

def normalize_port(token):
    token = token.lower().strip()
    valid_protos = {"tcp", "udp", "both"}
    if "/" not in token:
        if token.isdigit():
            return None
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
    invalid_action = config.get("invalid_action", "allow")
    logging_cfg = config.get("logging", {})
    if isinstance(logging_cfg, bool):
        logging_cfg = {"unm": logging_cfg, "inv": logging_cfg}

    nft = [
        "#!/usr/sbin/nft -o -f",
        "table inet yukiwall {",
        "    chain input {",
        "        type filter hook input priority -150;",
        f"        policy {policy};"
    ]

    if invalid_action == "drop":
        if logging_cfg.get("inv", False):
            nft.append('        ct state invalid limit rate 7/minute log prefix "[yw | drop, inv]: " drop;')
        else:
            nft.append("        ct state invalid drop;")
    else:
        if logging_cfg.get("inv", False):
            nft.append('        ct state invalid limit rate 7/minute log prefix "[yw | drop, inv]: ";')

    nft.append("        ct state established,related accept;")
    nft.append('        iif "lo" accept;')

    for r in rules:
        if r["action"] == "block" and r.get("source"):
            nft.append(f"        ip saddr {r['source']} drop;")

    for r in rules:
        if r["action"] == "allow" and r.get("ports") is None and r.get("source"):
            nft.append(f"        ip saddr {r['source']} accept;")

    for r in rules:
        if r["action"] == "allow" and r.get("ports"):
            ports = expand_ports(r["ports"])
            for p in ports:
                proto, port = p.split("/")
                if r.get("source"):
                    nft.append(f"        ip saddr {r['source']} {proto} dport {port} accept;")
                else:
                    nft.append(f"        {proto} dport {port} accept;")

    if logging_cfg.get("unm", False) and policy == "drop":
        nft.append('        limit rate 7/minute log prefix "[yw | drop, unm]: ";')

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
    try:
        subprocess.run(["nft", "-c", "-f", tmp], check=True, capture_output=True)
        if os.path.exists(NFT_PATH):
            os.replace(NFT_PATH, NFT_PATH + ".bak")
        os.replace(tmp, NFT_PATH)
        ensure_nftables()
        subprocess.run(["nft", "flush", "table", "inet", "yukiwall"], check=False)
        subprocess.run(["nft", "-f", NFT_PATH], check=True)
    except subprocess.CalledProcessError as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        stderr_msg = e.stderr.decode() if e.stderr else str(e)
        print(f"❌ Nftables error: {stderr_msg}")
        raise e