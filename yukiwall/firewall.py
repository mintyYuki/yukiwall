import json
import os
import subprocess

CONFIG_PATH = "/etc/yukiwall.json"
NFT_PATH = "/etc/nftables.conf"

def save_config(ports) -> None:
    config = {"allowed_ports": ports}
    with open(CONFIG_PATH, mode="w") as f:
        json.dump(config, fp=f, indent=4)

def load_config():
    if os.path.exists(path=CONFIG_PATH):
        with open(file=CONFIG_PATH, mode="r") as f:
            return json.load(fp=f)
    return {"allowed_ports": []}

def normalize_port(port_str) -> None | str:
    if "/" not in port_str:
        return None
    parts = port_str.split("/")
    p1, p2 = parts[0].lower(), parts[1].lower()

    if p1.isdigit():
        port, proto = p1, p2
    elif p2.isdigit():
        proto, port = p1, p2
    else:
        return None
        
    return f"{proto}/{port}"

def expand_ports(ports):
    result = []
    for p in ports:
        normalized: None | str = normalize_port(port_str=p)
        if not normalized:
            continue
        
        proto, port = normalized.split("/")
        if proto == "both":
            result.append(f"tcp/{port}")
            result.append(f"udp/{port}")
        else:
            result.append(f"{proto}/{port}")
    return result

def generate_nft_config(ports, policy="drop") -> str:
    expanded = expand_ports(ports=ports)
    nft_conf: list[str] = [
        "table inet filter {",
        "    chain input {",
        "        type filter hook input priority 0;",
        f"        policy {policy};",
        "        ct state established,related accept;",
        "        iifname \"lo\" accept;"
    ]
    for port_entry in expanded:
        proto, p = port_entry.split("/")
        nft_conf.append(f"        {proto} dport {p} accept;")
    
    nft_conf.append("    }")
    nft_conf.append("}")
    return "\n".join(nft_conf)

def apply_nft_config(ports, policy="drop") -> None:
    nft_conf: str = generate_nft_config(ports=ports, policy=policy)
    tmp_path = "/tmp/yukiwall.nft"
    with open(file=tmp_path, mode="w") as f:
        f.write(nft_conf)
    if os.path.exists(path=NFT_PATH):
        os.rename(src=NFT_PATH, dst=NFT_PATH + ".bak")
    subprocess.run(args=["mv", tmp_path, NFT_PATH], check=True)
    subprocess.run(args=["systemctl", "enable", "--now", "nftables"], check=True)
    subprocess.run(args=["nft", "-f", NFT_PATH], check=True)