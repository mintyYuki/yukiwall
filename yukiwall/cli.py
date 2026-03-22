import sys
import os
from yukiwall.firewall import load_config, save_config, apply_nft_config, expand_ports, normalize_port

def ensure_root() -> None:
    if os.getuid() != 0:
        print("🛑 Error: yukiwall requires root privileges.")
        sys.exit(1)

def ask_yn(prompt) -> bool:
    while True:
        ans: str = input(prompt + " (y/n): ").strip().lower()
        if ans in ("y", "n"):
            return ans == "y"

def ssh_check(ports) -> None:
    expanded = expand_ports(ports)
    if "tcp/22" not in expanded:
        print("\n⚠️  WARNING: Port 22 (SSH) is NOT in your allowed list.")
        if not ask_yn(prompt="Are you absolutely sure you want to proceed?"):
            print("Operation cancelled.")
            sys.exit(0)

def configure() -> None:
    print("💫 yukiwall - simple wrapper for nftables")
    while True:
        raw = input("Ports to allow (e.g., tcp/22, 80/tcp): ").strip()
        ports = []
        for p in raw.replace(",", " ").split():
            norm = normalize_port(p.strip())
            if norm:
                ports.append(norm)  

        print(f"Current selection: {', '.join(ports)}")
        ssh_check(ports=ports)
        if ask_yn(prompt="Is this correct?"):
            break
    save_config(ports=ports)
    apply_nft_config(ports=ports, policy="drop")
    print("✅ Firewall enabled!")

def add_ports(new_ports) -> None:
    cfg = load_config()
    current = set(cfg.get("allowed_ports", []))
    
    for p in new_ports:
        norm: None | str = normalize_port(port_str=p)
        if norm:
            current.add(norm)
    
    final_list = list(current)
    ssh_check(ports=final_list) 
    save_config(ports=final_list)
    apply_nft_config(ports=final_list, policy="drop")
    print(f"✅ Added and applied.")

def remove_ports(rem_ports) -> None:
    cfg = load_config()
    current = set(cfg.get("allowed_ports", []))
    for p in rem_ports:
        norm: None | str = normalize_port(port_str=p)
        if norm:
            current.discard(norm)
    
    final_list = list(current)
    ssh_check(ports=final_list)
    save_config(ports=final_list)
    apply_nft_config(ports=final_list, policy="drop")
    print(f"✅ Removed and applied.")

def list_ports() -> None:
    cfg = load_config()
    ports = cfg.get("allowed_ports", [])
    if ports:
        print("🔓 Allowed ports:", ", ".join(ports))
    else:
        print("🔒 All incoming traffic blocked.")

def flush_ports() -> None:
    """Remove all allowed ports and disable firewall rules (sets policy to drop)."""
    save_config(ports=[])
    apply_nft_config(ports=[], policy="drop")
    print("🧹 All allowed ports flushed! Firewall is now blocking everything.")

def main() -> None:
    ensure_root()

    usage_msg = (
        "Usage:\n"
        "  yukiwall configure          # Interactive port setup\n"
        "  yukiwall add <ports>        # Add ports, format: tcp/22, udp/53, both/80\n"
        "  yukiwall remove <ports>     # Remove ports, same format\n"
        "  yukiwall list               # List allowed ports\n"
        "  yukiwall enable             # Enable firewall\n"
        "  yukiwall disable            # Disable firewall\n"
        "  yukiwall flush              # Flush allowed ports"
    )

    if len(sys.argv) < 2:
        print(usage_msg)
        sys.exit(1)

    cmd: str = sys.argv[1].lower()
    args: list[str] = sys.argv[2:]

    if cmd == "configure":
        configure()
    elif cmd == "add":
        if not args:
            print(f"{usage_msg}\n\nFormat example: tcp/22, udp/53, both/80")
            sys.exit(1)
        add_ports(new_ports=args)
    elif cmd == "remove":
        if not args:
            print(f"{usage_msg}\n\nFormat example: tcp/22, udp/53, both/80")
            sys.exit(1)
        remove_ports(rem_ports=args)
    elif cmd == "list":
        list_ports()
    elif cmd == "enable":
        cfg = load_config()
        apply_nft_config(cfg.get("allowed_ports", []), policy="drop")
        print("✅ Firewall ENABLED")
    elif cmd == "disable":
        if ask_yn(prompt="Disable firewall (Allow ALL)?"):
            apply_nft_config(ports=[], policy="accept")
            print("🛑 Firewall DISABLED")
    elif cmd == "flush":
        if ask_yn(prompt="Are you sure you want to flush all allowed ports?"):
            flush_ports()
    else:
        print(usage_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()