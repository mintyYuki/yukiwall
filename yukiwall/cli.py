import sys
import os
from yukiwall.firewall import (
    load_config,
    save_config,
    apply_nft_config,
    normalize_port
)

def ensure_root():
    if os.getuid() != 0:
        print("🛑 Requires root.")
        sys.exit(1)

def parse_rule(args):
    action = args[0]
    source = None
    ports = []
    invalid = []

    i = 1
    while i < len(args):
        token = args[i]

        if token == "from":
            i += 1
            if i < len(args):
                source = args[i]
            else:
                raise ValueError("Missing value after 'from'")

        elif token == "to":
            i += 1
            if i >= len(args):
                raise ValueError("Missing ports after 'to'")

            raw_ports = args[i].replace(",", " ").split()
            for p in raw_ports:
                norm = normalize_port(p)
                if norm:
                    ports.append(norm)
                else:
                    invalid.append(p)

        else:
            norm = normalize_port(token)
            if norm:
                ports.append(norm)
            else:
                invalid.append(token)

        i += 1

    if invalid:
        raise ValueError(f"Invalid port/protocol: {', '.join(invalid)}")

    return {
        "action": action,
        "source": source,
        "ports": ports if ports else None
    }

def add_rule(args):
    try:
        rule = parse_rule(args)
    except ValueError as e:
        print(f"❌ {e}")
        return

    cfg = load_config()

    rules = cfg.get("rules", [])
    next_id = max([r["id"] for r in rules], default=0) + 1

    rule["id"] = next_id
    rules.append(rule)

    cfg["rules"] = rules
    save_config(cfg)
    apply_nft_config(cfg)

    print(f"✅ Rule {next_id} added.")

def remove_rule(rule_id):
    cfg = load_config()
    rules = cfg.get("rules", [])

    original_len = len(rules)
    new_rules = [r for r in rules if r["id"] != rule_id]

    if len(new_rules) == original_len:
        print(f"⚠️ No rule with ID {rule_id}.")
        return

    cfg["rules"] = new_rules
    save_config(cfg)
    apply_nft_config(cfg)

    print(f"🧹 Rule {rule_id} removed.")

def list_rules():
    cfg = load_config()
    rules = cfg.get("rules", [])

    if not rules:
        print("No rules.")
        return

    for r in rules:
        rid = r["id"]
        action = r["action"]
        src = r["source"] or "any"
        ports = r["ports"]

        if ports:
            ports_str = ", ".join(ports)
            print(f"[{rid}] {action.upper()} from {src} to {ports_str}")
        else:
            print(f"[{rid}] {action.upper()} from {src} (all ports)")

def set_logging(state):
    cfg = load_config()
    cfg["logging"] = state
    save_config(cfg)
    apply_nft_config(cfg)

    status = "enabled" if state else "disabled"
    print(f"🪵 Logging {status}.")

def print_usage():
    print("""💫 yukiwall - simple nftables wrapper

Usage:
  yukiwall allow from <ip/subnet> [to <ports>]
  yukiwall allow to <ports>
  yukiwall block from <ip/subnet>

Commands:
  allow ...        Add allow rule
  block ...        Add block rule
  remove <id>      Remove rule by ID
  list             Show rules
  reload           Reload rules
  flush            Remove all rules
  logging          Toggle logging on/off

Examples:
  yukiwall allow from 192.168.0.0/16
  yukiwall allow to tcp/22,80
  yukiwall block from 10.0.0.0/24
""")

def main():
    ensure_root()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd in ("allow", "block"):
        add_rule(sys.argv[1:])
    elif cmd == "remove" or cmd == "delete":
        remove_rule(int(sys.argv[2]))
    elif cmd == "list":
        list_rules()
    elif cmd == "reload":
        apply_nft_config(load_config())
        print("✅ Reloaded")
    elif cmd == "flush":
        save_config({"rules": [], "default_policy": "drop"})
        apply_nft_config(load_config())
        print("🧹 Flushed")
    elif cmd == "logging":
        if len(sys.argv) < 3:
            print("Usage: yukiwall logging on|off")
            sys.exit(1)

        val = sys.argv[2].lower()
        if val == "on":
            set_logging(True)
        elif val == "off":
            set_logging(False)
        else:
            print("Use 'on' or 'off'")
    else:
        print("Unknown command")

if __name__ == "__main__":
    main()