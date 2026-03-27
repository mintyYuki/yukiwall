import sys
import os
import subprocess
import re

IP_SUBNET_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$'
)

PORT_RE = re.compile(
    r'^\d{1,5}$'
)

PORT_PROTO_RE = re.compile(
    r'^(\d{1,5})/(tcp|udp|both)$', re.IGNORECASE
)

from yukiwall.firewall import (
    load_config,
    save_config,
    apply_nft_config,
    normalize_port,
    lock,
    CONFIG_PATH
)

def ensure_root():
    if os.getuid() != 0:
        print("🛑 Requires root.")
        sys.exit(1)

def parse_rule(args):
    action = args[0].lower()
    source = None
    ports = []
    invalid = []

    i = 1
    while i < len(args):
        token = args[i]

        if token == "from":
            i += 1
            if i >= len(args):
                raise ValueError("Missing value after 'from'")
            if not IP_SUBNET_RE.match(args[i]):
                raise ValueError(f"⚠ 'from' must be an IP/subnet, got: {args[i]}")
            source = args[i]

        elif token == "to":
            i += 1
            if i >= len(args):
                raise ValueError("Missing ports after 'to'")
            raw_ports = args[i].replace(",", " ").split()
            for p in raw_ports:
                if PORT_RE.match(p):
                    invalid.append(p)
                elif PORT_PROTO_RE.match(p):
                    ports.append(p.lower())
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
        for p in invalid[:]:
            if p.isdigit():
                print(f"⚠ You forgot to specify the protocol for port {p}.")
                choice = input("Specify the protocol now: 1 = TCP, 2 = UDP, 3 = Both: ").strip()
                proto_map = {"1": "tcp", "2": "udp", "3": "both"}
                if choice not in proto_map:
                    raise ValueError(f"Invalid protocol choice: {choice}")
                ports.append(f"{proto_map[choice]}/{p}")
                invalid.remove(p)
        if invalid:
            raise ValueError(f"Invalid port/protocol: {', '.join(invalid)}")

    if ports:
        ports.sort()

    return {
        "action": action,
        "source": source,
        "ports": ports if ports else None
    }

def is_duplicate(new_rule, existing_rules):
    for r in existing_rules:
        if (r["action"] == new_rule["action"] and 
            r["source"] == new_rule["source"] and 
            r["ports"] == new_rule["ports"]):
            return True
    return False

def add_rule(args):
    action = args[0].lower()
    if action == "deny":
        action = "block"
        args[0] = "block"

    try:
        rule = parse_rule(args)
    except ValueError as e:
        print(f"❌ {e}")
        return

    if rule["ports"] is None and rule["source"] is None:
        if action == "allow":
            ans = input(
                "⚠️ This action will allow ALL incoming packets and will disable filtering completely. Are you sure you want to continue? [y/N]: "
            ).strip().lower()
            if ans not in ("y", "yes"):
                print("❌ Aborted by user.")
                return
        elif action == "block":
            print("⚠️ Doing this might cause unexpected behavior. Thus, this action was blocked. You probably don't want to execute this.")
            return

    with lock():
        cfg = load_config()
        rules = cfg.get("rules", [])

        def is_duplicate(new_rule, existing_rules):
            for r in existing_rules:
                if (
                    r["action"] == new_rule["action"] and
                    r.get("source") == new_rule.get("source") and
                    r.get("ports") == new_rule.get("ports")
                ):
                    return True
            return False

        if is_duplicate(rule, rules):
            print("⚠ Duplicate rule detected. No changes made.")
            return

        next_id = max([r["id"] for r in rules], default=0) + 1
        rule["id"] = next_id
        rules.append(rule)

        cfg["rules"] = rules
        save_config(cfg)
        apply_nft_config(cfg)

    print(f"✅ Rule {next_id} added.")

def remove_rules(targets):
    with lock():
        cfg = load_config()
        rules = cfg.get("rules", [])
        initial_len = len(rules)
        removed_ids = []

        for target in targets:
            found = False
            if isinstance(target, int):
                for r in rules[:]:
                    if r["id"] == target:
                        rules.remove(r)
                        removed_ids.append(target)
                        found = True
                if not found:
                    print(f"⚠️ Warning: Rule ID {target} does not exist.")
            
            elif isinstance(target, dict):
                for r in rules[:]:
                    if (r["action"] == target["action"] and 
                        r["source"] == target["source"] and 
                        r["ports"] == target["ports"]):
                        removed_ids.append(r["id"])
                        rules.remove(r)
                        found = True
                if not found:
                    print(f"⚠️ Warning: No matching rule found for literal deletion.")

        if len(rules) == initial_len:
            return

        cfg["rules"] = rules
        save_config(cfg)
        apply_nft_config(cfg)

    ids_str = ", ".join(map(str, sorted(removed_ids)))
    print(f"🧹 Removed rule(s): {ids_str}")

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

def set_logging(which, state=None):
    with lock():
        cfg = load_config()
        logging_cfg = cfg.get("logging", {"unm": False, "inv": False})

        if state is None:
            current_state = logging_cfg.get(which, False)
            print(f"ℹ️ {which.upper()} packet drop logging state is currently {'enabled' if current_state else 'disabled'}.")
            return

        logging_cfg[which] = state
        cfg["logging"] = logging_cfg
        save_config(cfg)
        apply_nft_config(cfg)

    status = "enabled" if state else "disabled"
    print(f"🪵 {which.upper()} logging {status}.")

def set_invalid(mode):
    if mode != "drop" and mode != "allow":
        print("Usage: yukiwall invalid drop|allow")
        return

    with lock():
        cfg = load_config()
        cfg["invalid_action"] = mode
        save_config(cfg)
        apply_nft_config(cfg)

    print(f"🛡️ Policy for invalid packets is now set to {mode.upper()}.")

def print_status():
    cfg = load_config()
    exit_code = 0
    try:
        out = subprocess.run(["systemctl", "show", "nftables", "--property=UnitFileState,ActiveState"],
                            capture_output=True, text=True, check=True).stdout
        state = dict(line.split("=", 1) for line in out.strip().split("\n"))
        unit_enabled = state.get("UnitFileState", "disabled") == "enabled"
        active_running = state.get("ActiveState", "inactive") == "active"
    except Exception:
        unit_enabled = False
        active_running = False

    if unit_enabled and active_running:
        print("✅ The nftables service is set to auto-start and is currently running.")
    elif unit_enabled and not active_running:
        print("⚠ The nftables service is set to auto-start but is not running.")
        exit_code = 1
    else:
        print("❌ The nftables service is not enabled at boot.")
        exit_code = 1

    table_active = False
    try:
        subprocess.run(["nft", "list", "table", "inet", "yukiwall"], check=True, capture_output=True)
        table_active = True
    except subprocess.CalledProcessError:
        table_active = False

    if table_active:
        print("✅ Our table is active currently.")
    else:
        print("⚠ Our table is inactive currently.")
        exit_code = 1

    if os.path.exists(CONFIG_PATH):
        print("✅ The config file exists.")
    else:
        print("❌ Config file missing.")
        exit_code = 1

    config_rules = cfg.get("rules", [])
    desync = False
    try:
            nft_list = subprocess.run(["nft", "list", "table", "inet", "yukiwall"], capture_output=True, text=True, check=True).stdout
            for r in config_rules:
                ports = r.get("ports") or []
                proto_ports = []
                
                for p in ports:
                    proto, port = p.split("/")
                    if proto == "both":
                        proto_ports.extend([f"tcp dport {port}", f"udp dport {port}"])
                    else:
                        proto_ports.append(f"{proto} dport {port}")
                        
                source = r.get("source")
                
                if r["action"] == "allow":
                    for pp in proto_ports or [""]:
                        parts = []
                        if source:
                            parts.extend(["ip", "saddr", source])
                        if pp:
                            parts.append(pp)
                        parts.append("accept")
                        
                        pattern = " ".join(parts)
                        
                        if pattern not in nft_list:
                            desync = True
                            break
                            
                elif r["action"] == "block" and source:
                    pattern = f"ip saddr {source} drop"
                    if pattern not in nft_list:
                        desync = True
                        break
    except Exception:
        desync = True


    if not desync:
        print("✅ Changes are synchronized between backend (nftables) and frontend (this script).")
    else:
        print("⚠ There are unsynchronized changes between backend and frontend.")
        exit_code = 1

    logging_cfg = cfg.get("logging", {"unm": False, "inv": False})
    print(f"ℹ️ Logging unmatched packets is {'enabled' if logging_cfg.get('unm', False) else 'disabled'}.")
    print(f"ℹ️ Logging invalid packets is {'enabled' if logging_cfg.get('inv', False) else 'disabled'}.")

    try:
        nft_raw = subprocess.run(
            ["nft", "list", "table", "inet", "yukiwall"],
            capture_output=True, text=True, check=True
        ).stdout

        unm_rule = "[yw | drop, unm]:"
        inv_rule = "[yw | drop, inv]:"

        inv_drop_pattern = re.compile(r"ct state invalid.*\bdrop\b")

        if unm_rule not in nft_raw:
            print("ℹ️ Unmatched packet drop logging rule is missing.")
            exit_code = 1
        if inv_rule not in nft_raw:
            print("ℹ️ Invalid packet drop logging rule is missing.")
            exit_code = 1

        if not inv_drop_pattern.search(nft_raw):
            print("ℹ️ Dropping invalid packets is not enabled in nftables.")
            exit_code = 1
        else:
            print("ℹ️ Dropping invalid packets is enabled.")

    except Exception:
        print("⚠ Could not verify logging and invalid drop rules dynamically.")
        exit_code = 1

    sys.exit(exit_code)

def print_usage():
    print("""💫 yukiwall - simple nftables wrapper

Usage:
  yukiwall allow from <ip/subnet> [to <ports>]
  yukiwall allow to <ports>
  yukiwall block from <ip/subnet>

Commands:
  allow ...                    Add allow rule
  block ...                    Add block rule
  delete/remove <id>           Remove rule by ID
  delete/remove <id-id>        Delete range of IDs (e.g. 1-5)
  delete/remove <id,id,...>    Delete list of IDs (e.g. 1,3,7)
  delete/remove <literal>      Delete by rule content (e.g. delete allow to 80)
  list                         Show rules
  reload                       Reload rules
  flush                        Remove all rules
  logging on|off               Toggle logging on/off (toggles both 'unm' and 'inv')
  logging unm [on|off]         Toggle unmatched logging
  logging inv [on|off]         Toggle invalid logging
  invalid drop|allow           Set policy for invalid packets
  status                       Show current firewall status
""")

def main():
    ensure_root()

    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd in ["allow", "block", "deny"]:
        add_rule(sys.argv[1:])
    
    elif cmd == "remove" or cmd == "delete":
        if len(sys.argv) < 3:
            print("Usage: yukiwall delete <id|range|list|literal>")
            sys.exit(1)
        
        arg = sys.argv[2]
        targets = []

        if arg in ["allow", "block"]:
            try:
                targets.append(parse_rule(sys.argv[2:]))
            except ValueError as e:
                print(f"❌ {e}")
                sys.exit(1)
        
        elif "-" in arg:
            try:
                start, end = map(int, arg.split("-"))
                targets.extend(range(start, end + 1))
            except ValueError:
                print("❌ Invalid range format.")
                sys.exit(1)
        
        else:
            try:
                for item in arg.split(","):
                    targets.append(int(item))
            except ValueError:
                print("❌ ID must be a number, list, or valid rule.")
                sys.exit(1)
        
        remove_rules(targets)
    
    elif cmd == "list":
        list_rules()
    
    elif cmd == "reload":
        apply_nft_config(load_config())
        print("✅ Reloaded")
    
    elif cmd == "flush":
        with lock():
            save_config({"rules": [], "default_policy": "drop", "invalid_action": "allow"})
            apply_nft_config(load_config())
        print("🧹 Flushed")
    
    elif cmd == "logging":
        if len(sys.argv) < 3:
            print_usage()
            sys.exit(1)
        subcmd = sys.argv[2].lower()
        if subcmd in ["unm", "inv"]:
            if len(sys.argv) == 3:
                set_logging(subcmd)
            elif len(sys.argv) == 4:
                val = sys.argv[3].lower()
                set_logging(subcmd, True if val == "on" else False)
            else:
                print_usage()
        else:
            val = sys.argv[2].lower()
            if val == "on":
                set_logging("unm", True)
                set_logging("inv", True)
            elif val == "off":
                set_logging("unm", False)
                set_logging("inv", False)
            else:
                print_usage()

    elif cmd == "invalid":
        if len(sys.argv) < 3:
            print_usage()
            sys.exit(1)
        set_invalid(sys.argv[2].lower())

    elif cmd == "status":
        print_status()

    else:
        print("Unknown command")

if __name__ == "__main__":
    main()