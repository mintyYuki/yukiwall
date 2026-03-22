# 🌸 yukiwall

**yukiwall** is a tiny, ultra-cute firewall frontend for **nftables**, giving you simple control over Linux firewall rules without headaches.

---

## ✨ Features

* Add or remove rules with precision: `allow` / `block` / `remove`
* Filter by source IP or subnet: `from <ip/subnet>`
* Filter specific ports or protocols: `to <ports>` (tcp/udp/both)
* List all rules with IDs: `list`
* Reload rules instantly: `reload`
* Flush all rules: `flush`
* Optional logging for dropped packets: `logging on|off`
* Powered by **nftables** – modern, fast, clean

---

## 💻 Requirements

* Python 3.xx
* Root privileges for firewall changes
* Dependencies installed via `install.sh` script

---

## 🚀 Installation

Clone and install in one command:

```bash
cd $HOME && git clone https://github.com/mintyYuki/yukiwall.git && cd yukiwall && sudo bash install.sh
```

### 🔄 Updating

```bash
cd $HOME/yukiwall && sudo bash update.sh
```

### ❌ Uninstall

```bash
cd $HOME/yukiwall && sudo bash uninstall.sh
```

---

## 🛠 Usage

```bash
sudo yukiwall <command> [args...]
```

### Commands

| Command                               | Description                                                          |
| ------------------------------------- | -------------------------------------------------------------------- |
| `allow from <ip/subnet> [to <ports>]` | Allow traffic from a specific IP/subnet, optionally to certain ports |
| `allow to <ports>`                    | Allow ports globally                                                 |
| `block from <ip/subnet>`              | Block traffic from a specific source                                 |
| `remove <id>`                         | Remove a rule by its ID                                              |
| `list`                                | List all current rules with IDs                                      |
| `reload`                              | Apply current rules immediately                                      |
| `flush`                               | Remove all rules (resets to default drop)                            |
| `logging on/off`                      | Enable or disable logging of dropped packets                         |

### Examples

* Allow SSH from local network:

```bash
sudo yukiwall allow from 192.168.0.0/16 to tcp/22
```

* Allow web ports globally:

```bash
sudo yukiwall allow to tcp/80,443
```

* Block a malicious subnet:

```bash
sudo yukiwall block from 10.0.0.0/24
```

* Remove a rule by ID:

```bash
sudo yukiwall remove 3
```

* List rules:

```bash
sudo yukiwall list
```

* Enable logging:

```bash
sudo yukiwall logging on
```

* Flush all rules:

```bash
sudo yukiwall flush
```

---

## 🧩 How it works

1. Stores rules in `/etc/yukiwall.json`.
2. Generates a clean **nftables** config from the rules.
3. Applies rules via `nft` and ensures `nftables` service is running.
4. Optional logging for dropped packets if enabled.

> ⚠️ **SSH Warning:** Always make sure port 22 is allowed if you connect remotely — yukiwall will not block your access automatically.

---

## 🐛 Caveats

* **Fresh project:** some bugs might exist.
* Report issues on GitHub to help improve it.
* Future updates will expand features and stability.

---

Made with 💖 by **yuki**, for those who want a firewall that just works without drama.
