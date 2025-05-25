# 🔎 ReachRecon

**ReachRecon** is a fast, multithreaded Python tool for validating live subdomains and web URLs, perfect for bug bounty hunters, pentesters, and recon enthusiasts. It also allows format conversion between raw subdomains and fully qualified web URLs to streamline your workflow.

---

## ✨ Features

- ✅ Check live **subdomains** (e.g., `admin.example.com`)
- ✅ Check live **web URLs** (e.g., `http://admin.example.com`)
- 🔁 Convert:
  - Subdomains ➡️ Web URLs (`sub.example.com` ➜ `http://sub.example.com`)
  - Web URLs ➡️ Subdomains (`http://sub.example.com` ➜ `sub.example.com`)
- ⚡ Multithreaded processing using `ThreadPoolExecutor`
- ⏱️ Short 2-second timeout per request for fast scanning

---

## 🧠 Usage

```bash
# Check live subdomains from a file
python3 ReachRecon.py -s -f subs.txt

# Check live web URLs from a file
python3 ReachRecon.py -w -f urls.txt

# Convert subdomains to web URLs
python3 ReachRecon.py -cw -f subs.txt

# Convert web URLs to subdomains
python3 ReachRecon.py -cs -f urls.txt

# Check a single subdomain
python3 ReachRecon.py -s

# Check a single web URL
python3 ReachRecon.py -w
