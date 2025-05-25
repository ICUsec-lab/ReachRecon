# 🔎 ReachRecon

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Issues](https://img.shields.io/github/issues/ICUsec-lab/ReachRecon)](https://github.com/ICUsec-lab/ReachRecon/issues)

> **ReachRecon** is a blazing-fast Python tool to organize your pentest by checking which targets are live.

---

## 🚀 Features

- **Live Subdomain Checker:** Quickly find which subdomains are up (e.g., `admin.example.com`).
- **Live URL Checker:** Validate which web URLs are reachable (e.g., `http://admin.example.com`).
- **Smart Conversion:** Convert subdomain lists to full web URLs and back.
- **Multithreaded:** Super-fast results thanks to multithreading.
- **Clean Output:** Skips dead targets to keep your results clean and actionable.

---

## 🎯 Why Use ReachRecon?

During recon, you may collect hundreds of subdomains or URLs—but not all are alive.
Scanning dead ones wastes time and resources.

**ReachRecon helps you:**
- ✅ Focus only on valid attack surfaces.
- ✅ Organize recon data for better exploitation.
- ✅ Easily chain results with tools like `ffuf`, `nuclei`, `httpx`, etc.

---

## 📦 Usage

### ✅ Check live subdomains
```bash
python3 ReachRecon.py -s -f subs.txt
