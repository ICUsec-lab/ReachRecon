=========================
🔎 ReachRecon - README
=========================

ReachRecon is a fast Python tool for organizing your pentest by checking which targets are live.

🛠️ What it does:
-----------------
    ✔️ Checks which subdomains are up (e.g., admin.example.com)
    ✔️ Checks which web URLs are reachable (e.g., http://admin.example.com)
    🔁 Converts subdomain lists to full web URLs and back
    ⚡ Uses multithreading to make it FAST
    🚫 Skips dead targets to keep your results CLEAN and USEFUL

🎯 Why use it:
--------------
    During recon, you collect hundreds of subdomains or URLs.
    But not all of them are alive — and scanning dead ones wastes time.

    ReachRecon filters live targets, helping you:
        ✅ Focus only on valid attack surface
        ✅ Organize your recon for better exploitation
        ✅ Chain with tools like ffuf, nuclei, httpx, etc.

📦 How to run:
--------------
Check live subdomains:
    python3 ReachRecon.py -s -f subs.txt

Check live full web URLs:
    python3 ReachRecon.py -w -f urls.txt

Convert subdomains to web URLs:
    python3 ReachRecon.py -cw -f subs.txt

Convert web URLs to subdomains:
    python3 ReachRecon.py -cs -f urls.txt

👨‍💻 Built by ICUSec – Ethical Hackers on a mission to dominate the recon game 👑

📌 Pro tip:
------------
Use ReachRecon after tools like:
    - subfinder
    - assetfinder
    - amass

Then feed the live results into your fuzzing or scanning tools.

Example:
    subfinder -d example.com | tee subs.txt
    python3 ReachRecon.py -s -f subs.txt > live_subs.txt

Then fuzz:
    ffuf -u http://FUZZ.example.com -w live_subs.txt

⚠️ For authorized testing only. Stay ethical.
