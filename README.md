```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ███████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║███████║███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══██║╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              All-in-One Recon Dashboard | by Muhammad Zubair
```

**All-in-One Recon Dashboard** — automates subdomain enumeration, live host detection, optional port scanning, and generates both a terminal summary and a clean HTML report. Built to speed up the initial recon phase of web pentesting / bug bounty workflows.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## What it does

1. **Subdomain Enumeration** — runs [`subfinder`](https://github.com/projectdiscovery/subfinder) against the target domain
2. **Live Host Detection** — pipes discovered subdomains into [`httpx`](https://github.com/projectdiscovery/httpx) to check which hosts are alive, grabbing status code, page title, and detected tech stack
3. **Optional Port Scanning** — runs an [`nmap`](https://nmap.org/) top-100-ports scan against live hosts (opt-in via `--nmap`, requires explicit authorization confirmation — see [Active Scanning](#-active-scanning---nmap) below)
4. **Terminal Summary** — prints a full results table (live hosts, open ports, all subdomains) directly to the terminal, no need to open the HTML report just to see what was found
5. **HTML Dashboard** — generates a single self-contained HTML report with stats, a sortable-style table of live hosts, port scan results (if run), and a collapsible list of all discovered subdomains

One command instead of running each tool separately and copy-pasting output into a notes file.

## Demo

```
$ python3 recondash.py -d example.com

██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ███████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║███████║███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══██║╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              All-in-One Recon Dashboard | by Muhammad Zubair

[*] Running subfinder on example.com ...
[+] subfinder found 47 subdomains.
[*] Probing 47 hosts with httpx-toolkit ...
[+] httpx found 12 live hosts.

======================================================================
 RESULTS SUMMARY — example.com
======================================================================

LIVE HOSTS (12)
----------------------------------------------------------------------------------------------------
URL                                           STATUS   TITLE                          TECH
----------------------------------------------------------------------------------------------------
https://www.example.com                       200      Example Domain                 Nginx, jQuery
https://api.example.com                       200      Example API                    Cloudflare
...

ALL DISCOVERED SUBDOMAINS (47)
----------------------------------------------------------------------
  - www.example.com
  - api.example.com
  ...

======================================================================
[+] Report saved to: recondash_example_com.html
[+] Done. Open 'recondash_example_com.html' in your browser to view the dashboard.
```

The terminal output uses ANSI colors (green/yellow/red status codes) when run in a real terminal.

## Requirements

- Python 3.10+
- [`subfinder`](https://github.com/projectdiscovery/subfinder) installed and in `$PATH`
- [`httpx`](https://github.com/projectdiscovery/httpx) installed and in `$PATH`
  - On **Kali Linux**, this is packaged as `httpx-toolkit` (to avoid a naming clash with the unrelated Python `httpx` library). ReconDash detects and uses whichever one is available automatically.
- [`nmap`](https://nmap.org/) — **optional**, only required if you use the `--nmap` flag

### Install on Kali Linux

```bash
sudo apt update
sudo apt install httpx-toolkit nmap -y
```

`subfinder` usually comes pre-installed on Kali. Check with:
```bash
subfinder -version
```

### Install on other Linux distros

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install nmap -y   # or your distro's package manager
```

Make sure `~/go/bin` is in your `$PATH`.

## Usage

```bash
python3 recondash.py -d target.com
python3 recondash.py -d target.com -o myreport.html
python3 recondash.py -d target.com --nmap
python3 recondash.py -d target.com -v
python3 recondash.py -d target.com -q
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output HTML file path (optional, defaults to `recondash_<domain>.html`) |
| `--nmap` | Also run an nmap port scan (top 100 ports) against discovered live hosts. **Active scan** — see warning below |
| `-v`, `--verbose` | Show extra detail: exact commands run, every host as it's probed, raw findings as they're discovered |
| `-q`, `--quiet` | Show minimal output: skip the banner and progress lines, print only the final results summary |

`-v` and `-q` are mutually exclusive — use one or the other, not both.

## ⚠️ Active Scanning (`--nmap`)

Subdomain enumeration (`subfinder`) and host probing (`httpx`) are passive/low-noise — they mostly rely on public DNS and certificate data, plus a single HTTP request per host.

The `--nmap` flag is different: it performs an **active port scan**, sending packets directly to the target's infrastructure. Because of this:

- It is **opt-in only** — never runs unless you explicitly pass `--nmap`
- It requires you to **type `yes` at an interactive prompt** confirming you are authorized to scan the target before anything is sent
- It should only be used against:
  - Your own infrastructure
  - A bug bounty program's scope you are enrolled in
  - A lab/CTF environment built for this purpose

Running active scans against systems you don't have permission to test may be illegal. **When in doubt, don't.**

## Roadmap / Ideas for v3

- [ ] Add screenshot capture per live host (gowitness/playwright integration)
- [ ] Export results to JSON/CSV alongside HTML
- [ ] Add `waybackurls` integration for historical endpoint discovery
- [ ] Multi-threaded httpx batching for large subdomain lists
- [ ] Dark/light theme toggle in the HTML report
- [ ] Configurable nmap port range / scan profile

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorized security testing** — bug bounty programs you're enrolled in, CTF/lab environments, or systems you have explicit written permission to test. Running recon (and especially the `--nmap` active scan) against domains without authorization may be illegal. Use responsibly.

## Author

Built by [Muhammad Zubair](https://www.linkedin.com/in/oxdzubair) — cybersecurity student focused on web pentesting & red teaming.
