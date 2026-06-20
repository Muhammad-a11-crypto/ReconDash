```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ███████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║███████║███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══██║╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              All-in-One Recon Dashboard | by Muhammad Zubair
```

**All-in-One Recon Dashboard** — automates subdomain enumeration, live host detection, and generates a clean HTML report. Built to speed up the initial recon phase of web pentesting / bug bounty workflows.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## What it does

1. **Subdomain Enumeration** — runs [`subfinder`](https://github.com/projectdiscovery/subfinder) against the target domain
2. **Live Host Detection** — pipes discovered subdomains into [`httpx`](https://github.com/projectdiscovery/httpx) to check which hosts are alive, grabbing status code, page title, and detected tech stack
3. **HTML Dashboard** — generates a single self-contained HTML report with stats, a sortable-style table of live hosts, and a collapsible list of all discovered subdomains

No more manually running each tool and copy-pasting output into a notes file — one command, one report.

## Demo

```
$ python3 recondash.py -d example.com

===================================================
 ReconDash - All-in-One Recon Dashboard
===================================================
[*] Running subfinder on example.com ...
[+] subfinder found 47 subdomains.
[*] Probing 47 hosts with httpx ...
[+] httpx found 12 live hosts.
[+] Report saved to: recondash_example_com.html
===================================================
[+] Done. Open 'recondash_example_com.html' in your browser to view the dashboard.
===================================================
```

## Requirements

- Python 3.10+
- [`subfinder`](https://github.com/projectdiscovery/subfinder) installed and in `$PATH`
- [`httpx`](https://github.com/projectdiscovery/httpx) installed and in `$PATH`

Install both on Kali / Linux:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Make sure `~/go/bin` is in your `$PATH`.

## Usage

```bash
python3 recondash.py -d target.com
python3 recondash.py -d target.com -o myreport.html
```

| Flag | Description |
|------|-------------|
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output HTML file path (optional, defaults to `recondash_<domain>.html`) |

## Roadmap / Ideas for v2

- [ ] Add screenshot capture per live host (gowitness/playwright integration)
- [ ] Export results to JSON/CSV alongside HTML
- [ ] Add `waybackurls` integration for historical endpoint discovery
- [ ] Multi-threaded httpx batching for large subdomain lists
- [ ] Dark/light theme toggle in the HTML report

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorized security testing** — bug bounty programs you're enrolled in, CTF/lab environments, or systems you have explicit written permission to test. Running recon against domains without authorization may be illegal. Use responsibly.

## Author

Built by [Muhammad Zubair](https://www.linkedin.com/in/oxdzubair) — cybersecurity student focused on web pentesting & red teaming.
