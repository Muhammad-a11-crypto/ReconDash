#!/usr/bin/env python3
"""
ReconDash - All-in-One Recon Dashboard
----------------------------------------
Automates: subdomain enumeration (subfinder) -> live host detection (httpx)
-> HTML report generation.

Usage:
    python3 recondash.py -d target.com
    python3 recondash.py -d target.com -o report.html

Requirements:
    - subfinder (https://github.com/projectdiscovery/subfinder)
    - httpx     (https://github.com/projectdiscovery/httpx)
    Both should be installed and available in $PATH.

Author: Muhammad Zubair (oxdzubair)
"""

import argparse
import json
import subprocess
import shutil
import sys
from datetime import datetime
from pathlib import Path


def check_tool(name: str) -> bool:
    """Check if an external tool is available in PATH."""
    return shutil.which(name) is not None


def run_subfinder(domain: str, timeout: int = 120) -> list[str]:
    """Run subfinder against the domain and return a list of subdomains."""
    print(f"[*] Running subfinder on {domain} ...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("[!] subfinder timed out, using partial results if any.")
        return []
    except FileNotFoundError:
        print("[!] subfinder not found in PATH.")
        return []

    subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    print(f"[+] subfinder found {len(subs)} subdomains.")
    return subs


def run_httpx(subdomains: list[str], timeout: int = 180) -> list[dict]:
    """
    Run httpx against a list of subdomains to find live hosts.
    Returns a list of dicts with url, status_code, title, tech, etc.

    Note: On Kali Linux, ProjectDiscovery's httpx is packaged as
    'httpx-toolkit' to avoid a naming conflict with the Python httpx
    package. This function tries 'httpx-toolkit' first, then falls
    back to 'httpx'.
    """
    if not subdomains:
        return []

    httpx_bin = "httpx-toolkit" if check_tool("httpx-toolkit") else "httpx"

    print(f"[*] Probing {len(subdomains)} hosts with {httpx_bin} ...")
    input_data = "\n".join(subdomains)

    try:
        result = subprocess.run(
            [
                httpx_bin,
                "-silent",
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print("[!] httpx timed out, using partial results if any.")
        return []
    except FileNotFoundError:
        print(f"[!] {httpx_bin} not found in PATH.")
        return []

    live_hosts = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            live_hosts.append(
                {
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", ""),
                    "title": data.get("title", ""),
                    "tech": ", ".join(data.get("tech", [])) if data.get("tech") else "",
                    "webserver": data.get("webserver", ""),
                }
            )
        except json.JSONDecodeError:
            continue

    print(f"[+] httpx found {len(live_hosts)} live hosts.")
    return live_hosts


def generate_html_report(domain: str, subdomains: list[str], live_hosts: list[dict], output_path: str):
    """Generate a clean, self-contained HTML dashboard report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    status_color = {
        "2": "#22c55e",  # 2xx green
        "3": "#eab308",  # 3xx yellow
        "4": "#f97316",  # 4xx orange
        "5": "#ef4444",  # 5xx red
    }

    def color_for(status_code):
        s = str(status_code)
        return status_color.get(s[:1], "#94a3b8")

    rows_html = ""
    for host in live_hosts:
        c = color_for(host["status_code"])
        rows_html += f"""
        <tr>
            <td><a href="{host['url']}" target="_blank">{host['url']}</a></td>
            <td><span style="color:{c}; font-weight:600;">{host['status_code']}</span></td>
            <td>{host['title'] or '-'}</td>
            <td>{host['tech'] or '-'}</td>
            <td>{host['webserver'] or '-'}</td>
        </tr>"""

    all_subs_html = "".join(f"<li>{s}</li>" for s in subdomains)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconDash Report - {domain}</title>
<style>
    * {{ box-sizing: border-box; }}
    body {{
        background: #0f172a;
        color: #e2e8f0;
        font-family: 'Segoe UI', Consolas, monospace;
        margin: 0;
        padding: 30px;
    }}
    h1 {{ color: #38bdf8; margin-bottom: 0; }}
    .subtitle {{ color: #94a3b8; margin-top: 4px; }}
    .stats {{
        display: flex;
        gap: 20px;
        margin: 25px 0;
    }}
    .card {{
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 18px 25px;
        flex: 1;
    }}
    .card h2 {{ margin: 0; font-size: 28px; color: #38bdf8; }}
    .card p {{ margin: 4px 0 0; color: #94a3b8; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        background: #1e293b;
        border-radius: 10px;
        overflow: hidden;
    }}
    th, td {{
        padding: 10px 14px;
        text-align: left;
        border-bottom: 1px solid #334155;
        font-size: 14px;
    }}
    th {{
        background: #0f172a;
        color: #38bdf8;
        text-transform: uppercase;
        font-size: 12px;
        letter-spacing: 0.5px;
    }}
    tr:hover {{ background: #273449; }}
    a {{ color: #38bdf8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .section {{ margin-top: 35px; }}
    details {{
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 12px 18px;
    }}
    summary {{ cursor: pointer; color: #38bdf8; font-weight: 600; }}
    ul {{ columns: 3; column-gap: 30px; margin-top: 12px; }}
    li {{ margin-bottom: 4px; font-size: 13px; color: #cbd5e1; }}
    footer {{ margin-top: 40px; color: #64748b; font-size: 12px; text-align: center; }}
</style>
</head>
<body>
    <h1>ReconDash Report</h1>
    <p class="subtitle">Target: <strong>{domain}</strong> &nbsp;|&nbsp; Generated: {timestamp}</p>

    <div class="stats">
        <div class="card"><h2>{len(subdomains)}</h2><p>Subdomains Found</p></div>
        <div class="card"><h2>{len(live_hosts)}</h2><p>Live Hosts</p></div>
        <div class="card"><h2>{round((len(live_hosts)/len(subdomains)*100) if subdomains else 0, 1)}%</h2><p>Live Ratio</p></div>
    </div>

    <div class="section">
        <h3>Live Hosts</h3>
        <table>
            <tr>
                <th>URL</th>
                <th>Status</th>
                <th>Title</th>
                <th>Tech Stack</th>
                <th>Web Server</th>
            </tr>
            {rows_html if rows_html else '<tr><td colspan="5">No live hosts found.</td></tr>'}
        </table>
    </div>

    <div class="section">
        <details>
            <summary>All Discovered Subdomains ({len(subdomains)})</summary>
            <ul>{all_subs_html}</ul>
        </details>
    </div>

    <footer>Generated by ReconDash &middot; for authorized security testing only</footer>
</body>
</html>"""

    Path(output_path).write_text(html, encoding="utf-8")
    print(f"[+] Report saved to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="ReconDash - All-in-One Recon Dashboard (subfinder + httpx + HTML report)"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=None, help="Output HTML file path")
    args = parser.parse_args()

    domain = args.domain.strip()
    output_path = args.output or f"recondash_{domain.replace('.', '_')}.html"

    banner = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ███████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║███████║███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══██║╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              All-in-One Recon Dashboard | by Muhammad Zubair
"""
    print(banner)

    missing = []
    if not check_tool("subfinder"):
        missing.append("subfinder")
    if not check_tool("httpx") and not check_tool("httpx-toolkit"):
        missing.append("httpx (or httpx-toolkit)")

    if missing:
        print(f"[!] Missing required tools: {', '.join(missing)}")
        print("[!] Install them and ensure they're in your $PATH before running.")
        sys.exit(1)

    subdomains = run_subfinder(domain)
    if not subdomains:
        print("[!] No subdomains found. Exiting.")
        sys.exit(0)

    live_hosts = run_httpx(subdomains)
    generate_html_report(domain, subdomains, live_hosts, output_path)

    print("=" * 55)
    print(f"[+] Done. Open '{output_path}' in your browser to view the dashboard.")
    print("=" * 55)


if __name__ == "__main__":
    main()
