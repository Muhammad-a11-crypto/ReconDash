#!/usr/bin/env python3
"""
ReconDash - All-in-One Recon Dashboard
----------------------------------------
Automates: subdomain enumeration (subfinder) -> live host detection (httpx)
-> optional port scan (nmap) -> HTML report generation.

Usage:
    python3 recondash.py -d target.com
    python3 recondash.py -d target.com -o report.html
    python3 recondash.py -d target.com --nmap

Requirements:
    - subfinder (https://github.com/projectdiscovery/subfinder)
    - httpx     (https://github.com/projectdiscovery/httpx)
      On Kali Linux this is packaged as 'httpx-toolkit'.
    - nmap      (optional, only required if --nmap is used)
    All should be installed and available in $PATH.

IMPORTANT: The --nmap flag performs ACTIVE scanning (it sends packets
directly to the target). Only use it against systems you are explicitly
authorized to test (your own bug bounty scope, a lab environment, or
infrastructure you own). Subdomain enumeration and httpx probing are
passive/low-noise by comparison, but the same rule applies: only scan
targets you have permission to test.

Author: Muhammad Zubair (oxdzubair)
"""

import argparse
import json
import re
import subprocess
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ---- ANSI colors for the terminal (hacker-style output) ----
class C:
    GREEN = "\033[92m"
    BOLD_GREEN = "\033[1;92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


# Verbosity level: "quiet", "normal" (default), or "verbose".
# Set once in main() based on CLI flags, read everywhere else.
VERBOSITY = "normal"


def vprint(message: str, level: str = "normal"):
    """
    Print respecting the global VERBOSITY setting.
    level="normal"  -> shown in normal and verbose mode, hidden in quiet mode
    level="verbose" -> shown only in verbose mode
    level="always"  -> always shown, even in quiet mode (e.g. final report path)
    """
    if level == "always":
        print(message)
    elif level == "verbose":
        if VERBOSITY == "verbose":
            print(message)
    else:  # normal
        if VERBOSITY != "quiet":
            print(message)


def check_tool(name: str) -> bool:
    """Check if an external tool is available in PATH."""
    return shutil.which(name) is not None


def run_subfinder(domain: str, timeout: int = 120) -> list[str]:
    """Run subfinder against the domain and return a list of subdomains."""
    vprint(f"{C.GREEN}[*]{C.RESET} Running subfinder on {C.CYAN}{domain}{C.RESET} ...")
    vprint(f"{C.DIM}    command: subfinder -d {domain} -silent{C.RESET}", level="verbose")
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        vprint(f"{C.YELLOW}[!]{C.RESET} subfinder timed out, using partial results if any.")
        return []
    except FileNotFoundError:
        vprint(f"{C.RED}[!]{C.RESET} subfinder not found in PATH.")
        return []

    subs = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    vprint(f"{C.GREEN}[+]{C.RESET} subfinder found {C.BOLD}{len(subs)}{C.RESET} subdomains.")
    if VERBOSITY == "verbose":
        for s in subs:
            vprint(f"{C.DIM}    found: {s}{C.RESET}", level="verbose")
    return subs


def run_httpx(subdomains: list[str], timeout: int = 180) -> list[dict]:
    """
    Run httpx against a list of subdomains to find live hosts.
    Returns a list of dicts with url, status_code, title, tech, etc.

    On Kali Linux, ProjectDiscovery's httpx is packaged as 'httpx-toolkit'
    to avoid a naming conflict with the unrelated Python 'httpx' package.
    This function prefers 'httpx-toolkit' if present, otherwise falls
    back to 'httpx'.
    """
    if not subdomains:
        return []

    httpx_bin = "httpx-toolkit" if check_tool("httpx-toolkit") else "httpx"

    vprint(f"{C.GREEN}[*]{C.RESET} Probing {len(subdomains)} hosts with {httpx_bin} ...")
    vprint(f"{C.DIM}    command: {httpx_bin} -silent -json -status-code -title -tech-detect -follow-redirects{C.RESET}", level="verbose")
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
        vprint(f"{C.YELLOW}[!]{C.RESET} httpx timed out, using partial results if any.")
        return []
    except FileNotFoundError:
        vprint(f"{C.RED}[!]{C.RESET} {httpx_bin} not found in PATH.")
        return []

    live_hosts = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            entry = {
                "url": data.get("url", ""),
                "host": data.get("host", "") or data.get("input", ""),
                "status_code": data.get("status_code", ""),
                "title": data.get("title", ""),
                "tech": ", ".join(data.get("tech", [])) if data.get("tech") else "",
                "webserver": data.get("webserver", ""),
            }
            live_hosts.append(entry)
            vprint(f"{C.DIM}    live: {entry['url']} [{entry['status_code']}]{C.RESET}", level="verbose")
        except json.JSONDecodeError:
            continue

    vprint(f"{C.GREEN}[+]{C.RESET} httpx found {C.BOLD}{len(live_hosts)}{C.RESET} live hosts.")
    return live_hosts


def extract_hostname(url_or_host: str) -> str:
    """Strip scheme/path/port from a URL or host string to get a bare hostname."""
    h = re.sub(r"^https?://", "", url_or_host)
    h = h.split("/")[0]
    h = h.split(":")[0]
    return h


def _nmap_scan_single_host(host: str, timeout: int) -> tuple[str, list[dict]]:
    """Run nmap against a single host and return (host, list of open port dicts)."""
    try:
        proc = subprocess.run(
            ["nmap", "-F", "-T4", "--open", "-oG", "-", host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return host, []
    except FileNotFoundError:
        return host, []

    ports = []
    for line in proc.stdout.splitlines():
        if line.startswith("Host:") and "Ports:" in line:
            ports_part = line.split("Ports:")[1].split("Ignored")[0].strip()
            for entry in ports_part.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                fields = entry.split("/")
                if len(fields) >= 5:
                    port_num, state, _, _, service = fields[0], fields[1], fields[2], fields[3], fields[4]
                    if state == "open":
                        ports.append({"port": port_num, "state": state, "service": service or "unknown"})
    return host, ports


def run_nmap(hosts: list[str], timeout: int = 300, max_workers: int = 5) -> dict[str, list[dict]]:
    """
    Run a fast nmap scan (top 100 ports) against each given host, in parallel
    (up to max_workers concurrent scans) to keep total scan time reasonable
    when there are many live hosts.

    Returns a dict mapping host -> list of {port, state, service} dicts.
    Each entry reflects exactly what nmap reported — nothing is inferred
    or assumed; hosts behind the same CDN/load balancer may legitimately
    show the same open ports (e.g. 443) because they share infrastructure.

    Only called when the user has passed --nmap AND explicitly confirmed
    authorization at the interactive prompt in main().
    """
    results: dict[str, list[dict]] = {}

    if not check_tool("nmap"):
        vprint(f"{C.RED}[!]{C.RESET} nmap not found in PATH. Skipping port scan.")
        return results

    unique_hosts = sorted(set(extract_hostname(h) for h in hosts if h))

    vprint(
        f"{C.GREEN}[*]{C.RESET} Scanning {len(unique_hosts)} host(s) with nmap "
        f"({max_workers} in parallel, top 100 ports each) ..."
    )
    vprint(f"{C.DIM}    command per host: nmap -F -T4 --open -oG - <host>{C.RESET}", level="verbose")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_nmap_scan_single_host, host, timeout): host
            for host in unique_hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                host, ports = future.result()
            except Exception:
                ports = []

            if ports:
                port_summary = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
                vprint(
                    f"{C.GREEN}[+]{C.RESET} {host}: {C.BOLD}{len(ports)}{C.RESET} open port(s) -> "
                    f"{C.GREEN}{port_summary}{C.RESET}"
                )
            else:
                vprint(f"{C.DIM}[-] {host}: no open ports in top 100.{C.RESET}")

            results[host] = ports

    return results


def print_results_to_terminal(
    domain: str,
    subdomains: list[str],
    live_hosts: list[dict],
    nmap_results: dict[str, list[dict]],
):
    """Print a full summary of all findings directly to the terminal,
    in addition to the HTML report. Output is exactly what was found —
    no values are invented or guessed."""

    status_color = {
        "2": C.GREEN,
        "3": C.YELLOW,
        "4": C.YELLOW,
        "5": C.RED,
    }

    def color_for(status_code):
        return status_color.get(str(status_code)[:1], C.DIM)

    print()
    print(f"{C.BOLD_GREEN}{'=' * 70}{C.RESET}")
    print(f"{C.BOLD_GREEN} RESULTS SUMMARY — {domain}{C.RESET}")
    print(f"{C.BOLD_GREEN}{'=' * 70}{C.RESET}")

    # ---- Live hosts table ----
    print()
    print(f"{C.CYAN}{C.BOLD}LIVE HOSTS ({len(live_hosts)}){C.RESET}")
    if live_hosts:
        print(f"{C.DIM}{'-' * 100}{C.RESET}")
        print(f"{'URL':<45} {'STATUS':<8} {'TITLE':<30} {'TECH'}")
        print(f"{C.DIM}{'-' * 100}{C.RESET}")
        for host in live_hosts:
            url = (host["url"] or "-")[:44]
            status = str(host["status_code"] or "-")
            title = (host["title"] or "-")[:29]
            tech = host["tech"] or "-"
            c = color_for(host["status_code"])
            print(f"{url:<45} {c}{status:<8}{C.RESET} {title:<30} {tech}")
    else:
        print(f"{C.DIM}  No live hosts found.{C.RESET}")

    # ---- Nmap results table ----
    if nmap_results:
        print()
        print(f"{C.CYAN}{C.BOLD}PORT SCAN RESULTS (nmap, top 100 ports){C.RESET}")
        print(f"{C.DIM}{'-' * 70}{C.RESET}")
        for host, ports in sorted(nmap_results.items()):
            if ports:
                port_list = ", ".join(f"{p['port']}/{p['service']}" for p in ports)
                print(f"  {C.CYAN}{host}{C.RESET} -> {C.GREEN}{port_list}{C.RESET}")
            else:
                print(f"  {C.DIM}{host} -> no open ports found{C.RESET}")

    # ---- Subdomains list ----
    print()
    print(f"{C.CYAN}{C.BOLD}ALL DISCOVERED SUBDOMAINS ({len(subdomains)}){C.RESET}")
    print(f"{C.DIM}{'-' * 70}{C.RESET}")
    for sub in subdomains:
        print(f"  {C.DIM}-{C.RESET} {sub}")

    print()
    print(f"{C.BOLD_GREEN}{'=' * 70}{C.RESET}")


def generate_html_report(
    domain: str,
    subdomains: list[str],
    live_hosts: list[dict],
    nmap_results: dict[str, list[dict]],
    output_path: str,
):
    """Generate a clean, professional, self-contained HTML dashboard report."""
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

    nmap_section_html = ""
    if nmap_results:
        nmap_rows = ""
        any_open = False
        for host, ports in sorted(nmap_results.items()):
            if not ports:
                nmap_rows += f"""
                <tr>
                    <td>{host}</td>
                    <td colspan="3" style="color:#64748b;">No open ports found (top 100 scanned)</td>
                </tr>"""
                continue
            any_open = True
            for p in ports:
                nmap_rows += f"""
                <tr>
                    <td>{host}</td>
                    <td><span style="color:#22c55e; font-weight:600;">{p['port']}</span></td>
                    <td>{p['state']}</td>
                    <td>{p['service']}</td>
                </tr>"""

        nmap_section_html = f"""
    <div class="section">
        <h3>Port Scan Results (nmap, top 100 ports)</h3>
        <table>
            <tr>
                <th>Host</th>
                <th>Port</th>
                <th>State</th>
                <th>Service</th>
            </tr>
            {nmap_rows}
        </table>
    </div>"""

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
        flex-wrap: wrap;
    }}
    .card {{
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 18px 25px;
        flex: 1;
        min-width: 140px;
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
    {nmap_section_html}
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
    print(f"{C.GREEN}[+]{C.RESET} Report saved to: {C.CYAN}{output_path}{C.RESET}")


def confirm_authorization(domain: str) -> bool:
    """
    Require an explicit typed confirmation before running an active scan
    (nmap) against a target. Returns True only if the user types 'yes'.
    """
    print()
    print(f"{C.YELLOW}{C.BOLD}[WARNING]{C.RESET} You requested an nmap port scan against:")
    print(f"          {C.CYAN}{domain}{C.RESET}")
    print(f"{C.YELLOW}          This is an ACTIVE scan — it sends packets directly to the target.{C.RESET}")
    print(f"{C.YELLOW}          Only proceed if you are explicitly authorized to test this domain{C.RESET}")
    print(f"{C.YELLOW}          (your own bug bounty scope, a lab environment, or infrastructure you own).{C.RESET}")
    print()
    answer = input(f"Type {C.BOLD}yes{C.RESET} to confirm you are authorized to scan this target: ").strip().lower()
    return answer == "yes"


def main():
    global VERBOSITY

    parser = argparse.ArgumentParser(
        description="ReconDash - All-in-One Recon Dashboard (subfinder + httpx + optional nmap + HTML report)"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default=None, help="Output HTML file path")
    parser.add_argument(
        "--nmap",
        action="store_true",
        help="Also run an nmap port scan (top 100 ports) against discovered live hosts. "
             "ACTIVE scan — requires interactive authorization confirmation.",
    )
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show extra detail: exact commands run, every probed host, raw findings as they're discovered.",
    )
    verbosity_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Show minimal output: skip the banner and progress lines, print only the final results summary.",
    )
    args = parser.parse_args()

    if args.verbose:
        VERBOSITY = "verbose"
    elif args.quiet:
        VERBOSITY = "quiet"
    else:
        VERBOSITY = "normal"

    domain = args.domain.strip()
    output_path = args.output or f"recondash_{domain.replace('.', '_')}.html"

    banner = f"""{C.BOLD_GREEN}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗  █████╗ ███████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔════╝██║  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║  ██║███████║███████╗███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║  ██║██╔══██║╚════██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝██║  ██║███████║██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
{C.RESET}{C.DIM}              All-in-One Recon Dashboard | by Muhammad Zubair{C.RESET}
"""
    vprint(banner)
    if VERBOSITY == "verbose":
        vprint(f"{C.DIM}[mode: verbose]{C.RESET}", level="verbose")
    elif VERBOSITY == "quiet":
        pass  # banner and mode notice both suppressed in quiet mode

    missing = []
    if not check_tool("subfinder"):
        missing.append("subfinder")
    if not check_tool("httpx") and not check_tool("httpx-toolkit"):
        missing.append("httpx (or httpx-toolkit)")
    if args.nmap and not check_tool("nmap"):
        missing.append("nmap")

    if missing:
        print(f"{C.RED}[!]{C.RESET} Missing required tools: {', '.join(missing)}")
        print(f"{C.RED}[!]{C.RESET} Install them and ensure they're in your $PATH before running.")
        sys.exit(1)

    subdomains = run_subfinder(domain)
    if not subdomains:
        vprint(f"{C.YELLOW}[!]{C.RESET} No subdomains found. Exiting.")
        sys.exit(0)

    live_hosts = run_httpx(subdomains)

    nmap_results = {}
    if args.nmap:
        if confirm_authorization(domain):
            scan_targets = [h["host"] or h["url"] for h in live_hosts] if live_hosts else subdomains
            nmap_results = run_nmap(scan_targets)
        else:
            vprint(f"{C.YELLOW}[!]{C.RESET} Authorization not confirmed. Skipping nmap scan.")

    # The full results summary always prints, even in quiet mode —
    # quiet mode means "skip the noise", not "hide the findings".
    print_results_to_terminal(domain, subdomains, live_hosts, nmap_results)

    generate_html_report(domain, subdomains, live_hosts, nmap_results, output_path)

    vprint(f"{C.GREEN}{'=' * 55}{C.RESET}")
    print(f"{C.GREEN}[+]{C.RESET} Done. Open '{C.CYAN}{output_path}{C.RESET}' in your browser to view the dashboard.")
    vprint(f"{C.GREEN}{'=' * 55}{C.RESET}")


if __name__ == "__main__":
    main()
