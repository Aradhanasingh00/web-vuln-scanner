#!/usr/bin/env python3
"""
Web Vulnerability & Banner Scanner
---------------------------------
Scans target domain/IP for open ports, fetches HTTP/HTTPS headers,
checks for outdated server banners, and generates text, CSV, and HTML reports.
"""

import os
import nmap
import requests
import argparse
import csv
from colorama import Fore, Style
from jinja2 import Template

def scan_ports(target, ports):
    """
    Scans the target on given ports using python-nmap.
    Returns a list of tuples: (port, state).
    """
    print(f"\n🔍 Scanning ports on: {target}")
    nm = nmap.PortScanner()
    ports_info = []
    try:
        nm.scan(target, ports, arguments="-T4")  # speed up scan
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    state = nm[host][proto][port]['state']
                    print(Fore.GREEN + f"Port: {port}\tState: {state}" + Style.RESET_ALL)
                    ports_info.append((port, state))
    except Exception as e:
        print(f"Error running nmap: {e}")
    save_text_csv_report(target, ports_info)
    return ports_info

def save_text_csv_report(target, ports_info):
    """
    Saves ports_info to text & CSV in reports/ folder.
    """
    os.makedirs("reports", exist_ok=True)
    filename = target.replace('.', '_')
    with open(f"reports/scan_{filename}.txt", "w") as f:
        for port, state in ports_info:
            f.write(f"Port: {port}\tState: {state}\n")
    with open(f"reports/scan_{filename}.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Port", "State"])
        for port, state in ports_info:
            writer.writerow([port, state])

def get_http_headers(target):
    """
    Fetches HTTP & HTTPS headers.
    Returns list of tuples: (Header, Value)
    """
    headers_info = []
    for scheme in ["http", "https"]:
        url = f"{scheme}://{target}"
        print(f"\n🌐 Fetching HTTP headers from: {url}")
        try:
            response = requests.get(url, timeout=5, verify=False)
            print(f"Status Code: {response.status_code}")
            for header, value in response.headers.items():
                print(f"{header}: {value}")
                headers_info.append((f"{scheme.upper()} - {header}", value))
        except Exception as e:
            print(f"Could not fetch headers from {url}: {e}")
    return headers_info

def check_vulnerabilities(headers_info):
    """
    Looks for common outdated banners.
    Returns list of warning strings.
    """
    print("\n🛡️  Checking for common vulnerable banners:")
    found = []
    for header, value in headers_info:
        if "Apache/2.2" in value:
            msg = f"Potential outdated Apache found: {value}"
            print(Fore.RED + f"[!] {msg}" + Style.RESET_ALL)
            found.append(msg)
        elif "nginx/1.14" in value:
            msg = f"Potential outdated Nginx found: {value}"
            print(Fore.RED + f"[!] {msg}" + Style.RESET_ALL)
            found.append(msg)
    return found

def generate_html_report(target, ports_info, headers_info, vulnerabilities):
    """
    Generates pretty HTML report using Bootstrap & Jinja2.
    """
    filename = target.replace('.', '_')
    html_template = """
    <html>
    <head>
        <title>Scan Report for {{ target }}</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="p-4">
        <h1 class="mb-4">Scan Report for {{ target }}</h1>

        <h2>Open Ports</h2>
        <table class="table table-bordered">
            <tr><th>Port</th><th>State</th></tr>
            {% for port, state in ports %}
            <tr><td>{{ port }}</td><td>{{ state }}</td></tr>
            {% endfor %}
        </table>

        <h2>HTTP & HTTPS Headers</h2>
        <table class="table table-striped">
            <tr><th>Header</th><th>Value</th></tr>
            {% for header, value in headers %}
            <tr><td>{{ header }}</td><td>{{ value }}</td></tr>
            {% endfor %}
        </table>

        <h2>Detected Vulnerabilities</h2>
        {% if vulnerabilities %}
        <ul class="text-danger">
            {% for v in vulnerabilities %}
            <li>{{ v }}</li>
            {% endfor %}
        </ul>
        {% else %}
        <p class="text-success">No common vulnerable banners found.</p>
        {% endif %}
    </body>
    </html>
    """
    template = Template(html_template)
    html_content = template.render(
        target=target, ports=ports_info, headers=headers_info, vulnerabilities=vulnerabilities
    )
    with open(f"reports/scan_{filename}.html", "w") as f:
        f.write(html_content)
    print(f"✅ HTML report saved to reports/scan_{filename}.html")

def main():
    """
    CLI: parse args & run scanner.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', help='Target domain or IP')
    parser.add_argument('--ports', help='Port range (e.g. 1-1000 or 80,443)', default='80,443')
    args = parser.parse_args()

    target = args.target or input("Enter target domain (e.g., example.com): ").strip()
    ports_info = scan_ports(target, args.ports)
    headers_info = get_http_headers(target)
    vulnerabilities = check_vulnerabilities(headers_info)
    generate_html_report(target, ports_info, headers_info, vulnerabilities)

if __name__ == "__main__":
    main()

