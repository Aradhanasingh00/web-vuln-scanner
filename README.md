# 🛡️ Web Vulnerability Scanner

> A lightweight Python tool to scan target IP/domain for open ports, fetch HTTP/HTTPS headers, detect common outdated server banners, and generate reports.

---

## ✨ **Features**
- Port scanning using nmap
- Fetch HTTP & HTTPS headers
- Detect outdated server banners (e.g., old Apache/Nginx)
- Generate text, CSV, and HTML reports
- Use virtual environment (venv) for clean setup

---

## ⚙️ **Installation**
```bash
# Clone the repository
git clone https://github.com/Aradhanasingh00/web-vuln-scanner.git
cd web-vuln-scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
# Run scan (with root permission because nmap needs it)
sudo -E venv/bin/python scanner.py --target scanme.nmap.org --ports 80,443
