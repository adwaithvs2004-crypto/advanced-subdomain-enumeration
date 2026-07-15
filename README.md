# advanced-subdomain-enumeration
Advanced Python-based subdomain enumeration tool with DNS brute-forcing, Subfinder integration, HTTP/HTTPS probing, wildcard DNS detection, Gowitness screenshots, and TXT/JSON/CSV output. Built for security reconnaissance and authorized penetration testing.


# Advanced Subdomain Enumeration

A powerful Python-based subdomain enumeration tool for security researchers, penetration testers, and bug bounty hunters. It combines DNS brute-forcing, OSINT discovery, HTTP/HTTPS probing, wildcard DNS detection, and automated website screenshots to streamline reconnaissance.

> **Disclaimer:** This tool is intended for authorized security testing and educational purposes only. Only scan domains you own or have explicit permission to test.

---

## Features

- 🚀 Multi-threaded subdomain enumeration
- 🌐 DNS A and CNAME record resolution
- 🔍 Wildcard DNS detection and filtering
- 📡 OSINT discovery using Subfinder
- 🔒 HTTP & HTTPS live host detection
- 📊 HTTP status code collection
- 📸 Automated screenshots using Gowitness
- 📁 Export results to TXT, JSON, and CSV
- ⚙️ Configurable threads, timeouts, retries, and rate limiting
- 📝 Detailed logging with verbose mode

---

## Requirements

- Python 3.9+
- dnspython
- httpx
- urllib3

### Optional Tools

- Subfinder
- Gowitness

---

## Installation

```bash
git clone https://github.com/004-crypto/advanced-subdomain-enumeration.git
cd advanced-subdomain-enumeration

pip install -r requirements.txt
```

---

## Usage

```bash
python3 subdomain_scanner.py -d example.com -w wordlist.txt
```

### Example

```bash
python3 subdomain_scanner.py \
-d example.com \
-w wordlist.txt \
-t 100 \
--timeout 5 \
-o results
```

---

## Output

The tool generates:

- `live_subdomains.txt`
- `live_https.txt`
- `live_http.txt`
- `results_TIMESTAMP.json`
- `results_TIMESTAMP.csv`
- `screenshots/` (if Gowitness is installed)

---

## Command Line Options

| Option | Description |
|--------|-------------|
| `-d` | Target domain |
| `-w` | Wordlist |
| `-t` | Number of threads |
| `--timeout` | DNS/HTTP timeout |
| `--retries` | DNS retry attempts |
| `-o` | Output directory |
| `--rate-limit` | Delay between requests |
| `--no-subfinder` | Disable Subfinder |
| `--no-screenshots` | Disable Gowitness screenshots |
| `-v` | Verbose logging |

---

## Technologies Used

- Python
- dnspython
- httpx
- Subfinder
- Gowitness

---

## Author

**ADWAITH VS**

GitHub: https://github.com/004-crypto

---

## License

This project is licensed under the MIT License.

---

⭐ If you found this project useful, consider giving it a star on GitHub!
