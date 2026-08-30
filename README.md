# SENTINEL

### HTTP Security & CVE Scanner

SENTINEL is a Python-based HTTP security scanner that analyzes web
server information and checks detected software versions against
known vulnerabilities using the NVD API.

> **Current Version:** v0.1.0

---

## Overview

SENTINEL is an educational cybersecurity project focused on
automating a basic vulnerability assessment workflow.

The current version performs HTTP reconnaissance, identifies the
web server and version from the `Server` response header, validates
the detected version, and queries the National Vulnerability
Database (NVD) for relevant CVE information.

---

## How It Works

```text
Target URL
    │
    ▼
HTTP Request
    │
    ▼
HTTP Response
    │
    ├── Status Code
    ├── Content-Type
    └── Server Header
            │
            ▼
     Product & Version
        Detection
            │
            ▼
      Version Validation
            │
            ▼
         NVD API
            │
            ▼
       CVE Results
```

---

## Features

- HTTP target scanning
- HTTP response analysis
- Server header detection
- Web server product identification
- Server version extraction
- Semantic version validation
- NVD API integration
- CVE lookup
- Structured exception handling

## Example Workflow

```text
Target: http://example.com

[+] Sending HTTP request...

[+] Status Code: 200
[+] Server: Apache/2.4.49
[+] Product: Apache
[+] Version: 2.4.49

[+] Searching NVD for vulnerabilities...

[!] Potential vulnerabilities found

```
## Project Architecture

- SENTINEL v0.1 follows a simple scanning pipeline:

```text
  Scanner
   │
   ▼
HTTP Response Collection
   │
   ▼
Server Header Analyzer
   │
   ▼
Version Parser
   │
   ▼
Vulnerability Lookup
   │
   ▼
CVE Results

```
## Technologies
| Technology          | Purpose            |
| ------------------- | ------------------ |
| Python              | Core development   |
| Requests            | HTTP communication |
| Regular Expressions | Version extraction |
| NVD REST API        | CVE information    |

## Installation

- Clone the repository:

```text
git clone https://github.com/sovon-mitro/SENTINEL.git
cd SENTINEL
```
- Install the required dependencies:
```text
pip install -r requirements.txt
```
## Usage

- Run the scanner:
```text
python src/sentinel.py
```
- Enter a target URL when prompted.

- Only scan systems that you own or have explicit authorization to test.

## Version History

### v0.1.0 — Initial Release

- Initial HTTP scanning functionality
- Server/product detection
- Version parsing and validation
- NVD vulnerability lookup
- Basic error handling

## Disclaimer

SENTINEL is developed for educational purposes and authorized
security testing.

Do not use this tool against systems without explicit permission.
The author is not responsible for unauthorized or illegal use.

## Author

**Sovon Mitro**

Cybersecurity enthusiast focused on security automation,
vulnerability assessment, and offensive security.

- GitHub: [sovon-mitro](https://github.com/sovon-mitro)
- LinkedIn: [Sovon Mitro](https://www.linkedin.com/in/sovon-mitro)
