<div align="center">

# 🛡️ SENTINEL

### HTTP Security & CVE Scanner

<p>
<img src="https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/Requests-HTTP%20Client-2CA5E0?style=for-the-badge">
<img src="https://img.shields.io/badge/NVD-REST%20API-4D4D4D?style=for-the-badge">
<img src="https://img.shields.io/badge/Regex-Pattern%20Analysis-4D4D4D?style=for-the-badge">
<img src="https://img.shields.io/badge/Version-v0.1.0-success?style=for-the-badge">
</p>

<p>
<b>A Python-based HTTP security scanner that analyzes web-server responses,
identifies software and versions, and retrieves associated CVE information
from the National Vulnerability Database.</b>
</p>

</div>

---

## 📌 Overview

**SENTINEL** is a Python-based HTTP security and vulnerability analysis
tool developed to automate a basic web-server assessment workflow.

The current version analyzes HTTP responses, extracts server
product/version information from response headers, validates detected
versions, and queries the **National Vulnerability Database (NVD)**
for associated CVE information.

SENTINEL v0.1.0 establishes the foundation for progressively expanding
the scanner with additional security analysis capabilities.

---

## 🔍 How It Works

```text
                    Target URL
                        │
                        ▼
                 HTTP GET Request
                        │
                        ▼
                HTTP Response
                        │
             ┌──────────┼──────────┐
             │          │          │
             ▼          ▼          ▼
         Status      Server     Content-Type
          Code       Header
                        │
                        ▼
                Product & Version
                    Extraction
                        │
                        ▼
                 Version Parsing
                        │
                        ▼
                Version Validation
                        │
                        ▼
                    NVD API
                        │
                        ▼
                  CVE Analysis
                        │
                        ▼
                 Security Results
```

---

## 🎯 Objectives

### 🔐 Security Objectives

- Analyze HTTP responses from target web servers
- Identify exposed server information
- Extract software product and version information
- Validate detected software versions
- Identify associated vulnerabilities and CVEs

### 🐍 Development Objectives

- Build a Python-based security automation tool
- Implement HTTP request handling
- Develop reusable version parsing logic
- Integrate an external vulnerability database
- Implement structured exception handling
- Establish a foundation for future scanning capabilities

---

## 🛠️ Technology Stack

| Category | Technology | Purpose |
| -------- | ---------- | ------- |
| Development | Python 3 | Core implementation |
| HTTP Communication | Requests | Sending HTTP requests |
| Pattern Analysis | Regular Expressions | Product/version parsing |
| Vulnerability Database | NVD REST API | CVE identification |

---

## 🌐 HTTP Response Analysis

SENTINEL begins by sending an HTTP GET request to the specified
target and collecting relevant response information.

### Response Information

```text
HTTP Response
     │
     ├── URL
     ├── Status Code
     ├── Server Header
     └── Content-Type
```

This information is passed to the analysis stage for further
processing.

---

## 🔎 Server Detection

SENTINEL analyzes the HTTP `Server` header to identify the
web-server software and its version.

For example:

```text
Apache/2.4.49
      │
      ├── Product → Apache
      └── Version → 2.4.49
```

The extracted information is then used for vulnerability analysis.

If the server header does not contain a recognizable product/version
format, SENTINEL handles the response without assuming a version.

---

## 🧩 Version Analysis

SENTINEL includes semantic version parsing and validation to
support software-version vulnerability analysis.

Example:

```text
2.4.49
   │
   ▼
[2, 4, 49]
```

### Version Analysis Pipeline

```text
Detected Version
       │
       ▼
Version Parser
       │
       ▼
Version Validation
       │
       ▼
Vulnerability Analysis
```

Version comparison allows the scanner to determine whether a
detected software version falls within a vulnerable version range.

---

## 🚨 CVE Analysis

After identifying a software product and version, SENTINEL can
query the **NVD REST API** to retrieve vulnerability information
associated with the detected software.

### CVE Analysis Pipeline

```text
Product + Version
       │
       ▼
    NVD API
       │
       ▼
CVE Information
       │
       ├── CVE ID
       ├── Severity
       └── Description
```

This allows the scanner to connect basic HTTP reconnaissance with
publicly available vulnerability information.

---

## 🧪 Example Workflow

```text
Target: http://example.com

[+] Sending HTTP request...

[+] Status Code: 200
[+] Server: Apache/2.4.49
[+] Product: Apache
[+] Version: 2.4.49

[+] Analyzing software version...

[+] Querying vulnerability information...

[!] Potential vulnerability information found
```

> Example output is provided to demonstrate the intended workflow.

---

## ⚠️ Error Handling

SENTINEL uses structured exception handling to prevent unexpected
HTTP or API failures from terminating the scanning workflow.

```text
HTTP Request
     │
     ├── Success ─────────► Response Analysis
     │
     ├── Timeout ─────────► Structured Error
     │
     └── Request Error ───► Structured Error
```

The scanner handles request-related failures and timeouts and
returns structured error information for further processing.

---

## 📂 Project Structure

```text
SENTINEL/
├── README.md
├── requirements.txt
├── .gitignore
└── src/
    └── sentinel.py
```

---

## ⚙️ Installation

### Clone the Repository

```bash
git clone https://github.com/sovon-mitro/SENTINEL.git
cd SENTINEL
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 🚀 Usage

Run the scanner with:

```bash
python src/sentinel.py
```

Enter the target URL when prompted.

---

## 📊 Current Capabilities

| Capability | Status |
| ---------- | ------ |
| HTTP Request Handling | ✅ Implemented |
| Response Analysis | ✅ Implemented |
| Server Header Detection | ✅ Implemented |
| Product/Version Extraction | ✅ Implemented |
| Version Parsing | ✅ Implemented |
| Version Validation | ✅ Implemented |
| NVD API Integration | ✅ Implemented |
| Structured Error Handling | ✅ Implemented |

---

## 🧠 Skills Demonstrated

### 🔐 Cybersecurity

HTTP Security • Server Fingerprinting • Vulnerability Identification • CVE Analysis • Security Automation

### 🐍 Development

Python • Requests • Regular Expressions • REST API Integration • Exception Handling • Version Parsing

---

## 🚀 Roadmap

SENTINEL is designed to evolve through incremental releases.

```text
v0.1.0
Initial HTTP & CVE Scanner
        │
        ▼
v0.2.0
Improved Detection & CVE Matching
        │
        ▼
v0.3.0
Reporting & CLI Improvements
        │
        ▼
v1.0.0
Stable Security Scanner
```

### Planned Improvements

- [ ] Improved server fingerprinting
- [ ] More robust version detection
- [ ] Improved CVE matching
- [ ] Vulnerability severity filtering
- [ ] Structured JSON reporting
- [ ] Improved command-line interface
- [ ] Logging and scan history
- [ ] Additional security checks

---

## 📜 Version History

### v0.1.0 — Initial Release

- Implemented HTTP target scanning
- Added HTTP response analysis
- Added server product/version extraction
- Implemented semantic version parsing and validation
- Integrated NVD REST API
- Added structured HTTP/API error handling

---

## ⚠️ Disclaimer

SENTINEL is developed for educational purposes and authorized
security testing.

Only scan systems, applications, and infrastructure that you own
or have explicit permission to assess.

The author is not responsible for unauthorized or illegal use of
this software.

---

<div align="center">

## 👤 Author

**Sovon Mitro**

Cybersecurity | Vulnerability Assessment | Security Automation | Python

**SENTINEL — HTTP Security & CVE Scanner**

<br>

⭐ If you found this project useful, consider giving the repository a star.

</div>
