# Automated Web Security Scanner

**Author:** Waghade Rohini Shivaji (Roll No. 77), TYBCA
**Program:** IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares

## Project Description
A single-file Python tool that audits a website for common security misconfigurations. It sends HTTP requests to a target URL, inspects the responses, and produces a pass/fail report with an overall score (0-100) and grade (A-F). A simple web page is also included to analyze pasted response headers.

## What It Checks
- HTTPS usage
- Security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- CORS flaws: wildcard origin, reflected origin, credentials allowed with a foreign origin
- Cookie flags: Secure, HttpOnly, SameSite

## Technologies Used
- Python 3.8+
- `requests` library
- HTML, CSS and JavaScript (for the header checker web page)

## Dataset
Not applicable. The tool scans live websites and does not use a dataset.

## Project Structure
```
web-security-scanner/
├── RohiniWaghade_WebSecurityScanner.py   # main scanner (single file)
├── requirements.txt                      # Python dependency (requests)
├── README.md                             # project overview
└── web/
    ├── index.html                        # header checker page
    ├── style.css
    └── script.js
```

## Setup
1. Install Python 3.8 or newer from python.org (tick "Add Python to PATH").
2. Download this repository (Code > Download ZIP) and unzip it.
3. Open a terminal in the project folder and install the dependency:
```bash
pip install -r requirements.txt
```

## Run
```bash
python RohiniWaghade_WebSecurityScanner.py https://example.com
python RohiniWaghade_WebSecurityScanner.py https://example.com --json report.json
```
If no URL is given, the program asks for one. Use `py` instead of `python` if `python` is not recognized on Windows.

### Web page (optional)
Open `web/index.html` in any browser. Paste a website's response headers and click **Analyze**. The "Fetch from a URL" option only works for sites that allow cross-origin access, so pasting headers is more reliable.

## Sample Result
Scan of a GitHub Pages site: **50/100, Grade D**. HTTPS and Strict-Transport-Security passed; Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy were missing; CORS used a wildcard (*).

## Scoring
| Check | Points |
|---|---|
| HTTPS | 20 |
| Content-Security-Policy | 20 |
| Strict-Transport-Security | 20 |
| X-Frame-Options | 10 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 5 |
| Permissions-Policy | 5 |
| CORS | 10 |
| Cookie flags | 10 |

Grades: A (90+), B (75+), C (60+), D (40+), F (below 40).

## Requirements
- Python 3.8+
- Internet connection
- `requests` library (see `requirements.txt`)

## Legal Notice
Only scan websites you own or have written permission to test.
