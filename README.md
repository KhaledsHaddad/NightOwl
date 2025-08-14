# NightOwl – Web Reconnaissance Tool 🦉

**Author:** Khaled S. Haddad  
**Website:** [khaledhaddad.tech](https://khaledhaddad.tech)

---

## Overview

**NightOwl** is an advanced **graphical reconnaissance tool** designed for cybersecurity professionals and penetration testers. It offers a wide range of web reconnaissance capabilities in a sleek **black-and-green terminal-style GUI**, enabling efficient passive and active information gathering.

---

## Features

- **Subdomain Scan:** Enumerate all subdomains of a target domain via [crt.sh](https://crt.sh).  
- **DNS Lookup:** Retrieve A, AAAA, MX, NS, CNAME, and TXT records.  
- **Port Scan:** Scan ports `1–1024` to detect open services.  
- **SSL/TLS Info:** Fetch certificate details, including issuer, validity period, and serial number.  
- **HTTP Headers:** Retrieve HTTP headers from target domains.  
- **Subdomain Takeover Check:** Detect vulnerable subdomains susceptible to takeover.  
- **Technology Stack Detection:** Identify CMS, frameworks, and server technologies using `builtwith`.  
- **Backup File Check:** Detect common backup files accessible over HTTP/HTTPS.  
- **WHOIS Lookup:** Retrieve domain registration and ownership information.  
- **Screenshot Capture:** Take full-page screenshots of target websites.  
- **Save Report:** Export all results to a text file for offline analysis.

---

## Installation

Install the required Python libraries via `pip`:

```bash
pip install requests dnspython selenium builtwith python-whois
