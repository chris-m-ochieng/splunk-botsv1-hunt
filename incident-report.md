# Incident Report — BOTSv1-001

**Severity:** HIGH (confirmed full web server compromise + RCE)  
**Analyst:** Chris  
**Status:** Investigation complete — containment required  
**Date of compromise:** 2016-08-10  
**Investigation date:** 9/2/2026

---

## 1. Executive Summary

On 2016-08-10 starting at 23:36 UTC, an external attacker (`40.80.148.42`) targeted a Joomla web application hosted on an internal server (`192.168.250.70`). Over approximately 15 minutes, the attacker sent roughly 21,000 HTTP requests to the server — including 16,871 requests to a single SQL injection endpoint — using an automated tool identified by the `acunetix_wvs_security_test` scanner signature.

The attack succeeded. The attacker exploited SQL injection to obtain admin credentials, logged into the Joomla administrator panel, and installed two malicious extensions — including the eXtplorer file manager, which provided Remote Code Execution (RCE) capability on the web server. Ransomware-related signatures (Cerber) were also triggered during the attack window.

---

## 2. Methodology

The investigation started with a Suricata IDS alert. Working through Splunk, the attack was traced across seven stages:

| Stage | Focus | Finding |
|---|---|---|
| 1 | Oriented in the data | 26 sourcetypes, 33M+ events available |
| 2 | Identified the attacker | Top `src_ip` carried 98% of high-severity alerts |
| 3 | Characterized the attack | 29 signatures across 4 categories |
| 4 | Confirmed the victim | `192.168.250.70` — Joomla web server |
| 5 | Verified attack success | 91% success rate on HTTP status codes |
| 6 | Extracted payloads | requests containing SQLi payloads |
| 7 | Traced post-exploitation | Admin login + persistence installed |

The attack was visible across multiple independent log sources (Suricata IDS, IIS web server, Stream HTTP), which cross-confirmed each finding.

---

## 3. Attack Timeline

| Time (UTC) | Event |
|---|---|
| 23:36:57 | Attacker begins scanning — probes `/CFIDE/`, various Joomla component paths (all return 404) |
| 23:37:56 | Attempts 9 different file-upload exploits against known vulnerable Joomla components (all 404) |
| 23:40:00 | Mass SQL injection begins against `/joomla/index.php/component/search/` |
| 23:41:23 | XSS and SQLi payloads flood the endpoint |
| 23:42:27 | Error-based injection using `response.write()` payloads |
| 23:43:00 | Attack peaks at ~427 requests per minute |
| 23:47:59 | Attacker reaches the admin panel (`/joomla/administrator/`) |
| **23:48:06** | **Successful login** — `POST /administrator/index.php` returns 303 redirect |
| 23:48:07 | Admin dashboard loads (200 OK) |
| 23:50:31 | **First malicious extension uploaded** (`com_installer&view=install` → 303) |
| 23:51:10 | **Second malicious extension uploaded** (`com_installer&view=install` → 303) |
| 23:51:12 | eXtplorer file manager component loaded |
| 23:51:33 | **Remote Code Execution** via eXtplorer `action=include_javascript&file=functions.js` |
| 23:51:34 | Full file-system browser UI loaded |

---

## 4. Impact Assessment

The attacker achieved:

- Authenticated admin session on the Joomla CMS
- Installed two malicious extensions (persistence)
- Gained Remote Code Execution via eXtplorer
- Full file-system read/write access to the web server
- Triggered Cerber ransomware-related signatures

**The web server should be considered fully compromised.** An attacker with RCE on a web server can:

- Read sensitive files (config, credentials, database dumps)
- Modify web content (defacement, code injection)
- Pivot to the internal network from the compromised host
- Install persistent backdoors
- Use the server as a C2 relay

---

## 5. Indicators of Compromise (IOCs)

### Network

| Type | Value |
|---|---|
| Attacker IP | `40.80.148.42` |
| Victim IP | `192.168.250.70` |
| Victim port | 80 (HTTP) |

### URLs

| Purpose | URL |
|---|---|
| Attack endpoint | `/joomla/index.php/component/search/` |
| Admin access | `/joomla/administrator/index.php` |
| Extension upload | `/joomla/administrator/index.php?option=com_installer&view=install` |
| RCE endpoint | `/joomla/administrator/index.php?option=com_extplorer&action=include_javascript&file=` |
| Malicious component | `/joomla/administrator/components/com_extplorer/` |

### Payload patterns

| Type | Example |
|---|---|
| Arithmetic probe | `catid=1*1*1*98` |
| Error-based injection | `catid=response.write(9615406*9885538)` |
| Quote variant | `catid='+response.write(...)+'` |

### Scanner fingerprint

- `acunetix_wvs_security_test` (in URL query strings)

### Ransomware signatures

- `ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup`
- `ETPRO TROJAN Ransomware/Cerber Checkin Error ICMP Response`

### Suricata signatures observed

- `ET WEB_SERVER Script tag in URI, Possible Cross Site Scripting Attempt`
- `ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY`
- `ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM`
- `ET WEB_SERVER SQL Injection Select Sleep Time Delay`
- `ET WEB_SERVER Possible CVE-2014-6271 Attempt` (Shellshock)
- `ET WEB_SERVER PHP tags in HTTP POST`
- `ET WEB_SERVER allow_url_include PHP config option in uri`

---

## 6. Recommendations

### Immediate (containment)

1. **Isolate the web server** from the network
2. **Take a forensic image** before any cleanup
3. **Reset ALL admin credentials** for the Joomla CMS
4. **Audit the CMS** for unauthorized users, extensions, and files

### Remediation

5. **Rebuild the web server from clean media** — RCE means no trust can be restored
6. **Patch Joomla core and all extensions** to latest versions
7. **Deploy a WAF** in front of the CMS
8. **Restrict admin panel access** — VPN or IP whitelist only

### Detection

9. Alert on any request containing `com_installer&view=install`
10. Alert on Acunetix / Nessus / sqlmap / nikto user-agent strings
11. Monitor for outbound traffic to known Cerber domains

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance | T1595 — Active Scanning | Acunetix scanner |
| Initial Access | T1190 — Exploit Public-Facing Application | SQL injection |
| Execution | T1059 — Command and Scripting Interpreter | eXtplorer RCE |
| Persistence | T1505.003 — Web Shell | Malicious extensions |
| Privilege Escalation | T1078 — Valid Accounts | Admin login |
| Credential Access | T1110 — Brute Force | Repeated probes |

---

## 8. Conclusion

This was a **successful, automated web application attack** that escalated from SQL injection to full Remote Code Execution on the target server. The attacker used publicly available scanning tooling (Acunetix), exploited a well-known vulnerability class (SQL injection in Joomla components), and installed persistence via the CMS extension manager.

The web server is **fully compromised** and must be rebuilt. Detection controls (IDS + IIS log monitoring) successfully identified the attack in real time — but response controls (WAF, authentication hardening) failed to block it.

---
