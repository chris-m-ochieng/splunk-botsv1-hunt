# Indicators of Compromise (IOCs)

**Incident:** BOTSv1-001 — Joomla Web Compromise
**Source dataset:** Splunk BOTSv1
**Attack date:** 2016-08-10
**Attacker IP:** 40.80.148.42

---

## Network IOCs

| Type | Value | Notes |
|---|---|---|
| Attacker IP | 40.80.148.42 | External, Azure cloud range |
| Victim IP | 192.168.250.70 | Internal Joomla web server |
| Victim port | 80 | HTTP |
| Internal scan IP | 192.168.250.100 | Internal, low-volume noise |
| Internal scan IP | 192.168.2.50 | Internal, single alert |

---

## URL IOCs

### Attack endpoints

/joomla/index.php/component/search/
/joomla/index.php/component/mailto/

### Post-exploitation endpoints

/joomla/administrator/
/joomla/administrator/index.php
/joomla/administrator/index.php?option=com_installer
/joomla/administrator/index.php?option=com_installer&view=install
/joomla/administrator/index.php?option=com_extplorer
/joomla/administrator/index.php?option=com_extplorer&action=include_javascript&file=
/joomla/administrator/components/com_extplorer/
/joomla/administrator/components/com_extplorer/fetchscript.php
/joomla/index.php/log-out

### Failed reconnaissance paths

/CFIDE/administrator/index.cfm
/administrator/components/com_jnewsletter/includes/openflashchart/php-ofc-library/ofc_upload_image.php
/administrator/components/com_civicrm/civicrm/packages/OpenFlashChart/php-ofc-library/ofc_upload_image.php
/administrator/components/com_acymailing/inc/openflash/php-ofc-library/ofc_upload_image.php
/administrator/components/com_redmystic/chart/php-ofc-library/ofc_upload_image.php
/administrator/components/com_jmail15/charts/php-ofc-library/ofc_upload_image.php
/administrator/components/com_joomleague/assets/classes/php-ofc-library/ofc_upload_image.php
/administrator/components/com_jinc/classes/graphics/php-ofc-library/ofc_upload_image.php
/administrator/components/com_maimanmedia/utilities/charts/php-ofc-library/ofc_upload_image.php

---

## Payload IOCs

### SQL injection payload patterns

| Pattern | Type |
|---|---|
| catid=1*1*1*98 | Arithmetic probe |
| catid=9*350*345*0 | Arithmetic probe |
| catid=9*146*141*0 | Arithmetic probe |
| catid=9*67*62*0 | Arithmetic probe |
| catid=response.write(N*N) | Error-based injection |
| catid='+response.write(N*N)+' | Quote-wrapped variant |
| catid="+response.write(N*N)+" | Double-quote variant |

### XSS payload patterns

| Pattern | Type |
|---|---|
| wvstest=javascript:domxssExecutionSink(...) | DOM-based XSS probe |
| <xssstag> | XSS test marker |

### Scanner fingerprint

acunetix_wvs_security_test
%24%7B%40print(md5(acunetix_wvs_security_test))%7D

This string is unique to the Acunetix Web Vulnerability Scanner. Its presence confirms automated tooling.

---

## Suricata Signatures Observed

### Web Application Attack

ET WEB_SERVER Script tag in URI, Possible Cross Site Scripting Attempt
ET WEB_SERVER Onmouseover= in URI - Likely Cross Site Scripting Attempt
ET WEB_SERVER Possible XXE SYSTEM ENTITY in POST BODY
ET WEB_SERVER Possible SQL Injection Attempt SELECT FROM
ET WEB_SERVER SQL Injection Select Sleep Time Delay
ET WEB_SERVER PHP tags in HTTP POST
ET WEB_SERVER allow_url_include PHP config option in uri
ET WEB_SERVER auto_prepend_file PHP config option in uri
ET WEB_SERVER disable_functions PHP config option in uri
ET WEB_SERVER open_basedir PHP config option in uri
ET WEB_SERVER safe_mode PHP config option in uri
ET WEB_SERVER suhosin.simulation PHP config option in uri
GPL EXPLOIT unicode directory traversal attempt
GPL WEB_SERVER Tomcat directory traversal attempt
GPL WEB_SERVER Tomcat null byte directory listing attempt

### Attempted Administrator Privilege Gain

ET WEB_SERVER Possible CVE-2014-6271 Attempt
ET WEB_SERVER Possible CVE-2014-6271 Attempt in Headers

### Network Trojan (high severity)

ETPRO TROJAN Ransomware/Cerber Onion Domain Lookup
ETPRO TROJAN Ransomware/Cerber Checkin Error ICMP Response
ET WEB_SERVER PHP.//Input in HTTP POST
ET WEB_SERVER Possible SQLi Attempt in User Agent (Inbound)

### Privacy Violation

ET POLICY Incoming Basic Auth Base64 HTTP Password detected unencrypted

---

## HTTP Status Indicators

| Status | Meaning during this incident |
|---|---|
| 303 | Redirect — indicates successful login / accepted upload |
| 200 | Success — server returned valid content |
| 500 | Server error — payload reached application code |
| 404 | Not found — reconnaissance path incorrect |

---

## Attack Timeline (for correlation)

| Time (UTC) | Event |
|---|---|
| 2016-08-10 23:36:57 | Initial scanning begins |
| 2016-08-10 23:37:56 | Multiple file-upload exploit attempts |
| 2016-08-10 23:40:00 | Mass SQL injection begins |
| 2016-08-10 23:43:00 | Attack peak (~427 req/min) |
| 2016-08-10 23:47:59 | Admin panel reached |
| 2016-08-10 23:48:06 | Login success (POST -> 303) |
| 2016-08-10 23:50:31 | First malicious extension uploaded |
| 2016-08-10 23:51:10 | Second malicious extension uploaded |
| 2016-08-10 23:51:33 | Remote Code Execution via eXtplorer |

---

## Detection Recommendations

### Splunk alerts to create

1. Joomla extension install from external IP

index=* sourcetype=iis cs_uri_query="*com_installer*view=install*" sc_status=303
| where NOT match(c_ip, "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")

2. Acunetix scanner detection

index=* sourcetype=iis
| where match(cs_uri_query, "(?i)acunetix")
| stats count by c_ip
| where count > 10

3. eXtplorer RCE attempt

index=* sourcetype=iis cs_uri_query="*com_extplorer*action=include_javascript*"

4. SQL injection in User-Agent

index=* sourcetype=iis
| where match(cs_User_Agent, "(?i)select|union|sleep|benchmark")

5. Rapid requests to single endpoint (potential DoS / brute force)

index=* sourcetype=iis
| bin _time span=1m
| stats count by c_ip, cs_uri_stem, _time
| where count > 100

---

## Threat Intelligence Notes

- Attacker IP 40.80.148.42 is in the Microsoft Azure cloud range 
- Acunetix signature confirms automated, non-targeted tooling — this is likely not an APT
- Cerber ransomware check-ins suggest either a secondary payload or a coincidental malicious download during the window
- eXtplorer is a legitimate extension but is commonly abused post-compromise for file-system access

---

## References

- CVE-2014-6271 (Shellshock): https://nvd.nist.gov/vuln/detail/CVE-2014-6271
- CVE-2015-1635 (IIS Integer Overflow): https://nvd.nist.gov/vuln/detail/CVE-2015-1635
- MITRE ATT&CK T1190 (Exploit Public-Facing Application): https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1505.003 (Web Shell): https://attack.mitre.org/techniques/T1505/003/
- BOTSv1 Dataset: https://github.com/splunk/botsv1
