# Investigation Methodology

This document describes the step-by-step approach used to hunt the BOTSv1 web compromise in Splunk. 

## The hunting 

**Start broad → narrow progressively → pivot across log sources.**
 Let the data tell you where to look next.

---

## Stage 1 — Orient in the data

**Question:** What logs do I have available?

```spl
index=botsv1 earliest=0
| stats count by sourcetype
| sort -count
| head 30
```

**Finding:** 26 sourcetypes, 33M+ events. Split across three layers:
- **Network:** suricata, fgt_traffic, stream:*
- **Host:** WinEventLog:Security, XmlWinEventLog:*Sysmon*
- **Application:** iis

**Reasoning:** For a "web attack" investigation, prioritize iis (server view), suricata (network detections), and stream:http (traffic details).

---

## Stage 2 — Identify the attacker

**Question:** Who is generating high-severity alerts?

```spl
index=botsv1 sourcetype=suricata event_type=alert alert.severity=1 earliest=0
| stats count by src_ip
| sort -count
| head 10
```

**Finding:** 40.80.148.42 carried 385 of 392 alerts (98.2%). Clear top offender.

**Reasoning:** In any alert set, the attacker dominates by count. 

**Sanity check — the full category picture:**

```spl
index=botsv1 sourcetype=suricata event_type=alert alert.severity=1 earliest=0
| stats count by alert.category
| sort -count
```

**Finding:** Four categories — Web Application Attack (250), Network Trojan (104), Attempted Admin Privilege Gain (36), Privacy Violation (2).



---

## Stage 3 — Characterize the attack

**Question:** What specific attacks did this IP launch?

```spl
index=botsv1 sourcetype=suricata event_type=alert alert.severity=1 src_ip=40.80.148.42 earliest=0
| stats count by alert.category, alert.signature
| sort -count
```

**Finding:** 29 unique signatures including:
- SQL injection (multiple variants)
- XSS probes
- XXE (XML External Entity)
- Shellshock (CVE-2014-6271)
- PHP config bypass attempts
- Cerber ransomware C2 checkins

**Reasoning:** Grouping by two fields (category + signature) gives the right level of detail. Category alone is too broad; signature alone is too granular.

---

## Stage 4 — Pivot to the web server(iis)

**Question:** Did the attack reach the server? What URL was targeted?

```spl
index=botsv1 sourcetype=iis c_ip=40.80.148.42 s_ip=192.168.250.70 earliest=0
| stats count by cs_uri_stem
| sort -count
| head 10
```

**Finding:** 20,967 total requests. The URL /joomla/index.php/component/search/ received 16,871 requests (80.6%) — dominant attack endpoint.

**Field notes:** IIS uses W3C naming:
- c_ip = client
- s_ip = server IP 
- cs_uri_stem = URL path
- cs_uri_query = query string (where payloads live)

---

## Stage 5 — Verify attack success

**Question:** Did the server accept the malicious requests?

```spl
index=botsv1 sourcetype=iis c_ip=40.80.148.42 cs_uri_stem="/joomla/index.php/component/search/" earliest=0
| stats count by sc_status
| sort -count
```

**Finding:**

| Status | Count | Meaning |
|---|---|---|
| 303 | 11,057 | Redirect — server processed and reissued |
| 200 | 4,289 | OK — valid content returned |
| 500 | 1,496 | Server error — payload hit app code |
| 404 | 29 | Not found |

**Success rate:** 15,346 / 16,871 = 91% — the server processed almost every payload.

**Reasoning:**  A successful attack shows 200s and 303s. This was successful.

---

## Stage 6 — Extract and decode payloads

**Question:** What was actually sent to the server?

```spl
index=botsv1 sourcetype=iis c_ip=40.80.148.42 cs_uri_stem="/joomla/index.php/component/search/" earliest=0
| where match(cs_uri_query, "(?i)select|union|sleep|response.write|%27|%22|\*|acunetix")
| table _time, cs_method, cs_uri_query, sc_status
| sort _time
| head 30
```

**Finding:** 1,026 payloads including:
- catid=1*1*1*98 — arithmetic probe
- catid=response.write(9615406*9885538) — error-based injection
- catid='+response.write(...)+' — quote variant
- catid=%24%7B%40print(md5(acunetix_wvs_security_test))%7D — scanner fingerprint

**Technique:** where match() filters events by regex pattern. table (not stats) shows the payloads 

---

## Stage 7 — Trace post-exploitation

**Question:** Did the attacker get admin access? Install persistence?

```spl
index=botsv1 sourcetype=iis c_ip=40.80.148.42 earliest=0
| where match(cs_uri_stem, "/administrator/")
| table _time, cs_method, cs_uri_stem, cs_uri_query, sc_status
| sort _time
| head 50
```

**Finding:** 84 admin-panel requests. The sequence:

| Time | Method | Query | Status | Meaning |
|---|---|---|---|---|
| 23:47:59 | GET | /administrator/ | 200 | Panel reached |
| 23:48:06 | POST | /administrator/index.php | 303 | LOGIN SUCCESS |
| 23:48:07 | GET | /administrator/index.php | 200 | Dashboard loaded |
| 23:50:31 | POST | ?option=com_installer&view=install | 303 | UPLOAD #1 |
| 23:51:10 | POST | ?option=com_installer&view=install | 303 | UPLOAD #2 |
| 23:51:33 | GET | ?option=com_extplorer&action=include_javascript&file=functions.js | 200 | RCE |

**Verdict:** Full compromise — admin login, malicious extension install, RCE via eXtplorer file manager.

---



## Field mapping across sourcetypes

| Concept | Suricata | IIS |
|---|---|---|
| Client IP | src_ip | c_ip |
| Server IP | dest_ip | s_ip |
| URL | — | cs_uri_stem |
| Query string | — | cs_uri_query |
| Status code | — | sc_status |
| Method | — | cs_method |


---

## Lessons learned

1. Explore categories before filtering. 
2. Pivot using shared fields. Suricata's src_ip maps to IIS's c_ip — same value, different name.
3. Status codes tell the outcome. 200/303 = attack worked. 403/404 = blocked.
4. Payloads live in cs_uri_query.
5. The admin panel tells the persistence story. Login POST (303) → extension install (303) → RCE.
