# WAPITI_VERSION - wapiti-scanner.github.io

## Report for http://perdu.com
* Date of the scan : Thu, 01 Jan 1970 00:00:00 +0000
* Crawled pages : 123456
* Scope of the scan : folder

---

## Summary of vulnerabilities

| Category | Count |
|---|---|
| Backup file | 0 |
| Cleartext Submission of Password | 0 |
| Weak credentials | 0 |
| CRLF Injection | 0 |
| Content Security Policy Configuration | 0 |
| Cross Site Request Forgery | 0 |
| Potentially dangerous file | 0 |
| Command execution | 0 |
| Path Traversal | 0 |
| Fingerprint web application framework | 0 |
| Fingerprint web server | 0 |
| Htaccess Bypass | 0 |
| HTML Injection | 0 |
| Clickjacking Protection | 0 |
| HTTP Strict Transport Security (HSTS) | 0 |
| MIME Type Confusion | 0 |
| HttpOnly Flag cookie | 0 |
| Unencrypted Channels | 0 |
| Inconsistent Redirection | 0 |
| Information Disclosure - Full Path | 0 |
| LDAP Injection | 0 |
| Log4Shell | 0 |
| NS takeover | 0 |
| Open Redirect | 0 |
| Reflected Cross Site Scripting | 1 |
| Secure Flag cookie | 0 |
| Spring4Shell | 0 |
| SQL Injection | 0 |
| TLS/SSL misconfigurations | 0 |
| Server Side Request Forgery | 0 |
| Stored HTML Injection | 0 |
| Stored Cross Site Scripting | 0 |
| Subdomain takeover | 0 |
| Blind SQL Injection | 0 |
| Unrestricted File Upload | 0 |
| Vulnerable software | 0 |

---

### Reflected Cross Site Scripting
**Info**: This is dope
**WSTG code**: None
**Involved parameter**: foo

**Evil request**:

```http
    GET /riri?foo=bar HTTP/1.1
```

**cURL command PoC**:

```bash
curl "http://perdu.com/riri?foo=bar"
```

---


## Summary of anomalies

| Category | Count |
|---|---|
| Internal Server Error | 1 |
| Resource consumption | 0 |

---

### Internal Server Error
**Info**: This is the way
**WSTG code**: None

**Evil request**:

```http
    GET /fifi HTTP/1.1
```

**cURL command PoC**:

```bash
curl "http://perdu.com/fifi"
```

---


## Summary of additionals

| Category | Count |
|---|---|
| Review Webserver Metafiles for Information Leakage | 0 |
| Fingerprint web technology | 1 |
| HTTP Methods | 0 |
| TLS/SSL misconfigurations | 0 |

---

### Fingerprint web technology
**Info**: loulou
**WSTG**: None
**Involved parameter**: foo
---


