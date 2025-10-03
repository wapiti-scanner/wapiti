# Headless Mode Guide

## Overview

Wapiti supports a headless browser mode that uses Firefox with geckodriver and mitmproxy to capture dynamic web requests during the crawling phase. This significantly improves vulnerability detection for modern web applications but comes with performance tradeoffs.

## How Headless Mode Works

When you enable headless mode (`--headless hidden` or `--headless visible`):

1. **Crawling Phase**: Wapiti launches a Firefox headless browser with mitmproxy as an intercepting proxy
2. **Request Capture**: The browser executes JavaScript and captures XHR/Ajax requests that regular HTTP crawling misses
3. **Attack Phase**: The captured requests expand the attack surface, allowing modules to test more endpoints
4. **Detection Phase**: The `wapp` module can directly inspect the browser to detect JavaScript libraries and frameworks

**Important**: Headless mode affects the **crawling phase**, not the attack phase itself. More requests = more attack surface = more potential findings.

## Module Recommendations

### Modules that BENEFIT from headless mode:

| Module | Benefit | Reason |
|--------|---------|--------|
| `exec` | High | Command injection often found in dynamically-loaded endpoints |
| `xss` | High | XSS vulnerabilities in XHR-loaded content and AJAX forms |
| `sql` | High | SQL injection in API endpoints and dynamic queries |
| `file` | High | File inclusion in dynamically-loaded resources |
| `ssrf` | High | SSRF in API endpoints that handle external requests |
| `permanentxss` | Medium | Stored XSS in AJAX-submitted forms |
| `csrf` | Medium | CSRF tokens in dynamically-generated forms |
| `wapp` | High | JavaScript framework detection via browser inspection |
| `xxe` | Medium | XXE in AJAX-submitted XML/SVG content |
| `redirect` | Medium | Open redirects in dynamically-loaded links |

### Modules that DO NOT benefit from headless mode:

| Module | Benefit | Reason |
|--------|---------|--------|
| `ssl` | None | Direct SSL/TLS connection testing, no browser needed |
| `nikto` | Low | Server-level vulnerability scanning |
| `backup` | Low | Static file discovery |
| `htaccess` | Low | Apache configuration file discovery |
| `methods` | Low | HTTP method testing at protocol level |
| `shellshock` | Low | Server-level vulnerability, no JavaScript involved |

### Passive modules:

Passive modules analyze responses and don't perform attacks, so headless mode's extra requests can help discover more security headers, CSP policies, etc.

## Usage Patterns

### Pattern 1: Comprehensive Scan (Recommended for Security Audits)

```bash
# Full scan with headless mode for maximum coverage
wapiti -u https://webapp.example.com \
  --headless hidden \
  -m exec,xss,sql,file,ssrf,csrf,permanentxss \
  -f json -o full_scan_report.json
```

### Pattern 2: Quick Scan (CI/CD Integration)

```bash
# Fast scan without headless for continuous testing
wapiti -u https://webapp.example.com \
  -m exec,xss,sql \
  --flush-session \
  -f json -o quick_scan.json
```

### Pattern 3: Module-Specific Scans (Per-Module Optimization)

```bash
# Active modules with headless
wapiti -u https://webapp.example.com -m exec,xss,sql --headless hidden -o active_scan.xml

# SSL module without headless
wapiti -u https://webapp.example.com -m ssl -o ssl_scan.xml

# Passive modules without headless (they analyze responses)
wapiti -u https://webapp.example.com -m csp,http_headers,cookie_flags -o passive_scan.xml
```

### Pattern 4: Single Page Application (SPA)

```bash
# SPAs built with React/Vue/Angular REQUIRE headless mode
wapiti -u https://spa.example.com \
  --headless hidden \
  --wait 3 \
  -m exec,xss,sql,wapp \
  -f html -o spa_report.html
```

## Performance Considerations

| Mode | Speed | Coverage | Use Case |
|------|-------|----------|----------|
| Standard | Fast | Basic | Static sites, quick scans, CI/CD |
| Headless | Slow (3-5x) | Comprehensive | Modern web apps, SPAs, security audits |

**Memory Usage**: Headless mode uses ~500MB+ RAM for Firefox and mitmproxy

**Timeout Settings**: Use `--wait` to allow JavaScript to load (default: 2 seconds)

```bash
# Increase wait time for slow-loading SPAs
wapiti -u https://example.com --headless hidden --wait 5
```

## Troubleshooting

### Issue: SSL module shows no results with headless mode

**Solution**: Run SSL module separately without headless:
```bash
wapiti -u https://example.com -m ssl
```

### Issue: Exec module shows no results without headless mode

**Cause**: The vulnerable endpoint is only loaded via XHR

**Solution**: Use headless mode:
```bash
wapiti -u https://example.com -m exec --headless hidden
```

### Issue: Headless mode is too slow

**Solutions**:
1. Reduce depth: `--depth 2`
2. Limit scope: `--scope url`
3. Use parallel tasks: `--tasks 4`
4. Skip headless for non-JS-heavy modules

## Best Practices

1. **Run SSL separately**: Always run the `ssl` module without headless
2. **Use headless for SPAs**: Single Page Applications require headless mode
3. **Optimize for CI/CD**: Use standard mode for fast continuous testing
4. **Comprehensive audits**: Use headless mode for thorough security assessments
5. **Module selection**: Choose modules based on your target's technology stack

## FAQ

**Q: Should I always use headless mode?**
A: No. Use headless for JavaScript-heavy sites and when you need comprehensive coverage. Use standard mode for quick scans and static sites.

**Q: Why does SSL module fail with headless?**
A: The SSL module performs direct SSL/TLS checks and doesn't use crawled requests. It works better without headless mode.

**Q: Can I use headless mode in Docker?**
A: Yes, use the `Dockerfile.headless` provided in the repository which includes geckodriver and Firefox.

**Q: Does headless mode test for XSS differently?**
A: No, the XSS detection logic is the same. Headless mode just provides more endpoints to test (via XHR capture).

## Related Documentation

- FAQ: See "What is headless mode and when should I use it?"
- Docker: `Dockerfile.headless` for containerized headless scanning
- Authentication: `cookies_and_scripts_auth.md` for headless authentication workflows
