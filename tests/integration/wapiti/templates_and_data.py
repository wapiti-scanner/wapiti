DEFAULT_FILTER_TREE = {
    "vulnerabilities": {},
    "anomalies": {},
    "additionals": {},
    "infos": {}
}

EXISTING_MODULES = {
    "backup", "brute_login_form",
    "buster", "cookieflags",
    "crlf", "csp",
    "csrf", "cms",
    "exec", "file",
    "htaccess", "htp",
    "http_headers", "https_redirect",
    "ldap", "log4shell",
    "methods", "nikto",
    "permanentxss", "redirect",
    "shellshock", "sql",
    "ssl", "ssrf",
    "takeover", "timesql",
    "wapp", "wp_enum",
    "xss", "xxe", ""
}
# Empty string in EXISTING_MODULES is because Wapiti can be
# launched without any module, only to crawl a website for example

TREE_CHECKER = {
    "vulnerabilities": {
        'Backup file': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Blind SQL Injection': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'CRLF Injection': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Clickjacking Protection': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Command execution': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Content Security Policy Configuration': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Cross Site Request Forgery': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Fingerprint web application framework': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Fingerprint web server': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'HTTP Strict Transport Security (HSTS)': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Htaccess Bypass': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'HttpOnly Flag cookie': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'LDAP Injection': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Log4Shell': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'MIME Type Confusion': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Open Redirect': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Path Traversal': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Potentially dangerous file': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Reflected Cross Site Scripting': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'SQL Injection': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Secure Flag cookie': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Server Side Request Forgery': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Stored Cross Site Scripting': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Subdomain takeover': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'TLS/SSL misconfigurations': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Unencrypted Channels': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Vulnerable software': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'Weak credentials': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ],
        'XML External Entity': [
            {
                'curl_command': '',
                'detail': {
                    'response': {
                        'body': '',
                        'headers': [],
                        'status_code': 0
                    }
                },
                'http_request': '',
                'info': '',
                'level': 0,
                'method': '',
                'module': '',
                'parameter': '',
                'path': '',
                'referer': '',
                'wstg': []
            }
        ]
    },
    "anomalies": {
        'Internal Server Error': [],
        'Resource consumption': []
    },
    "additionals": {
        'Fingerprint web technology': [],
        'HTTP Methods': [],
        'Review Webserver Metafiles for Information Leakage': []
    },
    "infos": {
        'auth': None,
        'crawled_pages': [
            {
                'request': {
                    'depth': 0,
                    'encoding': "",
                    'enctype': "",
                    'headers': [],
                    'methods': "",
                    'referer': "",
                    'url': ""},
                'response': {
                    'body': "",
                    'headers': [],
                    'status_code': 0
                }
            }
        ],
        'crawled_pages_nbr': 0,
        'detailed_report_level': 0,
        'scope': "",
        'target': "",
        'version': ""
    }
}
