#!/usr/bin/env python3
# -*- coding: utf-8 -*-

TYPE = "vulnerability"

NAME = "Unencrypted Channels"
SHORT_NAME = NAME

WSTG_CODE = ["WSTG-CRYP-03"]

DESCRIPTION = (
    "Sensitive data must be protected when it is transmitted through the network."
)

SOLUTION = "Use HTTPS for the whole web site and redirect any HTTP requests to HTTPS."

REFERENCES = [
    {
        "title": "Testing for Sensitive Information Sent via Unencrypted Channels",
        "url": ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
                "09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"
        )
    },
    {
        "title": "Testing for Weak Transport Layer Security",
        "url": ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
                "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
        )
    }
]
