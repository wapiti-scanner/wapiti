#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from wapitiCore.language.language import _

TYPE = "vulnerability"
NAME = _("POST HTTP")
SHORT_NAME = NAME

DESCRIPTION = _(
    "The application configuration should ensure that SSL is used for all access controlled pages.\\n)."
) + " " + _(
    "If an application uses SSL to guarantee confidential communication with client browsers, "
) + " " + _(
    "the application configuration should make it impossible to view any access controlled page without SSL."
)

SOLUTION = _(
    "Force the use of HTTPS for all authentication requests"
)

REFERENCES = [
{
        "title": "OWASP: Insecure Transport",
        "url": "https://owasp.org/www-community/vulnerabilities/Insecure_Transport"
    },
    {
        "title": "Acunetix: Insecure Authentication",
        "url": "https://owasp.org/www-project-mobile-top-10/2016-risks/m4-insecure-authentication"
    }
]
