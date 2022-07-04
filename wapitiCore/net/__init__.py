from urllib.parse import quote, unquote
import html

from wapitiCore.net.web import Request, make_absolute
from wapitiCore.net.response import Response


def encode(params_list):
    """Encode a sequence of two-element lists or dictionary into a URL query string."""
    encoded_params = []
    for param_name, param_value in params_list:
        # not safe: '&=#' with of course quotes...
        param_name = quote(param_name, safe='/%[]:;$()+,!?*')
        param_value = quote(param_value, safe='/%[]:;$()+,!?*')
        encoded_params.append(f"{param_name}={param_value}")
    return "&".join(encoded_params)


def uqe(self, params_list):  # , encoding = None):
    """urlencode a string then interpret the hex characters (%41 will give 'A')."""
    return unquote(self.encode(params_list))  # , encoding))


def escape(url):
    """Change special characters in their html entities representation."""
    return html.escape(url, quote=True).replace("'", "%27")
