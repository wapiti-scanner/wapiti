from urllib.parse import quote, unquote
import html


def encode(params_list):
    """Encode a sequence of two-element lists or dictionary into a URL query string."""
    encoded_params = []
    for k, v in params_list:
        # not safe: '&=#' with of course quotes...
        k = quote(k, safe='/%[]:;$()+,!?*')
        v = quote(v, safe='/%[]:;$()+,!?*')
        encoded_params.append("%s=%s" % (k, v))
    return "&".join(encoded_params)


def uqe(self, params_list):  # , encoding = None):
    """urlencode a string then interpret the hex characters (%41 will give 'A')."""
    return unquote(self.encode(params_list))  # , encoding))


def escape(url):
    """Change special characters in their html entities representation."""
    return html.escape(url, quote=True).replace("'", "%27")

