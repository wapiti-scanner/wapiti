from urllib.parse import quote, unquote
import html


def encode(params_list):
    """Encode a sequence of two-element lists or dictionary into a URL query string."""
    encoded_params = []
    for par1, par2 in params_list:
        # not safe: '&=#' with of course quotes...
        par1 = quote(par1, safe='/%[]:;$()+,!?*')
        par2 = quote(par2, safe='/%[]:;$()+,!?*')
        encoded_params.append("%s=%s" % (k, v))
    return "&".join(encoded_params)


def uqe(self, params_list):  # , encoding = None):
    """urlencode a string then interpret the hex characters (%41 will give 'A')."""
    return unquote(self.encode(params_list))  # , encoding))


def escape(url):
    """Change special characters in their html entities representation."""
    return html.escape(url, quote=True).replace("'", "%27")
