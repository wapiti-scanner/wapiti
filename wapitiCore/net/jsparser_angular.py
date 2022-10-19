import re
from urllib.parse import urlparse
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl


class JsParserAngular:
    """
    A class that try to parse JS files from angular webapps
    and extract interesting subdomains and paths.
    """

    def __init__(self, url: str, data: str):
        """
        Create a new JsParserAngular object.

        Takes the following arguments:
            url: The absolute URL of the JS file on the server
            data: The content of the JS file as a string
        """
        self.links = []

        parts = urlparse(url)
        netloc = parts.netloc
        self.target_domain = netloc

        # if netloc and len(netloc.split('.')) > 2:
        #     netloc = '.'.join(netloc.split('.')[1:])

        # #self.domain = netloc
        self.domain = self.get_domain(url)
        self.scheme = parts.scheme

        if self.domain:
            self.parse_data(data)

    @staticmethod
    def get_domain(url):
        domain = None
        try:
            domain = get_fld(url)
        except TldDomainNotFound:
            # Not yet known TLD or IP address or local hostname
            domain = urlparse(url).netloc
        except TldBadUrl:
            domain = None
        return domain

    def get_links(self):
        return self.links

    def parse_data(self, data):
        path_found = []
        domain_found = []

        target_url = self.scheme + "://" + self.target_domain
        domain_found.append(target_url)

        # paths used to be in dict/json : {path: "/home", ...} or ["href", "/dashboard", ...]
        data_found = re.findall(r"(?:path|redirectTo|templateUrl)[\"']?:\s?[\"'](?P<path>[^\"'+*$(]*)[\"']", data)
        data_found += re.findall(r"\[\"(?:href|src)[\"'],\s?[\"'](?P<path>[^\"'(:]*)[\"']", data)
        data_found += \
            re.findall(r"router\.(?:navigateByUrl|parseUrl|isActive)\([\w\s.+]*[\"'](?P<path>.*?)[\"'].*?\)", data)

        data_found_with_params = \
            re.findall(r"router\.(?:navigate|createUrlTree)\(\[[\w\s]*[\"'](?P<path>.*?[\"'].*?)\](?:.*?)\)",data)
        # data_found_with_params : ['login"', '"', 't", "123" + this.testId + "/","settings"']
        for i, data_with_params in enumerate(data_found_with_params):
            data_with_params = re.sub(r'["+\s]','', data_with_params) # -> t,123this.testId/,settings'
            data_with_params = re.sub('/,', '/', data_with_params) # -> 't,123this.testId/settings'
            data_found_with_params[i] = re.sub(',','/', data_with_params) # -> 't/123this.testId/settings'
        data_found += data_found_with_params

        for path in data_found:
            if path and "http" not in path and path not in path_found:
                path_found.append(path)

        # catch full urls
        urls = re.findall(r"https?:\/\/[^\"'\\ )]+", data)
        for url in urls:
            # we only keep domains related with the target domain
            if self.domain == self.get_domain(url) and url not in domain_found:
                domain_found.append(url)
                self.links.append(url)

        for url in domain_found:
            parts = urlparse(url)
            domain = parts.netloc
            scheme = parts.scheme
            # since it is hard to determine on which domain we should use the paths, we try on every domain
            for path in path_found:
                if not path.startswith("/"):
                    path = "/" + path
                new_url = scheme + "://" + domain + path
                if new_url not in self.links:
                    self.links.append(new_url)
