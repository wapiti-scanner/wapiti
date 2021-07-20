
import re
from urllib.parse import urlparse
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl


class JsParserReact:
    """
    A class that try to parse JS files from react webapps
    and extract interesting subdomains and paths.
    """

    def __init__(self, url: str, data: str):
        """
        Create a new JsParserReact object.

        Takes the following arguments:
            url: The absolute URL of the JS file on the server
            data: The content of the JS file as a string
        """
        self.links = []

        parts = urlparse(url)
        netloc = parts.netloc
        self.target_domain = netloc

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

        # path used to be in <Link to="/test" /> or <Link to={'/dashboard'} /> or <Route path={`${match.url}/secret`} />
        # or <Redirect to={{pathname: '/login'}} />
        # if App.js accessible, but this will not append
        data_found = re.findall(r"<(?:Link to|Route (?:exact )?path)={?[\"'`](?P<path>[^\"'`]*)[\"'`][^>]*/>", data)

        # path used to be in createElement(var, {to:"/admin"}) or createElement(var, {path:"/test"})
        # basename used to be in createElement(var, {basename:"/base"})
        basename = re.findall(r"createElement\([^,]*,{basename:\"(?P<path>[^\"]*)\"", data)
        data_found += re.findall(r"createElement\([^,]*,{(?:to|path):\"(?P<path>[^\"]*)\"", data)

        for path in data_found:
            if path and "http" not in path and path not in path_found:
                if basename:
                    path_found.append(basename[0] + path)
                else:
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
