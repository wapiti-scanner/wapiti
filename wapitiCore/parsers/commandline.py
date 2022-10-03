import argparse

from wapitiCore import WAPITI_VERSION
from wapitiCore.report import GENERATORS


def parse_args():
    parser = argparse.ArgumentParser(description=f"Wapiti {WAPITI_VERSION}: Web application vulnerability scanner")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-u", "--url",
        help="The base URL used to define the scan scope (default scope is folder)",
        metavar="URL", dest="base_url",
        default="http://example.com/"
        # required=True
    )

    parser.add_argument(
        "--data",
        help="Urlencoded data to send with the base URL if it is a POST request",
        metavar="data", dest="data",
        default=None,
    )

    parser.add_argument(
        "--scope",
        help="Set scan scope",
        default="folder",
        choices=["page", "folder", "domain", "url", "punk"]
    )

    parser.add_argument(
        "-m", "--module",
        dest="modules", default=None,
        help="List of modules to load",
        metavar="MODULES_LIST"
    )

    group.add_argument(
        "--list-modules",
        action="store_true",
        help="List Wapiti attack modules and exit"
    )

    parser.add_argument(
        "-l", "--level",
        metavar="LEVEL",
        dest="level",
        help="Set attack level",
        default=1,
        type=int,
        choices=[1, 2]
    )

    parser.add_argument(
        "-p", "--proxy",
        default=argparse.SUPPRESS,
        help="Set the HTTP(S) proxy to use. Supported: http(s) and socks proxies",
        metavar="PROXY_URL",
        dest="proxy"
    )

    parser.add_argument(
        "--tor",
        action="store_true",
        help="Use Tor listener (127.0.0.1:9050)"
    )

    parser.add_argument(
        "--mitm-port",
        dest="mitm_port",
        default=argparse.SUPPRESS,
        help="Instead of crawling, launch an intercepting proxy on the given port",
        metavar="PORT",
        type=int
    )

    parser.add_argument(
        "--headless",
        dest="headless",
        default="no",
        help="Use a Firefox headless crawler for browsing (slower)",
        metavar="PORT",
        choices=["no", "hidden", "visible"]
    )

    parser.add_argument(
        "--wait",
        dest="wait_time",
        default=2.,
        help="Wait the specified amount of seconds before analyzing a webpage (headless mode only)",
        metavar="TIME",
        type=float
    )

    parser.add_argument(
        "-a", "--auth-cred",
        dest="credentials",
        default=argparse.SUPPRESS,
        help="Set HTTP authentication credentials",
        metavar="CREDENTIALS"
    )

    parser.add_argument(
        "--auth-type",
        default=argparse.SUPPRESS,
        help="Set the authentication type to use",
        choices=["basic", "digest", "ntlm", "post"]
    )

    parser.add_argument(
        "--auth-script",
        dest="auth_script",
        default=argparse.SUPPRESS,
        help="Use a custom Python authentication plugin",
        metavar="FILENAME"
    )

    parser.add_argument(
        "-c", "--cookie",
        help=(
            "Set a JSON cookie file to use. "
            "You can also pass 'firefox' or 'chrome' to load cookies from your browser."
        ),
        default=argparse.SUPPRESS,
        metavar="COOKIE_FILE"
    )

    parser.add_argument(
        "--drop-set-cookie",
        action="store_true",
        help="Ignore Set-Cookie header from HTTP responses"
    )

    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Don't resume the scanning process, attack URLs scanned during a previous session"
    )

    parser.add_argument(
        "--resume-crawl",
        action="store_true",
        help="Resume the scanning process (if stopped) even if some attacks were previously performed"
    )

    parser.add_argument(
        "--flush-attacks",
        action="store_true",
        help="Flush attack history and vulnerabilities for the current session"
    )

    parser.add_argument(
        "--flush-session",
        action="store_true",
        help="Flush everything that was previously found for this target (crawled URLs, vulns, etc)"
    )

    parser.add_argument(
        "--store-session",
        help="Directory where to store attack history and session data.",
        default=None,
        metavar="PATH",
    )

    parser.add_argument(
        "--store-config",
        help="Directory where to store configuration databases.",
        default=None,
        metavar="PATH",
    )

    parser.add_argument(
        "-s", "--start",
        action="append",
        default=[],
        help="Adds a url to start scan with",
        metavar="URL",
        dest="starting_urls"
    )

    parser.add_argument(
        "-x", "--exclude",
        action="append",
        default=[],
        help="Adds a url to exclude from the scan",
        metavar="URL",
        dest="excluded_urls"
    )

    parser.add_argument(
        "-r", "--remove",
        action="append",
        default=[],
        help="Remove this parameter from urls",
        metavar="PARAMETER",
        dest="excluded_parameters"
    )

    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="Skip attacking given parameter(s)",
        metavar="PARAMETER",
        dest="skipped_parameters"
    )

    parser.add_argument(
        "-d", "--depth",
        help="Set how deep the scanner should explore the website",
        type=int, default=40
    )

    parser.add_argument(
        "--max-links-per-page",
        metavar="MAX",
        help="Set how many (in-scope) links the scanner should extract for each page",
        type=int, default=100
    )

    parser.add_argument(
        "--max-files-per-dir",
        metavar="MAX",
        help="Set how many pages the scanner should explore per directory",
        type=int, default=0
    )

    parser.add_argument(
        "--max-scan-time",
        metavar="SECONDS",
        help="Set how many seconds you want the scan to last (floats accepted)",
        type=float, default=0
    )

    parser.add_argument(
        "--max-attack-time",
        metavar="SECONDS",
        help="Set how many seconds you want each attack module to last (floats accepted)",
        type=float, default=0
    )

    parser.add_argument(
        "--max-parameters",
        metavar="MAX",
        help="URLs and forms having more than MAX input parameters will be erased before attack.",
        type=int, default=0
    )

    parser.add_argument(
        "-S", "--scan-force",
        metavar="FORCE",
        help=(
            "Easy way to reduce the number of scanned and attacked URLs.\n"
            "Possible values: paranoid, sneaky, polite, normal, aggressive, insane"
        ),
        choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
        default="normal"
    )

    parser.add_argument(
        "--tasks",
        metavar="tasks",
        help="Number of concurrent tasks to use for the exploration (crawling) of the target.",
        type=int, default=32
    )

    parser.add_argument(
        "--external-endpoint",
        metavar="EXTERNAL_ENDPOINT_URL",
        default=argparse.SUPPRESS,
        help="Url serving as endpoint for target"
    )

    parser.add_argument(
        "--internal-endpoint",
        metavar="INTERNAL_ENDPOINT_URL",
        default=argparse.SUPPRESS,
        help="Url serving as endpoint for attacker"
    )

    parser.add_argument(
        "--endpoint",
        metavar="ENDPOINT_URL",
        default="https://wapiti3.ovh/",
        help="Url serving as endpoint for both attacker and target"
    )

    parser.add_argument(
        "--dns-endpoint",
        metavar="DNS_ENDPOINT_DOMAIN",
        default="dns.wapiti3.ovh",
        help="Domain serving as DNS endpoint for Log4Shell attack"
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float, default=6.0,
        help="Set timeout for requests",
        metavar="SECONDS"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Set a custom header to use for every requests",
        metavar="HEADER",
        dest="headers"
    )

    parser.add_argument(
        "-A", "--user-agent",
        default=argparse.SUPPRESS,
        help="Set a custom user-agent to use for every requests",
        metavar="AGENT",
        dest="user_agent"
    )

    parser.add_argument(
        "--verify-ssl",
        default=0,
        dest="check_ssl",
        help="Set SSL check (default is no check)",
        type=int,
        choices=[0, 1]
    )

    parser.add_argument(
        "--color",
        action="store_true",
        help="Colorize output"
    )

    parser.add_argument(
        "-v", "--verbose",
        metavar="LEVEL",
        dest="verbosity",
        help="Set verbosity level (0: quiet, 1: normal, 2: verbose)",
        default=0,
        type=int,
        choices=range(0, 3)
    )

    parser.add_argument(
        "--log",
        metavar="OUTPUT_PATH",
        default=None,
        help="Output log file"
    )

    parser.add_argument(
        "-f", "--format",
        metavar="FORMAT",
        help="Set output format. Supported: " + ", ".join(sorted(GENERATORS)) + ". Default is html.",
        default="html",
        choices=GENERATORS.keys()
    )

    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_PATH",
        default=argparse.SUPPRESS,
        help="Output file or folder"
    )

    parser.add_argument(
        "-dr", "--detailed-report",
        action="store_true",
        help="HTTP responses will appear in the generated report"
    )

    parser.add_argument(
        "--no-bugreport",
        action="store_true",
        help="Don't send automatic bug report when an attack module fails"
    )

    group.add_argument(
        "--update",
        action="store_true",
        help="Update Wapiti attack modules and exit"
    )

    parser.add_argument(
        "--version",
        action="version",
        help="Show program's version number and exit",
        version=WAPITI_VERSION
    )

    return parser.parse_args()
