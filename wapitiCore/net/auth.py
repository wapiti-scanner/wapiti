from typing import Tuple, List

from httpx import RequestError

from wapitiCore.net import Request, Response
from wapitiCore.parsers.html import Html
from wapitiCore.main.log import logging
from wapitiCore.language.language import _
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net.crawler import AsyncCrawler


async def async_try_login(
        crawler_configuration: CrawlerConfiguration,
        auth_url: str,
) -> Tuple[bool, dict, List[str]]:
    """
    Try to authenticate with the provided url and credentials.
    Returns if the authentication has been successful, the used form variables and the disconnect urls.
    """
    if len(crawler_configuration.auth_credentials) != 2:
        logging.error(_("Login failed") + " : " + _("Invalid credentials format"))
        return False, {}, []

    if crawler_configuration.auth_method == "post" and auth_url:
        return await _async_try_login_post(crawler_configuration, auth_url)
    return await _async_try_login_basic_digest_ntlm(crawler_configuration, auth_url)


async def _async_try_login_basic_digest_ntlm(
        crawler_configuration: CrawlerConfiguration,
        auth_url: str
) -> Tuple[bool, dict, List[str]]:
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request(auth_url))

        if response.status in (401, 403, 404):
            return False, {}, []
        return True, {}, []


async def _async_try_login_post(
        crawler_configuration: CrawlerConfiguration,
        auth_url: str
) -> Tuple[bool, dict, List[str]]:
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        # Fetch the login page and try to extract the login form
        try:
            response: Response = await crawler.async_get(Request(auth_url), follow_redirects=True)
            is_logged_in = False
            form = {}
            disconnect_urls = []

            page = Html(response.content, auth_url)

            username, password = crawler_configuration.auth_credentials
            login_form, username_field_idx, password_field_idx = page.find_login_form()
            if login_form:
                post_params = login_form.post_params
                get_params = login_form.get_params

                if login_form.method == "POST":
                    post_params[username_field_idx][1] = username
                    post_params[password_field_idx][1] = password
                    form["login_field"] = post_params[username_field_idx][0]
                    form["password_field"] = post_params[password_field_idx][0]
                else:
                    get_params[username_field_idx][1] = username
                    get_params[password_field_idx][1] = password
                    form["login_field"] = get_params[username_field_idx][0]
                    form["password_field"] = get_params[password_field_idx][0]

                login_request = Request(
                    path=login_form.url,
                    method=login_form.method,
                    post_params=post_params,
                    get_params=get_params,
                    referer=login_form.referer,
                    link_depth=login_form.link_depth
                )

                login_response = await crawler.async_send(
                    login_request,
                    follow_redirects=True
                )

                html = Html(login_response.content, login_response.url)

                # ensure logged in
                is_logged_in = html.is_logged_in()
                if is_logged_in:
                    logging.success(_("Login success"))
                    disconnect_urls = html.extract_disconnect_urls()
                else:
                    logging.warning(_("Login failed") + " : " + _("Credentials might be invalid"))
            else:
                logging.warning(_("Login failed") + " : " + _("No login form detected"))

            # In every case keep the cookies
            crawler_configuration.cookies = crawler.cookie_jar
            return is_logged_in, form, disconnect_urls

        except ConnectionError:
            logging.error(_("[!] Connection error with URL"), auth_url)
            return False, {}, []
        except RequestError as error:
            logging.error(_("[!] {} with URL {}").format(error.__class__.__name__, auth_url))
            return False, {}, []
