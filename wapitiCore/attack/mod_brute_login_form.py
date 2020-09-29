from os.path import join as path_join

from requests.exceptions import ReadTimeout

from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, _
from wapitiCore.net import web


class mod_brute_login_form(Attack):
    time_to_sleep = ''
    name = "brute_login_form"
    payloads_username = []
    payloads_password = []
    PAYLOADS_FILE = "passwords.txt"
    PAYLOADS_FILE_USER = "users.txt"
    PAYLOADS_SUCCESS = "successMessage.txt"
    PAYLOADS_FAIL = "incorrectMessage.txt"
    MSG_VULN = _("Brute force attack success")
    current_request_url = None
    current_request_method = None
    password_parameter = []
    username_parameter_field = []
    submit_var_name = None
    submit_var_value = None

    def set_timeout(self, timeout):
        self.time_to_sleep = str(1 + int(timeout))

    def check_success_auth(self, content_response: str):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_SUCCESS), 'r', errors='ignore') as success_pattern_file:
            for success_pattern in success_pattern_file:
                if success_pattern.strip("\n") in content_response:
                    return True

        return False

    def get_usernames(self):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE_USER), 'r', errors='ignore') as username_file:
            for line in username_file:
                username = line.strip()
                if username:
                    yield username

    def get_passwords(self):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE), 'r', errors='ignore') as password_file:
            for line in password_file:
                password = line.strip()
                if password:
                    yield password

    def test_credentials(self, login_form, username_index, password_index, username, password):
        post_params = login_form.post_params
        get_params = login_form.get_params

        if login_form.method == "POST":
            post_params[username_index][1] = username
            post_params[password_index][1] = password
        else:
            get_params[username_index][1] = username
            get_params[password_index][1] = password

        login_request = web.Request(
            path=login_form.url,
            method=login_form.method,
            post_params=post_params,
            get_params=get_params,
            referer=login_form.referer,
            link_depth=login_form.link_depth
        )

        try:
            login_response = self.crawler.send(
                login_request,
                follow_redirects=True
            )
        except ReadTimeout:
            return ""
        return login_response.content

    def attack(self):
        # TODO: do GET requests too and don't forget to yield for each tried resource!
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in forms:
            # We leverage the fact that the crawler will fill password entries with a known placeholder
            if "Letm3in_" not in original_request.encoded_data:
                continue

            # We may want to remove this but if not available fallback to target URL
            if not original_request.referer:
                continue

            request = Request(original_request.referer)
            page = self.crawler.get(request, follow_redirects=True)

            login_form, username_field_idx, password_field_idx = page.find_login_form()
            if not login_form:
                continue

            failure_text = self.test_credentials(
                login_form,
                username_field_idx, password_field_idx,
                "invalid", "invalid"
            )

            if self.check_success_auth(failure_text):
                # Ignore this case as it raise false positives
                continue

            for username in self.get_usernames():
                for password in self.get_passwords():

                    response = self.test_credentials(
                        login_form,
                        username_field_idx, password_field_idx,
                        username, password
                    )

                    if self.check_success_auth(response) and failure_text != response:
                        vuln_message = _("Credentials found for URL {} : {}:{}").format(
                            original_request.referer,
                            username,
                            password
                        )

                        # Recreate the request that succeed in order to print and store it
                        post_params = login_form.post_params
                        get_params = login_form.get_params

                        if login_form.method == "POST":
                            post_params[username_field_idx][1] = username
                            post_params[password_field_idx][1] = password
                        else:
                            get_params[username_field_idx][1] = username
                            get_params[password_field_idx][1] = password

                        evil_request = web.Request(
                            path=login_form.url,
                            method=login_form.method,
                            post_params=post_params,
                            get_params=get_params,
                            referer=login_form.referer,
                            link_depth=login_form.link_depth
                        )

                        # TODO: I should check if a missing "parameter" entry may cause any trouble just to be 100% sure
                        self.add_vuln(
                            request_id=original_request.path_id,
                            category=Vulnerability.BASIC_AUT_BF,
                            level=Vulnerability.HIGH_LEVEL,
                            request=evil_request,
                            info=vuln_message
                        )

                        self.log_red("---")
                        self.log_red(vuln_message),
                        self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                        self.log_red(evil_request.http_repr())
                        self.log_red("---")

                        return

            # Maybe but this one at the top
            yield original_request
