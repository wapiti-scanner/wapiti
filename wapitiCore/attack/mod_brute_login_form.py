from itertools import chain
from os.path import join as path_join
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ReadTimeout
from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
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

    def has_password_field(self):

        list = ['email','user','mail','session','login']
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True)
        content = response.content
        inputs = BeautifulSoup(content, features="lxml").findAll('input')
        if self.current_request_method == 'POST':
            for _input in inputs:

                if (_input.attrs['type']).lower() == 'submit':
                    self.submit_var_name = _input.attrs['name']
                    self.submit_var_value = _input.attrs['name']

                if any(ext in (_input.attrs['name']).lower() for ext in list):
                    # this condition is used to check that the field is not of type "password". For example : user_password
                    if (_input.attrs['type']).lower() == 'text':
                        self.username_parameter_field.append(_input.attrs['name'])

                if (_input.attrs['type']).lower() == 'password':
                    self.password_parameter.append(_input.attrs['name'])

        if self.password_parameter:
            return True
        else:
            return False

    def check_success_auth(self, content_response: str):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_SUCCESS), 'r', errors='ignore') as success_pattern_file:
            for success_pattern in success_pattern_file:
                if success_pattern.strip("\n") in content_response:
                    return True

        return False

    def get_username_list(self):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE_USER), 'r', errors='ignore') as username_file:
            data = username_file.readlines()
            for username in data:
                self.payloads_username.append(username.strip())

    def get_password_list(self):
        password_file = open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE), 'r', errors='ignore')
        while True:
            data = password_file.readline()
            if not data:
                break;

            self.payloads_password[0]=data.strip()

    def inject_username_payload(self, original_request, username_payload):
        for params_list in original_request.post_params:
            if self.username_parameter_field in params_list:
                original_request.post_params[original_request.post_params.index(params_list)][1] = username_payload
        return original_request

    def attack(self):
        false_response = None
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []
        timeouted = False


        for original_request in forms:
            page = original_request.path
            self.current_request_url = original_request.url
            self.current_request_method = original_request.method

            if self.has_password_field():
                false_data = [[self.username_parameter_field[0], "some_false_username"],
                              [self.password_parameter[0], "some_false_password"],
                              [self.submit_var_name, self.submit_var_value]]

                false_request = Request(
                    self.current_request_url,
                    method="POST",
                    post_params=false_data
                )

                false_response = self.crawler.send(false_request, follow_redirects=True)

            if self.has_password_field():
                self.get_username_list()

                for username in self.payloads_username:
                    if self.verbose >= 1:
                        print("[+] {}".format(original_request))

                    for payload in self.payloads:

                        data = [[self.username_parameter_field[0],username],
                                [self.password_parameter[0],payload[0]],
                                [self.submit_var_name,self.submit_var_value]]

                        request = Request(
                            self.current_request_url,
                            method="POST",
                            post_params=data
                        )

                        try:
                            response = self.crawler.send(request, follow_redirects=True)

                        except ReadTimeout:
                            if timeouted:
                                continue

                            self.log_orange("---")
                            self.log_orange(Anomaly.MSG_TIMEOUT, page)
                            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                            self.log_orange(request.http_repr())
                            self.log_orange("---")
                            anom_msg = Anomaly.MSG_QS_TIMEOUT

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Anomaly.RES_CONSUMPTION,
                                level=Anomaly.MEDIUM_LEVEL,
                                request=request,
                                info=anom_msg,
                                parameter=self.username_parameter_field[0]
                            )

                            timeouted = True

                        else:
                            if (self.check_success_auth(response.content)) and (response.content != false_response.content):
                                self.add_vuln(
                                    request_id=original_request.path_id,
                                    category=Vulnerability.BASIC_AUT_BF,
                                    level=Vulnerability.HIGH_LEVEL,
                                    request=request,
                                    parameter=self.username_parameter_field[0]
                                )

                                self.log_red("---")
                                self.log_red(_("Credentials found on {}").format(self.current_request_url)),
                                self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                self.log_red(request.http_repr())
                                self.log_red("---")

                                # We reached maximum exploitation for this parameter, don't send more payloads
                                # vulnerable_parameter : variable of wapiti
                                _vulnerable_parameter = True
                                return
            yield original_request
