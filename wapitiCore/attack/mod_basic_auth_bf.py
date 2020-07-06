from itertools import chain
from os.path import join as path_join
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ReadTimeout
from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack, Mutator
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_basic_auth_bf(Attack):
    time_to_sleep = ''
    name = "basic_auth_bf"
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
        content = requests.get(self.current_request_url).content
        inputs = BeautifulSoup(content, features="lxml").findAll('input')
        for _input in inputs:
            if _input.attrs['type'] == 'submit':
                self.submit_var_name = _input.attrs['name']
                self.submit_var_value = _input.attrs['name']
            if _input.attrs['type'] == 'password' and self.current_request_method == 'POST':
                self.password_parameter.append(_input.attrs['name'])
                self.username_parameter_field.append(inputs[inputs.index(_input) - 1].attrs['name'])
                return True
        return False

    def check_success_auth(self, content_response: str):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_SUCCESS), 'r') as success_pattern_file:
            for success_pattern in success_pattern_file:
                if success_pattern.strip("\n") in content_response:
                    return True
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FAIL), 'r') as fail_pattern_file:
            for fail_pattern in fail_pattern_file:
                if fail_pattern in content_response:
                    return False
        return False

    def get_username_list(self):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE_USER), 'r') as username_file:
            data = username_file.readlines()
            for username in data:
                self.payloads_username.append(username.strip())

    def get_password_list(self):
        with open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE), 'r') as password_file:
            data = password_file.readlines()
            for password in data:
                self.payloads_password.append(password.strip("\n"))

    def inject_username_payload(self, original_request, username_payload):
        for params_list in original_request.post_params:
            if self.username_parameter_field in params_list:
                original_request.post_params[original_request.post_params.index(params_list)][1] = username_payload
        return original_request

    def attack(self):
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []
        timeouted = False

        for original_request in chain(http_resources, forms):
            page = original_request.path
            self.current_request_url = original_request.url
            self.current_request_method = original_request.method
            if self.has_password_field():
                self.get_username_list()

                _mutator = Mutator(
                    methods="P",
                    parameters=self.password_parameter,
                    payloads=self.get_password_list(),
                    qs_inject=self.must_attack_query_string,
                    skip=self.options.get("skipped_parameters")
                )

                for username in self.payloads_username:
                    if self.verbose >= 1:
                        print("[+] {}".format(original_request))
                    for payload in self.payloads:

                        data_content = [(self.username_parameter_field[0], username),\
                                        (self.password_parameter[0], payload[0]),\
                                        (self.submit_var_name, self.submit_var_value)]
                        mutated_request = Request(original_request.url, method="POST",\
                                                  enctype="application/x-www-form-urlencoded", post_params=data_content)
                        session = requests.Session()
                        try:
                            response = session.post(original_request.url, data=data_content)

                        except ReadTimeout:
                            if timeouted:
                                continue

                            self.log_orange("---")
                            self.log_orange(Anomaly.MSG_TIMEOUT, page)
                            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                            self.log_orange(mutated_request.http_repr())
                            self.log_orange("---")

                            anom_msg = Anomaly.MSG_QS_TIMEOUT

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Anomaly.RES_CONSUMPTION,
                                level=Anomaly.MEDIUM_LEVEL,
                                request=mutated_request,
                                info=anom_msg,
                                parameter=self.username_parameter_field[0]
                            )
                            timeouted = True

                        else:
                            if self.check_success_auth(response.text):
                                self.log_red("credentials found on : ", self.current_request_url, " !")
                                vuln_message = "Brute force auth success"
                                log_message = "Brute force auth success"

                                self.add_vuln(
                                    request_id=original_request.path_id,
                                    category=Vulnerability.BASIC_AUT_BF,
                                    level=Vulnerability.HIGH_LEVEL,
                                    request=mutated_request,
                                    info=vuln_message,
                                    parameter=self.username_parameter_field[0]
                                )

                                self.log_red("---")
                                self.log_red(
                                    log_message,
                                    self.MSG_VULN,
                                    page,
                                    self.username_parameter_field[0]
                                )

                                self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                self.log_red(mutated_request.http_repr())
                                self.log_red("---")

                                # We reached maximum exploitation for this parameter, don't send more payloads
                                # vulnerable_parameter : variable of wapiti
                                _vulnerable_parameter = True
                                return
            yield original_request
