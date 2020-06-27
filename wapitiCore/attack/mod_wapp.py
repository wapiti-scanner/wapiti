#!/usr/bin/env python3
from wapitiCore.attack.attack import Attack
from wapitiCore.wappalyzer.wappalyzer import Wappalyzer, ApplicationData, ApplicationDataException
from wapitiCore.language.vulnerability import Additional
from wapitiCore.net.web import Request


class mod_wapp(Attack):
    """
    This class implements a web technology detection based on Wappalyzer
    """

    name = "wapp"

    do_get = False
    do_post = False

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        if self.verbose >= 1:
            print("[+] {}".format(request))

        try:
            application_data = ApplicationData()
        except ApplicationDataException as exception:
            print(exception)
            return

        response = self.crawler.send(request)
        wappalyzer = Wappalyzer(application_data, response)
        detected_applications = wappalyzer.detect_with_versions_and_categories()

        if len(detected_applications) > 0:
            self.log_blue("---")

        for application_name in sorted(detected_applications, key=lambda x: x.lower()):
            if len(detected_applications[application_name]["versions"]) > 0:
                self.log_blue(Additional.MSG_TECHNO_VERSIONED, application_name,
                              detected_applications[application_name]["versions"][0])

                self.add_addition(
                    category=Additional.TECHNO_DETECTED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info="{0} {1}".format(application_name,
                                          detected_applications[application_name]["versions"][0])
                    )
            else:
                self.log_blue(Additional.MSG_TECHNO, application_name)

                self.add_addition(
                    category=Additional.TECHNO_DETECTED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=application_name
                    )
        yield
