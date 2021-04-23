import sys
import os
from subprocess import Popen
from time import sleep
from pathlib import Path
from shutil import rmtree
import string
from random import choice

import pytest
import httpx


def rand_id():
    return "".join([choice(string.ascii_letters + string.digits) for __ in range(6)])


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    endpoint_directory = os.path.join(base_dir, "..", "endpoint")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", endpoint_directory])
    sleep(.5)
    yield
    proc.terminate()

    # cleanup: data directories should exist but be empty at the end of tests
    for directory in ("xxe_data", "ssrf_data"):
        rmtree(os.path.join(endpoint_directory, directory), ignore_errors=True)

    for directory in ("xxe_data", "ssrf_data"):
        dir_path = Path(endpoint_directory) / directory
        dir_path.mkdir(0o700)


def test_ssrf():
    response = httpx.get(
        "http://127.0.0.1:65080/ssrf_store.php?session_id=wapiti&path_id=53&hex_param=76756c6e",
        headers={"Host": "yolo.tld:65080"}
    )
    assert response.status_code == 200
    response = httpx.get(
        "http://127.0.0.1:65080/get_ssrf.php?session_id=wapiti",
        headers={"Host": "yolo.tld:65080"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["53"]["76756c6e"][0]["method"] == "GET"
    assert data["53"]["76756c6e"][0]["url"].startswith("http://yolo.tld:65080/ssrf_data/wapiti/53/76756c6e/")
    assert data["53"]["76756c6e"][0]["url"].endswith("-127.0.0.1.txt")
    assert data["53"]["76756c6e"][0]["ip"] == "127.0.0.1"
    assert "size" in data["53"]["76756c6e"][0]


def test_xxe_dtd():
    session_id = rand_id()
    response = httpx.get(
        f"http://127.0.0.1:65080/xxe_dtd.php?session_id={session_id}&path_id=53&hex_param=76756c6e&payload=linux2",
        headers={"Host": "yolo.tld:65080"}
    )
    assert response.status_code == 200
    assert "text/xml" in response.headers["content-type"]
    assert f"SYSTEM 'http://yolo.tld:65080/xoxo/{session_id}/53/76756c6e/0/" in response.text


def test_xxe_store():
    session_id = rand_id()
    response = httpx.get(
        (
            f"http://127.0.0.1:65080/xxe_store.php?session_id={session_id}"
            f"&path_id=53&hex_param=76756c6e&payload=0&data=impwned"
        ),
        headers={"Host": "yolo.tld:65080"}
    )
    assert response.status_code == 200
    response = httpx.get(
        f"http://127.0.0.1:65080/get_xxe.php?session_id={session_id}",
        headers={"Host": "yolo.tld:65080"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["53"]["76756c6e"][0]["payload"] == "linux2"
    assert data["53"]["76756c6e"][0]["url"].startswith(f"http://yolo.tld:65080/xxe_data/{session_id}/53/76756c6e/")
    assert data["53"]["76756c6e"][0]["url"].endswith("-0-127.0.0.1.txt")
    assert data["53"]["76756c6e"][0]["size"] == 5
    assert data["53"]["76756c6e"][0]["ip"] == "127.0.0.1"
