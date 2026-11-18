import base64

import httpx2
import pytest
import spnego

from wapitiCore.net.ntlm_auth import HttpNtlmAuth

URL = "http://perdu.com/secret"


class NtlmServer:
    """A server protecting a resource with NTLM. pyspnego plays the server side of the handshake,
    so the messages sent by HttpNtlmAuth are really verified against the account below."""

    def __init__(self, status=401, schemes=("Negotiate", "NTLM"), challenge_cookie=None):
        self.status = status
        self.schemes = schemes
        self.challenge_cookie = challenge_cookie
        self.challenge_header = "WWW-Authenticate" if status == 401 else "Proxy-Authenticate"
        self.answer_header = "Authorization" if status == 401 else "Proxy-Authorization"
        self.context = spnego.server(protocol="ntlm")
        self.requests = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        # The auth flow reuses and updates one request object: keep a copy of what was sent each time
        self.requests.append(httpx2.Request(request.method, request.url, headers=request.headers))
        answer = request.headers.get(self.answer_header)
        if answer is None:
            return httpx2.Response(self.status, headers=[(self.challenge_header, scheme) for scheme in self.schemes])

        scheme, token = answer.split(" ", 1)
        try:
            challenge = self.context.step(base64.b64decode(token))
        except spnego.exceptions.SpnegoError:
            return httpx2.Response(self.status, headers={self.challenge_header: scheme})

        if self.context.complete:
            return httpx2.Response(200, text=f"Welcome {self.context.client_principal}")

        headers = [(self.challenge_header, f"{scheme} {base64.b64encode(challenge).decode('ascii')}")]
        if self.challenge_cookie:
            headers.append(("Set-Cookie", self.challenge_cookie))
        return httpx2.Response(self.status, headers=headers)


@pytest.fixture(autouse=True)
def ntlm_account(tmp_path, monkeypatch):
    # pyspnego reads the accounts its NTLM server accepts from this file
    user_file = tmp_path / "ntlm_users.txt"
    user_file.write_text("PERDU:alice:Letmein!\n", encoding="utf-8")
    monkeypatch.setenv("NTLM_USER_FILE", str(user_file))


async def fetch(server, auth):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(server), auth=auth) as client:
        return await client.get(URL)


@pytest.mark.asyncio
async def test_ntlm_handshake_succeeds_with_valid_credentials():
    server = NtlmServer()
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert response.status_code == 200
    assert response.text == "Welcome PERDU\\alice"
    # Anonymous request, negotiate message, authenticate message
    assert len(server.requests) == 3
    assert all(request.headers["Connection"] == "Keep-Alive" for request in server.requests)


@pytest.mark.asyncio
async def test_ntlm_is_preferred_to_negotiate():
    # IIS advertises both by default: with only a username and a password Kerberos is not an option
    server = NtlmServer(schemes=("Negotiate", "NTLM"))
    await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert server.requests[1].headers["Authorization"].startswith("NTLM ")


@pytest.mark.asyncio
async def test_ntlm_token_is_sent_with_negotiate_when_it_is_the_only_scheme():
    server = NtlmServer(schemes=("Negotiate",))
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert response.status_code == 200
    assert server.requests[1].headers["Authorization"].startswith("Negotiate ")


@pytest.mark.asyncio
async def test_challenges_in_a_single_comma_separated_header():
    server = NtlmServer(schemes=("Negotiate, NTLM",))
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert response.status_code == 200
    assert server.requests[1].headers["Authorization"].startswith("NTLM ")


@pytest.mark.asyncio
async def test_proxy_authentication_uses_the_proxy_headers():
    server = NtlmServer(status=407)
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert response.status_code == 200
    assert "Authorization" not in server.requests[2].headers
    assert server.requests[2].headers["Proxy-Authorization"].startswith("NTLM ")


@pytest.mark.asyncio
async def test_wrong_password_returns_the_refusal_without_looping():
    server = NtlmServer()
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "wrong"))

    assert response.status_code == 401
    assert len(server.requests) == 3


@pytest.mark.asyncio
async def test_cookie_set_with_the_challenge_is_sent_back():
    server = NtlmServer(challenge_cookie="session=abc")
    response = await fetch(server, HttpNtlmAuth("PERDU\\alice", "Letmein!"))

    assert response.status_code == 200
    assert "Cookie" not in server.requests[1].headers
    assert server.requests[2].headers["Cookie"] == "session=abc"


@pytest.mark.asyncio
async def test_other_schemes_and_other_statuses_are_left_alone():
    basic_only = NtlmServer(schemes=('Basic realm="x"',))
    response = await fetch(basic_only, HttpNtlmAuth("PERDU\\alice", "Letmein!"))
    assert response.status_code == 401
    assert len(basic_only.requests) == 1

    def not_found(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404)

    response = await fetch(not_found, HttpNtlmAuth("PERDU\\alice", "Letmein!"))
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_malformed_challenge_returns_the_last_response():
    def garbage(request: httpx2.Request) -> httpx2.Response:
        if "Authorization" not in request.headers:
            return httpx2.Response(401, headers={"WWW-Authenticate": "NTLM"})
        return httpx2.Response(401, headers={"WWW-Authenticate": "NTLM bm90IGEgY2hhbGxlbmdl"})

    response = await fetch(garbage, HttpNtlmAuth("PERDU\\alice", "Letmein!"))
    assert response.status_code == 401

    def not_base64(request: httpx2.Request) -> httpx2.Response:
        if "Authorization" not in request.headers:
            return httpx2.Response(401, headers={"WWW-Authenticate": "NTLM"})
        return httpx2.Response(401, headers={"WWW-Authenticate": "NTLM !!!"})

    response = await fetch(not_base64, HttpNtlmAuth("PERDU\\alice", "Letmein!"))
    assert response.status_code == 401
