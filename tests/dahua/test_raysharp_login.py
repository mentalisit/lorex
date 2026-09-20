"""Tests for the Raysharp / Lorex login on custom_components.dahua.client."""
import json

import pytest

from custom_components.dahua.client import DahuaClient, RaysharpAuthError

REFUSAL = {
    "result": "failed",
    "reason": "User name or password error! Please try again later.",
    "error_code": "verify_failed",
    "data": {"block_remain_time": "180"},
}


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.headers = {}
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeAuth:
    """Stands in for DigestAuth: records the body and answers canned replies."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.payloads = []

    def __call__(self, *args, **kwargs):
        return self

    async def request(self, method, url, *, json=None, **kwargs):
        self.payloads.append(json)
        return self.replies.pop(0)


@pytest.fixture
async def client():
    client = DahuaClient("admin", "florian88", "d", 80, 554, None)
    yield client
    if client._raysharp_session is not None:
        await client._raysharp_session.close()


async def test_login_sends_a_version_like_every_other_call(client, monkeypatch):
    auth = FakeAuth([FakeResponse(200, json.dumps({"result": "success"}))])
    monkeypatch.setattr("custom_components.dahua.client.DigestAuth", auth)

    assert await client.async_login() is True
    assert auth.payloads[0]["version"] == "1.0"


async def test_a_refusal_is_not_retried_while_the_account_is_blocked(client, monkeypatch):
    """The device counts attempts made during the block, so one must not poll it."""
    auth = FakeAuth([FakeResponse(400, json.dumps(REFUSAL))])
    monkeypatch.setattr("custom_components.dahua.client.DigestAuth", auth)

    with pytest.raises(RaysharpAuthError, match="rejected the credentials"):
        await client.async_login()

    with pytest.raises(RaysharpAuthError, match="not retrying"):
        await client.async_login()

    assert len(auth.payloads) == 1, "the client kept knocking while blocked"
