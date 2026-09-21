"""Dahua Digest Auth Support"""
import os
import time
import hashlib
import aiohttp
from aiohttp.client_reqrep import ClientResponse
from aiohttp.client_exceptions import ClientError
from yarl import URL


# Seems that aiohttp doesn't support Diegest Auth, which Dahua cams require. So I had to bake it in here.
# Copied and then modified from https://github.com/aio-libs/aiohttp/pull/2213
# I really wish this was baked into aiohttp :-(

# How many times one request may answer a 401 before giving up.
MAX_AUTH_ATTEMPTS = 3


class DigestAuth:
    """HTTP digest authentication helper.
    The work here is based off of
    https://github.com/requests/requests/blob/v2.18.4/requests/auth.py.
    """

    def __init__(self, username: str, password: str, session: aiohttp.ClientSession, previous=None):
        if previous is None:
            previous = {}

        self.username = username
        self.password = password
        # Held by reference, so a challenge accepted by one request is reused by
        # the next. Callers passing nothing keep the old per-request behaviour.
        self._state = previous
        self.session = session

    # Challenge and nonce count live in the shared state, exposed as attributes.
    @property
    def challenge(self):
        return self._state.get("challenge")

    @challenge.setter
    def challenge(self, value):
        self._state["challenge"] = value

    @property
    def last_nonce(self):
        return self._state.get("last_nonce", "")

    @last_nonce.setter
    def last_nonce(self, value):
        self._state["last_nonce"] = value

    @property
    def nonce_count(self):
        return self._state.get("nonce_count", 0)

    @nonce_count.setter
    def nonce_count(self, value):
        self._state["nonce_count"] = value

    async def request(self, method, url, *, headers=None, **kwargs):
        """Makes a request, absorbing digest challenges up to a fixed budget."""
        if headers is None:
            headers = {}

        refused = 0
        response = None

        for _ in range(MAX_AUTH_ATTEMPTS):
            attempt_headers = dict(headers)
            sent_nonce = None

            if self.challenge:
                authorization = self._build_digest_header(method.upper(), url)
                if authorization:
                    attempt_headers["AUTHORIZATION"] = authorization
                    sent_nonce = self.challenge.get("nonce")
                else:
                    # A challenge we cannot build a header from would otherwise
                    # fail every later request too. Drop it and probe instead.
                    self.challenge = None

            response = await self.session.request(method, url, headers=attempt_headers, **kwargs)

            if response.status != 401:
                return response

            challenge = self._parse_401(response)
            if challenge is None:
                return response

            if sent_nonce is not None:
                stale = str(challenge.get("stale", "")).lower() == "true"
                if challenge.get("nonce") == sent_nonce and not stale:
                    # Same nonce, not flagged stale: either the credentials are
                    # wrong or our nonce count arrived out of order. One retry
                    # covers the count; a second failure means it is the password.
                    refused += 1
                    if refused > 1:
                        self.challenge = None
                        return response

            response.close()
            self.challenge = challenge

        return response

    def _parse_401(self, response: ClientResponse):
        """Returns the digest challenge carried by a 401, or None."""
        parts = response.headers.get("www-authenticate", "").split(" ", 1)
        if "digest" == parts[0].lower() and len(parts) > 1:
            try:
                return parse_key_value_list(parts[1])
            except (IndexError, ValueError):
                return None
        return None

    def _build_digest_header(self, method, url):
        """
        :rtype: str
        """

        realm = self.challenge.get("realm")
        nonce = self.challenge.get("nonce")
        if realm is None or nonce is None:
            return ""
        qop = self.challenge.get("qop")
        algorithm = self.challenge.get("algorithm", "MD5").upper()
        opaque = self.challenge.get("opaque")

        if qop and not (qop == "auth" or "auth" in qop.split(",")):
            raise ClientError("Unsupported qop value: %s" % qop)

        # lambdas assume digest modules are imported at the top level
        if algorithm == "MD5" or algorithm == "MD5-SESS":
            hash_fn = hashlib.md5
        elif algorithm == "SHA":
            hash_fn = hashlib.sha1
        else:
            return ""

        def H(x):
            return hash_fn(x.encode()).hexdigest()

        def KD(s, d):
            return H("%s:%s" % (s, d))

        # raw_path_qs, not path_qs: the request-URI that goes on the wire is
        # percent-encoded by yarl, and RFC 7616 wants the uri in the header to
        # be that same string. path_qs hands back the decoded form, so every URL
        # carrying a square bracket -- which is every indexed write, from
        # MotionDetect[0].Enable to Lighting_V2[3][0][1] -- was signed as
        # "[0]" while "%5B0%5D" was sent. A device that checks is entitled to
        # refuse that, and 403 is what refusing it looks like.
        path = URL(url).raw_path_qs

        # RFC 7616 userhash=true (Lorex / Raysharp OpenResty): only the username
        # carried in the Authorization header is hashed, so the server can look
        # the account up without the name crossing the wire. A1 keeps the plain
        # username -- hashing it there produces a response the device reads as a
        # wrong password, and a few of those lock the account out for 180s.
        use_userhash = str(self.challenge.get("userhash", "")).lower() == "true"
        auth_username = H("%s:%s" % (self.username, realm)) if use_userhash else self.username

        A1 = "%s:%s:%s" % (self.username, realm, self.password)
        A2 = "%s:%s" % (method, path)

        HA1 = H(A1)
        HA2 = H(A2)

        if nonce == self.last_nonce:
            self.nonce_count += 1
        else:
            self.nonce_count = 1

        self.last_nonce = nonce

        ncvalue = "%08x" % self.nonce_count

        # cnonce is just a random string generated by the client.
        cnonce_data = "".join(
            [
                str(self.nonce_count),
                nonce,
                time.ctime(),
                os.urandom(8).decode(errors="ignore"),
            ]
        ).encode()
        cnonce = hashlib.sha1(cnonce_data).hexdigest()[:16]

        if algorithm == "MD5-SESS":
            HA1 = H("%s:%s:%s" % (HA1, nonce, cnonce))

        # This assumes qop was validated to be 'auth' above. If 'auth-int'
        # support is added this will need to change.
        if qop:
            noncebit = ":".join([nonce, ncvalue, cnonce, "auth", HA2])
            response_digest = KD(HA1, noncebit)
        else:
            response_digest = KD(HA1, "%s:%s" % (nonce, HA2))

        # algorithm and qop are tokens, not quoted strings (RFC 7616 3.4), and
        # a strict parser is entitled to read "MD5" with the quotes as an
        # algorithm it does not have -- which is what a device that answers
        # curl but not us looks like. This is byte-for-byte what curl sends.
        base = ", ".join(
            [
                'username="%s"' % auth_username,
                'realm="%s"' % realm,
                'nonce="%s"' % nonce,
                'uri="%s"' % path,
                'response="%s"' % response_digest,
                "algorithm=%s" % algorithm,
            ]
        )
        if opaque:
            base += ', opaque="%s"' % opaque
        if qop:
            base += ', qop=auth, nc=%s, cnonce="%s"' % (ncvalue, cnonce)
        if use_userhash:
            base += ", userhash=true"

        return "Digest %s" % base


def parse_pair(pair):
    key, value = pair.strip().split("=", 1)

    # If it has a trailing comma, remove it.
    if value[-1] == ",":
        value = value[:-1]

    # If it is quoted, then remove them.
    if value[0] == value[-1] == '"':
        value = value[1:-1]

    return key, value


def parse_key_value_list(header):
    return {
        key: value
        for key, value in [parse_pair(header_pair) for header_pair in header.split(",")]
    }
