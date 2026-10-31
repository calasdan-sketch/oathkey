"""Key validation: one minimal API call to prove the credentials work.

Only the HTTP status is inspected - response bodies are discarded
immediately so nothing secret-adjacent lingers. The one exception is the
OAuth2 token exchange, whose JSON answer is read for its access_token and
dropped as soon as the validation call has used it.

A credential is one value or several (see recipes.fields): an API key, an
App ID plus a secret, an AWS access key plus its secret. `validate_key`
takes either the single key as a string or a {field name: value} dict.

Auth shapes (recipes.AUTH_TYPES):

- bearer:  ``Authorization: <scheme> <value>``
- header:  the raw value in one named header
- headers: several named headers, each a value template ("{app_id}")
- basic:   HTTP Basic - a static username or a field as the username, and
           the key as the password
- query:   the value as a URL query parameter (``?appid=...``); such a
           request follows NO redirect, because the key is in the URL
- oauth2_client_credentials: POST the client id and secret to the vendor's
           token endpoint (the ONLY POST stuntkey ever makes, and only to
           the token_url the recipe names), then GET validate.url with the
           temporary token - or, with token_only, judge the token answer
- aws_sigv4: an AWS Signature Version 4 signed GET (STS GetCallerIdentity)

Redirects: credentials travel ONLY to the origin named in the recipe. If
the validation endpoint redirects to another host, another port, or from
https to http, the credential headers are stripped before the redirect is
followed (what browsers and `requests` do) and the result is reported as a
validation error, because a response from somewhere else proves nothing
about the key. Requests that carry a credential where a header cannot be
stripped (the URL, a POST body) follow no redirect at all.

A value an HTTP request cannot carry (a character outside Latin-1, a line
break or any other character that cannot be seen) is refused BEFORE any
request is built, with a sentence that never repeats the value
(UnsendableKey). Whatever else the HTTP library refuses to put in a
header is reported without its message, which can hold the whole header
value - the key included.
"""

from __future__ import annotations

import base64
import datetime
import email.utils
import hashlib
import hmac
import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from . import redact as redact_mod
from .recipes import ALLOWED_METHODS, DEFAULT_FIELD, STS_BODY, printable

USER_AGENT = f"stuntkey/{__version__}"
DEFAULT_PORTS = {"http": 80, "https": 443}
REJECT_DEFAULT = (401, 403)
TOKEN_REJECT = (400, 401, 403)    # OAuth2: invalid_client is usually a 400 or 401
MAX_TOKEN_BYTES = 64 * 1024       # an access-token answer is a few KB at most
PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


class ValidationError(Exception):
    pass


MAX_VERDICT_BODY = 4096     # read this much of an error answer, only to look for a phrase


class Result:
    """What the vendor said about a key. Truthy when the key is good enough
    to keep: status "valid" (it works) or "limited" (it is a real key that
    lacks a permission, so a vendor check that needs that permission cannot
    pass; `note` says which, in the recipe's own words). "invalid" is falsy.
    It never holds the key or any part of the vendor's answer."""

    __slots__ = ("status", "note", "identity")

    def __init__(self, status: str, note: str | None = None):
        self.status = status
        self.note = note
        self.identity = None    # a login name the vendor reports (not a secret), when the recipe asks

    def __bool__(self) -> bool:
        return self.status != "invalid"

    def __eq__(self, other) -> bool:
        if isinstance(other, bool):
            return bool(self) == other
        return isinstance(other, Result) and (self.status, self.note) == (other.status, other.note)

    def __hash__(self) -> int:
        return hash((self.status, self.note))

    def __repr__(self) -> str:
        return f"Result({self.status!r})"


NOT_PRINTABLE = ("a character that is not printable (a tab, a line break or "
                 "another invisible character)")
NOT_LATIN_1 = ("a character outside Latin-1 (a curly quote or an emoji, say), "
               "which an HTTP header cannot carry")


class ClockSkew(ValidationError):
    """A signed request was refused and the server's clock disagrees with this
    computer's by more than the signature allows: the key may be fine."""

    def __init__(self, minutes: int, ahead: bool):
        super().__init__(f"your computer's clock is about {minutes} minute(s) "
                         f"{'ahead of' if ahead else 'behind'} the server's. Signed requests are "
                         f"refused when the clock is off by more than 5 minutes. Fix the clock "
                         f"(turn on automatic time) and try again - the key may be fine.")
        self.minutes = minutes


MAX_SKEW_SECONDS = 300


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _skew(server_date: str | None) -> float | None:
    """Local clock minus the server's, in seconds, or None."""
    if not server_date:
        return None
    try:
        theirs = email.utils.parsedate_to_datetime(server_date)
    except (TypeError, ValueError):
        return None
    if theirs.tzinfo is None:
        theirs = theirs.replace(tzinfo=datetime.timezone.utc)
    return (_utcnow() - theirs).total_seconds()


class UnsendableKey(ValidationError):
    """A value cannot go into the request: it holds a character an HTTP
    request cannot carry. Raised before anything is built or sent. `reason`
    completes "the key contains ..." and never repeats the value; `field`
    names which value (None for a single-key recipe)."""

    def __init__(self, reason: str, field: str | None = None):
        super().__init__(f"the key contains {reason}")
        self.reason = reason
        self.field = field


def _unsendable_reason(atype: str, key: str) -> str | None:
    """Why `key` cannot be sent with this kind of auth, or None when it can.

    http.client puts a header value on the wire as Latin-1 and refuses a
    line break in it - and its error message holds the whole value. Basic
    auth base64-encodes the key (as UTF-8), and a query parameter, a POST
    body and a signing secret are percent-encoded or hashed, so any visible
    character does for those. A character that cannot be seen is refused
    for every kind: in a pasted key it is nearly always a copy accident, and
    the .env file refuses it too."""
    if not key.isprintable():
        return NOT_PRINTABLE
    if atype not in ("basic", "query", "body", "secret"):
        try:
            key.encode("latin-1")
        except UnicodeEncodeError:
            return NOT_LATIN_1
    return None


def _creds(key) -> dict[str, str]:
    """A single key string becomes {DEFAULT_FIELD: key}."""
    return {DEFAULT_FIELD: key} if isinstance(key, str) else dict(key)


def _value(creds: dict[str, str], name: str, kind: str) -> str:
    """The credential called `name`, checked for what `kind` of carrier
    can hold. A recipe that names a field nobody filled in is a bug in the
    recipe, said without any value."""
    if name not in creds:
        raise ValidationError(f"recipe auth names field '{printable(name)}' "
                              f"but no value was collected for it")
    value = creds[name]
    reason = _unsendable_reason(kind, value)
    if reason:
        raise UnsendableKey(reason, None if name == DEFAULT_FIELD else name)
    return value


def _fill(template: str, creds: dict[str, str], kind: str) -> str:
    return PLACEHOLDER.sub(lambda m: _value(creds, m.group(1), kind), template)


def _credential_headers(spec: dict) -> set[str]:
    """Lower-case names of every header that carries a credential - the ones
    stripped when a redirect leaves the origin."""
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    if atype in ("bearer", "basic", "oauth2_client_credentials"):
        return {"authorization"}
    if atype == "aws_sigv4":
        return {"authorization", "x-amz-security-token"}
    if atype == "header":
        return {auth["header"].lower()}
    if atype == "headers":
        return {name.lower() for name in auth["headers"]}
    if atype == "query":
        return set()
    raise ValidationError(f"unknown auth type: {atype}")


def _credential_header(spec: dict) -> str:
    """The main credential header (kept for callers of the one-header API)."""
    names = _credential_headers(spec)
    return "Authorization" if "authorization" in names or not names else next(iter(names))


def _base_headers(spec: dict) -> dict[str, str]:
    headers: dict[str, str] = {"User-Agent": USER_AGENT}
    for name, value in (spec.get("headers") or {}).items():
        headers[str(name)] = str(value)
    return headers


SIGV4_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"


def _is_sts_post(spec: dict) -> bool:
    """The one POST a validation may make besides an OAuth token call: AWS
    documents STS GetCallerIdentity as a POST. It only reads who you are."""
    auth = spec.get("auth", {})
    return (str(spec.get("method", "")).upper() == "POST"
            and auth.get("type") == "aws_sigv4" and auth.get("service") == "sts"
            and spec.get("body") == STS_BODY)


def _sts_body(spec: dict) -> bytes | None:
    return STS_BODY.encode() if _is_sts_post(spec) else None


def _check_method(spec: dict) -> str:
    method = str(spec.get("method", "GET")).upper()
    if method not in ALLOWED_METHODS and not _is_sts_post(spec):
        # The loader refuses such a recipe; this is for one that never went
        # through it. Nothing has been sent yet.
        raise ValidationError(
            f"validate.method must be GET or HEAD - a validation call only "
            f"reads - got {printable(spec.get('method'))!r}")
    return method


def _build_request(spec: dict, key, bearer_token: str | None = None) -> urllib.request.Request:
    """The one request that proves the credentials. `key` is the single key
    (a string) or {field: value}. See the module docstring for the auth
    shapes; ``spec["headers"]`` adds static headers some APIs insist on
    (``anthropic-version``, ``Notion-Version``) and a credential header
    always wins over a same-named static one."""
    method = _check_method(spec)
    creds = _creds(key)
    url = spec["url"]
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    headers = _base_headers(spec)
    if atype == "bearer":
        scheme = auth.get("scheme") or "Bearer"
        headers["Authorization"] = f"{scheme} {_value(creds, auth.get('field', DEFAULT_FIELD), atype)}"
    elif atype == "header":
        headers[auth["header"]] = _value(creds, auth.get("field", DEFAULT_FIELD), atype)
    elif atype == "headers":
        filled = {name: _fill(tpl, creds, "header") for name, tpl in auth["headers"].items()}
        headers.update(filled)
    elif atype == "basic":
        if auth.get("username_field"):
            user = _value(creds, auth["username_field"], "basic")
            password = _value(creds, auth.get("password_field", DEFAULT_FIELD), "basic")
            pair = f"{user}:{password}"
        else:
            key_value = _value(creds, auth.get("password_field", DEFAULT_FIELD), "basic")
            username = auth.get("username")
            pair = f"{username}:{key_value}" if username else f"{key_value}:"
        headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
    elif atype == "query":
        value = _value(creds, auth.get("field", DEFAULT_FIELD), "query")
        parts = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        query.append((auth["param"], value))
        url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))
    elif atype == "oauth2_client_credentials":
        if bearer_token is None:
            raise ValidationError("internal: the OAuth2 token must be fetched first")
        headers["Authorization"] = f"Bearer {bearer_token}"
    elif atype == "aws_sigv4":
        headers.update(_sigv4_headers(auth, creds, method, url,
                                      body=_sts_body(spec)))
    else:
        raise ValidationError(f"unknown auth type: {atype}")
    data = _sts_body(spec)
    if data is not None:
        headers["Content-Type"] = SIGV4_CONTENT_TYPE
    return urllib.request.Request(url, headers=headers, method=method,
                                  data=data)


# ---- AWS Signature Version 4 (GET with a query string, empty body) ----------

def _sigv4_headers(auth: dict, creds: dict[str, str], method: str, url: str,
                   now: datetime.datetime | None = None,
                   body: bytes | None = None) -> dict[str, str]:
    access = _value(creds, auth.get("access_key_field", "access_key_id"), "header")
    secret = _value(creds, auth.get("secret_key_field", "secret_access_key"), "secret")
    token_field = auth.get("session_token_field")
    token = _value(creds, token_field, "header") if token_field and creds.get(token_field) else None
    region, service = auth["region"], auth["service"]
    now = now or datetime.datetime.now(datetime.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    query = sorted(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    canonical_query = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
                               for k, v in query)
    signed = {"host": host, "x-amz-date": amz_date}
    if body is not None:
        signed["content-type"] = SIGV4_CONTENT_TYPE
    if token:
        signed["x-amz-security-token"] = token
    names = sorted(signed)
    # AWS double-encodes the path for every service but S3 (as botocore does)
    path = urllib.parse.quote(parts.path or "/", safe="/-_.~")
    canonical = "\n".join([method, path, canonical_query,
                           "".join(f"{n}:{signed[n]}\n" for n in names), ";".join(names),
                           hashlib.sha256(body or b"").hexdigest()])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (day, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {"X-Amz-Date": amz_date,
           "Authorization": (f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
                             f"SignedHeaders={';'.join(names)}, Signature={signature}")}
    if token:
        out["X-Amz-Security-Token"] = token
    return out


# ---- redirects ---------------------------------------------------------------

def _origin(url: str) -> tuple[str, str, int | None]:
    p = urllib.parse.urlsplit(url)
    scheme = (p.scheme or "").lower()
    try:
        port = p.port
    except ValueError:
        port = None
    return scheme, (p.hostname or "").lower(), port or DEFAULT_PORTS.get(scheme)


def should_strip_auth(old_url: str, new_url: str) -> bool:
    """True when following old_url -> new_url must drop credentials:
    any change of host, a change of scheme (including https -> http),
    or a change of port. Mirrors requests' Session.should_strip_auth,
    minus its one leniency (http -> https upgrades): recipes are https
    already, so an upgrade never legitimately happens."""
    old_scheme, old_host, old_port = _origin(old_url)
    new_scheme, new_host, new_port = _origin(new_url)
    return (old_host != new_host or old_scheme != new_scheme
            or old_port != new_port)


class _CredentialScrubbingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects like urllib does, but never carry a credential
    header across an origin change. Remembers that it had to strip.
    `credential_header` is one header name or several. With
    follow=False no redirect is followed at all (credentials in the URL or
    the body cannot be stripped) and the target is remembered."""

    def __init__(self, credential_header, follow: bool = True):
        super().__init__()
        names = [credential_header] if isinstance(credential_header, str) else list(credential_header)
        self._creds = {n.lower() for n in names}
        self._follow = follow
        self.stripped_to: str | None = None
        self.blocked_to: str | None = None
        self.server_date: str | None = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self._follow:
            self.blocked_to = newurl
            return None
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        if should_strip_auth(req.full_url, newurl):
            for name in list(new_req.headers) + list(new_req.unredirected_hdrs):
                if name.lower() in self._creds:
                    new_req.remove_header(name)
            self.stripped_to = newurl
        return new_req


def _send(req: urllib.request.Request, scrubber: _CredentialScrubbingRedirectHandler,
          timeout: float, read_limit: int = 0, no_proxy: bool = False) -> tuple[int, bytes]:
    """(status, up to read_limit bytes of body). Errors become
    ValidationError without repeating anything the request carried."""
    opener = (urllib.request.build_opener(urllib.request.ProxyHandler({}), scrubber)
              if no_proxy else urllib.request.build_opener(scrubber))
    body = b""
    try:
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = resp.status
                scrubber.server_date = resp.headers.get("Date")
                if read_limit:
                    body = resp.read(read_limit + 1)
        except urllib.error.HTTPError as e:
            status = e.code
            scrubber.server_date = e.headers.get("Date") if e.headers else None
            if read_limit:
                try:
                    body = e.read(read_limit + 1)
                except (OSError, http.client.HTTPException):
                    body = b""
            e.close()           # the error object owns the response; Python 3.14 warns when it is only garbage-collected
    except urllib.error.URLError as e:
        raise ValidationError(f"network error during validation: {e.reason}")
    except http.client.HTTPException as e:
        # BadStatusLine / RemoteDisconnected / IncompleteRead: something
        # answered, but not with HTTP (a proxy page, a TLS mismatch, a
        # non-HTTP service on the port). Not a crash, not a verdict.
        raise ValidationError(
            f"validation endpoint did not speak HTTP ({type(e).__name__}: "
            f"{str(e)[:80]!r}); check the recipe's validate.url")
    except OSError as e:
        raise ValidationError(f"network error during validation: {e}")
    except ValueError:
        # What http.client refuses to put in a header (and a few other
        # things it cannot encode, such as a host name) comes as a
        # ValueError whose text holds the whole header value - "Invalid
        # header value b'Bearer <the key>'". _build_request already stops a
        # key like that; this is for the rest (a header value in the recipe
        # itself, say) and must not repeat the text. `from None`: the
        # original is not chained either.
        raise ValidationError(
            "the HTTP library refused to send the request (its message is "
            "left out - it can hold the key). Check the key you pasted and "
            "the recipe's validate section") from None
    if scrubber.blocked_to is not None:
        raise ValidationError(
            f"the endpoint redirected to {printable(safe_url(scrubber.blocked_to))}; the "
            f"credentials were not sent there. Fix the recipe to point at the "
            f"final endpoint.")
    if scrubber.stripped_to is not None:
        raise ValidationError(
            "validation endpoint redirected to a different origin "
            f"({printable(safe_url(scrubber.stripped_to))}); the key was not sent there. "
            "Fix the recipe's validate.url to point at the final endpoint.")
    return status, body


def safe_url(url) -> str:
    """scheme://host/path only - never the query or fragment, where a key in
    a redirect target would sit."""
    try:
        u = urllib.parse.urlsplit(str(url))
        return f"{u.scheme}://{u.hostname or ''}{':' + str(u.port) if u.port else ''}{u.path}"
    except ValueError:
        return "(an address that could not be read)"


def _verdict(status: int, spec: dict, reject_default=REJECT_DEFAULT,
             body: bytes = b"") -> Result:
    """Order matters: what the recipe expects, then its body rules (a vendor
    that says the same 401 for "dead" and "valid but restricted"), then its
    "limited" statuses (a 403 that means "real key, missing permission"),
    then the statuses that mean "bad key". The vendor's text is only searched,
    never kept or shown."""
    if status in set(spec.get("expect", [200])):
        return Result("valid")
    text = body.decode("utf-8", "replace").lower() if body else ""
    for rule in spec.get("body_rules") or []:
        if rule["status"] == status and rule["body_contains"].lower() in text:
            return Result(rule["result"], rule.get("meaning") or None)
    for item in spec.get("limited") or []:
        if item["status"] == status:
            return Result("limited", item["meaning"])
    if status in set(spec.get("reject") or reject_default):
        return Result("invalid")  # credentials rejected (validation failed, not a crash)
    raise ValidationError(f"validation endpoint error: HTTP {status}")


# ---- OAuth2 client credentials -----------------------------------------------

def _fetch_token(spec: dict, creds: dict[str, str], timeout: float,
                 no_proxy: bool = False) -> str | None:
    """POST the client credentials to the recipe's token_url. Returns the
    access token, or None when the vendor said the credentials are wrong.
    No redirect is followed: a token endpoint never needs one, and the
    secret must reach that exact origin or nowhere."""
    auth = spec["auth"]
    client_id = _value(creds, auth.get("client_id_field", "client_id"), "basic")
    secret = _value(creds, auth.get("client_secret_field", "client_secret"), "basic")
    form = {"grant_type": "client_credentials"}
    if auth.get("scope"):
        form["scope"] = auth["scope"]
    headers = _base_headers(spec)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Accept"] = "application/json"
    if auth.get("send", "basic") == "body":
        form.update({"client_id": client_id, "client_secret": secret})
    else:
        pair = f"{client_id}:{secret}"
        headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
    req = urllib.request.Request(auth["token_url"], data=urllib.parse.urlencode(form).encode(),
                                 headers=headers, method="POST")
    status, body = _send(req, _CredentialScrubbingRedirectHandler("Authorization", follow=False),
                         timeout, MAX_TOKEN_BYTES, no_proxy)
    if status in TOKEN_REJECT:
        return None
    if status != 200:
        raise ValidationError(f"token endpoint error: HTTP {status}")
    try:
        token = json.loads(body[:MAX_TOKEN_BYTES]).get("access_token")
    except (ValueError, AttributeError):
        token = None
    finally:
        body = None
    if not isinstance(token, str) or not token or _unsendable_reason("bearer", token):
        raise ValidationError("the token endpoint answered 200 but gave no usable access_token")
    return token


def validate_key(spec: dict, key, timeout: float = 10.0) -> Result:
    """See _validate_key. Any error text is scrubbed of the key (and its
    encodings) before it leaves, whatever produced it."""
    try:
        return _validate_key(spec, key, timeout)
    except ValidationError as e:
        values = list(_creds(key).values())
        clean = redact_mod.Redactor(values).text(str(e)) if values else str(e)
        if clean == str(e):
            raise
        raise ValidationError(clean) from None


def _validate_key(spec: dict, key, timeout: float = 10.0) -> Result:
    """Return a Result: truthy if the API accepts the credentials (status in
    spec['expect']) or shows they are real but limited; falsy if rejected.
    `key` is the single key or {field: value}.

    Raises ValidationError on network failure, or when the endpoint
    redirected off-origin (the credentials were NOT sent there). Never logs
    a value."""
    creds = _creds(key)
    auth = spec.get("auth", {})
    atype = auth.get("type", "bearer")
    token = None
    if atype == "oauth2_client_credentials":
        token = _fetch_token(spec, creds, timeout)
        if token is None:
            return Result("invalid")
        if auth.get("token_only"):
            return Result("valid")    # the vendor issued a token: the id and secret are good
    try:
        req = _build_request(spec, creds, bearer_token=token)
        scrubber = _CredentialScrubbingRedirectHandler(_credential_headers(spec),
                                                       follow=atype != "query")
        wants_body = bool(spec.get("body_rules")) or bool(spec.get("identity"))
        status, body = _send(req, scrubber, timeout,
                             MAX_VERDICT_BODY if wants_body else 0)
    finally:
        token = None
    if atype == "aws_sigv4" and status in (400, 401, 403):
        skew = _skew(scrubber.server_date)
        if skew is not None and abs(skew) > MAX_SKEW_SECONDS:
            raise ClockSkew(int(abs(skew) // 60), skew > 0)
    result = _verdict(status, spec, body=body[:MAX_VERDICT_BODY])
    if result and result.status == "valid" and spec.get("identity"):
        result.identity = _identity(spec["identity"], body[:MAX_VERDICT_BODY])
    return result


_IDENTITY_OK = re.compile(r"[A-Za-z0-9-]{1,39}\Z")      # a GitHub-style login: nothing to mislead a person


def _identity(field: str, body: bytes) -> str | None:
    """The account's login name from the vendor's JSON answer (`validate.identity`
    names the member, e.g. "login"). A login is not a secret; anything that is
    not a short plain name is dropped."""
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    value = data.get(field) if isinstance(data, dict) else None
    return value if isinstance(value, str) and _IDENTITY_OK.match(value) else None
