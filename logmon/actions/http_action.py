from typing import Iterable, Optional, NotRequired, TypedDict, override

import re
import uuid
import json
import logging
import pydantic

from http.client import HTTPConnection, HTTPSConnection, NotConnected, HTTPException, HTTPResponse
from urllib.parse import urlencode, urljoin, urlparse
from base64 import b64encode
from datetime import timedelta, datetime
from urllib.request import urlopen, Request

from ..types import ContentType, OAuth2GrantType
from ..schema import Config
from ..yaml import yaml_dump
from ..constants import *
from .remote_action import RemoteAction
from ..entry_readers import LogEntry
from ..template import expand, expand_object

__all__ = (
    'HttpAction',
)

logger = logging.getLogger(__name__)

HTTP_REDIRECT_STATUSES = frozenset((301, 302, 307, 308))

class MultipartFile(TypedDict):
    filename: str
    content_type: NotRequired[str]
    content: bytes

FIELD_NAME_PATTERN = re.compile(r'["\x00-\x1F]')

def quote_field_name(name: str) -> str:
    return FIELD_NAME_PATTERN.sub(lambda m: '%%%02X' % ord(m[0]), name)

def encode_multipart(fields: Iterable[tuple[str, str|MultipartFile]]) -> tuple[dict[str, str], bytes]:
    buf: list[bytes] = []
    boundary = uuid.uuid4().hex
    bin_boundary = f'--{boundary}\r\n'.encode()
    headers: dict[str, str] = {
        'Content-Type': f'multipart/form-data; boundary={boundary}'
    }

    for key, value in fields:
        buf.append(bin_boundary)
        if isinstance(value, str):
            buf.append(f'Content-Disposition: form-data; name="{quote_field_name(key)}"\r\n'.encode())
            buf.append(b'\r\n')
            buf.append(value.encode())
            buf.append(b'\r\n')
        else:
            buf.append(f'Content-Disposition: form-data; name="{quote_field_name(key)}", filename="{quote_field_name(value["filename"])}"\r\n'.encode())
            content_type = value.get('content_type', 'application/octet-stream').replace('\n', ' ').replace('\r', '')
            buf.append(f'Content-Type: {content_type}\r\n'.encode())
            buf.append(b'\r\n')
            buf.append(value['content'])
            buf.append(b'\r\n')

    buf.append(f'--{boundary}--\r\n'.encode())
    body = b''.join(buf)

    return headers, body

class OAuth2Token(pydantic.BaseModel):
    access_token: str
    token_type: str
    expires_in: Optional[int|float] = None
    refresh_token: Optional[str] = None

class OAuth2Error(pydantic.BaseModel):
    error: str
    error_description: Optional[str] = None

class OAuth2Response(pydantic.BaseModel):
    response: OAuth2Token|OAuth2Error

class HttpAction(RemoteAction):
    __slots__ = (
        'http_method',
        'http_path',
        'http_params',
        'http_content_type',
        'http_headers',
        'http_max_redirect',
        'http_connection',
        'http_timeout',
        'oauth2_grant_type',
        'oauth2_token_url',
        'oauth2_client_id',
        'oauth2_client_secret',
        'oauth2_scope',
        'oauth2_refresh_margin',
        'oauth2_token',
        'oauth2_token_expires_at',
    )
    http_method: str
    http_path: str
    http_params: Optional[list[tuple[str, str]]]
    http_content_type: Optional[ContentType]
    http_headers: Optional[dict[str, str]]
    http_max_redirect: int
    http_connection: HTTPConnection
    http_timeout: Optional[float]

    oauth2_grant_type: OAuth2GrantType
    oauth2_token_url: Optional[str]
    oauth2_client_id: Optional[str]
    oauth2_client_secret: Optional[str]
    oauth2_scope: Optional[list[str]]
    oauth2_refresh_margin: timedelta
    oauth2_token: Optional[OAuth2Token]
    oauth2_token_expires_at: Optional[datetime]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.http_method = config.get('http_method', DEFAULT_HTTP_METHOD)
        http_path = config.get('http_path', '/')
        if not http_path.startswith('/'):
            http_path = f'/{http_path}'
        self.http_path = http_path
        http_params = config.get('http_params')
        self.http_params = list(http_params.items()) if isinstance(http_params, dict) else http_params
        self.http_content_type = config.get('http_content_type')
        self.http_headers = config.get('http_headers')
        self.http_max_redirect = config.get('http_max_redirect', DEFAULT_HTTP_MAX_REDIRECT)
        http_timeout = config.get('http_timeout')
        self.http_timeout = http_timeout
        self.http_connection = HTTPConnection(self.host, self.port, timeout=http_timeout) if self.action == 'HTTP' else \
                               HTTPSConnection(self.host, self.port, timeout=http_timeout)
        self.oauth2_grant_type = config.get('oauth2_grant_type') or DEFAULT_OAUTH2_GRANT_TYPE
        self.oauth2_token_url = config.get('oauth2_token_url') or None
        self.oauth2_client_id = config.get('oauth2_client_id')
        self.oauth2_client_secret = config.get('oauth2_client_secret')
        self.oauth2_scope = config.get('oauth2_scope')
        oauth2_refresh_margin = config.get('oauth2_refresh_margin')
        self.oauth2_refresh_margin = oauth2_refresh_margin if oauth2_refresh_margin is not None else timedelta(0)
        self.oauth2_token = None
        self.oauth2_token_expires_at = None

    def connect(self) -> None:
        if self.http_connection.sock is None:
            self.http_connection.connect()

    def reconnect(self) -> None:
        try:
            if self.http_connection.sock is not None:
                self.http_connection.close()
        except Exception as exc:
            logger.warning(f"Closing connection: {exc}", exc_info=exc)

        self.http_connection = HTTPConnection(self.host, self.port, timeout=self.http_timeout) if self.action == 'HTTP' else \
                               HTTPSConnection(self.host, self.port, timeout=self.http_timeout)
        self.connect()

    def refresh_token_if_needed(self) -> None:
        oauth2_token_url = self.oauth2_token_url
        if oauth2_token_url:
            expires_at = self.oauth2_token_expires_at
            if self.oauth2_token is None or expires_at is not None and expires_at <= datetime.now() - self.oauth2_refresh_margin:
                grant_type = self.oauth2_grant_type
                data: dict[str, str|None] = {
                    "grant_type": grant_type,
                }
                # TODO: support refresh token
                match grant_type:
                    case 'client_credentials':
                        data['client_id'] = self.oauth2_client_id
                        data['client_secret'] = self.oauth2_client_secret

                    case 'password':
                        data['username'] = self.username
                        data['password'] = self.password

                    case _:
                        raise ValueError(f'[{oauth2_token_url}] Illegal grant type: {grant_type}')

                scope = self.oauth2_scope
                if scope:
                    data['scope'] = ' '.join(scope)

                request = Request(
                    oauth2_token_url,
                    method = 'POST',
                    data = urlencode(data).encode(),
                    headers = {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                )
                response: HTTPResponse
                now = datetime.now()
                with urlopen(request, timeout=self.http_timeout) as response:
                    body = response.read()

                    content_type = response.headers.get('Content-Type') or 'application/json'
                    pure_content_type = content_type.split(';')[0]

                    try:
                        data = json.loads(body)
                    except Exception as exc:
                        raise HTTPException(f"[{oauth2_token_url}] Error parsing OAuth2 response: {exc}") from exc

                    if pure_content_type != 'application/json':
                        raise HTTPException(f"[{oauth2_token_url}] Illegal content-type of OAuth2 token endpoint response: {content_type}")

                    if response.status < 200 or response.status >= 300:
                        msg = f"[{oauth2_token_url}] HTTP status {response.status} when fetching access token"
                        if isinstance(data, dict) and 'error' in data:
                            msg = f"{msg}, response body:\n{body.decode(errors='replace')}"
                        raise HTTPException(msg)

                    try:
                        oauth2_response = OAuth2Response(
                            response=data # type: ignore
                        ).response

                        if isinstance(oauth2_response, OAuth2Error):
                            raise HTTPException(f"[{oauth2_token_url}] OAuth2 error: {oauth2_response.error} {oauth2_response.error_description or ''}")

                        self.oauth2_token = oauth2_response

                        expires_in = oauth2_response.expires_in
                        if expires_in is None:
                            self.oauth2_token_expires_at = None
                        else:
                            self.oauth2_token_expires_at = now + timedelta(seconds=expires_in)

                    except Exception as exc:
                        raise HTTPException(f"[{oauth2_token_url}] Error parsing OAuth2 response: {exc}") from exc

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return

        try:
            subject = self.subject_templ.format_map(templ_params)
            templ_params['subject'] = subject

            if logger.isEnabledFor(logging.DEBUG):
                debug_url = f'{self.action.lower()}://{self.host}:{self.port}{self.http_path}'
                logger.debug(f'{logfile}: {self.http_method}-ing to {debug_url}: {subject}')

            http_params = self.http_params
            if http_params is None:
                http_params = DEFAULT_HTTP_PARAMS

            body: Optional[bytes]
            content_type: Optional[str] = None
            http_method = self.http_method
            relative_url = self.http_path

            if http_method == 'GET':
                query = urlencode([
                    (key, value)
                    for key, templ in http_params
                    for value in expand(templ, templ_params)
                ])
                relative_url = f'{relative_url}?{query}'
                body = None
            else:
                http_content_type = self.http_content_type or DEFAULT_HTTP_CONTENT_TYPE
                output_indent = self.output_indent or None
                match http_content_type:
                    case 'URL':
                        body = urlencode([
                            (key, value)
                            for key, templ in http_params
                            for value in expand(templ, templ_params)
                        ]).encode()
                        content_type = 'application/x-www-form-urlencoded'

                    case 'JSON':
                        data = expand_object(http_params, templ_params)
                        body = json.dumps(data, indent=output_indent).encode()
                        content_type = 'application/json; charset=UTF-8'

                    case 'YAML':
                        data = expand_object(http_params, templ_params)
                        body = yaml_dump(data, indent=output_indent).encode()
                        content_type = 'application/x-yaml; charset=UTF-8'

                    case 'multipart':
                        headers, body = encode_multipart([
                            (key, value)
                            for key, templ in http_params
                            for value in expand(templ, templ_params)
                        ])

                    case _:
                        raise ValueError(f'illegal http_content_type: {http_content_type}')

            if self.http_headers:
                headers = dict(self.http_headers)
            else:
                headers = {}

            if content_type:
                headers['Content-Type'] = content_type

            if self.keep_connected:
                headers['Connection'] = 'keep-alive'

            self.refresh_token_if_needed()
            self.connect()

            token = self.oauth2_token
            if token is not None:
                headers['Authorization'] = f"{token.token_type} {token.access_token}"

            elif self.username or self.password:
                credentials = f'{self.username or ''}:{self.password or ''}'.encode()
                headers['Authorization'] = f"Basic {b64encode(credentials).decode('ASCII')}"

            try:
                self.http_connection.request(http_method, relative_url, body, headers)
            except NotConnected:
                self.reconnect()
                self.http_connection.request(http_method, relative_url, body, headers)

            res = self.http_connection.getresponse()
            status = res.status

            # TODO: check for token expiration error and retry?

            scheme = self.action.lower()
            url = urljoin(f'{scheme}://{self.host}:{self.port}/', relative_url)

            if status in HTTP_REDIRECT_STATUSES:
                if http_method != 'GET':
                    raise HTTPException(f'Got {status} {res.reason} for {http_method} request to {url}')

                visited = {url}

                new_headers = dict(self.http_headers) if self.http_headers else {}

                if content_type:
                    new_headers['Content-Type'] = content_type

                redirect_count = 0
                while True:
                    redirect_count += 1
                    if redirect_count > self.http_max_redirect:
                        raise HTTPException(f'Maximum number of redirects ({self.http_max_redirect}) exceeded!')

                    location = res.headers.get('location')

                    if not location:
                        raise HTTPException(f'Redirect {status} {res.reason} is missing a Location header!')

                    new_url = urljoin(url, location)
                    if new_url in visited:
                        raise HTTPException(f'Redirection loop to {new_url} detected!')
                    visited.add(new_url)

                    new_url_obj = urlparse(new_url)
                    new_relative_url = (new_url_obj.path or '/')
                    if new_url_obj.query:
                        new_relative_url = f'{new_relative_url}?{new_url_obj.query}'

                    new_port = new_url_obj.port
                    if new_port is None:
                        if new_url_obj.scheme == 'http':
                            new_port = 80

                        elif new_url_obj.scheme == 'https':
                            new_port = 443

                    if self.keep_connected and new_url_obj.scheme == scheme and new_url_obj.netloc == self.host and new_port == self.port:
                        try:
                            self.http_connection.request(http_method, new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })
                        except NotConnected:
                            self.reconnect()
                            self.http_connection.request(http_method, new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })

                        res = self.http_connection.getresponse()
                    else:
                        conn = HTTPConnection(new_url_obj.netloc, new_port, timeout=self.http_timeout) if new_url_obj.scheme == 'http' else \
                               HTTPSConnection(new_url_obj.netloc, new_port, timeout=self.http_timeout)
                        try:
                            conn.connect()
                            conn.request(http_method, new_relative_url, body, new_headers)
                            res = self.http_connection.getresponse()
                        finally:
                            conn.close()

                    status = res.status
                    url = new_url

                    if status in HTTP_REDIRECT_STATUSES:
                        continue

                    if status < 200 or status >= 300:
                        raise HTTPException(f'HTTP status error: {status} {res.reason}')

            elif status < 200 or status >= 300:
                raise HTTPException(f'[{url}] HTTP status error: {status} {res.reason}\n{res.read(1024).decode(errors='replace')}')

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.http_connection.close()
