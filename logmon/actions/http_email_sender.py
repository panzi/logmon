from typing import Any, Optional, NotRequired, TypedDict, Mapping, override

import re
import uuid
import json
import logging

from http.client import HTTPConnection, HTTPSConnection, NotConnected, HTTPException
from urllib.parse import urlencode, urljoin, urlparse
from base64 import b64encode

from ..types import ContentType
from ..schema import Config
from ..yaml import yaml_dump
from ..constants import *
from .remote_email_sender import RemoteEmailSender
from ..entry_readers import LogEntry

__all__ = (
    'HttpEmailSender',
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

def encode_multipart(fields: Mapping[str, str|MultipartFile]) -> tuple[dict[str, str], bytes]:
    buf: list[bytes] = []
    boundary = uuid.uuid4().hex
    bin_boundary = f'--{boundary}\r\n'.encode()
    headers: dict[str, str] = {
        'Content-Type': f'multipart/form-data; boundary={boundary}'
    }

    for key, value in fields.items():
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

class HttpEmailSender(RemoteEmailSender):
    __slots__ = (
        'http_method',
        'http_path',
        'http_params',
        'http_content_type',
        'http_headers',
        'http_max_redirect',
        'http_connection',
    )
    http_method: str
    http_path: str
    http_params: Optional[dict[str, str]]
    http_content_type: Optional[ContentType]
    http_headers: Optional[dict[str, str]]
    http_max_redirect: int
    http_connection: HTTPConnection

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.http_method = config.get('http_method', 'POST')
        http_path = config.get('http_path', '/')
        if not http_path.startswith('/'):
            http_path = f'/{http_path}'
        self.http_path = http_path
        self.http_params = config.get('http_params')
        self.http_content_type = config.get('http_content_type')
        self.http_headers = config.get('http_headers')
        self.http_max_redirect = config.get('http_max_redirect', DEFAULT_HTTP_MAX_REDIRECT)
        self.http_connection = HTTPConnection(self.host, self.port) if self.action == 'HTTP' else \
                               HTTPSConnection(self.host, self.port)

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return

        try:
            subject = self.subject_templ.format_map(templ_params)

            if logger.isEnabledFor(logging.DEBUG):
                debug_url = f'{self.action.lower()}://{self.host}:{self.port}{self.http_path}'
                logger.debug(f'{logfile}: {self.http_method}-ing to {debug_url}: {subject}')

            http_params = self.http_params
            if http_params is None:
                http_params = DEFAULT_HTTP_PARAMS

            http_params = { **http_params, 'subject': subject }

            # XXX: support JSON entries in JSON body again! using template.expand()?
            data = {
                key: templ.format_map(templ_params)
                for key, templ in http_params.items()
            }

            body: Optional[bytes]
            content_type: Optional[str] = None
            http_method = self.http_method
            relative_url = self.http_path

            if http_method == 'GET':
                query = urlencode(data)
                relative_url = f'{relative_url}?{query}'
                body = None
            else:
                http_content_type = self.http_content_type or DEFAULT_HTTP_CONTENT_TYPE
                output_indent = self.output_indent or None
                match http_content_type:
                    case 'URL':
                        body = urlencode(data).encode()
                        content_type = 'application/x-www-form-urlencoded'

                    case 'JSON':
                        body = json.dumps(data, indent=output_indent).encode()
                        content_type = 'application/json; charset=UTF-8'

                    case 'YAML':
                        body = yaml_dump(data, indent=output_indent).encode()
                        content_type = 'application/x-yaml; charset=UTF-8'

                    case 'multipart':
                        headers, body = encode_multipart(data)

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

            if self.username or self.password:
                credentials = f'{self.username or ''}:{self.password or ''}'.encode()
                headers['Authorization'] = f"Basic {b64encode(credentials).decode('ASCII')}"

            if self.http_connection.sock is None:
                self.http_connection.connect()

            try:
                self.http_connection.request(http_method, relative_url, body, headers)
            except NotConnected:
                self.http_connection.connect()
                self.http_connection.request(http_method, relative_url, body, headers)

            res = self.http_connection.getresponse()
            status = res.status

            if status in HTTP_REDIRECT_STATUSES:
                scheme = self.action.lower()
                url = f'{scheme}://{relative_url}'

                if http_method != 'GET':
                    raise HTTPException(f'Got {status} {res.reason} for {http_method} request to {url}')

                visited = {url}

                if self.http_headers:
                    new_headers = dict(self.http_headers)
                else:
                    new_headers = {}

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
                            self.http_connection.request('GET', new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })
                        except NotConnected:
                            self.http_connection.connect()
                            self.http_connection.request('GET', new_relative_url, body, { **new_headers, 'Connection': 'keep-alive' })

                        res = self.http_connection.getresponse()
                    else:
                        conn = HTTPConnection(new_url_obj.netloc, new_port) if new_url_obj.scheme == 'http' else \
                               HTTPSConnection(new_url_obj.netloc, new_port)
                        try:
                            conn.connect()
                            conn.request('GET', new_relative_url, body, new_headers)
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
                raise HTTPException(f'HTTP status error: {status} {res.reason}')

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.http_connection.close()
