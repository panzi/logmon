from typing import Literal

__all__ = (
    'SecureOption',
    'ActionType',
    'Logmails',
    'ContentType',
    'OutputFormat',
    'JsonPath',
    'SystemDPriority',
    'OAuth2GrantType',
    'FileType',
)

type SecureOption = Literal[None, 'STARTTLS', 'SSL/TLS']
type ActionType = Literal['SMTP', 'IMAP', 'HTTP', 'HTTPS', 'COMMAND', 'FILE']
type Logmails = Literal['always', 'never', 'onerror', 'instead']
type ContentType = Literal['JSON', 'YAML', 'URL', 'multipart']
type OutputFormat = Literal['JSON', 'YAML']
type JsonPath = list[str|int]

type SystemDPriority = Literal[
    'PANIC', 'WARNING', 'ALERT', 'NONE', 'CRITICAL',
    'DEBUG', 'INFO', 'ERROR', 'NOTICE',
]

type OAuth2GrantType = Literal['client_credentials', 'password']

type FileType = Literal['regular', 'fifo']
