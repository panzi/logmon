from typing import Literal

__all__ = (
    'SecureOption',
    'EmailProtocol',
    'Logmails',
    'ContentType',
    'OutputFormat',
    'JsonPath',
    'SystemDPriority',
)

type SecureOption = Literal[None, 'STARTTLS', 'SSL/TLS']
type EmailProtocol = Literal['SMTP', 'IMAP', 'HTTP', 'HTTPS']
type Logmails = Literal['always', 'never', 'onerror', 'instead']
type ContentType = Literal['JSON', 'YAML', 'URL', 'multipart']
type OutputFormat = Literal['JSON', 'YAML']
type JsonPath = list[str|int]

type SystemDPriority = Literal[
    'PANIC', 'WARNING', 'ALERT', 'NONE', 'CRITICAL',
    'DEBUG', 'INFO', 'ERROR', 'NOTICE',
]
