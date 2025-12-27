from typing import Optional

import ssl

from ..types import SecureOption
from ..schema import Config
from .remote_email_sender import RemoteEmailSender

__all__ = (
    'SslEmailSender',
)

class SslEmailSender(RemoteEmailSender):
    __slots__ = (
        'secure',
        'ssl_context',
    )

    secure: SecureOption
    ssl_context: Optional[ssl.SSLContext]

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        self.secure = secure = config.get('secure')
        self.ssl_context = ssl.create_default_context() if secure else None
