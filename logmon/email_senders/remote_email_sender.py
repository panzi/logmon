from typing import Optional

from ..schema import Config, EMailConfig
from ..constants import *
from .email_sender import EmailSender

__all__ = (
    'get_default_port',
    'RemoteEmailSender',
)

def get_default_port(config: EMailConfig) -> int:
    protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

    match protocol:
        case 'HTTP':
            return 80

        case 'HTTPS':
            return 443

        case 'SMTP':
            match config.get('secure'):
                case 'STARTTLS':
                    return 587

                case 'SSL/TLS':
                    return 465

                case None:
                    return 25

        case 'IMAP':
            match config.get('secure'):
                case 'STARTTLS' | None:
                    return 993

                case 'SSL/TLS':
                    return 143

        case _:
            raise ValueError(f'Illegal protocol: {protocol!r}')

class RemoteEmailSender(EmailSender):
    __slots__ = (
        'host',
        'port',
        'username',
        'password',
        'keep_connected',
    )

    host: str
    port: int
    username: Optional[str]
    password: Optional[str]
    keep_connected: bool

    def __init__(self, config: Config) -> None:
        super().__init__(config)

        port = config.get('port')
        self.host = config.get('host', DEFAULT_EMAIL_HOST)
        self.port = port if port is not None else get_default_port(config)
        self.username = config.get('user')
        self.password = config.get('password')
        self.keep_connected = config.get('keep_connected', False)
