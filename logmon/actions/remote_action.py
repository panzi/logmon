from typing import Optional

from ..schema import Config, ActionConfig
from ..constants import *
from .action import Action

__all__ = (
    'get_default_port',
    'RemoteAction',
)

def get_default_port(action_config: ActionConfig) -> int:
    action = action_config.get('action', DEFAULT_ACTION)

    match action:
        case 'HTTP':
            return 80

        case 'HTTPS':
            return 443

        case 'SMTP':
            match action_config.get('secure'):
                case 'STARTTLS':
                    return 587

                case 'SSL/TLS':
                    return 465

                case None:
                    return 25

        case 'IMAP':
            match action_config.get('secure'):
                case 'STARTTLS' | None:
                    return 993

                case 'SSL/TLS':
                    return 143

        case _:
            raise ValueError(f'Illegal action: {action!r}')

class RemoteAction(Action):
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

    def __init__(self, action_config: ActionConfig, config: Config) -> None:
        super().__init__(action_config, config)

        port = action_config.get('port')
        self.host = action_config.get('host', DEFAULT_EMAIL_HOST)
        self.port = port if port is not None else get_default_port(action_config)
        self.username = action_config.get('user')
        self.password = action_config.get('password')
        self.keep_connected = action_config.get('keep_connected', False)
