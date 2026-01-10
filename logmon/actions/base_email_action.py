from typing import Optional

import ssl

from ..types import SecureOption
from ..schema import Config, ActionConfig
from .remote_action import RemoteAction

__all__ = (
    'BaseEmailAction',
)

class BaseEmailAction(RemoteAction):
    __slots__ = (
        'secure',
        'ssl_context',
    )

    secure: SecureOption
    ssl_context: Optional[ssl.SSLContext]

    def __init__(self, action_config: ActionConfig, config: Config) -> None:
        super().__init__(action_config, config)

        self.secure = secure = action_config.get('secure')
        self.ssl_context = ssl.create_default_context() if secure else None
