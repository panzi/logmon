from typing import Optional, override

import ssl
import errno
import imaplib
import logging

from ..schema import Config, ActionConfig
from .action import make_message
from .ssl_email_sender import SslEmailSender
from ..entry_readers import LogEntry

__all__ = (
    'ImapEmailSender',
)

logger = logging.getLogger(__name__)

class ImapEmailSender(SslEmailSender):
    __slots__ = (
        'imap',
    )

    imap: Optional[imaplib.IMAP4]

    def __init__(self, action_config: ActionConfig, config: Config) -> None:
        super().__init__(action_config, config)

        self.imap = None

    @override
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        imap = self.imap
        if imap is not None:
            imap.__exit__(exc_type, exc_value, traceback)
            self.imap = None

    def connect(self) -> imaplib.IMAP4:
        imap = self.imap

        if imap is not None:
            try:
                imap.shutdown()
            except Exception as exc:
                logger.error(f'Error shutting down existing IMAP connection: {exc}', exc_info=exc)

            self.imap = None

        if self.secure == 'SSL/TLS':
            imap = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=self.ssl_context)
        else:
            imap = imaplib.IMAP4(self.host, self.port)

        self.imap = imap
        imap.open(self.host, self.port)

        if self.secure == 'STARTTLS':
            if self.ssl_context is None:
                self.ssl_context = ssl.create_default_context()
            imap.starttls(ssl_context=self.ssl_context)

        if self.username or self.password:
            imap.login(self.username or '', self.password or '')

        return imap

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return

        try:
            msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
            msg_bytes = msg.as_bytes()

            try:
                imap = self.imap
                if imap is None:
                    imap = self.connect()

                try:
                    imap.send(msg_bytes)
                except OSError as exc:
                    if exc.errno == errno.ECONNRESET or exc.errno == errno.ENOTCONN:
                        imap = self.connect()
                        imap.send(msg_bytes)
                    else:
                        raise
            finally:
                if not self.keep_connected:
                    self.__exit__(None, None, None)

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise
