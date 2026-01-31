from typing import override

import ssl
import smtplib

from .action import make_message
from .base_email_action import BaseEmailAction
from ..schema import Config, ActionConfig
from ..entry_readers import LogEntry
from ..limiter import AbstractLimiter

__all__ = (
    'SmtpEmailAction',
)

class SmtpEmailAction(BaseEmailAction):
    __slots__ = (
        'smtp',
    )

    smtp: smtplib.SMTP

    def __init__(self, action_config: ActionConfig, config: Config, limiter: AbstractLimiter) -> None:
        super().__init__(action_config, config, limiter)

        if self.secure == 'SSL/TLS':
            self.smtp = smtplib.SMTP_SSL()
        else:
            self.smtp = smtplib.SMTP()

    @override
    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.smtp.sock is not None:
            self.smtp.__exit__(exc_type, exc_value, traceback)

    def connect(self) -> None:
        self.smtp.connect(self.host, self.port)

        if self.secure == 'STARTTLS':
            if self.ssl_context is None:
                self.ssl_context = ssl.create_default_context()
            self.smtp.starttls(context=self.ssl_context)

        if self.username or self.password:
            self.smtp.login(self.username or '', self.password or '')

    @override
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> bool:
        if not self.limiter.check():
            return False

        templ_params = self.get_templ_params(logfile, entries, brief)
        if not self.check_logmails(logfile, templ_params):
            return True

        try:
            msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)

            try:
                if self.smtp.sock is None:
                    self.connect()

                try:
                    self.smtp.send_message(msg)
                except smtplib.SMTPServerDisconnected:
                    self.connect()
                    self.smtp.send_message(msg)
            finally:
                if not self.keep_connected:
                    self.__exit__(None, None, None)

        except Exception as exc:
            self.handle_error(templ_params, exc)
            raise

        return True
