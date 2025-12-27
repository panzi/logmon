from typing import override

import ssl
import smtplib

from ..schema import Config
from .action import make_message
from .ssl_email_sender import SslEmailSender
from ..entry_readers import LogEntry

__all__ = (
    'SmtpEmailSender',
)

class SmtpEmailSender(SslEmailSender):
    __slots__ = (
        'smtp',
    )

    smtp: smtplib.SMTP

    def __init__(self, config: Config) -> None:
        super().__init__(config)

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
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        templ_params = self.get_templ_params(logfile, entries, brief)
        proceed, msg = self.check_logmails(logfile, templ_params)

        if not proceed:
            return

        try:
            if msg is None:
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
            self.handle_error(msg, templ_params, exc)
            raise
