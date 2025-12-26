from typing import Optional, Self

import json
import logging

from abc import ABC, abstractmethod
from email.message import EmailMessage
from email.policy import SMTP

from ..types import EmailProtocol, Logmails
from ..schema import Config, EMailConfig
from ..constants import *

__all__ = (
    'EmailSender',
)

logger = logging.getLogger(__name__)

def make_message(
        sender: str,
        receivers: list[str],
        templ_params: dict[str, str],
        subject_templ: str,
        body_templ: str,
) -> EmailMessage:
    subject = subject_templ.format_map(templ_params)
    body = body_templ.format_map(templ_params)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(receivers)
    msg.set_content(body)

    return msg

class EmailSender(ABC):
    __slots__ = (
        'subject_templ',
        'body_templ',
        'sender',
        'receivers',
        'logmails',
        'protocol',
    )

    subject_templ: str
    body_templ: str

    sender: str
    receivers: list[str]
    protocol: EmailProtocol

    logmails: Logmails

    @staticmethod
    def from_config(config: Config) -> "EmailSender":
        protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

        match protocol:
            case 'HTTP' | 'HTTPS':
                from .http_email_sender import HttpEmailSender
                return HttpEmailSender(config)

            case 'IMAP':
                from .imap_email_sender import ImapEmailSender
                return ImapEmailSender(config)

            case 'SMTP':
                from .smtp_email_sender import SmtpEmailSender
                return SmtpEmailSender(config)

            case _:
                raise ValueError(f'Illegal protocol: {protocol!r}')

    def __init__(self, config: EMailConfig) -> None:
        self.subject_templ = config.get('subject', DEFAULT_SUBJECT)
        self.body_templ = config.get('body', DEFAULT_BODY)

        self.sender = config['sender']
        self.receivers = config['receivers']
        self.protocol = config.get('protocol', DEFAULT_EMAIL_PROTOCOL)

        self.logmails = config.get('logmails', DEFAULT_LOGMAILS)

    @abstractmethod
    def send_email(self, logfile: str, entries: list[str], brief: str) -> None:
        ...

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        pass

    def handle_error(self, msg: Optional[EmailMessage], templ_params: dict[str, str], exc: Exception) -> None:
        if self.logmails == 'onerror':
            if msg is None:
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
            logger.error('Error while sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))

    def get_templ_params(self, logfile: str, entries: list[str], brief: str) -> dict[str, str]:
        entries_str = '\n\n'.join(entries)
        first_entry = entries[0]
        lines = first_entry.split('\n')
        first_line = lines[0]

        templ_params = {
            'entries': entries_str,
            'entries_json': json.dumps(entries, indent=2),
            'logfile': logfile,
            'brief': brief,
            'line1': first_line,
            'entry1': first_entry,
            'entrynum': str(len(entries)),
            'receivers': ', '.join(self.receivers),
        }

        return templ_params

    def check_logmails(self, logfile: str, templ_params: dict[str, str]) -> tuple[bool, Optional[EmailMessage]]:
        msg: Optional[EmailMessage]
        match self.logmails:
            case 'always':
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
                logger.info(f'{logfile}: Sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))

            case 'instead':
                msg = make_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ)
                logger.info(f'{logfile}: Simulate sending email\n> ' + '\n> '.join(msg.as_string(policy=SMTP).split('\n')))
                return False, None

            case _:
                msg = None

        return True, msg
