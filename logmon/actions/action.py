from typing import Optional, Self

import json
import logging

from abc import ABC, abstractmethod
from email.message import EmailMessage
from email.policy import SMTP

from ..types import ActionType, Logmails
from ..schema import Config
from ..entry_readers import LogEntry
from ..constants import *

__all__ = (
    'Action',
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

class Action(ABC):
    __slots__ = (
        'subject_templ',
        'body_templ',
        'sender',
        'receivers',
        'logmails',
        'action',
        'output_indent',
    )

    subject_templ: str
    body_templ: str

    sender: str
    receivers: list[str]
    action: ActionType

    logmails: Logmails
    output_indent: int

    @staticmethod
    def from_config(config: Config) -> "Action":
        action = config.get('action', DEFAULT_ACTION)

        match action:
            case 'HTTP' | 'HTTPS':
                from .http_email_sender import HttpEmailSender
                return HttpEmailSender(config)

            case 'IMAP':
                from .imap_email_sender import ImapEmailSender
                return ImapEmailSender(config)

            case 'SMTP':
                from .smtp_email_sender import SmtpEmailSender
                return SmtpEmailSender(config)

            case 'COMMAND':
                from .command_action import CommandAction
                return CommandAction(config)

            case _:
                raise ValueError(f'Illegal action: {action!r}')

    def __init__(self, config: Config) -> None:
        self.subject_templ = config.get('subject', DEFAULT_SUBJECT)
        self.body_templ = config.get('body', DEFAULT_BODY)

        sender = config.get('sender')
        if not sender:
            host = config.get('host', DEFAULT_EMAIL_HOST)
            sender = f'{DEFAULT_EMAIL_SENDER}@{host}'

        self.sender = sender
        self.receivers = config.get('receivers') or [sender]
        self.action = config.get('action', DEFAULT_ACTION)

        self.logmails = config.get('logmails', DEFAULT_LOGMAILS)
        self.output_indent = config.get('output_indent', DEFAULT_OUTPUT_INDENT)

    @abstractmethod
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
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

    def get_templ_params(self, logfile: str, entries: list[LogEntry], brief: str) -> dict[str, str]:
        entries_str = '\n\n'.join(entry.formatted for entry in entries)
        first_entry = entries[0].formatted
        lines = first_entry.split('\n')
        first_line = lines[0]

        templ_params = {
            'entries': entries_str,
            'entries_json': json.dumps([entry.data for entry in entries], indent=self.output_indent or None),
            'logfile': logfile,
            'brief': brief,
            'line1': first_line,
            'entry1': first_entry,
            'entrynum': str(len(entries)),
            'sender': self.sender,
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
