from typing import TypedDict, Self, Any, NotRequired, Optional

import logging

from abc import ABC, abstractmethod
from email.message import EmailMessage

from ..types import ActionType, Logmails
from ..schema import Config
from ..entry_readers import LogEntry
from ..constants import *

__all__ = (
    'Action',
)

logger = logging.getLogger(__name__)

class TemplParams(TypedDict):
    entries: list[str]
    entries_str: str
    entries_raw: list[Any]
    logfile: str
    brief: str
    line1: str
    entry1: str
    entrynum: str
    sender: str
    receivers: str
    receiver_list: list[str]
    nl: str
    subject: NotRequired[str]

def make_message(
        sender: str,
        receivers: list[str],
        templ_params: TemplParams,
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

def debug_message(
        sender: str,
        receivers: list[str],
        templ_params: TemplParams,
        subject_templ: str,
        body_templ: str,
        line_prefix: str = '',
) -> str:
    subject = subject_templ.format_map(templ_params)
    body = body_templ.format_map(templ_params)

    prefixed_body = body.replace('\n', f'\n{line_prefix}') if line_prefix else body

    return f'''\
{line_prefix}Subject: {subject}
{line_prefix}From: {sender}
{line_prefix}To: {", ".join(receivers)}
{line_prefix}
{line_prefix}{prefixed_body}'''

class Action(ABC):
    __slots__ = (
        'subject_templ',
        'body_templ',
        'sender',
        'receivers',
        'logmails',
        'action',
        'output_indent',
        'line_prefix',
    )

    subject_templ: str
    body_templ: str

    sender: str
    receivers: list[str]
    action: ActionType

    logmails: Logmails
    output_indent: Optional[int]
    line_prefix: str

    @staticmethod
    def from_config(config: Config) -> "Action":
        action = config.get('action', DEFAULT_ACTION)

        match action:
            case 'HTTP' | 'HTTPS':
                from .http_action import HttpAction
                return HttpAction(config)

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
        self.line_prefix = '> '

    @abstractmethod
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> None:
        ...

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        pass

    def handle_error(self, templ_params: TemplParams, exc: Exception) -> None:
        if self.logmails == 'onerror':
            msg_str = debug_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ, line_prefix=self.line_prefix)
            logger.error(f'Error while sending email: {exc}\n{msg_str}')

    def get_templ_params(self, logfile: str, entries: list[LogEntry], brief: str) -> TemplParams:
        entries_str = '\n\n'.join(entry.formatted for entry in entries)
        first_entry = entries[0].formatted
        first_line = first_entry.split('\n', 1)[0]

        templ_params: TemplParams = {
            'entries': [entry.formatted for entry in entries],
            'entries_str': entries_str,
            'entries_raw': [entry.data for entry in entries],
            'logfile': logfile,
            'brief': brief,
            'line1': first_line,
            'entry1': first_entry,
            'entrynum': str(len(entries)),
            'sender': self.sender,
            'receivers': ', '.join(self.receivers),
            'receiver_list': self.receivers,
            'nl': '\n',
        }

        return templ_params

    def check_logmails(self, logfile: str, templ_params: TemplParams) -> bool:
        match self.logmails:
            case 'always':
                msg = debug_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ, line_prefix=self.line_prefix)
                logger.info(f'{logfile}: Sending email\n{msg}')

            case 'instead':
                msg = debug_message(self.sender, self.receivers, templ_params, self.subject_templ, self.body_templ, line_prefix=self.line_prefix)
                logger.info(f'{logfile}: Simulate sending email\n{msg}')
                return False

        return True
