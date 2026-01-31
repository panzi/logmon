from typing import TypedDict, Self, Any, NotRequired, Optional, Generator, Mapping

import logging

from abc import ABC, abstractmethod
from email.message import EmailMessage
from contextlib import contextmanager

from ..types import ActionType, Logmails, OutputFormat
from ..schema import Config, ActionConfig
from ..entry_readers import LogEntry
from ..limiter import AbstractLimiter, resolve_limiter
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
        'limiter',
        'subject_templ',
        'body_templ',
        'sender',
        'receivers',
        'logmails',
        'action',
        'output_format',
        'output_indent',
        'line_prefix',
    )

    limiter: AbstractLimiter

    subject_templ: str
    body_templ: str

    sender: str
    receivers: list[str]
    action: ActionType

    logmails: Logmails
    output_indent: Optional[int]
    output_format: OutputFormat
    line_prefix: str

    @staticmethod
    def from_config(action_config: ActionConfig, config: Config, limiters: Mapping[str, AbstractLimiter]) -> "Action":
        action = action_config.get('action', DEFAULT_ACTION)

        limiter = resolve_limiter(limiters, action_config, config)

        match action:
            case 'HTTP' | 'HTTPS':
                from .http_action import HttpAction
                return HttpAction(action_config, config, limiter)

            case 'IMAP':
                from .imap_email_action import ImapEmailAction
                return ImapEmailAction(action_config, config, limiter)

            case 'SMTP':
                from .smtp_email_action import SmtpEmailAction
                return SmtpEmailAction(action_config, config, limiter)

            case 'COMMAND':
                from .command_action import CommandAction
                return CommandAction(action_config, config, limiter)

            case 'FILE':
                from .file_action import FileAction
                return FileAction(action_config, config, limiter)

            case _:
                raise ValueError(f'Illegal action: {action!r}')

    @contextmanager
    @staticmethod
    def open_actions(config: Config, limiters: Mapping[str, AbstractLimiter]) -> Generator[list["Action"], None, None]:
        actions: list["Action"] = []

        for action_config in config['do']:
            try:
                action = Action.from_config(action_config, config, limiters)
                action = action.__enter__()
                actions.append(action)
            except Exception as exc:
                for action in reversed(actions):
                    try:
                        action.__exit__(type(exc), exc, exc.__traceback__)
                    except Exception as nested_exc:
                        logger.error(f'Error calling action.__exit__() during error handling: {nested_exc}', exc_info=nested_exc)
                raise

        try:
            yield actions
        finally:
            excs: list[Exception] = []

            for action in reversed(actions):
                try:
                    action.__exit__(None, None, None)
                except Exception as exc:
                    logger.error(f'Error calling action.__exit__(): {exc}', exc_info=exc)
                    excs.append(exc)

            if len(excs) == 1:
                raise excs[0]
            elif excs:
                raise ExceptionGroup('Multiple errors during action cleanup', excs)

    def __init__(self, action_config: ActionConfig, config: Config, limiter: AbstractLimiter) -> None:
        self.limiter = limiter
        self.subject_templ = action_config.get('subject', DEFAULT_SUBJECT)
        self.body_templ = action_config.get('body', DEFAULT_BODY)

        sender = action_config.get('sender')
        if not sender:
            host = action_config.get('host', DEFAULT_EMAIL_HOST)
            sender = f'{DEFAULT_EMAIL_SENDER}@{host}'

        self.sender = sender
        self.receivers = action_config.get('receivers') or [sender]
        self.action = action_config.get('action', DEFAULT_ACTION)

        self.logmails = action_config.get('logmails', DEFAULT_LOGMAILS)
        self.output_format = action_config.get('output_format', DEFAULT_OUTPUT_FORMAT)
        self.output_indent = action_config.get('output_indent', DEFAULT_OUTPUT_INDENT)
        self.line_prefix = '> '

    @abstractmethod
    def perform_action(self, logfile: str, entries: list[LogEntry], brief: str) -> bool:
        """
        Returns `False` if the action was rate limited.
        """
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
        output_format = self.output_format
        output_indent = self.output_indent
        formatted = [entry.format(output_format, output_indent) for entry in entries]
        entries_str = '\n\n'.join(formatted)
        first_entry = formatted[0]
        first_line = first_entry.split('\n', 1)[0]

        templ_params: TemplParams = {
            'entries': formatted,
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
