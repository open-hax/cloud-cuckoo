# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact test contracts for deliberately exercised Python logging records.

Capture changes neither logger levels nor filters. Every record remains in
pytest's standard caplog capture; the evidence observer independently retains
all warning/error observations. An acknowledgement follows a complete match.
"""
import inspect
import logging
import sys


class DiagnosticContractError(RuntimeError):
    """A diagnostic mismatch is infrastructure/runtime evidence, never a kill."""


def exception_snapshot(error, seen=None):
    """Freeze primitive exception contents without formatting lazy arguments."""
    if error is None:
        return None
    if not isinstance(error, BaseException):
        return {'opaque': True}
    renderer = inspect.getattr_static(type(error), '__str__')
    native_state = {}
    if isinstance(error, BaseExceptionGroup):
        if type(error) not in (BaseExceptionGroup, ExceptionGroup) or renderer is not BaseExceptionGroup.__str__:
            return {'opaque': True}
    elif renderer is OSError.__str__:
        native_state = {name: getattr(OSError, name).__get__(error)
                        for name in ('errno', 'strerror', 'filename', 'filename2')}
        if not all(type(value) in (str, int, float, bool, type(None)) for value in native_state.values()):
            return {'opaque': True}
    elif renderer is not BaseException.__str__:
        # A custom __str__ may read mutable state outside primitive args.
        # It cannot be frozen safely without running arbitrary rendering code.
        return {'opaque': True}
    seen = {} if seen is None else seen
    if id(error) in seen:
        return {'reference': seen[id(error)]}
    seen[id(error)] = len(seen)
    arguments = BaseException.args.__get__(error)
    children = []
    if isinstance(error, BaseExceptionGroup):
        arguments = (BaseExceptionGroup.message.__get__(error),)
        children = [exception_snapshot(child, seen)
                    for child in BaseExceptionGroup.exceptions.__get__(error)]
    if not all(type(value) in (str, int, float, bool, type(None)) for value in arguments):
        return {'opaque': True}
    return {'index': seen[id(error)], 'type': type(error).__module__ + '.' + type(error).__qualname__,
        'arguments': list(arguments),
        'suppress_context': BaseException.__suppress_context__.__get__(error),
        'cause': exception_snapshot(BaseException.__cause__.__get__(error), seen),
        'context': exception_snapshot(BaseException.__context__.__get__(error), seen),
        'children': children, 'native_state': native_state}


def snapshot_is_exact(value):
    if isinstance(value, dict):
        return value.get('opaque') is not True and all(snapshot_is_exact(child) for child in value.values())
    if isinstance(value, list):
        return all(snapshot_is_exact(child) for child in value)
    return True


def exception_chain(error, seen=None):
    """Describe exact exception types, messages, chaining and grouped children."""
    if error is None:
        return None
    seen = {} if seen is None else seen
    if id(error) in seen:
        return {'reference': seen[id(error)]}
    seen[id(error)] = len(seen)
    return {'index': seen[id(error)], 'type': type(error).__module__ + '.' + type(error).__qualname__,
            'message': str(error), 'suppress_context': BaseException.__suppress_context__.__get__(error),
            'cause': exception_chain(BaseException.__cause__.__get__(error), seen),
            'context': exception_chain(BaseException.__context__.__get__(error), seen),
            'children': [exception_chain(child, seen) for child in BaseExceptionGroup.exceptions.__get__(error)]
                        if isinstance(error, BaseExceptionGroup) else []}


def describe_record(record):
    """Render only a record explicitly presented to a test-side contract."""
    return {'logger': record.name, 'level': record.levelno,
            'message': record.getMessage(),
            'exception': exception_chain(record.exc_info[1] if record.exc_info else None)}


class capture_expected_logs:
    """Route named logger trees into standard caplog, retaining every record."""
    def __init__(self, caplog, *logger_names):
        if not logger_names or not all(isinstance(name, str) and name for name in logger_names):
            raise DiagnosticContractError('Explicit logger names are required')
        self.caplog, self.names = caplog, logger_names
        self.accepted = set()

    def __enter__(self):
        self.before = {id(record) for record in self._records()}
        self.saved = []
        for name in self.names:
            logger = logging.getLogger(name)
            self.saved.append((logger, logger.handlers[:], logger.propagate, logger.level, logger.filters[:]))
            logger.handlers = [self.caplog.handler]
            logger.propagate = False
        return self

    def _records(self):
        records = []
        seen = set()
        for phase in ('setup', 'call', 'teardown'):
            for record in self.caplog.get_records(phase):
                if id(record) not in seen:
                    records.append(record)
                    seen.add(id(record))
        for record in self.caplog.records:
            if id(record) not in seen:
                records.append(record)
                seen.add(id(record))
        return records

    def expect(self, *, logger, level, message, exception=None):
        """Acknowledge one exact occurrence only after its full contract passes."""
        contract = {'logger': logger, 'level': level, 'message': message,
                    'exception': exception_chain(exception)}
        if not isinstance(logger, str) or type(level) is not int or not isinstance(message, str):
            raise DiagnosticContractError('Exact diagnostic fields are required')
        matches = [record for record in self._records()
                   if id(record) not in self.before and id(record) not in self.accepted
                   and describe_record(record) == contract]
        if not matches:
            raise DiagnosticContractError('Expected exact diagnostic was not observed')
        record = matches[0]
        observer = sys.modules.get('pytest_evidence')
        if observer is not None and getattr(observer, '_STATE', None) is not None:
            frame = inspect.currentframe().f_back
            try:
                observer.acknowledge_expected(record, contract, (frame.f_code.co_filename, frame.f_lineno))
            finally:
                del frame
        self.accepted.add(id(record))
        return record

    def __exit__(self, error_type, error, traceback):
        remaining = [record for record in self._records()
                     if id(record) not in self.before and record.levelno >= logging.WARNING
                     and id(record) not in self.accepted]
        for logger, handlers, propagate, level, filters in reversed(self.saved):
            unchanged = logger.level == level and logger.filters == filters
            logger.handlers, logger.propagate = handlers, propagate
            if not unchanged and error_type is None:
                raise DiagnosticContractError('Capture changed logger severity or filters')
        if remaining and error_type is None:
            raise DiagnosticContractError('Unconsumed warning/error diagnostic')
        return False
