"""A small, dependency-free filter expression language for captured frames.

The language is intentionally narrow: it matches on decoded frame fields using
simple comparisons combined with ``and``, ``or`` and ``not``. It exists so a
caller can say "only DHCP offers from this server" without pulling in libpcap.

Grammar::

    expression  := or_expr
    or_expr     := and_expr ( "or" and_expr )*
    and_expr    := not_expr ( "and" not_expr )*
    not_expr    := [ "not" ] primary
    primary     := "(" expression ")" | comparison
    comparison  := field operator value
    operator    := "==" | "!=" | ">" | ">=" | "<" | "<=" | "~" | "in"
    value       := quoted-string | bare-token | number

Field names are dotted paths into the decoded frame, such as ``ipv4.source_ip``,
``ipv4.tcp.destination_port``, ``protocol``, ``dhcp.message_type_name`` or
``arp.sender_ip``. A dotted path that is present in a list (``vlan_ids``) is
tested against the whole list, so ``vlan_ids == 300`` matches any frame carrying
VLAN 300.
"""

from __future__ import annotations

import re
from typing import Any, Callable

_TOKEN_PATTERN = re.compile(
    r"""
    \s*(?:
        (?P<lparen>\()
      | (?P<rparen>\))
      | (?P<comma>,)
      | (?P<op>==|!=|>=|<=|>|<|~)
      | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
      | (?P<bare_dotted>\d[\w.\-]*)
      | (?P<number>-?\d+)
      | (?P<ident>[A-Za-z_][A-Za-z0-9_.\-]*)
    )
    """,
    re.VERBOSE,
)

_KEYWORDS = {"and", "or", "not", "in"}
_COMPARISON_OPERATORS = {"==", "!=", ">", ">=", "<", "<=", "~"}


class FilterError(ValueError):
    """Raised when a filter expression cannot be parsed or evaluated."""


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(text):
        match = _TOKEN_PATTERN.match(text, position)
        if not match:
            if text[position:].strip() == "":
                break
            raise FilterError(f"unexpected character at offset {position}: {text[position]!r}")
        position = match.end()
        kind = match.lastgroup
        assert kind is not None
        tokens.append((kind, match.group(kind)))
    return tokens


def _unquote(token: str) -> str:
    return token[1:-1].replace('\\"', '"').replace("\\'", "'")


class _Node:
    def evaluate(self, frame: dict) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class _Comparison(_Node):
    def __init__(self, field: str, operator: str, value: Any, is_text: bool):
        self.field = field
        self.operator = operator
        self.value = value
        self.is_text = is_text

    def evaluate(self, frame: dict) -> bool:
        found, actual = _lookup(frame, self.field)
        if not found:
            # A missing field never matches, so a filter cannot be satisfied by
            # a frame that merely lacks the field it mentions.
            return False
        if isinstance(actual, list):
            return any(_compare_value(item, self.operator, self.value, self.is_text) for item in actual)
        return _compare_value(actual, self.operator, self.value, self.is_text)

    def __repr__(self) -> str:
        return f"<{self.field} {self.operator} {self.value!r}>"


class _And(_Node):
    def __init__(self, left: _Node, right: _Node):
        self.left, self.right = left, right

    def evaluate(self, frame: dict) -> bool:
        return self.left.evaluate(frame) and self.right.evaluate(frame)


class _Or(_Node):
    def __init__(self, left: _Node, right: _Node):
        self.left, self.right = left, right

    def evaluate(self, frame: dict) -> bool:
        return self.left.evaluate(frame) or self.right.evaluate(frame)


class _Not(_Node):
    def __init__(self, inner: _Node):
        self.inner = inner

    def evaluate(self, frame: dict) -> bool:
        return not self.inner.evaluate(frame)


class _InList(_Node):
    def __init__(self, field: str, values: list[Any], is_text: bool):
        self.field = field
        self.values = values
        self.is_text = is_text

    def evaluate(self, frame: dict) -> bool:
        found, actual = _lookup(frame, self.field)
        if not found:
            return False
        candidates = actual if isinstance(actual, list) else [actual]
        for candidate in candidates:
            for value in self.values:
                if _compare_value(candidate, "==", value, self.is_text):
                    return True
        return False


def _lookup(frame: dict, path: str) -> tuple[bool, Any]:
    """Resolve a dotted path, tolerating a missing nesting level."""
    current: Any = frame
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return False, None
            current = current[part]
        else:
            return False, None
    return True, current


def _coerce(actual: Any, expected: Any, is_text: bool) -> tuple[Any, Any]:
    """Coerce both sides to a comparable type, or report incomparability."""
    if is_text or isinstance(actual, str):
        return str(actual), str(expected)
    if isinstance(actual, bool):
        return actual, bool(expected)
    if isinstance(actual, (int, float)):
        try:
            return actual, float(expected)
        except (TypeError, ValueError):
            return str(actual), str(expected)
    return str(actual), str(expected)


def _compare_value(actual: Any, operator: str, expected: Any, is_text: bool) -> bool:
    left, right = _coerce(actual, expected, is_text)

    if operator == "~":
        return str(right).lower() in str(left).lower()

    if operator in ("==", "!=") and isinstance(left, float) and not isinstance(actual, bool):
        try:
            equal = left == float(right)
        except (TypeError, ValueError):
            equal = str(left) == str(right)
        return equal if operator == "==" else not equal

    try:
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
    except TypeError:
        return False
    raise FilterError(f"unsupported operator: {operator}")


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.position = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _next(self) -> tuple[str, str]:
        token = self._peek()
        if token is None:
            raise FilterError("unexpected end of filter expression")
        self.position += 1
        return token

    def parse(self) -> _Node:
        node = self._parse_or()
        if self._peek() is not None:
            raise FilterError(f"unexpected trailing token: {self._peek()[1]!r}")
        return node

    def _parse_or(self) -> _Node:
        node = self._parse_and()
        while True:
            token = self._peek()
            if token and token[0] == "ident" and token[1].lower() == "or":
                self._next()
                node = _Or(node, self._parse_and())
            else:
                return node

    def _parse_and(self) -> _Node:
        node = self._parse_not()
        while True:
            token = self._peek()
            if token and token[0] == "ident" and token[1].lower() == "and":
                self._next()
                node = _And(node, self._parse_not())
            else:
                return node

    def _parse_not(self) -> _Node:
        token = self._peek()
        if token and token[0] == "ident" and token[1].lower() == "not":
            self._next()
            return _Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> _Node:
        token = self._next()
        if token[0] == "lparen":
            node = self._parse_or()
            closing = self._next()
            if closing[0] != "rparen":
                raise FilterError("missing closing parenthesis")
            return node
        if token[0] != "ident":
            raise FilterError(f"expected a field name, got {token[1]!r}")

        field = token[1]
        operator_token = self._peek()
        if operator_token and operator_token[0] == "ident" and operator_token[1].lower() == "in":
            self._next()
            return self._parse_in_list(field)

        operator = self._next()
        if operator[0] != "op":
            raise FilterError(f"expected an operator after {field!r}, got {operator[1]!r}")
        value_token = self._next()
        if value_token[0] == "string":
            return _Comparison(field, operator[1], _unquote(value_token[1]), is_text=True)
        if value_token[0] == "bare_dotted":
            # A bare token starting with a digit is an unquoted value such as an
            # IP address, unless it is a plain integer.
            if re.fullmatch(r"-?\d+", value_token[1]):
                return _Comparison(field, operator[1], int(value_token[1]), is_text=False)
            return _Comparison(field, operator[1], value_token[1], is_text=True)
        if value_token[0] == "number":
            return _Comparison(field, operator[1], int(value_token[1]), is_text=False)
        if value_token[0] == "ident":
            return _Comparison(field, operator[1], value_token[1], is_text=True)
        raise FilterError(f"expected a value after {field!r} {operator[1]!r}")

    def _parse_in_list(self, field: str) -> _Node:
        opening = self._next()
        if opening[0] != "lparen":
            raise FilterError("expected '(' after 'in'")
        values: list[Any] = []
        is_text = False
        while True:
            token = self._next()
            if token[0] == "rparen":
                break
            if token[0] == "comma":
                # A trailing comma before ')' is tolerated.
                following = self._peek()
                if following is not None and following[0] == "rparen":
                    continue
                if not values:
                    raise FilterError("unexpected ',' at the start of a value list")
                continue
            if token[0] == "string":
                values.append(_unquote(token[1]))
                is_text = True
            elif token[0] == "bare_dotted":
                if re.fullmatch(r"-?\d+", token[1]):
                    values.append(int(token[1]))
                else:
                    values.append(token[1])
                    is_text = True
            elif token[0] == "number":
                values.append(int(token[1]))
            elif token[0] == "ident":
                values.append(token[1])
                is_text = True
            else:
                raise FilterError(f"unexpected token in value list: {token[1]!r}")
        if not values:
            raise FilterError("'in' requires at least one value")
        return _InList(field, values, is_text)


def compile_filter(expression: str | None) -> Callable[[dict], bool] | None:
    """Compile a filter expression into a predicate over decoded frames.

    Returns ``None`` for an empty expression, meaning "match everything".
    """
    if expression is None:
        return None
    if not isinstance(expression, str):
        raise FilterError("filter must be a string")
    if len(expression) > 4096:
        raise FilterError('filter exceeds 4096 characters')
    if not expression.strip():
        return None
    tokens = _tokenize(expression)
    # This also bounds recursive parse and evaluation depth, including long
    # Boolean chains and unary not/parenthesis nesting.
    if len(tokens) > 128:
        raise FilterError('filter exceeds 128 tokens')
    try:
        return _Parser(tokens).parse().evaluate
    except RecursionError as error:
        raise FilterError('filter nesting is too deep') from error


def frame_matches(expression: str, frame: dict) -> bool:
    """Convenience wrapper that compiles and applies a filter to one frame."""
    predicate = compile_filter(expression)
    if predicate is None:
        return True
    return predicate(frame)


# Filtering operates on the *decoded* frame, so the decoded dictionary is what
# callers pass in. This alias documents that contract for tool implementations.
FilteredFrame = dict
