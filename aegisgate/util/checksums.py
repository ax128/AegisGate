"""Check-digit validators for the PII patterns that match on shape alone.

The CARD rule matches any 13-16 digit run, so a 15-digit order number or a
timestamp is a card as far as the regex is concerned. These functions answer
whether the value is really one.

``luhn`` is a gate (:data:`ENFORCED_VALIDATORS`): a value it rejects is not
labeled and not redacted. The other functions stay observational — the caller
still redacts and records the failure. All three pattern compile sites have to
honour that split; a gate that lived in only one of them would keep labeling
the same digits on the other two.

Separators are stripped before validation because the patterns match them:
``4111 1111 1111 1111`` and ``4111-1111-1111-1111`` are the same number.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from aegisgate.util.rule_regex import RulePattern

_SEPARATORS = str.maketrans("", "", "- ")

# GB11643-1999 uses ISO 7064 MOD 11-2: weights are 2^(n-1) mod 11 over the 17
# body digits, and the check character is indexed out of this table.
_CN_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_CN_ID_CHECK_CHARS = "10X98765432"


def _normalise(value: str) -> str:
    """Separators removed; anything with a non-ASCII character rejected outright.

    ``\\d`` in Python's ``re`` matches every Unicode decimal digit, so a rule
    that matches on shape alone can hand these functions e.g. Arabic-Indic
    digits. ``str.isdigit`` says yes to those while ``ord(char) - 48`` computes
    nonsense from them — the value would still be redacted either way, but the
    failure count this whole change exists to produce would be wrong rather than
    merely conservative. Returning "" makes every caller's length check reject
    it, which is the same "cannot be validated" answer as a malformed value.
    """
    stripped = value.translate(_SEPARATORS)
    return stripped if stripped.isascii() else ""


def luhn_valid(value: str) -> bool:
    """Luhn (ISO/IEC 7812-1) check digit, as used by payment cards."""
    digits = _normalise(value)
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    # Right to left: every second digit is doubled, and a doubled value over 9
    # has its digits summed (equivalently, 9 subtracted).
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def cn_id_valid(value: str) -> bool:
    """GB11643-1999 (18-digit) mainland China resident ID check character.

    The 15-digit pre-1999 form carries no check digit, so it cannot be
    validated and returns False — the caller treats that as "redact and record
    a failure", never as "do not redact".
    """
    body = _normalise(value).upper()
    if len(body) != 18 or not body[:17].isdigit():
        return False
    total = sum(
        (ord(char) - 48) * weight for char, weight in zip(body[:17], _CN_ID_WEIGHTS)
    )
    return body[17] == _CN_ID_CHECK_CHARS[total % 11]


def iban_mod97_valid(value: str) -> bool:
    """ISO 13616 IBAN: move the first four characters to the end, map letters to
    two-digit numbers (A=10 ... Z=35), and check the result is 1 mod 97."""
    account = _normalise(value).upper()
    if len(account) < 5 or not account[:2].isalpha() or not account[2:4].isdigit():
        return False
    if not account.isalnum():
        return False
    rearranged = account[4:] + account[:4]
    digits: list[str] = []
    for char in rearranged:
        digits.append(str(ord(char) - 55) if char.isalpha() else char)
    try:
        return int("".join(digits)) % 97 == 1
    except ValueError:  # pragma: no cover - isalnum already excludes this
        return False


def de_vat_valid(value: str) -> bool:
    """ISO 7064 MOD 11,10 over the 9 digits of a German VAT identifier.

    The last digit is the check digit. Prefix ``DE`` (and spaces) are stripped
    so the function accepts both the regex hit and a bare 9-digit body.
    """
    body = _normalise(value).upper()
    if body.startswith("DE"):
        body = body[2:]
    if len(body) != 9 or not body.isdigit():
        return False
    p = 10
    for char in body[:8]:
        s = (ord(char) - 48 + p) % 10
        if s == 0:
            s = 10
        p = (2 * s) % 11
    remainder = 11 - p
    if remainder == 10:
        remainder = 0
    return remainder == (ord(body[8]) - 48)


_AT_SV_NR_WEIGHTS = (3, 7, 9, 0, 5, 8, 4, 2, 1, 6)


def at_sv_nr_valid(value: str) -> bool:
    """Austrian SV-Nummer: 10 digits ``LLLP TTMMJJ``, modulo 11.

    Weights ``3,7,9,0,5,8,4,2,1,6`` (the 0 sits on the check-digit position).
    The sum modulo 11 must equal the fourth digit. Remainder 10 is never
    issued. The first digit must be 1–9.
    """
    digits = _normalise(value)
    if len(digits) != 10 or not digits.isdigit() or digits[0] == "0":
        return False
    total = sum(
        (ord(char) - 48) * weight for char, weight in zip(digits, _AT_SV_NR_WEIGHTS)
    )
    remainder = total % 11
    if remainder == 10:
        return False
    return remainder == (ord(digits[3]) - 48)


VALIDATORS = {
    "luhn": luhn_valid,
    "cn_id": cn_id_valid,
    "iban_mod97": iban_mod97_valid,
    "de_vat": de_vat_valid,
    "at_sv_nr": at_sv_nr_valid,
}
"""Name -> function. The keys are the only values a rule's ``validator`` may
take; anything else reads as "no validator", so a typo degrades to today's
behaviour rather than to an exception on the request path."""

# A failing luhn means "not a card". The others mean "redact it anyway and
# remember that the check digit disagreed" — a bad CN_ID is still ID-shaped.
ENFORCED_VALIDATORS = frozenset({"luhn"})


def enforced_validator_rejects(validator_name: str | None, value: str) -> bool:
    """True when this match must be left in place instead of labeled."""
    if not validator_name or validator_name not in ENFORCED_VALIDATORS:
        return False
    check = VALIDATORS.get(validator_name)
    return check is not None and not check(value)


def pattern_keeps_a_match(
    pattern: RulePattern,
    validator_name: str | None,
    haystacks: Sequence[str],
) -> bool:
    """True when some haystack match would still be labeled.

    Observational validators, and rules with no validator, keep the old
    "any hit" answer. An enforced validator that rejects every hit does not
    count: otherwise a digit run Luhn already refused on the raw text would
    be redacted again as a whole leaf once the normalized copy is searched.
    """
    if validator_name not in ENFORCED_VALIDATORS:
        return any(pattern.search(hay) for hay in haystacks)
    for hay in haystacks:
        for match in pattern.finditer(hay):
            if not enforced_validator_rejects(validator_name, match.group(0)):
                return True
    return False
