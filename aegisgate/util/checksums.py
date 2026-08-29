"""Check-digit validators for the PII patterns that match on shape alone.

The CARD rule matches any 13-16 digit run, so a 15-digit order number or a
timestamp is a card as far as the regex is concerned. Rule ordering decided
which *label* such a value got; it never decided whether the value was really
one. These three functions answer that second question.

They are pure and dependency-free, and they only ever *observe*: the redaction
filter still redacts a value whose checksum fails, and records that it failed.

Separators are stripped before validation because the patterns match them:
``4111 1111 1111 1111`` and ``4111-1111-1111-1111`` are the same number.
"""

from __future__ import annotations

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


VALIDATORS = {
    "luhn": luhn_valid,
    "cn_id": cn_id_valid,
    "iban_mod97": iban_mod97_valid,
}
"""Name -> function. The keys are the only values a rule's ``validator`` may
take; anything else reads as "no validator", so a typo degrades to today's
behaviour rather than to an exception on the request path."""
