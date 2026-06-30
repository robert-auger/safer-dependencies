"""Go module proxy URL helpers.

The Go module proxy protocol (https://go.dev/ref/mod#goproxy-protocol)
case-encodes module paths to avoid ambiguity on case-insensitive file
systems: every uppercase letter is replaced with ``!`` followed by the
corresponding lowercase letter. So a request for
``github.com/Masterminds/squirrel`` must be sent as
``github.com/!masterminds/squirrel`` — the literal-uppercase form returns
404 from ``proxy.golang.org``.

Shipping the literal form (the historical behavior of this codebase)
caused widely-used real packages — ``Masterminds/squirrel``,
``IBM/sarama``, ``AlecAivazis/survey/v2``, ``BurntSushi/toml``,
``PuerkitoBio/goquery`` — to fall through every check that depends on the
proxy: existence, version listing, staleness. The existence check then
emits ``UNKNOWN: ... possible typo or fabricated name`` for legitimate
dependencies, training users to ignore the signal.

This module centralizes the encoding so all proxy URL builders use it.
"""
from __future__ import annotations


def encode_module_path(module: str) -> str:
    """Apply Go module proxy case-encoding to ``module``.

    Replaces every uppercase ASCII letter with ``!`` + its lowercase
    counterpart. Lowercase, digits, and other characters (``.``, ``/``,
    ``-``, ``_``, ``~``) pass through unchanged.

    Examples:
      >>> encode_module_path("github.com/Masterminds/squirrel")
      'github.com/!masterminds/squirrel'
      >>> encode_module_path("github.com/IBM/sarama")
      'github.com/!i!b!m/sarama'
      >>> encode_module_path("github.com/gin-gonic/gin")
      'github.com/gin-gonic/gin'
      >>> encode_module_path("")
      ''

    The empty-string case returns ``""`` unchanged so callers don't need
    a separate guard. Non-string inputs raise the natural ``AttributeError``
    from ``str.isupper`` rather than being silently coerced.
    """
    out = []
    for ch in module:
        if "A" <= ch <= "Z":
            out.append("!")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)
