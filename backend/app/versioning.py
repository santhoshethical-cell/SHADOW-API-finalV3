"""Deterministic, scheme-aware version parsing and comparison.

Version strings are NEVER compared lexicographically. Every product in the
component catalog declares the scheme its upstream project uses, and both the
observed version and every affected-range boundary are parsed with that scheme
before comparison. Anything that cannot be parsed confidently raises
``VersionParseError`` so callers report "unknown" instead of guessing.

Schemes
-------
``semver``   SemVer 2.0 precedence (npm libraries: jQuery, React, Angular…).
             ``1.2`` is accepted and padded to ``1.2.0``. Pre-release
             identifiers follow SemVer rules (``3.5.0-beta.1 < 3.5.0``).
``dotted``   Arbitrary-length numeric releases (nginx 1.20.1, PHP 8.1.2,
             IIS 10.0). Shorter releases are zero-padded for comparison.
``openssl``  Legacy OpenSSL letter releases (``1.1.1k``): the trailing
             letter run orders after the numeric release (``1.1.1`` <
             ``1.1.1a`` < ``1.1.1za``). OpenSSL 3.x is plain dotted.

Vendor / distribution suffixes (``1.18.0-6ubuntu14``, ``2.4.6+deb10u2``,
``8.0.30-el8``) are separated into ``vendor_suffix``. They do NOT take part in
ordering because a distribution may back-port fixes without changing the
upstream number; callers must treat such versions as uncertain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

SCHEMES = ("semver", "dotted", "openssl")


class VersionParseError(ValueError):
    """The version string cannot be interpreted under the requested scheme."""


# Pre-release labels recognised across schemes, in ascending precedence for the
# dotted scheme (semver uses its own identifier rules).
_PRE_LABELS = ("dev", "a", "alpha", "b", "beta", "pre", "preview", "next", "rc")
_PRE_LABEL_RANK = {
    "dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "pre": 3,
    "preview": 3, "next": 3, "rc": 4,
}
# Markers that indicate a distribution/vendor build rather than upstream.
_VENDOR_MARKERS = re.compile(
    r"(ubuntu|debian|deb\d|\bdeb\b|el\d|rhel|centos|fc\d|fedora|suse|sles|"
    r"amzn|alpine|bionic|focal|jammy|noble|bookworm|bullseye|buster|"
    r"redhat|oracle|win|custom|patched|p\d+$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ParsedVersion:
    raw: str
    scheme: str
    release: tuple[int, ...]
    prerelease: tuple = ()           # () means a final release
    letter: str = ""                 # openssl letter suffix
    vendor_suffix: Optional[str] = None
    build: str = ""                  # semver build metadata (ignored in order)
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    @property
    def has_vendor_suffix(self) -> bool:
        return bool(self.vendor_suffix)

    def upstream(self) -> str:
        """Human-readable upstream part (without vendor suffix)."""
        base = ".".join(str(p) for p in self.release) + self.letter
        if self.prerelease:
            base += "-" + ".".join(str(p) for p in self.prerelease)
        return base


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_SEMVER = re.compile(
    r"^v?(?P<rel>\d+(?:\.\d+){0,2})"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
# CPE "update" style pre-release glued to a label: alpha1, beta2, rc1, next0.
_GLUED_PRE = re.compile(r"^(?P<label>[A-Za-z]+)\.?(?P<num>\d*)$")
_DOTTED = re.compile(r"^v?(?P<rel>\d+(?:\.\d+)*)(?P<rest>.*)$")
_OPENSSL = re.compile(r"^(?P<rel>\d+(?:\.\d+){1,3})(?P<letter>[a-z]{0,2})(?P<rest>.*)$")


def _norm_pre_token(token: str):
    return int(token) if token.isdigit() else token.lower()


def _split_glued_prerelease(text: str) -> Optional[tuple]:
    """'beta2' -> ('beta', 2); 'rc' -> ('rc',); returns None if not a label."""
    m = _GLUED_PRE.match(text)
    if not m or m.group("label").lower() not in _PRE_LABEL_RANK:
        return None
    label = m.group("label").lower()
    return (label, int(m.group("num"))) if m.group("num") else (label,)


def parse_version(raw: str, scheme: str, update: str = "") -> ParsedVersion:
    """Parse ``raw`` under ``scheme``.

    ``update`` is the CPE 2.3 *update* field (e.g. ``alpha1``) that NVD uses
    for pre-releases of an exact version; ``*``/``-``/empty mean "none".
    """
    if scheme not in SCHEMES:
        raise VersionParseError(f"unknown version scheme {scheme!r}")
    text = (raw or "").strip()
    if not text or text in ("*", "-"):
        raise VersionParseError("no concrete version")
    upd = (update or "").strip()
    if upd in ("*", "-"):
        upd = ""
    if scheme == "semver":
        pv = _parse_semver(text)
    elif scheme == "openssl":
        pv = _parse_openssl(text)
    else:
        pv = _parse_dotted(text)
    if upd:
        pre = _split_glued_prerelease(upd)
        if pre is None:
            raise VersionParseError(f"unrecognised CPE update qualifier {upd!r}")
        if pv.prerelease:
            raise VersionParseError("pre-release given twice")
        pv = ParsedVersion(raw=f"{text}:{upd}", scheme=scheme, release=pv.release,
                           prerelease=pre, letter=pv.letter,
                           vendor_suffix=pv.vendor_suffix, build=pv.build)
    return pv


def _parse_semver(text: str) -> ParsedVersion:
    m = _SEMVER.match(text)
    if not m:
        # Allow glued npm/CPE style "5.0.0alpha1" / "11.1.0next0".
        g = re.match(r"^v?(\d+(?:\.\d+){0,2})([A-Za-z]+\d*)$", text)
        if g and _split_glued_prerelease(g.group(2)):
            release = _pad(tuple(int(p) for p in g.group(1).split(".")), 3)
            return ParsedVersion(text, "semver", release,
                                 _split_glued_prerelease(g.group(2)))
        raise VersionParseError(f"{text!r} is not a SemVer version")
    release = _pad(tuple(int(p) for p in m.group("rel").split(".")), 3)
    pre_text = m.group("pre") or ""
    vendor = None
    prerelease: tuple = ()
    if pre_text:
        if _VENDOR_MARKERS.search(pre_text):
            vendor = pre_text            # distro build, not a pre-release
        else:
            # Normalise glued labels ("beta2" -> "beta", 2) so npm-style and
            # NVD CPE-update style pre-releases ("alpha1") compare equal to
            # their dotted form ("alpha.1"). Other identifiers keep SemVer rules.
            tokens: list = []
            for t in pre_text.split("."):
                glued = _split_glued_prerelease(t)
                tokens.extend(glued if glued and len(glued) == 2 else
                              (_norm_pre_token(t),))
            prerelease = tuple(tokens)
    return ParsedVersion(text, "semver", release, prerelease,
                         vendor_suffix=vendor, build=m.group("build") or "")


def _parse_dotted(text: str) -> ParsedVersion:
    m = _DOTTED.match(text)
    if not m:
        raise VersionParseError(f"{text!r} has no numeric release")
    release = tuple(int(p) for p in m.group("rel").split("."))
    rest = m.group("rest")
    prerelease: tuple = ()
    vendor = None
    if rest:
        stripped = rest.lstrip("-_.~+")
        pre = _split_glued_prerelease(stripped) if rest[:1] in "-_.~" or rest[0].isalpha() else None
        if pre is not None and not _VENDOR_MARKERS.search(stripped):
            prerelease = pre
        elif stripped:
            vendor = stripped            # e.g. "6ubuntu14", "deb10u2", "-custom"
        else:
            raise VersionParseError(f"{text!r} has a dangling separator")
    return ParsedVersion(text, "dotted", release, prerelease, vendor_suffix=vendor)


def _parse_openssl(text: str) -> ParsedVersion:
    m = _OPENSSL.match(text)
    if not m:
        raise VersionParseError(f"{text!r} is not an OpenSSL version")
    release = tuple(int(p) for p in m.group("rel").split("."))
    letter = m.group("letter") or ""
    rest = m.group("rest") or ""
    if letter and release[0] >= 3:
        raise VersionParseError("OpenSSL 3.x does not use letter releases")
    prerelease: tuple = ()
    vendor = None
    if rest:
        stripped = rest.lstrip("-_.~+")
        pre = _split_glued_prerelease(stripped)
        if pre is not None:
            prerelease = pre
        elif stripped:
            vendor = stripped
    return ParsedVersion(text, "openssl", release, prerelease, letter=letter,
                         vendor_suffix=vendor)


def _pad(t: tuple[int, ...], n: int) -> tuple[int, ...]:
    return t + (0,) * (n - len(t)) if len(t) < n else t


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #

def compare(a: ParsedVersion, b: ParsedVersion) -> int:
    """Return -1, 0 or 1. Both versions must use the same scheme.

    Vendor suffixes and build metadata are ignored (see module docstring);
    callers decide how much to trust a version that carries one.
    """
    if a.scheme != b.scheme:
        raise VersionParseError(
            f"cannot compare {a.scheme} version with {b.scheme} version")
    n = max(len(a.release), len(b.release))
    ra, rb = _pad(a.release, n), _pad(b.release, n)
    if ra != rb:
        return -1 if ra < rb else 1
    if a.scheme == "openssl" and a.letter != b.letter:
        # '' < 'a' < 'z' < 'za' : shorter-then-lexical within a-z is correct
        # because OpenSSL appends letters after 'z' (1.0.2za).
        ka, kb = (len(a.letter), a.letter), (len(b.letter), b.letter)
        return -1 if ka < kb else 1
    return _compare_pre(a.prerelease, b.prerelease, a.scheme)


def _compare_pre(pa: tuple, pb: tuple, scheme: str) -> int:
    # A final release has higher precedence than any pre-release.
    if not pa and not pb:
        return 0
    if not pa:
        return 1
    if not pb:
        return -1
    if scheme != "semver":
        ka = (_PRE_LABEL_RANK.get(str(pa[0]), -1), pa[1] if len(pa) > 1 else 0)
        kb = (_PRE_LABEL_RANK.get(str(pb[0]), -1), pb[1] if len(pb) > 1 else 0)
        return 0 if ka == kb else (-1 if ka < kb else 1)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        xi, yi = isinstance(x, int), isinstance(y, int)
        if xi and yi:
            return -1 if x < y else 1
        if xi != yi:                      # numeric identifiers sort lower
            return -1 if xi else 1
        return -1 if str(x) < str(y) else 1   # SemVer 2.0 §11.4.2 (ASCII)
    if len(pa) == len(pb):
        return 0
    return -1 if len(pa) < len(pb) else 1
