import pytest

from app.versioning import VersionParseError, compare, parse_version


def cmp(a, b, scheme="semver", ua="", ub=""):
    return compare(parse_version(a, scheme, ua), parse_version(b, scheme, ub))


@pytest.mark.parametrize("a,b,expected", [
    ("1.10.0", "1.9.0", 1),           # numeric, not lexicographic
    ("3.5.0", "3.5.0", 0),
    ("3.5", "3.5.0", 0),              # padding
    ("3.5.0-beta.1", "3.5.0", -1),    # pre-release < release
    ("3.5.0-alpha.1", "3.5.0-beta.1", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.2", "1.0.0-alpha.10", -1),   # numeric identifiers
    ("1.0.0-rc.1", "1.0.0-beta.11", 1),
    ("2.0.0+build.5", "2.0.0", 0),    # build metadata ignored
])
def test_semver_precedence(a, b, expected):
    assert cmp(a, b) == expected


def test_glued_and_cpe_update_prerelease_are_equivalent():
    assert cmp("5.0.0-alpha.1", "5.0.0", ub="alpha1") == 0
    assert cmp("5.0.0-alpha1", "5.0.0", ub="alpha1") == 0
    assert cmp("5.0.0-beta.1", "5.0.0", ub="alpha1") == 1


@pytest.mark.parametrize("a,b,expected", [
    ("1.20", "1.20.0", 0), ("1.20.1", "1.20", 1), ("1.9.15", "1.20.0", -1),
    ("10.0", "8.5", 1), ("1.18.0-rc1", "1.18.0", -1),
])
def test_dotted(a, b, expected):
    assert cmp(a, b, "dotted") == expected


def test_vendor_suffix_is_separated_not_ordered():
    pv = parse_version("1.18.0-6ubuntu14", "dotted")
    assert pv.vendor_suffix == "6ubuntu14" and pv.release == (1, 18, 0)
    assert not pv.is_prerelease
    sv = parse_version("7.4.3-4ubuntu2.19", "semver")
    assert sv.vendor_suffix and not sv.is_prerelease


@pytest.mark.parametrize("a,b,expected", [
    ("1.1.1", "1.1.1k", -1), ("1.1.1k", "1.1.1l", -1), ("1.1.1z", "1.1.1za", -1),
    ("1.0.2u", "1.1.0", -1), ("3.0.7", "3.0.12", -1),
])
def test_openssl_letters(a, b, expected):
    assert cmp(a, b, "openssl") == expected


@pytest.mark.parametrize("raw,scheme", [
    ("", "semver"), ("*", "semver"), ("-", "dotted"), ("abc", "semver"),
    ("v", "dotted"), ("3.0.1a", "openssl"), ("1.2.3", "nosuchscheme"),
])
def test_unparseable_raises(raw, scheme):
    with pytest.raises(VersionParseError):
        parse_version(raw, scheme)


def test_cross_scheme_compare_refused():
    with pytest.raises(VersionParseError):
        compare(parse_version("1.0.0", "semver"), parse_version("1.0.0", "dotted"))
