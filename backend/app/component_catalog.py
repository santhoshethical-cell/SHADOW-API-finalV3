"""Component identity catalog: fingerprint names -> CPE identities + version scheme.

A component is only looked up in the CVE database when its fingerprint maps to
a catalog entry. Each entry lists every NVD CPE ``vendor:product`` pair known to
be used for that upstream project (NVD has renamed several over time, e.g.
``nginx:nginx`` -> ``f5:nginx``, ``expressjs:express`` -> ``openjsf:express``)
and the version scheme the upstream project follows.

Identity confidence
-------------------
``high``       The evidence names the product unambiguously (runtime global
               such as ``jQuery.fn.jquery``, or a ``Server: nginx/x`` header).
``medium``     Indirect evidence (a versioned bundle filename) that a build
               pipeline may rename, or a generic header token.
``ambiguous``  The evidence fits more than one catalog product (e.g. a file
               called ``angular-1.8.2.min.js`` is AngularJS, not Angular).
Only ``high`` identities can produce a "version match"; everything else is
reported as *potential* and requires manual validation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class CatalogEntry:
    key: str                         # normalized component identity
    display: str
    cpes: tuple[tuple[str, str], ...]  # (vendor, product) pairs used by NVD
    scheme: str                      # versioning scheme (see versioning.py)
    kind: str = "library"            # library | server | runtime
    notes: tuple[str, ...] = field(default_factory=tuple)


CATALOG: dict[str, CatalogEntry] = {e.key: e for e in (
    CatalogEntry("jquery", "jQuery", (("jquery", "jquery"),), "semver"),
    CatalogEntry("angular", "Angular", (("angular", "angular"),), "semver",
                 notes=("Angular CVEs frequently affect server-side or build "
                        "packages (@angular/ssr, compiler); a runtime "
                        "ng-version does not prove the vulnerable package is "
                        "deployed.",)),
    CatalogEntry("angularjs", "AngularJS", (("angularjs", "angularjs"),
                                            ("angularjs", "angular.js")),
                 "semver"),
    CatalogEntry("react", "React", (("facebook", "react"),), "semver",
                 notes=("Some React CVEs apply only to server packages "
                        "(react-server-dom-*); the client runtime version "
                        "alone cannot show they are in use.",)),
    CatalogEntry("vue", "Vue.js", (("vuejs", "vue"), ("vuejs", "vue.js")),
                 "semver"),
    CatalogEntry("bootstrap", "Bootstrap", (("getbootstrap", "bootstrap"),),
                 "semver"),
    CatalogEntry("lodash", "Lodash", (("lodash", "lodash"),), "semver"),
    CatalogEntry("express", "Express", (("openjsf", "express"),
                                        ("expressjs", "express")),
                 "semver", kind="server"),
    CatalogEntry("nginx", "nginx", (("f5", "nginx"), ("nginx", "nginx")),
                 "dotted", kind="server"),
    CatalogEntry("apache_http_server", "Apache HTTP Server",
                 (("apache", "http_server"),), "dotted", kind="server"),
    CatalogEntry("php", "PHP", (("php", "php"),), "dotted", kind="runtime"),
    CatalogEntry("iis", "Microsoft IIS",
                 (("microsoft", "internet_information_services"),), "dotted",
                 kind="server",
                 notes=("IIS versions are tied to the Windows release and are "
                        "patched through Windows Update without a version "
                        "change.",)),
    CatalogEntry("openssl", "OpenSSL", (("openssl", "openssl"),), "openssl",
                 kind="library"),
)}

# Fingerprint product token -> catalog key, per evidence source.
_RUNTIME_MAP = {
    "jquery": "jquery", "angular": "angular", "angularjs": "angularjs",
    "react": "react", "vue": "vue", "bootstrap": "bootstrap",
}
_HEADER_MAP = {
    "nginx": "nginx", "apache": "apache_http_server", "httpd": "apache_http_server",
    "php": "php", "microsoft-iis": "iis", "openssl": "openssl",
    "express": "express",
}
_BUNDLE_MAP = {
    "jquery": "jquery", "react": "react", "vue": "vue", "bootstrap": "bootstrap",
    "lodash": "lodash", "angularjs": "angularjs",
}


@dataclass
class Identity:
    candidates: list[str]            # catalog keys (len > 1 => ambiguous)
    confidence: str                  # high | medium | ambiguous | unrecognized
    rationale: str

    @property
    def key(self) -> Optional[str]:
        return self.candidates[0] if len(self.candidates) == 1 else None


def resolve(product: str, version: Optional[str], source: str) -> Identity:
    """Map a fingerprinted (product, version, source) to catalog identities."""
    p = (product or "").strip().lower()
    src = (source or "").lower()
    if src == "runtime" and p in _RUNTIME_MAP:
        return Identity([_RUNTIME_MAP[p]], "high",
                        f"Runtime global reported by the page ({p}).")
    if src == "bundle":
        if p == "angular":
            major = (version or "").split(".")[0]
            if major == "1":
                return Identity(["angularjs", "angular"], "ambiguous",
                                "Bundle file named 'angular' with a 1.x version is "
                                "normally AngularJS, but the filename alone cannot "
                                "distinguish it from Angular.")
            return Identity(["angular", "angularjs"], "ambiguous",
                            "Bundle file named 'angular' could be Angular or AngularJS.")
        if p in _BUNDLE_MAP:
            return Identity([_BUNDLE_MAP[p]], "medium",
                            "Versioned script filename; build pipelines can rename "
                            "or re-bundle files, so the identity is indirect.")
    if src not in ("runtime", "bundle") and p in _HEADER_MAP:
        conf = "high" if p in ("nginx", "php", "microsoft-iis", "openssl") else "medium"
        why = (f"Response header '{source}' names the product."
               if conf == "high" else
               f"Generic header token '{p}' in '{source}'; several products use it.")
        return Identity([_HEADER_MAP[p]], conf, why)
    return Identity([], "unrecognized",
                    f"'{product}' is not in the component catalog; no CVE lookup "
                    "is possible for it.")


def all_cpe_pairs() -> list[tuple[str, str]]:
    seen: list[tuple[str, str]] = []
    for entry in CATALOG.values():
        for pair in entry.cpes:
            if pair not in seen:
                seen.append(pair)
    return seen
