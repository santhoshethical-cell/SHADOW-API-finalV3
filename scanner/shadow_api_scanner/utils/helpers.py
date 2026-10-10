"""
Utility helpers for Shadow API Scanner.

URL normalization, domain extraction, content-type detection,
logging setup, and other shared functionality.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger("shadow_api_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(fmt)
        logger.addHandler(handler)

    return logger


def normalize_url(url: str) -> str:
    """
    Normalize a URL for consistent comparison.

    - Lowercases scheme and host
    - Removes default ports
    - Strips trailing slashes
    - Sorts query parameters
    - Removes fragments
    """
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port

    # Remove default ports
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    netloc = host
    if port:
        netloc = f"{host}:{port}"
    if parsed.username:
        user_info = parsed.username
        if parsed.password:
            user_info += f":{parsed.password}"
        netloc = f"{user_info}@{netloc}"

    # Collapse Socket.IO transport handshakes: their query carries volatile
    # per-connection tokens (EIO/transport/t/sid) that would otherwise make
    # each poll a distinct "endpoint". The logical route is just /socket.io/.
    query = parsed.query
    if "/socket.io" in parsed.path.lower():
        query = ""

    # Sort query params
    query_params = parse_qs(query, keep_blank_values=True)
    sorted_query = urlencode(
        sorted(
            [(k, v[0] if len(v) == 1 else v) for k, v in query_params.items()]
        )
    ) if query_params else ""

    path = parsed.path.rstrip("/") or "/"

    normalized = urlunparse((scheme, netloc, path, parsed.params, sorted_query, ""))
    return normalized


def extract_domain(url: str) -> str:
    """Extract the domain (host:port) from a URL."""
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        domain += f":{parsed.port}"
    return domain


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs share the same origin."""
    p1 = urlparse(url1)
    p2 = urlparse(url2)
    return (
        p1.scheme == p2.scheme and
        p1.hostname == p2.hostname and
        (p1.port or 443 if p1.scheme == "https" else 80) ==
        (p2.port or 443 if p2.scheme == "https" else 80)
    )


def resolve_url(base_url: str, relative_url: str) -> str:
    """Resolve a relative URL against a base URL."""
    if relative_url.startswith(("http://", "https://", "//")):
        if relative_url.startswith("//"):
            scheme = urlparse(base_url).scheme
            return f"{scheme}:{relative_url}"
        return relative_url
    return urljoin(base_url, relative_url)


# Directory names and file extensions that mark a URL as a static asset
# rather than an API operation. Generic (framework-agnostic): applies to any
# target, no application-specific paths.
_STATIC_ASSET_DIRS = {
    "assets", "static", "dist", "build", "public", "_next", "_nuxt",
    "fonts", "img", "images", "css", "media",
}
_STATIC_ASSET_EXTENSIONS = (
    ".js", ".mjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".less",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".mp4", ".webm", ".webp", ".avif", ".mp3", ".wav",
    ".pdf", ".txt", ".md", ".csv",
)

# Distinctive API path prefixes — specific enough to match anywhere in a path.
_API_PATH_MARKERS = (
    "/api/", "/api/v", "/v1/", "/v2/", "/v3/", "/v4/",
    "/rest/", "/graphql", "/gql",
    "/ws/", "/wss/", "/socket", "/oauth/", "/webhook", "/callback",
)
# Generic single-word markers matched as *whole path segments* only, so that
# e.g. "/upload_paste" (an HTML page) is not mistaken for "/upload".
_API_SEGMENT_MARKERS = {
    "api", "rest", "graphql", "gql", "query", "users", "admin", "config",
    "settings", "search", "upload", "download", "auth", "token", "oauth",
    "webhook", "callback", "notify",
}


def is_static_asset(url: str) -> bool:
    """Return True when a URL points to a static asset, not an API operation."""
    path = urlparse(url).path.lower()
    segments = [segment for segment in path.split("/") if segment]
    if any(segment in _STATIC_ASSET_DIRS for segment in segments):
        return True
    return path.endswith(_STATIC_ASSET_EXTENSIONS)


def is_api_url(url: str) -> bool:
    """Heuristic check if a URL looks like an API endpoint.

    Matching is whole-path-segment aware for generic word markers and
    excludes static assets, so an HTML page like ``/upload_paste`` or a
    bundled asset like ``/assets/i18n/en.json`` is not misclassified as an
    API.
    """
    if is_static_asset(url):
        return False
    path = urlparse(url).path.lower()
    if any(marker in path for marker in _API_PATH_MARKERS):
        return True
    segments = [segment for segment in path.split("/") if segment]
    if any(segment in _API_SEGMENT_MARKERS for segment in segments):
        return True
    return path.endswith((".json", ".xml"))


def is_js_file(url: str) -> bool:
    """Check if a URL points to a JavaScript file."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    return path.endswith((".js", ".mjs", ".jsx", ".ts", ".tsx"))


def hash_content(content: str) -> str:
    """SHA-256 hash of content string."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


def safe_filename(url: str) -> str:
    """Convert a URL to a safe filename."""
    parsed = urlparse(url)
    path = parsed.path.replace("/", "_").strip("_")
    if not path:
        path = "index"
    name = re.sub(r"[^a-zA-Z0-9._-]", "_", path)
    # Truncate if too long
    if len(name) > 100:
        name = name[:90] + "_" + hash_content(url)[:8]
    return name


def detect_content_type(headers: dict) -> str:
    """Extract content type from response headers."""
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if "json" in ct:
        return "json"
    elif "xml" in ct:
        return "xml"
    elif "html" in ct:
        return "html"
    elif "javascript" in ct or "ecmascript" in ct:
        return "javascript"
    elif "text" in ct:
        return "text"
    return "unknown"


def truncate(text: str, max_len: int = 500) -> str:
    """Truncate text to max_len, appending '...' if truncated."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def ensure_dir(path: str) -> str:
    """Ensure a directory exists, creating it if needed."""
    directory = Path(path).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory)


def extract_path_params(url_pattern: str) -> list[str]:
    """
    Extract path parameter placeholders from a URL pattern.

    Examples:
        /api/users/{id}  -> ["id"]
        /api/v1/:userId/posts/:postId  -> ["userId", "postId"]
    """
    params = []
    # Match {param} style
    params.extend(re.findall(r"\{(\w+)\}", url_pattern))
    # Match :param style
    params.extend(re.findall(r":(\w+)", url_pattern))
    return params


def mask_sensitive(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value, showing only the first N characters."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)
