# Vendored scanner

This directory is a vendored copy of the Shadow / Unmanaged API Scanner
(https://github.com/kabila5h/API-Scanner) — the validated CLI/library layer.

It is vendored (rather than a git submodule) so a plain `git clone` of this
web-app repo works without needing credentials for the private scanner repo.
The scanner core is unmodified; the web app installs it as a package
(`pip install ./scanner`). To update, re-copy the scanner's `shadow_api_scanner/`
package and `setup.py` from upstream.
