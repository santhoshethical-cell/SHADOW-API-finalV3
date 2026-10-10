"""Setup script for Shadow API Scanner."""

import re
from pathlib import Path

from setuptools import find_packages, setup

PROJECT_ROOT = Path(__file__).resolve().parent
PACKAGE_INIT = PROJECT_ROOT / "shadow_api_scanner" / "__init__.py"

version_match = re.search(
    r'^__version__\s*=\s*["\']([^"\']+)["\']',
    PACKAGE_INIT.read_text(encoding="utf-8"),
    re.MULTILINE,
)
if version_match is None:
    raise RuntimeError("Unable to determine package version")

with (PROJECT_ROOT / "requirements.txt").open(encoding="utf-8") as f:
    requirements = [
        line.strip()
        for line in f
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="shadow-api-scanner",
    version=version_match.group(1),
    description=(
        "Automated Shadow / Unmanaged API Detection and Security Testing "
        "Tool for SPAs"
    ),
    author="Security Engineering Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "shadow-scan=shadow_api_scanner.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
)
