"""nis2check: an open-source NIS2 self-assessment and gap report tool for SMEs."""

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the only place the version is set.
    __version__ = version("nis2check")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"
