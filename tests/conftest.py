"""Test configuration and the gate for tests needing a licensed binary.

Most of this suite runs on assets the repository can carry: synthetic encodings,
the marty_dasm crate's own output, and MIT-licensed hardware recordings. A few
tests need a specific third-party DOS binary and a Ghidra listing taken over it,
and those two files are **not** in the repository -- see `NOTICE` for why.

They are gated rather than deleted, because they are the strongest evidence the
project has for its rendering rules and anyone who legitimately holds the binary
should be able to run them. Point `PYDASM_CORPUS` at a directory holding both
files:

    PYDASM_CORPUS=/path/to/corpus python -m pytest

and they run; leave it unset and they skip with a reason rather than failing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

#: Environment variable naming a directory holding the corpus. See the module
#: docstring.
CORPUS_ENV = "PYDASM_CORPUS"

#: The corpus file names. The target is named generically because which binary a
#: caller has is their business, not this repository's.
TARGET_NAME = "target.EXE"
LISTING_NAME = "listing.txt"
SEGMENTS_NAME = "segments.json"

_REQUIRED = (TARGET_NAME, LISTING_NAME, SEGMENTS_NAME)


def corpus_dir() -> Path | None:
    """The directory holding the gated corpus, or None if it is not available.

    Falls back to `tests/data` as well as the environment variable, so a
    checkout that still has the files in place works without configuration.
    """
    candidates = []
    configured = os.environ.get(CORPUS_ENV)
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path(__file__).resolve().parent / "data")
    for candidate in candidates:
        if all((candidate / name).is_file() for name in _REQUIRED):
            return candidate
    return None


@pytest.fixture(scope="session")
def corpus() -> Path:
    """The licensed corpus directory, or skip the test that asked for it."""
    found = corpus_dir()
    if found is None:
        pytest.skip(
            f"needs a licensed binary corpus ({', '.join(_REQUIRED)}); "
            f"set {CORPUS_ENV} to a directory holding them -- see NOTICE"
        )
    return found
