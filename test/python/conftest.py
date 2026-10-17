"""pytest setup for the Python proto-2 device library.

Run from the repository root:

    /tmp/opencode/pyenv/bin/python -m pytest test/python -q

Needs ``cryptography`` and ``pytest`` (see src/python/requirements.txt). The interop test also needs
``node`` and the C++ simulator (built once with the g++ line in test_interop.py), and is skipped with a
message when either is missing.
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Iterator, List

import pytest

import helpers
from helpers import ROOT


@pytest.fixture(scope="session")
def vectors() -> Dict[str, Any]:
    with open(ROOT / "test" / "fixtures" / "proto2" / "vectors.json", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def component() -> Iterator[Callable[..., Any]]:
    """Factory for started in-process devices; everything is closed at the end of the test."""
    created: List[Any] = []

    def factory(*args: Any, **kwargs: Any) -> Any:
        c = helpers.make_component(*args, **kwargs)
        created.append(c)
        return c

    yield factory
    for c in created:
        c.close()
