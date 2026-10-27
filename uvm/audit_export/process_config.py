"""Environment loading shared by the separately supervised O3 processes."""

from __future__ import annotations

import importlib
import os
from typing import Any, Callable


def load_factory(name: str) -> Callable[[], Any]:
    value = os.environ[name]
    module_name, separator, attribute = value.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError(f"{name} must be module:callable")
    factory = getattr(importlib.import_module(module_name), attribute)
    if not callable(factory):
        raise TypeError(f"{name} does not resolve to a callable")
    return factory


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"required environment variable {name} is unset")
    return value
