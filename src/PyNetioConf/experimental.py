"""
Marking of methods for a feature whose firmware isn't released yet. Such a method may change or go with the release.
"""

import functools
import warnings
from collections.abc import Callable
from typing import ParamSpec, TypeVar

P = ParamSpec("P")
R = TypeVar("R")

_warned: set[str] = set()


class ExperimentalWarning(UserWarning):
    """An experimental method was called: its firmware isn't released yet, and the method may change or go."""


def experimental(feature: str, firmware: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Warns with ExperimentalWarning the first time the decorated method is called in a process."""

    def decorate(method: Callable[P, R]) -> Callable[P, R]:
        @functools.wraps(method)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            if method.__qualname__ not in _warned:
                _warned.add(method.__qualname__)
                warnings.warn(
                    f"{method.__name__}() is experimental: {feature} came with firmware {firmware}, which isn't "
                    "released yet, so the method may change or go",
                    ExperimentalWarning,
                    stacklevel=2,
                )
            return method(*args, **kwargs)

        return wrapper

    return decorate
