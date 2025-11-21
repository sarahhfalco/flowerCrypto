"""Utilities to measure end-to-end encryption scenario runtimes.

This module provides a small timing harness that can be used to wrap any
encryption workflow and capture the wall-clock time for the entire process.
It is intentionally dependency-free so it can be dropped into existing
experiments without extra requirements.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import Any, Callable, Iterable, List, Mapping, Tuple


# Public data structures ---------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    """Container for a single scenario execution."""

    name: str
    duration_seconds: float
    output: Any


# Timing helpers ------------------------------------------------------------------------------------


def time_call(name: str, func: Callable[..., Any], *args: Any, **kwargs: Any) -> ScenarioResult:
    """Execute ``func`` while measuring its wall-clock duration.

    Parameters
    ----------
    name:
        Descriptive name for the scenario. This is used only for reporting.
    func:
        Callable representing the encryption scenario to execute.
    *args, **kwargs:
        Positional and keyword arguments forwarded to ``func``.

    Returns
    -------
    ScenarioResult
        Object containing the scenario name, duration in seconds, and the return
        value produced by ``func``.
    """

    start = perf_counter()
    output = func(*args, **kwargs)
    duration_seconds = perf_counter() - start
    return ScenarioResult(name=name, duration_seconds=duration_seconds, output=output)


def run_suite(
    scenarios: Mapping[str, Callable[[], Any]] | Iterable[Tuple[str, Callable[[], Any]]]
) -> Tuple[List[ScenarioResult], float]:
    """Run multiple scenarios while tracking individual and total duration.

    The function accepts either a mapping (preserving insertion order) or an
    iterable of ``(name, callable)`` pairs. The suite runtime measures the entire
    process from the first scenario invocation to the completion of the last one.

    Parameters
    ----------
    scenarios:
        Encryption scenarios keyed by a human-readable name.

    Returns
    -------
    Tuple[List[ScenarioResult], float]
        A list of per-scenario results paired with the overall wall-clock time
        (in seconds) needed to run the entire suite.
    """

    ordered: List[Tuple[str, Callable[[], Any]]]
    if isinstance(scenarios, Mapping):
        ordered = list(scenarios.items())
    else:
        ordered = list(scenarios)

    suite_start = perf_counter()
    results = [time_call(name, fn) for name, fn in ordered]
    total_duration = perf_counter() - suite_start
    return results, total_duration


# Example usage ------------------------------------------------------------------------------------


def _xor_cipher(payload: bytes, key: bytes) -> bytes:
    """Very small XOR-based cipher used only for demonstration.

    This is intentionally simple and **not** intended for production use. It
    allows us to exercise the timing harness without external dependencies.
    """

    return bytes(b ^ key[i % len(key)] for i, b in enumerate(payload))


def example_scenarios() -> List[Tuple[str, Callable[[], Any]]]:
    """Build lightweight example scenarios for manual testing.

    Returns
    -------
    List[Tuple[str, Callable[[], Any]]]
        Ready-to-run scenarios demonstrating how to plug encryption workflows
        into :func:`run_suite`.
    """

    payload = b"Secret payload to encrypt multiple times for timing."
    key_a = b"key-a"
    key_b = b"key-b"

    return [
        (
            "xor-single-pass",
            lambda: _xor_cipher(payload, key_a),
        ),
        (
            "xor-double-pass",
            lambda: _xor_cipher(_xor_cipher(payload, key_a), key_b),
        ),
    ]


if __name__ == "__main__":
    scenarios = example_scenarios()
    results, total = run_suite(scenarios)

    print("Scenario timing summary:\n")
    for result in results:
        print(f"- {result.name}: {result.duration_seconds:.6f}s")
    print(f"\nTempo totale esecuzione suite: {total:.6f}s")
