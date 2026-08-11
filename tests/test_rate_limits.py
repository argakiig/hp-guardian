from __future__ import annotations

import threading

import pytest

from hp_guard import InMemoryRateLimitStore, PolicyCall, RateLimitedPolicyStore, StateError


POLICY = """version: 2
rules:
  - action: allow
    target:
      tool: search
    rate_limit:
      max_calls: 1
      window_seconds: 60
"""


def test_concurrent_calls_cannot_exceed_a_fixed_window_quota() -> None:
    store = RateLimitedPolicyStore(POLICY, InMemoryRateLimitStore(), now_monotonic_seconds=lambda: 10)
    decisions = []
    lock = threading.Lock()

    def resolve() -> None:
        decision = store.resolve(PolicyCall(tool="search"))
        with lock:
            decisions.append(decision.action.value)

    threads = [threading.Thread(target=resolve) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert decisions.count("allow") == 1
    assert decisions.count("throttle") == 15


def test_monotonic_clock_regression_fails_closed() -> None:
    now = [10]
    store = RateLimitedPolicyStore(POLICY, InMemoryRateLimitStore(), now_monotonic_seconds=lambda: now[0])
    assert store.resolve(PolicyCall(tool="search")).action.value == "allow"
    now[0] = 9

    with pytest.raises(StateError) as raised:
        store.resolve(PolicyCall(tool="search"))
    assert raised.value.code == "state_unavailable"
