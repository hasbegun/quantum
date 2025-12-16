"""Pytest fixtures for QKD tests."""

import pytest

from qkd import BB84Protocol, Alice, Bob, Eve


@pytest.fixture
def protocol():
    """Create a BB84 protocol with fixed seed."""
    return BB84Protocol(num_bits=100, seed=42)


@pytest.fixture
def alice():
    """Create Alice with fixed seed."""
    return Alice(num_bits=50, seed=42)


@pytest.fixture
def bob():
    """Create Bob with fixed seed."""
    return Bob(num_bits=50, seed=43)


@pytest.fixture
def eve():
    """Create Eve with fixed seed."""
    return Eve(seed=44)
