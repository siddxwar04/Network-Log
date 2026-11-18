"""Confirms the package installs and imports. Real tests arrive with each feature."""

import netlog


def test_package_imports():
    assert netlog.__version__ == "0.1.0"
