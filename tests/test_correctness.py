# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the correctness of the code using linters and unit tests."""

import subprocess

def test_style():
    """Test rust style using `cargo fmt`."""
    subprocess.run(['cargo', 'fmt', '--all', '--', '--check'], check=True)


def test_clippy():
    """Run clippy."""
    subprocess.run(['cargo', 'clippy'], check=True)


def test_unittests():
    """Run unit tests."""
    subprocess.run(['cargo', 'test', '--all'], check=True)
