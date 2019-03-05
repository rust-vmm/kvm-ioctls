# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import subprocess


def test_build():
    """Test release build using the default gnu target."""
    subprocess.run(['cargo', 'build', '--release'], check=True)


def test_build_musl():
    """Test release build using the musl target."""
    subprocess.run(
        [
            'cargo',
            'build',
            '--release',
            '--target',
            'x86_64-unknown-linux-musl'
        ],
        check=True
    )
