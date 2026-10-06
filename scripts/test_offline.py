#!/usr/bin/env python3
"""Run tests with AF_PACKET explicitly disabled, even on a capable interpreter.

The live-test permission checks see EPERM and skip real-device tests. This is
not a general network sandbox: it prevents accidental raw-packet operations in
this suite, and does not replace independent physical verification.
"""
import errno
import socket
import sys

import pytest


class OfflineSocket(socket.socket):
    def __init__(self, family=socket.AF_INET, *args, **kwargs):
        if family == socket.AF_PACKET:
            raise PermissionError(errno.EPERM, 'AF_PACKET disabled by offline test runner')
        super().__init__(family, *args, **kwargs)


if __name__ == '__main__':
    socket.socket = OfflineSocket
    sys.exit(pytest.main(sys.argv[1:] or ['tests', '-q', '-p', 'no:cacheprovider']))
