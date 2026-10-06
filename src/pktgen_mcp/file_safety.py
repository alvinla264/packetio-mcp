"""Linux file-descriptor-based I/O: no symlinks, special files or overwrites.

Directory components are opened relative to held descriptors, never re-resolved
at the point of use. Outputs are private temporary files published with link()
(no replacement), so failed writes do not leave a partial destination.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import uuid


def directory_fd(path, *, create=False, private=False):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        if private:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise PermissionError('capture directory must be owned by this user and mode 0700')
        return fd
    except BaseException:
        os.close(fd)
        raise


def check_new_output(path):
    path = Path(path)
    fd = directory_fd(path.parent, create=True)
    try:
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise FileExistsError('output already exists; choose a new filename')
    finally:
        os.close(fd)


def open_regular(path):
    path = Path(path)
    directory = directory_fd(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('capture input must be a regular file')
        handle = os.fdopen(fd, 'rb')
        fd = None
        return handle
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


@contextmanager
def private_output(path):
    path = Path(path)
    directory = directory_fd(path.parent, create=True)
    temporary = '.pktgen-' + uuid.uuid4().hex + '.tmp'
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as handle:
            yield handle
            if not handle.closed:
                handle.flush()
                os.fsync(handle.fileno())
        # An existing regular file, symlink, FIFO or concurrent writer wins:
        # never overwrite any of them.
        os.link(temporary, path.name, src_dir_fd=directory,
                dst_dir_fd=directory, follow_symlinks=False)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def write_private_text(path, text):
    with private_output(path) as handle:
        handle.write(text.encode('utf-8'))
