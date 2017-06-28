import os
import shutil
from snapshotter import snapshotter


def _is_subdir(path, directory):
    path = os.path.realpath(path)
    directory = os.path.realpath(directory)
    relative = os.path.relpath(path, directory)
    return not relative.startswith(os.pardir)


def _get_parent_dir(path):
    return os.path.abspath(os.path.join(path, os.pardir))


class Snapshot(object):

    def __init__(self, path):
        self._snapshot(path)
        self._snapshot_path = os.path.join('/tmp/snap', os.readlink('/tmp/snap/latest.snapshot'))
        self._snapshotted_path = path

    def _snapshot(self, path):
        snapshotter.snapshot(path, '/tmp/snap')

    def rollback(self):
        pass

    def snapshotted_path(self):
        return self._snapshotted_path


class Snapshots(object):

    def __init__(self):
        self._snapshots = []
        if os.path.isdir('/tmp/snap'):
            self.clean()
        os.mkdir('/tmp/snap')

    def snapshot_path(self, changed_path):
        snapshotted_path = _get_parent_dir(changed_path)
        # if any parent or self path is already snapshotted -> return:
        for snapshot in self._snapshots:
            if _is_subdir(snapshotted_path, snapshot.snapshotted_path()):
                return
        self._snapshots.append(Snapshot(snapshotted_path))

    def rollback_all(self):
        for snapshot in self._snapshots:
            snapshot.rollback()

    def clean(self):
        shutil.rmtree('/tmp/snap', True)

