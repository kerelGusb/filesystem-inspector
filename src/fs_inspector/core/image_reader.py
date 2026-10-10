import os
from pathlib import Path
from threading import Lock

DEFAULT_MAX_READ_SIZE = 1024 * 1024


class SourceRangeError(ValueError):
    pass


class ReadLimitError(SourceRangeError):
    pass


class ShortReadError(EOFError):
    pass


class FileImageReader:
    def __init__(
        self,
        path,
        *,
        max_read_size = DEFAULT_MAX_READ_SIZE,
    ):
        if isinstance(max_read_size, bool) or not isinstance(max_read_size, int) or max_read_size <= 0:
            raise ValueError("max_read_size must be a positive integer")

        self.path = Path(path)
        self.max_read_size = max_read_size
        self._lock = Lock()
        self._file = self.path.open("rb", buffering=0)
        try:
            self.size = os.fstat(self._file.fileno()).st_size
        except BaseException:
            self._file.close()
            raise
        self.closed = False

    def read_at(self, offset, length):
        with self._lock:
            if self._file.closed:
                raise ValueError("Image reader is closed")
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                raise SourceRangeError("offset must be a nonnegative integer")
            if isinstance(length, bool) or not isinstance(length, int) or length < 0:
                raise SourceRangeError("length must be a nonnegative integer")
            if length > self.max_read_size:
                raise ReadLimitError(
                    f"read length {length} exceeds limit {self.max_read_size}"
                )
            if offset > self.size or length > self.size - offset:
                raise SourceRangeError(
                    f"range [{offset}, {offset + length}) exceeds image size {self.size}"
                )
            if length == 0:
                return b""

            self._file.seek(offset)
            data = self._file.read(length)
            if len(data) != length:
                raise ShortReadError(
                    f"short read at offset {offset}: requested {length} bytes, got {len(data)}"
                )
            return data

    def close(self):
        with self._lock:
            self._file.close()
            self.closed = True

    def __enter__(self):
        if self.closed:
            raise ValueError("Image reader is closed")
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        self.close()
