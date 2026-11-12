"""Python binding for the LogForge C core, using only ctypes (no compiler needed at install time).

    from logforge import LogForge
    with LogForge() as lf:
        lf.analyze_file("access.log")
        print(lf.report()["attacks"])
"""
import ctypes
import json
import os
import sys
from pathlib import Path

_REPORT_CAP = 1 << 16


def _find_library():
    env = os.environ.get("LOGFORGE_LIB")
    candidates = [Path(env)] if env else []
    root = Path(__file__).resolve().parents[2] / "build"
    candidates += [root / "liblogforge.so", root / "liblogforge.dylib", root / "logforge.dll"]
    for p in candidates:
        if p.exists():
            return p
    raise FileNotFoundError("liblogforge not found; run `make` or set LOGFORGE_LIB (looked in %s)" % root)


_lib = None


def _load():
    global _lib
    if _lib is None:
        lib = ctypes.CDLL(str(_find_library()))
        lib.lf_new.restype = ctypes.c_void_p
        lib.lf_free.argtypes = [ctypes.c_void_p]
        lib.lf_feed.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.lf_flush.argtypes = [ctypes.c_void_p]
        lib.lf_report_json.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
        lib.lf_report_json.restype = ctypes.c_size_t
        lib.lf_attack_lines.argtypes = [ctypes.c_void_p]
        lib.lf_attack_lines.restype = ctypes.c_uint64
        _lib = lib
    return _lib


class LogForge:
    def __init__(self):
        self._lib = _load()
        self._ctx = self._lib.lf_new()
        if not self._ctx:
            raise MemoryError("lf_new failed")

    def feed(self, data):
        """Feed bytes in any chunking; lines may span calls."""
        if self._ctx is None:
            raise ValueError("closed")
        data = bytes(data)
        self._lib.lf_feed(self._ctx, data, len(data))

    def analyze_file(self, path, chunk=1 << 20):
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                self.feed(b)

    def report(self):
        """Flushes a final line without newline and returns the report as a dict."""
        if self._ctx is None:
            raise ValueError("closed")
        self._lib.lf_flush(self._ctx)
        buf = ctypes.create_string_buffer(_REPORT_CAP)
        n = self._lib.lf_report_json(self._ctx, buf, _REPORT_CAP)
        if n == 0:
            raise RuntimeError("report buffer too small")
        return json.loads(buf.raw[:n].decode("ascii"))

    @property
    def attack_lines(self):
        return self._lib.lf_attack_lines(self._ctx)

    def close(self):
        if self._ctx:
            self._lib.lf_free(self._ctx)
            self._ctx = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: python logforge.py access.log [more.log ...]\n")
        return 2
    with LogForge() as lf:
        for p in argv[1:]:
            lf.analyze_file(p)
        lf._lib.lf_flush(lf._ctx)
        buf = ctypes.create_string_buffer(_REPORT_CAP)
        n = lf._lib.lf_report_json(lf._ctx, buf, _REPORT_CAP)
        sys.stdout.write(buf.raw[:n].decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
