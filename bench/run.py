"""Benchmark: same input, same output, five implementations. Prints a Markdown table.

    python3 bench/run.py [lines]       (default 1,000,000)
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1_000_000
LOG = ROOT / "build" / ("bench-%d.log" % N)
RUNS = 3

IMPLS = [
    ("C (native CLI)", [str(ROOT / "build" / "logforge"), "--json", str(LOG)]),
    ("C via Python ctypes", [sys.executable, str(ROOT / "bindings/python/logforge.py"), str(LOG)]),
    ("C via Node WASM", ["node", str(ROOT / "bindings/node/cli.mjs"), str(LOG)]),
    ("Pure Node", ["node", str(ROOT / "bench/ref.mjs"), str(LOG)]),
    ("Pure Python", [sys.executable, str(ROOT / "bench/ref.py"), str(LOG)]),
]


def main():
    if not LOG.exists():
        subprocess.run([sys.executable, str(ROOT / "bench/gen_log.py"), str(LOG), str(N), "--seed", "1"], check=True)
    size = LOG.stat().st_size
    results, outputs = [], []
    for name, cmd in IMPLS:
        best = None
        for _ in range(RUNS):
            t = time.perf_counter()
            r = subprocess.run(cmd, capture_output=True, check=True)
            dt = time.perf_counter() - t
            best = dt if best is None or dt < best else best
        outputs.append(r.stdout.strip())
        results.append((name, best))
    same = all(o == outputs[0] for o in outputs)
    base = results[-1][1]
    print("Input: %s lines, %.1f MB, best of %d runs, wall clock including process start\n" % (format(N, ","), size / 1e6, RUNS))
    print("| Implementation | Time | Lines/s | MB/s | Speedup vs pure Python |")
    print("|---|---|---|---|---|")
    for name, t in results:
        print("| %s | %.3f s | %s | %.0f | %.0fx |" % (name, t, format(int(N / t), ","), size / 1e6 / t, base / t))
    print("\nOutputs byte-identical across all five: %s" % ("yes" if same else "NO"))
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
