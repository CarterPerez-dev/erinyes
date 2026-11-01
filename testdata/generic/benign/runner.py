"""
©AngelaMos | 2026
runner.py
"""

import sys


def run_script(path):
    with open(path) as fh:
        source = fh.read()
    exec(compile(source, path, "exec"), {"__name__": "__main__"})


if __name__ == "__main__":
    run_script(sys.argv[1])
