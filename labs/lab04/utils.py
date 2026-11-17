import sys

VERBOSE = False


def error(*s):
    print(*s, file=sys.stderr)


def debug(*s):
    if VERBOSE:
        print(*s, file=sys.stderr)  # тоді у stdout піде тільки json
