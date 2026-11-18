import sys

VERBOSE = False


def error(*s):
    """Print the supplied message to standard error."""

    print(*s, file=sys.stderr)


def debug(*s):
    """Print the supplied debug message when verbose mode is enabled."""

    if VERBOSE:
        print(*s, file=sys.stderr)  # тоді у stdout піде тільки json
