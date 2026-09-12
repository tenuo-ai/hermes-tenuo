"""One-command allow/deny transcript. No Hermes process, no API key.

    python examples/demo.py
    # or: hermes-tenuo demo
"""

from hermes_tenuo.demo import main

if __name__ == "__main__":
    raise SystemExit(main())
