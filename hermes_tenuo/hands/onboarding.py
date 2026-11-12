"""A disposable, dependency-free first project for Hands."""

from pathlib import Path
import shlex
import tempfile


def create_demo() -> str:
    folder = Path(tempfile.mkdtemp(prefix="hands-practice-"))
    (folder / "invoice.py").write_text(
        'def total_after_discount(subtotal, discount):\n'
        '    """Return the amount due after a fractional discount (0.1 means 10%)."""\n'
        '    return subtotal * discount\n')
    (folder / "test_invoice.py").write_text(
        'import unittest\nfrom invoice import total_after_discount\n\n'
        'class InvoiceTests(unittest.TestCase):\n'
        '    def test_ten_percent_discount(self):\n'
        '        self.assertEqual(total_after_discount(100, 0.1), 90)\n\n'
        '    def test_no_discount(self):\n'
        '        self.assertEqual(total_after_discount(100, 0), 100)\n')
    (folder / "README.md").write_text(
        '# Hands practice project\n\n'
        'Run `python3 -m unittest -v`. The invoice calculation is intentionally wrong.\n'
        'Ask Hermes to fix invoice.py without changing the tests, then run the tests again.\n'
        'No dependencies or internet access are needed. This folder is disposable.\n')
    return (f"Practice project created: {folder}\n"
            f"On this machine: cd {shlex.quote(str(folder))}\n"
            "In your remote Hermes chat: /hands setup edit\n"
            "Run its command here, then /hands verify in the chat.\n"
            "Ask: Run python3 -m unittest -v, fix invoice.py without changing the tests, and rerun them.\n"
            "Inspect invoice.py locally. Press Ctrl-C in hands up to end access; /hands off returns chat to the server.\n"
            "Nothing was paired. You can delete this practice folder when finished.")
