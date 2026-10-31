#!/usr/bin/env python3
"""Negative controls for the installed-boot driver's adopted S02 oracles.

These execute the actual fixture assertions on explicitly synthetic evidence.
They do not replace Nix evaluation or a real installed-entry VM run.
"""

import ast
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "boot-entries.nix"


def embedded_driver():
    source = FIXTURE.read_text()
    driver = source.split("    testScript = ''\n", 1)[1].rsplit("    '';", 1)[0]
    if "''" in driver:
        raise ValueError("premature Nix indented-string terminator in boot driver")
    substitutions = {
        '${if crashPoint == null then "None" else builtins.toJSON crashPoint}': "None",
        '${builtins.toJSON recoverer}': '"daemon"',
        '${if confirm then "True" else "False"}': "False",
        "${../template/planarian/overrides.nix}": "/nix/store/template",
    }
    for name in ("g1", "g2", "g3", "exports", "shim"):
        substitutions["${" + name + "}"] = "/nix/store/" + name
    for before, after in substitutions.items():
        driver = driver.replace(before, after)
    if "${" in driver:
        raise ValueError("unhandled Nix interpolation in boot-driver control")
    return ast.parse(textwrap.dedent(driver))


def subtest_body(title):
    matches = [
        node for node in ast.walk(embedded_driver())
        if isinstance(node, ast.With)
        and isinstance(node.items[0].context_expr, ast.Call)
        and isinstance(node.items[0].context_expr.func, ast.Name)
        and node.items[0].context_expr.func.id == "subtest"
        and node.items[0].context_expr.args[0].value == title
    ]
    if len(matches) != 1:
        raise ValueError("missing or duplicated boot-driver milestone oracle")
    return compile(ast.Module(body=matches[0].body, type_ignores=[]), str(FIXTURE), "exec")


class SyntheticMachine:
    """Fixture-assertion controls only; never represented as VM results."""

    def __init__(self, uptime=600):
        self.uptime = uptime
        self.booted = True

    def succeed(self, *commands):
        return str(self.uptime) if any("/proc/uptime" in command for command in commands) else ""

    def wait_until_succeeds(self, command, timeout):
        pass

    def shutdown(self):
        pass

    def start(self):
        self.booted = True


def evidence(state, *, known_good, floor, live_tested, uptime=600, admission=False, live=None):
    machine = SyntheticMachine(uptime)
    machine.booted = not admission
    return {
        "machine": machine,
        "submit": lambda slot: None,
        "wait_ready": lambda: None,
        "status": lambda: {"generation": 2, "known_good": known_good, "live_tested": live_tested},
        "transaction": lambda number: {"state": state, "live": state == "Promoted" if live is None else live},
        "floor": lambda: floor,
        "variable": lambda name: ("g2" if machine.booted else "g1") if name == "LoaderEntryDefault"
                    else ("" if machine.booted else "g2"),
        "profile_entry": lambda path: path,
        "paths": {1: "g1", 2: "g2", 3: "g3"},
        "g1_id": 1,
        "g2_id": 2,
    }


class InstalledBootFixtureContract(unittest.TestCase):
    def test_admission_rejects_early_commit_floor_livetested_or_confirmation(self):
        code = subtest_body("G2 admits its installed entry without committing before confirmation")
        exec(code, evidence("Promoted", known_good=1, floor=None, live_tested=None, admission=True))
        bad = [
            evidence("Committed", known_good=1, floor=2, live_tested=2, admission=True),
            evidence("Promoted", known_good=1, floor=2, live_tested=None, admission=True),
            evidence("Promoted", known_good=1, floor=None, live_tested=2, admission=True),
            evidence("Promoted", known_good=2, floor=None, live_tested=None, admission=True),
            evidence("Promoted", known_good=1, floor=None, live_tested=None, admission=True, live=False),
        ]
        for case in bad:
            with self.subTest(state=case["transaction"](1), status=case["status"](), floor=case["floor"]()):
                with self.assertRaises(AssertionError):
                    exec(code, case)

    def test_confirmation_requires_real_checkpoint_commit_floor_and_known_good(self):
        code = subtest_body("G2 confirms and commits only at the real ten-minute checkpoint")
        exec(code, evidence("Committed", known_good=2, floor=2, live_tested=None))
        bad = [
            evidence("Committed", known_good=2, floor=2, live_tested=None, uptime=599),
            evidence("Promoted", known_good=2, floor=2, live_tested=None),
            evidence("Committed", known_good=1, floor=2, live_tested=None),
            evidence("Committed", known_good=2, floor=None, live_tested=None),
            evidence("Committed", known_good=2, floor=2, live_tested=2),
            evidence("Committed", known_good=2, floor=2, live_tested=None, live=True),
        ]
        for case in bad:
            with self.subTest(state=case["transaction"](1), status=case["status"](), floor=case["floor"]()):
                with self.assertRaises(AssertionError):
                    exec(code, case)

    def test_actual_terminal_helper_establishes_terminal_and_propagates_status(self):
        source = FIXTURE.read_text()
        helper = source.split('onTerminal = pkgs.writeScriptBin "boot-test-terminal" \'\'\n', 1)[1]
        helper = textwrap.dedent(helper.split("\n    '';", 1)[0])
        helper = helper.replace("#!${pkgs.python3}/bin/python3", "#!/usr/bin/env python3")
        ast.parse(helper)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "terminal.py"
            path.write_text(helper)
            code = ('import os; fd=os.open("/dev/tty",os.O_RDWR); '
                    'assert os.isatty(fd); assert os.getsid(0)==os.getpid(); print("terminal verified")')
            run = subprocess.run([sys.executable, str(path), sys.executable, "-c", code],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn(b"terminal verified", run.stdout)
            run = subprocess.run([sys.executable, str(path), sys.executable, "-c", "raise SystemExit(7)"],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 7, run.stderr)
            run = subprocess.run([sys.executable, str(path), sys.executable, "-c", 'import os; os.write(1,b"x"*600000)'],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn(b"512 KiB", run.stderr)


if __name__ == "__main__":
    unittest.main()
