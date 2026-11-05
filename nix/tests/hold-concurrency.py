#!/usr/bin/env python3
"""D16: run the built hold script against a deterministic concurrent nft stub.

Only the runtime root and PATH change. No real systemd or nft commands run.
The last old lift pauses at table deletion while a different unit's apply
either waits for the shared lock or, with the fix removed, completes first.
"""

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time


def wait_for(predicate, message):
    deadline = time.monotonic() + 10
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(0.01)


def main():
    source = Path(sys.argv[1]).read_text()
    real_flock = sys.argv[2]
    shell = source.splitlines()[0]
    with tempfile.TemporaryDirectory(prefix="hold-concurrency-") as tmp:
        root = Path(tmp)
        stub = root / "bin"
        stub.mkdir()
        hold = root / "hold"
        rendered = source.replace("/run/planarian", str(root / "run"))
        rendered = rendered.replace("\nPATH=", f"\nPATH={stub}:", 1)
        assert rendered != source, "the built script has no runtime root or PATH"
        hold.write_text(rendered)
        hold.chmod(0o755)

        def executable(name, body):
            path = stub / name
            path.write_text(shell + "\n" + body)
            path.chmod(0o755)

        executable("nft", '''
if [ "$1" = delete ]; then
  touch "$HOLD_TEST_ROOT/delete-pending"
  for _ in $(seq 1000); do
    [ -e "$HOLD_TEST_ROOT/continue-delete" ] && break
    sleep 0.01
  done
  [ -e "$HOLD_TEST_ROOT/continue-delete" ] || exit 1
  rm -f "$HOLD_TEST_ROOT/table"
  exit 0
fi
[ "$*" = '-f -' ] || exit 1
cat > "$HOLD_TEST_ROOT/table"
''')
        # Signal that B reached the lock before waiting on A. Without the
        # fix B never invokes flock; its completion selects the bad order.
        executable("flock", '''
touch "$HOLD_TEST_ROOT/locking-$HOLD_TEST_CALL"
exec ''' + shlex.quote(real_flock) + ''' "$@"
''')
        for name in ("loginctl", "ss"):
            executable(name, "exit 0\n")
        markers = root / "run" / "hold"
        markers.mkdir(parents=True)
        (markers / "A").touch()
        (root / "table").write_text("the old hold's table\n")
        env = dict(os.environ, HOLD_TEST_ROOT=str(root))
        children = []
        try:
            lifting = subprocess.Popen([str(hold), "lift", "A"], env=dict(env, HOLD_TEST_CALL="A"))
            children.append(lifting)
            wait_for(lambda: (root / "delete-pending").exists(), "A did not reach table deletion")
            applying = subprocess.Popen([str(hold), "apply", "B"], env=dict(env, HOLD_TEST_CALL="B"))
            children.append(applying)
            wait_for(lambda: (root / "locking-B").exists() or applying.poll() is not None,
                     "B neither reached the lock nor completed")
            if (root / "locking-B").exists():
                assert not (markers / "B").exists(), "B changed markers outside the shared lock"
            (root / "continue-delete").touch()
            assert lifting.wait(timeout=10) == 0
            assert applying.wait(timeout=10) == 0
            assert (markers / "B").exists(), "B's hold marker is missing"
            assert (root / "table").exists(), "a concurrent lift deleted B's hold table"
            assert "policy drop" in (root / "table").read_text(), "B's table does not hold traffic"
            assert not (markers / "A").exists(), "A's lifted marker remains"
            print("ok: a last lift racing another apply preserves the new hold's table")
        finally:
            (root / "continue-delete").touch()
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait()


if __name__ == "__main__":
    main()
