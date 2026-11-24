import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_control_has_existing_evidence():
    r = subprocess.run([sys.executable, str(ROOT / "scripts/compliance.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
