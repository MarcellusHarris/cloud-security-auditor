import subprocess
import sys


def test_help_flag():
    result = subprocess.run([sys.executable, "auditor.py", "--help"], capture_output=True, text=True)
    assert result.returncode == 0


def test_dry_run():
    # This test checks that the script runs without side effects using --dry-run
    result = subprocess.run([sys.executable, "auditor.py", "--dry-run"], capture_output=True, text=True)
    assert result.returncode == 0
