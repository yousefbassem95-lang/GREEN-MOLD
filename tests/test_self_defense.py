import os
import time
import shutil
import subprocess
import pytest
from pathlib import Path
from utils.integrity import integrity_monitor
from utils.platform import platform_info
from utils.logger import logger

@pytest.fixture
def monitor():
    # Use a temporary directory for testing
    test_root = Path("test_fortress")
    test_root.mkdir(exist_ok=True)

    # Create a dummy file
    dummy_file = test_root / "core_module.py"
    dummy_file.write_text("print('Secure core logic')")

    # Initialize monitor on this directory
    m = integrity_monitor
    m.root_dir = test_root
    m.db_path = test_root / "integrity_baseline.json"
    m.backup_dir = test_root / "integrity_backups"

    m.create_baseline()
    m.start_monitoring()

    yield m, test_root, dummy_file

    m.stop_monitoring()
    shutil.rmtree(test_root)

def test_integrity_check(monitor):
    m, root, dummy = monitor
    assert m.check_integrity() is True

    # Tamper with file
    dummy.write_text("print('Pwned!')")
    assert m.check_integrity() is False

def test_auto_recovery(monitor):
    m, root, dummy = monitor
    original_content = dummy.read_text()

    # Tamper with file
    dummy.write_text("print('Pwned!')")

    # Wait for watchdog to trigger (async)
    time.sleep(2)

    # Check if restored
    assert dummy.read_text() == original_content

def test_deletion_recovery(monitor):
    m, root, dummy = monitor

    # Delete file
    dummy.unlink()

    # Wait for watchdog
    time.sleep(2)

    # Check if restored
    assert dummy.exists()
    assert dummy.read_text() == "print('Secure core logic')"
