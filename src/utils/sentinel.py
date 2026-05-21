import os
import sys
import time
import subprocess
import psutil
from pathlib import Path
from utils.logger import logger
from utils.platform import platform_info

def run_sentinel(main_pid: int):
    """
    Monitors the main Green Mold Cure process and restarts it if it dies.
    """
    logger.info(f"Sentinel started, monitoring PID: {main_pid}")

    # Create sentinel PID file
    sentinel_pid_file = platform_info.get_app_data_dir() / "sentinel.pid"
    with open(sentinel_pid_file, "w") as f:
        f.write(str(os.getpid()))

    try:
        main_process = psutil.Process(main_pid)
    except psutil.NoSuchProcess:
        logger.error(f"Main process {main_pid} not found. Sentinel exiting.")
        return

    while True:
        try:
            if not main_process.is_running() or main_process.status() == psutil.STATUS_ZOMBIE:
                logger.security("SENTINEL ALERT: Main process died. Restarting...", event_type="sentinel_action")
                restart_main()
                break # Sentinel will be restarted by the new main process
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.security("SENTINEL ALERT: Main process disappeared. Restarting...", event_type="sentinel_action")
            restart_main()
            break

        time.sleep(5)

def restart_main():
    """Restarts the main application."""
    main_script = Path(__file__).parent.parent / "main.py"
    # We use sys.executable to ensure we use the same python interpreter
    subprocess.Popen([sys.executable, str(main_script)])
    logger.info("Main process restart command issued.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sentinel.py <main_pid>")
        sys.exit(1)

    main_pid = int(sys.argv[1])
    run_sentinel(main_pid)
