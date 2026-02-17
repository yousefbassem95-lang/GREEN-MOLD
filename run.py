#!/usr/bin/env python3
"""
Green Mold Cure Launcher
Run this script from the project root directory to start the application.
"""

import sys
from pathlib import Path

# Add src directory to Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Import and run
from main import main

if __name__ == "__main__":
    main()
