"""
DefendX — Entry Point
Launches the DefendX AI Insider Threat Detection desktop application.
"""

import os
import sys

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def main():
    """Main entry point for DefendX."""
    print("=" * 50)
    print("  DefendX — AI Insider Threat Detection")
    print("  Starting application...")
    print("=" * 50)
    
    from app.main import launch_app
    launch_app()


if __name__ == '__main__':
    main()
