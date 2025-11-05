import subprocess
import sys


def install_browser():
    """Installs the firefox browser for playwright."""
    try:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "firefox"],
            check=True,
            capture_output=True,
            text=True
        )
        print("Successfully installed firefox for playwright.")
    except subprocess.CalledProcessError as e:
        print(f"Error installing firefox for playwright: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: playwright not found. Make sure it's installed.")
        sys.exit(1)
