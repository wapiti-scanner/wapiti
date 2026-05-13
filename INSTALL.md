Introduction
============

All installation methods assume you already have Python 3.12, 3.13 or 3.14 on your system.

Wapiti is a command-line tool. You can install it from the Python Package Index (PyPI) or from the source code.
Using a virtual environment is highly recommended to avoid conflicts with other Python packages on your system.

# Installing Wapiti using pip (Recommended)

The easiest way to install the latest stable version of Wapiti is using pip:

```sh
pip install wapiti3
```

# Installing from source

If you have downloaded the source archive or cloned the repository, you can install it using:

```sh
pip install .
```

If you are using the provided Makefile:

```sh
make install
```

# Installing Wapiti using a virtual environment

To avoid breaking system dependencies, it is recommended to use a virtual environment:

1. Create a virtual environment:
   ```sh
   python -m venv wapiti3_env
   ```

2. Activate it:
   - On Linux/macOS:
     ```sh
     . wapiti3_env/bin/activate
     ```
   - On Windows:
     ```sh
     wapiti3_env\Scripts\activate
     ```

3. Install Wapiti:
   ```sh
   pip install wapiti3
   ```

# For Contributors

If you are a developer and want to run Wapiti without installing it, you can use the scripts located in the `bin/` folder.
Note that you must have all dependencies installed (see `pyproject.toml`).

```sh
python3 bin/wapiti -u http://example.com/
```

# Installation tutorials

You can find several YouTube videos showing Wapiti installation:

* on OpenSUSE : https://www.youtube.com/watch?v=RmF2Sr2B3ZA
* on Ubuntu : https://www.youtube.com/watch?v=TD5rehelHPY

Enjoy Wapiti.
