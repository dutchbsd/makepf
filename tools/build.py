"""Build a standalone executable archive using only the standard library."""

import argparse
from pathlib import Path
import shutil
import sys
import tempfile
import zipapp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable, help="runtime interpreter (default: the Python running this build)")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    destination = root / "dist" / "makepf"
    destination.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory)
        shutil.copytree(root / "makepf", source / "makepf", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copyfile(root / "LICENSE", source / "LICENSE")
        (source / "__main__.py").write_text("from makepf.cli import main\nmain()\n", encoding="utf-8")
        zipapp.create_archive(source, destination, interpreter=args.python, compressed=True)
    print(destination)


if __name__ == "__main__":
    main()
