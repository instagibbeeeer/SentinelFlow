import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str):
    path = ROOT / relative_path

    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module

    root_dir = str(ROOT)
    inserted = root_dir not in sys.path

    if inserted:
        sys.path.insert(0, root_dir)

    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(root_dir)

    return module
