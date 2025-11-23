import json
import os
from pathlib import Path

builders = []
builder_names = []
root = Path("builders")
if root.exists():
    for path in sorted(p for p in root.iterdir() if p.is_dir()):
        config = path / "config.yaml"
        if config.exists():
            builders.append({"builder": path.name, "config": str(config)})
            builder_names.append(path.name)

repo_lc = os.environ["GITHUB_REPOSITORY"].lower()
matrix = {"include": builders}
with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
    handle.write(f"matrix={json.dumps(matrix)}\n")
    handle.write(f"has_builders={'true' if builders else 'false'}\n")
    handle.write(f"builder_names={json.dumps(builder_names)}\n")
    handle.write(f"repo_lc={repo_lc}\n")
