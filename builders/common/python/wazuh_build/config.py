from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from . import utils


class BuilderConfig:
    def __init__(self, path: Path):
        self.path = path
        self.data: Dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))

    @property
    def pipeline(self) -> Dict[str, Any]:
        return self.data.get("pipeline", {})

    @property
    def dependencies(self) -> Dict[str, List[str]]:
        deps = self.data.get("dependencies", {})
        return {k: list(v) for k, v in deps.items()} if isinstance(deps, dict) else {}

    def dependency_section(self, name: str) -> List[str]:
        deps = self.dependencies
        items = deps.get(name, [])
        return list(items) if isinstance(items, list) else []

    def build_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        build = self.data.get("build", {})
        if not isinstance(build, dict):
            return default
        value = build.get(key, default)
        return str(value) if value is not None else None


def resolve_artifact_dest(config_dir: Path, artifacts_cfg: Dict[str, Any], artifact_triplet: Optional[str]) -> Path:
    artifact_dest_cfg = artifacts_cfg.get("dest")
    if artifact_triplet:
        return (config_dir / "dist" / artifact_triplet).resolve()
    if artifact_dest_cfg:
        dest = Path(artifact_dest_cfg)
        if not dest.is_absolute():
            dest = (config_dir / dest).resolve()
        return dest
    return (config_dir / "dist").resolve()


def ensure_artifact_dest(path: Path) -> None:
    if path.exists():
        import shutil

        shutil.rmtree(path)
    utils.ensure_dir(path)
