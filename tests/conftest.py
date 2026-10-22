import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "builders" / "common" / "python"))
sys.path.insert(0, str(repo_root / "builders" / "common"))
sys.path.insert(0, str(repo_root / ".github" / "scripts"))
sys.path.insert(0, str(repo_root))
