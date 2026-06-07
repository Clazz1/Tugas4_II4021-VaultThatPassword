from __future__ import annotations

import json
from pathlib import Path


class LocalStore:
    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, user_id: str) -> Path:
        safe = "".join(ch for ch in user_id if ch.isalnum() or ch in ("-", "_", "."))
        if not safe:
            raise ValueError("user id contains no usable characters")
        return self.base_dir / f"{safe}.json"

    def exists(self, user_id: str) -> bool:
        return self.path_for(user_id).exists()

    def load(self, user_id: str) -> dict:
        path = self.path_for(user_id)
        if not path.exists():
            raise KeyError(f"local data for {user_id!r} was not found")
        return json.loads(path.read_text(encoding="utf-8"))

    def save(self, user_id: str, data: dict) -> None:
        self.path_for(user_id).write_text(json.dumps(data, indent=2), encoding="utf-8")
