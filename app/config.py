"""Application settings loaded explicitly at startup, never during module import."""

import os
from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    fireworks_api_key: str = field(default="", repr=False)
    fireworks_model: str = ""
    typesafe_api_key: str = field(default="", repr=False)
    typesafe_model: str = "jev-latest"
    github_token: str = field(default="", repr=False)
    port: int = 8000
    max_files: int = 40
    max_file_bytes: int = 24_000
    max_total_bytes: int = 180_000

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if environ is None else environ
        port = int(env.get("PORT", "8000"))
        if not 1 <= port <= 65535:
            raise ValueError("PORT must be between 1 and 65535.")
        return cls(
            fireworks_api_key=env.get("FIREWORKS_API_KEY", ""),
            fireworks_model=env.get("FIREWORKS_MODEL", ""),
            typesafe_api_key=env.get("TYPESAFE_API_KEY", ""),
            typesafe_model=env.get("TYPESAFE_MODEL") or "jev-latest",
            github_token=env.get("GITHUB_TOKEN", ""),
            port=port,
        )

    @property
    def provider_status(self) -> dict[str, bool]:
        return {
            "fireworks": bool(self.fireworks_api_key and self.fireworks_model),
            "jev": bool(self.typesafe_api_key),
        }
