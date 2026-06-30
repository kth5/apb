"""Configuration loading."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from apb.constants import DEFAULT_CONFIG_PATHS

logger = logging.getLogger(__name__)


def load_config(config_path: Optional[Path] = None, *, strict: bool = False) -> Dict[str, Any]:
    """Load configuration from standard APB config file locations."""
    config_locations = list(DEFAULT_CONFIG_PATHS)
    if config_path:
        config_locations.insert(0, Path(config_path))

    for config_file in config_locations:
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as handle:
                    return json.load(handle)
            except (json.JSONDecodeError, OSError) as exc:
                if strict:
                    logger.error("Error loading config from %s: %s", config_file, exc)
                continue

    if strict:
        logger.error("No configuration file found")
        return {"servers": {}}

    return {
        "servers": {"x86_64": ["http://localhost:8000"]},
        "default_server": "http://localhost:8000",
        "default_arch": "x86_64",
        "output_dir": "./output",
        "farm_url": "http://localhost:8080",
    }
