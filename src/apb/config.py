"""Configuration loading."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from apb.constants import DEFAULT_CONFIG_PATHS, DEFAULT_FARM_URL, DEFAULT_SERVER_URL

logger = logging.getLogger(__name__)


def load_config_with_source(
    config_path: Optional[Path] = None, *, strict: bool = False
) -> Tuple[Dict[str, Any], Optional[Path]]:
    """Configuration from the first readable standard location, and the file it came from (None for defaults).

    Files that exist but cannot be read or parsed are skipped with a warning (an error when strict).
    """
    config_locations = list(DEFAULT_CONFIG_PATHS)
    if config_path:
        config_locations.insert(0, Path(config_path))

    log_unusable = logger.error if strict else logger.warning
    for config_file in config_locations:
        if not config_file.exists():
            continue
        try:
            with open(config_file, "r", encoding="utf-8") as handle:
                return json.load(handle), config_file
        except (json.JSONDecodeError, OSError) as exc:
            log_unusable("Ignoring config file %s: %s", config_file, exc)

    if strict:
        logger.error("No configuration file found")
        return {"servers": {}}, None

    return {
        "servers": {"x86_64": [DEFAULT_SERVER_URL]},
        "default_server": DEFAULT_SERVER_URL,
        "default_arch": "x86_64",
        "output_dir": "./output",
        "farm_url": DEFAULT_FARM_URL,
    }, None


def load_config(config_path: Optional[Path] = None, *, strict: bool = False) -> Dict[str, Any]:
    """Load configuration from standard APB config file locations."""
    return load_config_with_source(config_path, strict=strict)[0]
