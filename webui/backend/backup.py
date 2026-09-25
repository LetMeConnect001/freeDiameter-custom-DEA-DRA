"""
Timestamped backups of the config files this webui writes to, taken before every write so a bad
Apply is always recoverable from the filesystem (this webui has no config history/versioning of
its own -- see webui/README.md's "Known limitations" -- a plain file copy is the whole mechanism).
"""

import os
import shutil
from datetime import datetime, timezone
from typing import Optional

BACKUP_DIR_ENV = "WEBUI_BACKUP_DIR"


def _backup_dir(conf_path: str) -> str:
    configured = os.environ.get(BACKUP_DIR_ENV)
    d = configured if configured else os.path.join(os.path.dirname(conf_path), "webui-backups")
    os.makedirs(d, exist_ok=True)
    return d


def backup_file(conf_path: str) -> Optional[str]:
    """Copy conf_path into the backup directory with a timestamp suffix. Returns the backup
    path, or None if conf_path does not exist yet (nothing to back up on a first-ever write)."""
    if not os.path.exists(conf_path):
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = os.path.basename(conf_path)
    dest = os.path.join(_backup_dir(conf_path), f"{base}.{ts}.bak")
    shutil.copy2(conf_path, dest)
    return dest
