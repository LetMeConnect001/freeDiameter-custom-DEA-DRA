"""
Write the generated rt_rewrite.conf to disk and trigger a live reload.

rt_rewrite supports config reload on SIGUSR1 (extensions/rt_rewrite/rt_rewrite.c, registered via
fd_event_trig_regcb(SIGUSR1, MODULE_NAME, sig_hdlr) -- see doc/rt_rewrite.conf.sample: "This
extension supports configuration reload at runtime. Send signal SIGUSR1 to the process to cause
the process to reload its config."). This module writes the file, then finds the freeDiameter
process and sends it that signal -- no restart needed.
"""

import os
import signal
import subprocess

CONF_PATH_ENV = "RT_REWRITE_CONF_PATH"
PID_FILE_ENV = "FREEDIAMETER_PID_FILE"
PROCESS_NAME_ENV = "FREEDIAMETER_PROCESS_NAME"
DEFAULT_PROCESS_NAME = "freeDiameterd"


class ReloadError(Exception):
    pass


def _conf_path() -> str:
    path = os.environ.get(CONF_PATH_ENV)
    if not path:
        raise ReloadError(
            f"{CONF_PATH_ENV} is not set -- point it at the rt_rewrite config file path "
            f"referenced by your freediameter.conf's LoadExtension directive for rt_rewrite."
        )
    return path


def _find_pid() -> int:
    """Prefer a PID file if configured (exact, no ambiguity). Fall back to `pgrep -f` against
    the configured (or default) process name -- this can match more than one process if several
    freeDiameter instances run on the same host; we refuse to guess which one in that case."""
    pidfile = os.environ.get(PID_FILE_ENV)
    if pidfile:
        if not os.path.exists(pidfile):
            raise ReloadError(f"{PID_FILE_ENV} is set to '{pidfile}' but that file does not exist")
        with open(pidfile) as f:
            content = f.read().strip()
        try:
            return int(content)
        except ValueError:
            raise ReloadError(f"PID file '{pidfile}' does not contain a valid integer PID")

    proc_name = os.environ.get(PROCESS_NAME_ENV, DEFAULT_PROCESS_NAME)
    result = subprocess.run(["pgrep", "-f", proc_name], capture_output=True, text=True)
    pids = [p for p in result.stdout.split() if p]

    if not pids:
        raise ReloadError(
            f"No running process found matching '{proc_name}' (checked via `pgrep -f`). "
            f"Set {PID_FILE_ENV} or {PROCESS_NAME_ENV} if freeDiameter runs under a different name."
        )
    if len(pids) > 1:
        raise ReloadError(
            f"Multiple processes match '{proc_name}' (pids: {', '.join(pids)}) -- refusing to "
            f"guess which one to signal. Set {PID_FILE_ENV} to disambiguate."
        )
    return int(pids[0])


def write_config(config_text: str) -> str:
    """Write config_text to the configured path. Writes to a temp file in the same directory
    and renames it into place (os.replace is atomic on POSIX for same-filesystem renames), so a
    reader (or rt_rewrite re-reading on SIGUSR1) never sees a half-written file."""
    conf_path = _conf_path()
    tmp_path = conf_path + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(config_text)
    os.replace(tmp_path, conf_path)
    return conf_path


def apply_and_reload(config_text: str) -> dict:
    conf_path = write_config(config_text)
    pid = _find_pid()
    os.kill(pid, signal.SIGUSR1)
    return {"conf_path": conf_path, "pid": pid}
