# rt_rewrite Rule Manager (webui)

A small local web app to create/edit/delete AVP manipulation rules through a form instead of
hand-writing `rt_rewrite.conf`, and apply them live (write the file + trigger `rt_rewrite`'s
existing SIGUSR1 config reload -- no restart of freeDiameter needed).

This does **not** replace or modify `extensions/rt_rewrite` itself -- it is a config generator
and reload trigger for the rule engine that already ships in this repo. The rule model (Move /
Delete / Add, with an optional condition) maps 1:1 onto `rt_rewrite`'s real MAP/DROP/ADD/IF
grammar (`extensions/rt_rewrite/rt_rewrite_conf.y`), not onto any other product's rule set.

## Requirements

- Runs on the **same host** as the freeDiameter process (it needs local filesystem access to
  write the config file, and sends a Unix signal to the process by PID).
- Python 3.9+.

## Setup

```sh
cd webui/backend
python3 -m venv venv
./venv/bin/pip install -r requirements.txt
```

## Configuration (environment variables)

| Variable | Required | Meaning |
|---|---|---|
| `RT_REWRITE_CONF_PATH` | yes | Path to the rt_rewrite config file, exactly as referenced by your `freediameter.conf`'s `LoadExtension` line for rt_rewrite. |
| `FREEDIAMETER_PID_FILE` | no | Path to a file containing freeDiameter's PID. Preferred if you have one -- exact, no ambiguity. |
| `FREEDIAMETER_PROCESS_NAME` | no | Process name to search for via `pgrep -f` if no PID file is set. Default: `freeDiameterd`. |
| `RULES_DB_PATH` | no | Where to store the SQLite rules database. Default: `webui/backend/rules.db`. |

## Running

```sh
cd webui/backend
RT_REWRITE_CONF_PATH=/etc/freeDiameter/rt_rewrite.conf \
FREEDIAMETER_PID_FILE=/var/run/freeDiameter.pid \
./venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/` in a browser on the same host (or over SSH port-forwarding /
your internal network if you prefer not to expose it further -- there is no authentication
built in, see "Known limitations" below).

## What the UI gives you

- A form for each rule: **Move** (MAP), **Delete** (DROP), **Add** (ADD), with an optional
  single condition (`IF <avp> <op> <value>`, operators `< <= = >= >`, matching what the grammar
  actually supports -- one condition per rule, not several combined).
- A live preview of the generated config text before you commit to anything.
- **Apply and reload**: writes the file atomically (temp file + rename) and sends `SIGUSR1` to
  the freeDiameter process, triggering `rt_rewrite`'s own live config reload.

## Known limitations

- **No authentication.** Anyone who can reach the HTTP port can rewrite your Diameter message
  manipulation rules and trigger a reload. Bind it to `127.0.0.1` and reach it over SSH
  port-forwarding, or put it behind a reverse proxy with auth, unless it only ever runs on a
  host you fully trust and control access to.
- **No config history / rollback.** Each Apply overwrites the target file. If you need to revert,
  the previous rule set is only recoverable from whatever backup/VCS you keep of the conf file
  yourself.
- **AVP names are not validated against a dictionary.** The UI does not check that an AVP name
  you type actually exists in freeDiameter's loaded dictionaries -- a typo will produce a config
  that `rt_rewrite` rejects on reload (check the freeDiameter log). A dictionary-aware
  autocomplete would need the backend to either parse the same dictionary definitions freeDiameter
  loads, or query a running instance for them -- not implemented.
- **Single freeDiameter instance only.** `FREEDIAMETER_PID_FILE`/`FREEDIAMETER_PROCESS_NAME`
  target one process; running this against a multi-instance host requires disambiguating
  yourself (a PID file per instance, one webui instance per target).
