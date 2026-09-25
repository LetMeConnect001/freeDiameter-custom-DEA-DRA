"""
FastAPI app: REST API for CRUD on rules, plus /api/preview (generate config without writing)
and /api/apply (generate, write to disk, send SIGUSR1 to freeDiameter). Serves the static
frontend from the same origin so there is no CORS configuration to get wrong -- one process,
one port, meant to run on the same host as freeDiameter (see reload.py's PID lookup, which
assumes local process visibility).
"""

import os

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

import config_generator
import daemon_config
import reload as reload_mod
import storage
from models import DeaIdentity, Peer, Rule

app = FastAPI(title="rt_rewrite rule manager")


@app.on_event("startup")
def on_startup() -> None:
    storage.init_db()


@app.get("/api/rules")
def list_rules():
    return storage.list_rules()


@app.get("/api/rules/{rule_id}")
def get_rule(rule_id: int):
    rule = storage.get_rule(rule_id)
    if rule is None:
        raise HTTPException(404, "Rule not found")
    return rule


@app.post("/api/rules")
def create_rule(rule: Rule):
    try:
        return storage.create_rule(rule)
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, str(e))


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, rule: Rule):
    try:
        updated = storage.update_rule(rule_id, rule)
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, str(e))
    if updated is None:
        raise HTTPException(404, "Rule not found")
    return updated


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int):
    if not storage.delete_rule(rule_id):
        raise HTTPException(404, "Rule not found")
    return {"ok": True}


@app.get("/api/preview")
def preview():
    """Generate the config text without writing or reloading anything -- lets the UI show what
    would be applied before the operator commits to it."""
    try:
        return {"config": config_generator.generate_config(storage.list_rules())}
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.post("/api/apply")
def apply_rules():
    try:
        config_text = config_generator.generate_config(storage.list_rules())
    except ValueError as e:
        raise HTTPException(422, str(e))

    try:
        result = reload_mod.apply_and_reload(config_text)
    except reload_mod.ReloadError as e:
        raise HTTPException(500, str(e))

    return {"ok": True, "config": config_text, **result}


@app.post("/api/backup/rt_rewrite")
def backup_rt_rewrite():
    try:
        return reload_mod.backup_rt_rewrite_config()
    except reload_mod.ReloadError as e:
        raise HTTPException(500, str(e))


@app.post("/api/backup/daemon")
def backup_daemon():
    try:
        return reload_mod.backup_daemon_config()
    except reload_mod.ReloadError as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Peers + DEA identity (Identity/Realm/ConnectPeer, in freeDiameter.conf)
#
# IMPORTANT: unlike rt_rewrite, the daemon has no live-reload for these -- Apply here only
# writes the file (with a backup taken first). Applying it requires a manual restart of
# freeDiameterd to take effect. The response's `restart_required: true` flag exists so the
# frontend never has to guess this, and must surface it, not paper over it.
# ---------------------------------------------------------------------------

@app.get("/api/peers")
def list_peers():
    return storage.list_peers()


@app.get("/api/peers/{peer_id}")
def get_peer(peer_id: int):
    peer = storage.get_peer(peer_id)
    if peer is None:
        raise HTTPException(404, "Peer not found")
    return peer


@app.post("/api/peers")
def create_peer(peer: Peer):
    try:
        return storage.create_peer(peer)
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, str(e))


@app.put("/api/peers/{peer_id}")
def update_peer(peer_id: int, peer: Peer):
    try:
        updated = storage.update_peer(peer_id, peer)
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, str(e))
    if updated is None:
        raise HTTPException(404, "Peer not found")
    return updated


@app.delete("/api/peers/{peer_id}")
def delete_peer(peer_id: int):
    if not storage.delete_peer(peer_id):
        raise HTTPException(404, "Peer not found")
    return {"ok": True}


@app.get("/api/identity")
def get_identity():
    identity = storage.get_identity()
    if identity is None:
        # Not configured yet through the UI -- not an error, the frontend shows an empty form.
        return None
    return identity


@app.put("/api/identity")
def set_identity(identity: DeaIdentity):
    return storage.set_identity(identity)


@app.get("/api/daemon-config/preview")
def preview_daemon_config():
    identity = storage.get_identity()
    if identity is None:
        raise HTTPException(422, "Set the DEA Identity and Realm before previewing.")
    try:
        return {"config": daemon_config.generate_managed_section(identity, storage.list_peers())}
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.post("/api/daemon-config/apply")
def apply_daemon_config():
    identity = storage.get_identity()
    if identity is None:
        raise HTTPException(422, "Set the DEA Identity and Realm before applying.")

    try:
        section = daemon_config.generate_managed_section(identity, storage.list_peers())
    except ValueError as e:
        raise HTTPException(422, str(e))

    try:
        result = reload_mod.write_daemon_config(section)
    except reload_mod.ReloadError as e:
        raise HTTPException(500, str(e))

    return {"ok": True, "config": section, "restart_required": True, **result}


# ---------------------------------------------------------------------------
# Peer discovery + live add (extensions/app_dea/dea_peer_mgmt.c)
# ---------------------------------------------------------------------------

@app.get("/api/discovered-peers")
def discovered_peers():
    """Candidates seen knocking (CER) but not yet configured -- read-only, does not affect
    whether they're accepted (see dea_peer_mgmt.c: the discovery callback always defers to the
    daemon's own default of rejecting unknown peers)."""
    return reload_mod.read_discovered_peers()


@app.post("/api/peers/{peer_id}/live-add")
def live_add_peer(peer_id: int):
    """Add an already-saved Peer live, via fd_peer_add() (SIGUSR2), without restarting
    freeDiameterd. Does NOT also write it into freeDiameter.conf -- if the daemon restarts later
    for any other reason, this peer will be gone unless the operator also uses "Écrire la
    config" to persist it. The two are deliberately separate actions."""
    peer = storage.get_peer(peer_id)
    if peer is None:
        raise HTTPException(404, "Peer not found")
    try:
        result = reload_mod.live_add_peer(peer)
    except reload_mod.ReloadError as e:
        raise HTTPException(500, str(e))
    return {"ok": True, **result}


@app.post("/api/discovered-peers/{diameter_id}/adopt")
def adopt_discovered_peer(diameter_id: str):
    """Turn a discovered candidate into a saved Peer (pre-filled from what its CER told us), so
    the operator can review/edit it in the normal peer form before deciding whether to live-add
    and/or persist it to freeDiameter.conf."""
    candidates = reload_mod.read_discovered_peers()
    match = next((c for c in candidates if c.get("diameter_id") == diameter_id), None)
    if match is None:
        raise HTTPException(404, "Candidate not found (it may have expired from the discovery list)")

    peer = Peer(diameter_id=match["diameter_id"], realm=match.get("realm") or None)
    return storage.create_peer(peer)


# Serve the frontend last, so it doesn't shadow the /api routes above.
_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="static")
