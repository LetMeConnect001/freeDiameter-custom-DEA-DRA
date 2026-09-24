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
import reload as reload_mod
import storage
from models import Rule

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


# Serve the frontend last, so it doesn't shadow the /api routes above.
_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
app.mount("/", StaticFiles(directory=_frontend_dir, html=True), name="static")
