"""
Generate the Identity/Realm/ConnectPeer section of freeDiameter.conf and merge it into the
existing file without touching anything else (TLS_Cred, TLS_CA, LoadExtension, timers, etc. are
all set up by hand and must survive untouched).

Grammar generated against here is read directly from libfdcore/fdd.y (the real freeDiameter.conf
parser), not guessed from doc/freediameter.conf.sample's comments:

    identity:  IDENTITY '=' QSTRING ';'
    realm:     REALM '=' QSTRING ';'
    ConnectPeer '=' QSTRING peerinfo ';'
    peerinfo:  /* empty */ | '{' peerparams '}'
    peerparams: peerparams NOIP ';' | NOIP6 ';' | NOTCP ';' | NOSCTP ';' | PREFERTCP ';'
              | OLDTLS ';' | NOTLS ';' | REALM '=' QSTRING ';' | PORT '=' INTEGER ';'
              | TCTIMER '=' INTEGER ';' | TWTIMER '=' INTEGER ';' | TLS_PRIO '=' QSTRING ';'
              | CONNTO '=' QSTRING ';'

Unlike rt_rewrite.conf (which the webui owns entirely), freeDiameter.conf is only PARTLY
webui-managed: everything outside the marked section below is left exactly as found.

IMPORTANT: unlike rt_rewrite, the core daemon has no live-reload signal for Identity/Realm/peers
-- these only take effect on a full daemon restart. Callers must not imply otherwise.
"""

from typing import List

from models import DeaIdentity, Peer

BEGIN_MARKER = "# >>> BEGIN WEBUI MANAGED SECTION -- do not edit by hand, regenerated on Apply <<<"
END_MARKER = "# >>> END WEBUI MANAGED SECTION <<<"


def _escape(value: str) -> str:
    """fdd.l's QSTRING follows the same `\"[^\"\\n]*\"` pattern as every other Flex/Bison config
    parser in this codebase: no escape sequences, so a value containing a quote or newline
    cannot be safely represented and must be refused rather than silently mangled."""
    if ('"' in value) or ("\n" in value):
        raise ValueError(f"Value {value!r} contains a double-quote or newline, which the "
                          f"freeDiameter.conf format cannot represent")
    return value


def generate_peer_block(peer: Peer) -> str:
    params: List[str] = []

    if peer.no_ip:
        params.append("No_IP;")
    if peer.no_ipv6:
        params.append("No_IPv6;")
    if peer.no_tcp:
        params.append("No_TCP;")
    if peer.no_sctp:
        params.append("No_SCTP;")
    if peer.prefer_tcp:
        params.append("Prefer_TCP;")
    if peer.tls_old_method:
        params.append("TLS_old_method;")
    if peer.no_tls:
        params.append("No_TLS;")
    if peer.realm:
        params.append(f'Realm = "{_escape(peer.realm)}";')
    if peer.port is not None:
        params.append(f"Port = {peer.port};")
    if peer.tc_timer is not None:
        params.append(f"TcTimer = {peer.tc_timer};")
    if peer.tw_timer is not None:
        params.append(f"TwTimer = {peer.tw_timer};")
    if peer.tls_prio:
        params.append(f'TLS_Prio = "{_escape(peer.tls_prio)}";')
    for ct in peer.connect_to:
        params.append(f'ConnectTo = "{_escape(ct)}";')

    head = f'ConnectPeer = "{_escape(peer.diameter_id)}"'
    if params:
        return f"{head} {{ {' '.join(params)} }};"
    return f"{head};"


def generate_managed_section(identity: DeaIdentity, peers: List[Peer]) -> str:
    lines = [
        f'Identity = "{_escape(identity.identity)}";',
        f'Realm = "{_escape(identity.realm)}";',
        "",
    ]
    for p in peers:
        if p.enabled:
            lines.append(generate_peer_block(p))
    return "\n".join(lines) + "\n"


def merge_managed_section(existing_text: str, managed_section: str) -> str:
    """Replace the content between BEGIN_MARKER/END_MARKER with managed_section, or append a
    new marked block at the end of the file if none exists yet. Everything outside the markers
    (TLS_Cred, LoadExtension, timers, comments, ...) is preserved verbatim."""
    block = f"{BEGIN_MARKER}\n{managed_section}{END_MARKER}\n"

    has_begin = BEGIN_MARKER in existing_text
    has_end = END_MARKER in existing_text

    if has_begin and has_end:
        pre, _, rest = existing_text.partition(BEGIN_MARKER)
        _, _, post = rest.partition(END_MARKER)
        # Strip a single leading newline left behind on `post` so we don't accumulate blank
        # lines across repeated applies.
        if post.startswith("\n"):
            post = post[1:]
        return pre + block + post

    if has_begin != has_end:
        raise ValueError(
            "freeDiameter.conf contains only one of the WEBUI MANAGED SECTION markers -- it was "
            "likely edited by hand in a way that broke the pair. Fix or remove the stray marker "
            "before applying from the web UI."
        )

    # First time: append at the end.
    sep = "" if existing_text.endswith("\n\n") else ("\n" if existing_text.endswith("\n") else "\n\n")
    return existing_text + sep + block
