/*
 * app_dea : Diameter Edge Agent extension for freeDiameter.
 *
 * Phase 1 implements topology hiding for messages relayed from an internal
 * (trusted) realm towards any other realm: the Origin-Host is replaced with
 * a configured pseudonym identity, and Route-Record AVPs added by internal
 * peers are stripped and replaced with that same pseudonym.
 *
 * Phase 2 implements Session-Id pseudonymization: for the same internal ->
 * external crossing, the Session-Id AVP is replaced with a generated
 * pseudonym for the lifetime of the Diameter session (which spans many
 * request/answer transactions), and consistently rewritten back and forth
 * on every subsequent message of that session, in both directions. This is
 * OPT-IN (see doc/app_dea.conf.sample) because it deviates from the base
 * protocol's expectation that relays do not modify Session-Id (RFC 6733) --
 * see extensions/app_dea/README for the tradeoffs.
 *
 * See doc/app_dea.conf.sample for the configuration file format, and
 * extensions/app_dea/README for the architecture and the roadmap of the
 * remaining DEA/DRA features (IMSI mapping, fraud detection,
 * high-availability, observability, ...).
 */

#include <freeDiameter/extension.h>

/* Extension configuration, built while parsing the config file (dea_conf.y) */
struct dea_config {
	os0_t		hidden_id;		/* Identity presented to external peers instead of real Origin-Host / Route-Record entries. NULL = topology hiding disabled. */
	size_t		hidden_id_len;

	struct fd_list	internal_realms;	/* list of struct dea_realm: realms considered internal/trusted */

	int		hide_origin_host;	/* mask Origin-Host on egress requests leaving the internal realms (default: 1) */
	int		hide_route_record;	/* strip/replace Route-Record entries added by internal peers (default: 1) */

	int		hide_session_id;	/* mask Session-Id AVP for the life of the session (default: 0 -- opt-in, deviates from RFC 6733 relay behavior) */
	uint32_t	session_id_lifetime;	/* seconds of inactivity before a Session-Id pairing expires (default: 86400) */
};
extern struct dea_config * dea_conf;

/* An entry in dea_conf->internal_realms */
struct dea_realm {
	struct fd_list	chain;
	os0_t		name;
	size_t		len;
};

/* Per-transaction data attached to a request and retrievable from its matching answer
 * (see fd_hook_data_register / fd_hook_get_pmd / fd_hook_get_request_pmd in libfdcore.h).
 * The framework allocates and frees this automatically for the lifetime of the request/answer
 * transaction; it does NOT survive across a whole Diameter session (multiple transactions) --
 * a persistent store is needed for that, see the Session-Id masking item in the README roadmap. */
struct fd_hook_permsgdata {
	int	masked;				/* whether this request was topology-hidden */
	os0_t	orig_origin_host;		/* real Origin-Host of the internal peer, saved before masking */
	size_t	orig_origin_host_len;
};
extern struct fd_hook_data_hdl * dea_hook_hdl;

/* Phase 2: state attached to a freeDiameter `struct session` object (real or masked side of a
 * Session-Id pairing), via fd_sess_handler_create / fd_sess_state_store / fd_sess_state_retrieve.
 * This is the concrete definition of the opaque type libfdproto.h asks each extension to declare
 * (see "struct sess_state" in libfdproto.h, "declare this in your own extension"). Each side of a
 * pairing stores the *other* side's Session-Id string:
 *   - stored on the real session: the masked pseudonym to present externally.
 *   - stored on the masked session: the real Session-Id to restore internally.
 * Unlike struct fd_hook_permsgdata (one request/answer transaction), this survives for the whole
 * Diameter session, bounded by session_id_lifetime inactivity (see dea_conf.hide_session_id). */
struct sess_state {
	os0_t	peer_sid;
	size_t	peer_sid_len;
};
extern struct session_handler * dea_sid_hdl;

/* AVP dictionary objects resolved once at extension load (app_dea.c) */
extern struct dict_object * dea_avp_origin_host;
extern struct dict_object * dea_avp_origin_realm;
extern struct dict_object * dea_avp_destination_realm;
extern struct dict_object * dea_avp_route_record;
extern struct dict_object * dea_avp_session_id;

/* Parse the configuration file (dea_conf.y / dea_conf.l) */
int dea_conf_handle(char * conffile);

/* Returns 1 if the realm (realmlen bytes at realm) matches one of the configured internal realms */
int dea_is_internal_realm(uint8_t * realm, size_t realmlen);

/* Topology hiding forwarding callbacks (dea_hiding.c), registered with fd_rt_fwd_register */
int dea_fwd_req(void * cbdata, struct msg ** msg);
int dea_fwd_ans(void * cbdata, struct msg ** msg);

/* Phase 2: Session-Id pseudonymization (dea_hiding.c).
 * may_mint: 1 to allow creating a brand new masked pairing if none exists yet for this message's
 * session (only ever passed from a confirmed internal->external request); 0 to only reuse an
 * existing pairing, never fabricate one (external->internal requests, and all answers). */
int dea_rewrite_session_id(struct msg * msg, int may_mint);

/* Session handler cleanup callback (must free the sess_state, see fd_sess_handler_create doc) */
void dea_sid_cleanup(struct sess_state * st, os0_t sid, void * opaque);
