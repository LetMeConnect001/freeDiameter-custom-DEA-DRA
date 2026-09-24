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
 * Phase 2.5 implements subscriber identifier pseudonymization FOR THIS
 * EXTENSION'S OWN LOG OUTPUT ONLY -- the real IMSI/User-Name is never
 * modified on the wire (the external partner legitimately needs it to do
 * its job, unlike Origin-Host/Route-Record/Session-Id). A deterministic,
 * reversible AES-256-SIV token is logged instead of the raw identifier, so
 * multiple log lines about the same subscriber stay correlatable for
 * debugging without ever printing PII, and an operator holding the
 * configured key can still recover the real value offline (with a separate
 * tool, not the running daemon) for a genuine incident investigation. See
 * extensions/app_dea/README for the full rationale.
 *
 * Phase 3 implements interconnect policy enforcement for messages FROM
 * external peers: a per-realm Application-Id allow-list (default-deny once
 * at least one rule is configured: an external realm with no matching rule
 * is rejected, matching real interconnect practice of only accepting
 * traffic from partners you have an explicit agreement with), and a fraud
 * check correlating a message's claimed Origin-Realm against the realm the
 * sending peer actually presented during CER/CEA (peer identity is
 * authenticated at the connection level; a mismatch means someone is using
 * an established connection to claim a realm that was not negotiated for
 * it). The fraud check's reaction (log-only vs. reject) is configurable,
 * defaulting to log-only so it can be safely enabled in an unfamiliar
 * network before committing to blocking traffic on it.
 *
 * Phase 4 (started with observability) implements privacy-aware operational
 * counters: bare integer counts of event categories (requests masked,
 * Session-Id pairings minted/reused, interconnect rejections, fraud
 * detections, ...), never any AVP value or identity -- safe to expose at
 * any log level. Dumped periodically (configurable interval) and on
 * SIGUSR2, following the same pattern as the dbg_monitor extension.
 *
 * See doc/app_dea.conf.sample for the configuration file format, and
 * extensions/app_dea/README for the architecture and the roadmap of the
 * remaining DEA/DRA features (high-availability, throttling, ...).
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

	int		pseudonymize_subscriber_id;	/* pseudonymize IMSI/User-Name in this extension's own logs (default: 0 -- opt-in, needs imsi_pseudonym_key) */
	uint8_t		imsi_pseudonym_key[64];		/* AES-256-SIV key (RFC 5297: 64 bytes = two 256-bit subkeys) */
	int		imsi_pseudonym_key_set;		/* whether imsi_pseudonym_key was configured */

	struct fd_list	interconnect_rules;	/* list of struct dea_interconnect_rule: per-realm Application-Id allow-lists */

	int		fraud_check_realm_consistency;	/* compare a message's Origin-Realm against the sending peer's CER/CEA realm (default: 0 -- opt-in) */
	int		fraud_reject_on_mismatch;	/* 0 (default): log only. 1: also reject the message. */

	uint32_t	stats_interval;	/* seconds between periodic counter dumps (default: 300). 0 disables the periodic dump (SIGUSR2 still works). */
};
extern struct dea_config * dea_conf;

/* An entry in dea_conf->internal_realms */
struct dea_realm {
	struct fd_list	chain;
	os0_t		name;
	size_t		len;
};

/* Phase 3: an Application-Id entry in a dea_interconnect_rule->allowed_apps */
struct dea_app_id {
	struct fd_list	chain;
	uint32_t	id;
};

/* Phase 3: a per-realm Application-Id allow-list entry in dea_conf->interconnect_rules.
 * A request from an external peer whose Origin-Realm matches `realm` must have its
 * Application-Id (message header, not an AVP) in `allowed_apps`, or it is rejected. An
 * external realm with NO matching rule at all is also rejected, as soon as at least one
 * interconnect_realm directive exists in the config (see dea_check_interconnect in
 * dea_policy.c and extensions/app_dea/README for the default-deny rationale). */
struct dea_interconnect_rule {
	struct fd_list	chain;
	os0_t		realm;
	size_t		realmlen;
	struct fd_list	allowed_apps;	/* list of struct dea_app_id */
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
extern struct dict_object * dea_avp_user_name;			/* base protocol, always resolvable */
extern struct dict_object * dea_avp_subscription_id;		/* RFC 4006 / dict_dcca, optional */
extern struct dict_object * dea_avp_subscription_id_type;	/* RFC 4006 / dict_dcca, optional */
extern struct dict_object * dea_avp_subscription_id_data;	/* RFC 4006 / dict_dcca, optional */

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

/* Phase 2.5: best-effort extraction of a subscriber identifier (Subscription-Id-Data with type
 * END_USER_IMSI, falling back to User-Name) from msg, encrypted with AES-256-SIV and hex-encoded
 * (dea_pseudonym.c), for use in THIS extension's own log lines only -- see the file header
 * comment above for why this never touches the wire. Returns 0 with *out_hex set to a malloc'd
 * string on success, or 0 with *out_hex == NULL if pseudonymization is disabled, no key is
 * configured, or no subscriber identifier was found in msg (all non-fatal, non-error cases). */
int dea_pseudonymize_subscriber_id(struct msg * msg, char ** out_hex);

/* Phase 3 (dea_policy.c). Both apply only to requests from external peers (see dea_fwd_req).
 * On a policy violation, the message is turned into an error answer in place and sent (same
 * fd_msg_new_answer_from_req + fd_msg_rescode_set + fd_msg_send idiom as app_redirect/rt_rewrite),
 * exactly like fd_rt_fwd_register's contract requires when a callback decides to fully take over
 * a message: *msg is set to NULL and *rejected is set to 1, telling the caller to stop processing
 * it any further. If *rejected is 0, msg was left untouched and forwarding continues normally. */
int dea_check_interconnect(struct msg ** msg, int * rejected);
int dea_check_fraud(struct msg ** msg, int * rejected);

/* Phase 4: privacy-aware operational counters (dea_stats.c). Every counter is a bare integer
 * count of an event category -- never a per-message value or AVP content -- safe to expose at
 * any log level or observability pipeline without re-introducing the leakage Phase 1/2/2.5 were
 * built to prevent. */
enum dea_stat_id {
	DEA_STAT_REQUESTS_SEEN = 0,
	DEA_STAT_EXTERNAL_REQUESTS,
	DEA_STAT_TOPOLOGY_MASKED,
	DEA_STAT_SESSION_ID_MINTED,
	DEA_STAT_SESSION_ID_REUSED,
	DEA_STAT_SUBSCRIBER_PSEUDONYMIZED,
	DEA_STAT_INTERCONNECT_ALLOWED,
	DEA_STAT_INTERCONNECT_REJECTED_NO_RULE,
	DEA_STAT_INTERCONNECT_REJECTED_APP,
	DEA_STAT_FRAUD_MISMATCH_DETECTED,
	DEA_STAT_FRAUD_REJECTED,
	DEA_STAT_COUNT	/* must stay last: array size for dea_stats.c's internal counters/names */
};

void dea_stats_inc(enum dea_stat_id id);
void dea_stats_dump(void);

/* Starts the periodic dump thread (if dea_conf->stats_interval > 0) and registers the SIGUSR2
 * on-demand dump handler. Call once from the extension entry point, after config parsing. */
int dea_stats_init(void);
/* Stops the periodic dump thread, if running. Call from fd_ext_fini. */
void dea_stats_fini(void);
