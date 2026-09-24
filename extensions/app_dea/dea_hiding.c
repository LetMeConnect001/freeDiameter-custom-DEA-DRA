/*
 * app_dea : topology hiding logic.
 *
 * dea_fwd_req is registered with fd_rt_fwd_register(..., RT_FWD_REQ, ...): it runs for every
 * request the daemon forwards to another peer, AFTER the daemon has already added a Route-Record
 * AVP for the peer that sent us the message (this is done unconditionally by the core, see
 * p_psm.c) and BEFORE the routing-out logic picks the next hop / filters candidates using
 * Route-Record (see libfdcore.h "ROUTING" section). So by the time this callback runs, masking
 * the Route-Record chain here is both necessary (the real chain is already present) and safe
 * (routing-out will use whatever we leave in the message).
 *
 * dea_fwd_ans is registered with RT_FWD_ANS: it runs for the matching answer. The daemon
 * associates every answer with its request via the Hop-by-Hop Id automatically (fd_msg_answ_associate,
 * called from p_psm.c for every received answer), so fd_hook_get_request_pmd reliably retrieves
 * the per-message data we attached to the request in dea_fwd_req, for the lifetime of that single
 * transaction.
 *
 * Phase 2 (Session-Id pseudonymization) uses a different, longer-lived mechanism: freeDiameter's
 * own session store (fd_sess_* in libfdproto.h), via fd_msg_sess_get() on the live struct msg
 * being forwarded. This is deliberate: fd_msg_sess_get() ties the returned struct session's
 * message refcount to the real struct msg flowing through the daemon, so it is reclaimed
 * correctly by the framework itself. Minting a brand new masked Session-Id uses fd_sess_fromsid()
 * instead of fd_sess_new(): fd_sess_new() pins the new session with an initial message refcount
 * of 1 that is only released once some live struct msg later attaches to it via fd_msg_sess_get()
 * -- something our synthetic masked session has no guarantee of ever getting on its own, which
 * would otherwise leak `struct session` objects one per session ever seen. fd_sess_fromsid() does
 * not touch that refcount (confirmed in libfdproto/sessions.c), so we generate the Session-Id
 * string ourselves (mirroring fd_sess_new()'s own RFC 6733 SS8.8 format) and register it with
 * fd_sess_fromsid(). See extensions/app_dea/README for the full writeup of this pitfall.
 */

#include "app_dea.h"
#include <pthread.h>
#include <time.h>

int dea_is_internal_realm(uint8_t * realm, size_t realmlen)
{
	struct fd_list * li;

	if (!realm || !realmlen)
		return 0;

	for (li = dea_conf->internal_realms.next; li != &dea_conf->internal_realms; li = li->next) {
		struct dea_realm * r = li->o;
		if (fd_os_almostcasesrch(realm, realmlen, r->name, r->len, NULL) == 0)
			return 1;
	}
	return 0;
}

/* Replace the value of the (already-parsed) Origin-Host AVP with the configured pseudonym,
 * saving the real value in the request's per-message data. */
static int mask_origin_host(struct msg * msg, struct fd_hook_permsgdata * pmd)
{
	struct avp * avp;
	struct avp_hdr * ahdr;
	os0_t masked;

	CHECK_FCT( fd_msg_search_avp(msg, dea_avp_origin_host, &avp) );
	if (!avp)
		return 0;

	CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
	if (!ahdr->avp_value)
		return 0;

	CHECK_MALLOC( pmd->orig_origin_host = os0dup(ahdr->avp_value->os.data, ahdr->avp_value->os.len) );
	pmd->orig_origin_host_len = ahdr->avp_value->os.len;

	/* The AVP already has a value set, so fd_msg_avp_setvalue (which requires a NULL
	 * avp_value) cannot be used here. We mutate the octet-string buffer directly instead,
	 * as documented for struct avp_hdr in libfdproto.h ("if the AVP is an OctetString, and
	 * you change the value of the pointer avp_value->os.data, then you must call free() on
	 * the previous value, and the new one must be free()-able"). */
	CHECK_MALLOC( masked = os0dup(dea_conf->hidden_id, dea_conf->hidden_id_len) );
	free(ahdr->avp_value->os.data);
	ahdr->avp_value->os.data = masked;
	ahdr->avp_value->os.len  = dea_conf->hidden_id_len;

	return 0;
}

/* Remove all Route-Record AVP instances (they were added by internal peers, including the one
 * the daemon just added for the peer that sent us this message) and, if we have a pseudonym
 * identity, add a single Route-Record carrying it, so that a message which later comes back
 * through us can still be attributed to "this DEA" without leaking any internal hop.
 *
 * Note: this intentionally trades away fine-grained loop detection (based on Route-Record)
 * for messages that leave and later re-enter the internal network through a different path.
 * Internal loop prevention is expected to be handled by the internal network itself -- see the
 * README for a discussion of this tradeoff. */
static int mask_route_records(struct msg * msg)
{
	struct avp * avp, * next;

	CHECK_FCT( fd_msg_browse(msg, MSG_BRW_FIRST_CHILD, &avp, NULL) );
	while (avp) {
		struct avp_hdr * ahdr;
		CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
		CHECK_FCT( fd_msg_browse(avp, MSG_BRW_NEXT, &next, NULL) );
		if ((ahdr->avp_code == AC_ROUTE_RECORD) && (ahdr->avp_vendor == 0)) {
			CHECK_FCT( fd_msg_free(avp) );
		}
		avp = next;
	}

	CHECK_FCT( fd_msg_source_setrr(msg, (DiamId_t)dea_conf->hidden_id, dea_conf->hidden_id_len, fd_g_config->cnf_dict) );

	return 0;
}

/* ---------------------------------------------------------------------- */
/* Phase 2: Session-Id pseudonymization                                   */
/* ---------------------------------------------------------------------- */

/* Serializes the whole "does a pairing already exist? if not, mint one" sequence below.
 * fd_sess_state_retrieve() is destructive (it detaches the state from the session -- see its doc
 * in libfdproto.h), so every call site below immediately fd_sess_state_store()s it back before
 * releasing this lock; without a lock spanning that retrieve+store round-trip, two threads
 * handling two messages of the same brand-new session concurrently could both see "no pairing"
 * and mint two different, inconsistent masked Session-Ids for the same real session. A single
 * global mutex is the simplest correct choice for this Phase 2 foundation (mirrors the
 * always-write-lock hot path pattern in extensions/rt_rewrite/rt_rewrite.c); it does serialize all
 * Session-Id rewriting across all sessions, which is a scalability limit to revisit if profiling
 * ever shows contention here (see extensions/app_dea/README, Phase 4). */
static pthread_mutex_t dea_sid_lock = PTHREAD_MUTEX_INITIALIZER;

/* Generate an RFC 6733 SS8.8-style Session-Id ("<hidden_identity>;<high32>;<low32>"), mirroring
 * fd_sess_new()'s own algorithm, without using fd_sess_new() -- see the file header comment for
 * why. `*out` is malloc'd (os0dup'd) and must be freed by the caller. */
static int gen_masked_sid(os0_t * out, size_t * outlen)
{
	static pthread_mutex_t ctr_lock = PTHREAD_MUTEX_INITIALIZER;
	static int seeded = 0;
	static uint32_t hi, lo;
	char buf[512];
	int len;

	CHECK_FCT( pthread_mutex_lock(&ctr_lock) );
	if (!seeded) {
		hi = (uint32_t) time(NULL);
		lo = 0;
		seeded = 1;
	}
	lo++;
	if (lo == 0)
		hi++; /* wrap of the low part, mirror fd_sess_new()'s counter behavior */
	len = snprintf(buf, sizeof(buf), "%s;%u;%u", (char *)dea_conf->hidden_id, hi, lo);
	CHECK_FCT( pthread_mutex_unlock(&ctr_lock) );

	if ((len <= 0) || ((size_t)len >= sizeof(buf)))
		return EINVAL;

	CHECK_MALLOC( *out = os0dup((os0_t)buf, (size_t)len) );
	*outlen = (size_t)len;
	return 0;
}

/* Replace the value of the (already-parsed) Session-Id AVP of `msg` with sid/sidlen, using the
 * same in-place octet-string mutation as mask_origin_host() above. */
static int rewrite_session_id_avp(struct msg * msg, os0_t sid, size_t sidlen)
{
	struct avp * avp;
	struct avp_hdr * ahdr;
	os0_t copy;

	CHECK_FCT( fd_msg_search_avp(msg, dea_avp_session_id, &avp) );
	if (!avp)
		return 0;

	CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
	if (!ahdr->avp_value)
		return 0;

	CHECK_MALLOC( copy = os0dup(sid, sidlen) );
	free(ahdr->avp_value->os.data);
	ahdr->avp_value->os.data = copy;
	ahdr->avp_value->os.len  = sidlen;

	return 0;
}

/* Refresh the expiry of both sides of a pairing to the same timestamp, so they expire together
 * (see extensions/app_dea/README for why this is preferred over cross-destroying them from the
 * cleanup callback). Best-effort: a failure here only means the mapping might outlive
 * session_id_lifetime slightly, never a functional error, so it is logged and swallowed. */
static void refresh_pairing_timeout(struct session * a, struct session * b)
{
	struct timespec exp;

	clock_gettime(CLOCK_REALTIME, &exp);
	exp.tv_sec += (time_t) dea_conf->session_id_lifetime;

	CHECK_FCT_DO( fd_sess_settimeout(a, &exp), TRACE_DEBUG(INFO, "app_dea: fd_sess_settimeout failed") );
	CHECK_FCT_DO( fd_sess_settimeout(b, &exp), TRACE_DEBUG(INFO, "app_dea: fd_sess_settimeout failed") );
}

/* Mint a brand new masked pairing for `sess` (the real session of the message currently being
 * forwarded) and rewrite the message's Session-Id AVP to the masked value. Called with
 * dea_sid_lock already held. */
static int mint_session_pairing(struct msg * msg, struct session * sess)
{
	os0_t real_sid = NULL, masked_sid = NULL;
	size_t real_sidlen = 0, masked_sidlen = 0;
	struct session * masked_sess = NULL;
	struct sess_state * real_st = NULL, * masked_st = NULL;
	int isnew, ret = 0;

	CHECK_FCT( fd_sess_getsid(sess, &real_sid, &real_sidlen) );

	ret = gen_masked_sid(&masked_sid, &masked_sidlen);
	if (ret != 0)
		return ret;

	CHECK_FCT_DO( fd_sess_fromsid(masked_sid, masked_sidlen, &masked_sess, &isnew), { ret = __ret__; goto out; } );

	CHECK_MALLOC_DO( real_st = malloc(sizeof(struct sess_state)), { ret = ENOMEM; goto out; } );
	memset(real_st, 0, sizeof(struct sess_state));
	CHECK_MALLOC_DO( real_st->peer_sid = os0dup(masked_sid, masked_sidlen), { ret = ENOMEM; goto out; } );
	real_st->peer_sid_len = masked_sidlen;

	CHECK_MALLOC_DO( masked_st = malloc(sizeof(struct sess_state)), { ret = ENOMEM; goto out; } );
	memset(masked_st, 0, sizeof(struct sess_state));
	CHECK_MALLOC_DO( masked_st->peer_sid = os0dup(real_sid, real_sidlen), { ret = ENOMEM; goto out; } );
	masked_st->peer_sid_len = real_sidlen;

	CHECK_FCT_DO( fd_sess_state_store(dea_sid_hdl, sess, &real_st), { ret = __ret__; goto out; } );
	real_st = NULL; /* ownership transferred to the session store */
	CHECK_FCT_DO( fd_sess_state_store(dea_sid_hdl, masked_sess, &masked_st), { ret = __ret__; goto out; } );
	masked_st = NULL; /* ownership transferred to the session store */

	refresh_pairing_timeout(sess, masked_sess);

	ret = rewrite_session_id_avp(msg, masked_sid, masked_sidlen);
	if (ret == 0)
		dea_stats_inc(DEA_STAT_SESSION_ID_MINTED);

	TRACE_DEBUG(FULL, "app_dea: minted a masked Session-Id pairing (real '%.*s' <-> masked '%.*s')",
		(int)real_sidlen, (char *)real_sid, (int)masked_sidlen, (char *)masked_sid);

out:
	if (real_st) { if (real_st->peer_sid) free(real_st->peer_sid); free(real_st); }
	if (masked_st) { if (masked_st->peer_sid) free(masked_st->peer_sid); free(masked_st); }
	if (masked_sid) free(masked_sid);
	return ret;
}

/* Phase 2 entry point: rewrite the Session-Id AVP of `msg` to the other side of an existing
 * pairing, or -- only when may_mint is set -- create a new pairing (masking the real Session-Id)
 * if this is the first message of this session that crosses the internal/external boundary.
 * See app_dea.h for the may_mint contract. */
int dea_rewrite_session_id(struct msg * msg, int may_mint)
{
	struct session * sess;
	int isnew, ret = 0;
	struct sess_state * st = NULL;

	CHECK_FCT( fd_msg_sess_get(fd_g_config->cnf_dict, msg, &sess, &isnew) );
	if (!sess)
		return 0; /* no Session-Id AVP in this message */

	CHECK_FCT( pthread_mutex_lock(&dea_sid_lock) );

	CHECK_FCT_DO( fd_sess_state_retrieve(dea_sid_hdl, sess, &st), { ret = __ret__; goto out; } );

	if (st) {
		/* Existing pairing: put the state back immediately (retrieve is destructive), then
		 * reuse it. */
		struct sess_state * put_back = st;
		CHECK_FCT_DO( fd_sess_state_store(dea_sid_hdl, sess, &put_back), { ret = __ret__; goto out; } );

		ret = rewrite_session_id_avp(msg, st->peer_sid, st->peer_sid_len);
		if (ret == 0)
			dea_stats_inc(DEA_STAT_SESSION_ID_REUSED);
		goto out;
	}

	if (!may_mint)
		goto out; /* no known pairing, and not allowed to create one here: leave untouched */

	ret = mint_session_pairing(msg, sess);

out:
	CHECK_FCT_DO( pthread_mutex_unlock(&dea_sid_lock), { if (!ret) ret = __ret__; } );
	return ret;
}

/* Forwarding callback for requests: mask topology when a request leaves an internal (trusted)
 * realm towards any other realm. */
int dea_fwd_req(void * cbdata, struct msg ** msg)
{
	struct avp * avp;
	struct avp_hdr * ahdr;
	int from_internal = 0, to_internal = 1; /* fail safe: do not mask unless proven internal -> external */
	struct fd_hook_permsgdata * pmd;

	TRACE_ENTRY("%p %p", cbdata, msg);
	CHECK_PARAMS(msg && *msg);

	dea_stats_inc(DEA_STAT_REQUESTS_SEEN);

	/* Determine from_internal/to_internal once: needed both by Phase 3's policy checks below
	 * (independent of whether topology hiding itself is configured) and by the masking logic
	 * further down. */
	CHECK_FCT( fd_msg_search_avp(*msg, dea_avp_origin_realm, &avp) );
	if (avp) {
		CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
		if (ahdr->avp_value)
			from_internal = dea_is_internal_realm(ahdr->avp_value->os.data, ahdr->avp_value->os.len);
	}

	CHECK_FCT( fd_msg_search_avp(*msg, dea_avp_destination_realm, &avp) );
	if (avp) {
		CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
		if (ahdr->avp_value)
			to_internal = dea_is_internal_realm(ahdr->avp_value->os.data, ahdr->avp_value->os.len);
	}

	/* Phase 3: interconnect policy & fraud detection apply to any request from an external
	 * peer, independent of whether Phase 1/2 topology hiding is configured below (an operator
	 * may want Phase 3's protections without hidden_id being set). */
	if (!from_internal) {
		int rejected;

		dea_stats_inc(DEA_STAT_EXTERNAL_REQUESTS);

		CHECK_FCT( dea_check_fraud(msg, &rejected) );
		if (rejected)
			return 0;

		CHECK_FCT( dea_check_interconnect(msg, &rejected) );
		if (rejected)
			return 0;
	}

	if (!dea_conf->hidden_id)
		return 0; /* topology hiding not configured */

	if (!from_internal || to_internal) {
		/* Not an internal -> external transition: leave Origin-Host/Route-Record untouched
		 * (Missing Origin-Realm/Destination-Realm AVPs fail safe to "do not mask"). Still
		 * attempt to un-mask Session-Id: this branch also covers a server-initiated request
		 * from an external partner (RAR/ASR) addressed back into the internal network using a
		 * Session-Id we previously masked -- may_mint=0, so this only ever reuses an existing
		 * pairing, never fabricates one for a session we did not ourselves mask on egress. */
		if (dea_conf->hide_session_id) {
			CHECK_FCT( dea_rewrite_session_id(*msg, 0) );
		}
		return 0;
	}

	pmd = fd_hook_get_pmd(dea_hook_hdl, *msg);
	if (!pmd) {
		TRACE_DEBUG(INFO, "app_dea: unable to get per-message data, message will not be topology-hidden");
		return 0;
	}
	pmd->masked = 1;
	dea_stats_inc(DEA_STAT_TOPOLOGY_MASKED);

	if (dea_conf->hide_origin_host) {
		CHECK_FCT( mask_origin_host(*msg, pmd) );
	}
	if (dea_conf->hide_route_record) {
		CHECK_FCT( mask_route_records(*msg) );
	}
	if (dea_conf->hide_session_id) {
		CHECK_FCT( dea_rewrite_session_id(*msg, 1) );
	}

	{
		/* Phase 2.5: best-effort, log-only. Never written back into the message -- see
		 * dea_pseudonym.c and extensions/app_dea/README for why the real value stays on
		 * the wire (the external partner needs it). */
		char * sub_token = NULL;
		if (dea_conf->pseudonymize_subscriber_id) {
			CHECK_FCT( dea_pseudonymize_subscriber_id(*msg, &sub_token) );
		}
		TRACE_DEBUG(FULL, "app_dea: topology-hid a request%s%s%s towards an external realm (real Origin-Host was '%.*s')",
			sub_token ? " for subscriber [" : "", sub_token ? sub_token : "", sub_token ? "]" : "",
			(int)pmd->orig_origin_host_len, pmd->orig_origin_host ? (char *)pmd->orig_origin_host : "");
		if (sub_token)
			free(sub_token);
	}

	return 0;
}

/* Forwarding callback for answers: rewrites Session-Id back to whichever side of a pairing the
 * answer's recipient expects (an answer to a masked internal->external request currently carries
 * the masked value and must show the real one to the internal peer; an answer to an unmasked
 * external->internal request currently carries the real value and must show the masked one to
 * the external partner -- dea_rewrite_session_id's "swap to the paired value" behavior handles
 * both uniformly, see its own comment). Also the anchor point correlating an answer with the
 * Origin-Host/Route-Record topology hiding applied to its request; nothing needs rewriting there
 * in Phase 1 -- the daemon routes the answer back using the Hop-by-Hop Id, not any AVP we rewrote
 * in the request -- but Phase 3 features (audit logging, fraud-detection correlation) hook in
 * here. See extensions/app_dea/README. */
int dea_fwd_ans(void * cbdata, struct msg ** msg)
{
	struct fd_hook_permsgdata * pmd;

	TRACE_ENTRY("%p %p", cbdata, msg);
	CHECK_PARAMS(msg && *msg);

	if (!dea_conf->hidden_id)
		return 0;

	if (dea_conf->hide_session_id) {
		CHECK_FCT( dea_rewrite_session_id(*msg, 0) );
	}

	pmd = fd_hook_get_request_pmd(dea_hook_hdl, *msg);
	if (!pmd || !pmd->masked)
		return 0;

	TRACE_DEBUG(FULL, "app_dea: answer received for a topology-hidden request (real Origin-Host was '%.*s')",
		(int)pmd->orig_origin_host_len, pmd->orig_origin_host ? (char *)pmd->orig_origin_host : "");

	return 0;
}
