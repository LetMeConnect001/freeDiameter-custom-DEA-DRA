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
 */

#include "app_dea.h"

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

	if (!dea_conf->hidden_id)
		return 0; /* topology hiding not configured */

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

	if (!from_internal || to_internal) {
		/* Not an internal -> external transition: leave the message untouched.
		 * (Missing Origin-Realm/Destination-Realm AVPs fail safe to "do not mask".) */
		return 0;
	}

	pmd = fd_hook_get_pmd(dea_hook_hdl, *msg);
	if (!pmd) {
		TRACE_DEBUG(INFO, "app_dea: unable to get per-message data, message will not be topology-hidden");
		return 0;
	}
	pmd->masked = 1;

	if (dea_conf->hide_origin_host) {
		CHECK_FCT( mask_origin_host(*msg, pmd) );
	}
	if (dea_conf->hide_route_record) {
		CHECK_FCT( mask_route_records(*msg) );
	}

	TRACE_DEBUG(FULL, "app_dea: topology-hid a request towards an external realm (real Origin-Host was '%.*s')",
		(int)pmd->orig_origin_host_len, pmd->orig_origin_host ? (char *)pmd->orig_origin_host : "");

	return 0;
}

/* Forwarding callback for answers: anchor point correlating an answer with the topology hiding
 * applied to its request. Nothing needs rewriting in the answer itself in Phase 1 -- the daemon
 * routes it back to the originating internal peer using the Hop-by-Hop Id, not any AVP we
 * rewrote in the request -- but Phase 2 features (audit logging, fraud-detection correlation,
 * restoring identifiers for internal applications) hook in here. See extensions/app_dea/README. */
int dea_fwd_ans(void * cbdata, struct msg ** msg)
{
	struct fd_hook_permsgdata * pmd;

	TRACE_ENTRY("%p %p", cbdata, msg);
	CHECK_PARAMS(msg && *msg);

	if (!dea_conf->hidden_id)
		return 0;

	pmd = fd_hook_get_request_pmd(dea_hook_hdl, *msg);
	if (!pmd || !pmd->masked)
		return 0;

	TRACE_DEBUG(FULL, "app_dea: answer received for a topology-hidden request (real Origin-Host was '%.*s')",
		(int)pmd->orig_origin_host_len, pmd->orig_origin_host ? (char *)pmd->orig_origin_host : "");

	return 0;
}
