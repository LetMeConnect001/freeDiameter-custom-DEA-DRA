/*
 * app_dea : Diameter Edge Agent extension for freeDiameter.
 * See app_dea.h and extensions/app_dea/README for the architecture.
 */

#include "app_dea.h"

struct fd_hook_data_hdl * dea_hook_hdl = NULL;
struct session_handler * dea_sid_hdl = NULL;

struct dict_object * dea_avp_origin_host = NULL;
struct dict_object * dea_avp_origin_realm = NULL;
struct dict_object * dea_avp_destination_realm = NULL;
struct dict_object * dea_avp_route_record = NULL;
struct dict_object * dea_avp_session_id = NULL;
struct dict_object * dea_avp_user_name = NULL;
struct dict_object * dea_avp_subscription_id = NULL;
struct dict_object * dea_avp_subscription_id_type = NULL;
struct dict_object * dea_avp_subscription_id_data = NULL;

static struct fd_rt_fwd_hdl * dea_fwd_req_hdl = NULL;
static struct fd_rt_fwd_hdl * dea_fwd_ans_hdl = NULL;

static void dea_pmd_init(struct fd_hook_permsgdata * pmd)
{
	memset(pmd, 0, sizeof(struct fd_hook_permsgdata));
}

static void dea_pmd_fini(struct fd_hook_permsgdata * pmd)
{
	if (pmd->orig_origin_host) {
		free(pmd->orig_origin_host);
		pmd->orig_origin_host = NULL;
	}
}

/* Phase 2: called by the framework when a session (real or masked side of a Session-Id
 * pairing) is destroyed (timeout or explicit fd_sess_destroy). Must free the state -- see
 * fd_sess_handler_create doc. Does NOT try to destroy the paired session: both sides are kept
 * synchronized by refreshing the same fd_sess_settimeout value on every reuse instead (see
 * dea_rewrite_session_id in dea_hiding.c and extensions/app_dea/README), which avoids any
 * re-entrant fd_sess_destroy call from within this callback. */
void dea_sid_cleanup(struct sess_state * st, os0_t sid, void * opaque)
{
	(void)sid;
	(void)opaque;

	if (!st)
		return;
	if (st->peer_sid)
		free(st->peer_sid);
	free(st);
}

/* entry point */
static int dea_entry(char * conffile)
{
	TRACE_ENTRY("%p", conffile);

	/* Parse the configuration file */
	CHECK_FCT( dea_conf_handle(conffile) );

	/* Resolve the dictionary objects we use */
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Host", &dea_avp_origin_host, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Origin-Realm", &dea_avp_origin_realm, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Destination-Realm", &dea_avp_destination_realm, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Route-Record", &dea_avp_route_record, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Session-Id", &dea_avp_session_id, ENOENT) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "User-Name", &dea_avp_user_name, ENOENT) );

	/* Phase 2.5: these come from RFC 4006 (dict_dcca), which may not be loaded -- resolve them
	 * best-effort (retval=0: leaves the pointer NULL instead of failing extension load). */
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id", &dea_avp_subscription_id, 0) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id-Type", &dea_avp_subscription_id_type, 0) );
	CHECK_FCT( fd_dict_search( fd_g_config->cnf_dict, DICT_AVP, AVP_BY_NAME, "Subscription-Id-Data", &dea_avp_subscription_id_data, 0) );
	if (dea_conf->pseudonymize_subscriber_id && !dea_avp_subscription_id) {
		fd_log_notice("app_dea: pseudonymize_subscriber_id is enabled but the Subscription-Id AVP "
			"(RFC 4006) is not in the dictionary -- load the dict_dcca extension before app_dea "
			"if you need IMSI pseudonymization; falling back to User-Name only for now.");
	}

	/* Reserve a per-message data slot to carry the real identity of a topology-hidden
	 * request over to its matching answer (see dea_hiding.c) */
	CHECK_FCT( fd_hook_data_register( sizeof(struct fd_hook_permsgdata), dea_pmd_init, dea_pmd_fini, &dea_hook_hdl ) );

	/* Phase 2: reserve a session-scoped data slot for the Session-Id pairing (survives across
	 * the whole session, unlike the per-transaction hook data above). fd_sess_start() is already
	 * running by the time extensions load (started from libfdcore's core.c), so no need to call it. */
	CHECK_FCT( fd_sess_handler_create( &dea_sid_hdl, dea_sid_cleanup, NULL, NULL ) );

	/* Register the topology hiding callbacks: mask on the way out, anchor point for
	 * Phase 2 processing on the way back in (see dea_fwd_ans in dea_hiding.c) */
	CHECK_FCT( fd_rt_fwd_register( dea_fwd_req, NULL, RT_FWD_REQ, &dea_fwd_req_hdl ) );
	CHECK_FCT( fd_rt_fwd_register( dea_fwd_ans, NULL, RT_FWD_ANS, &dea_fwd_ans_hdl ) );

	/* Phase 4: start the operational counters dump (periodic thread + SIGUSR2 handler) */
	CHECK_FCT( dea_stats_init() );

	fd_log_notice("app_dea: extension loaded (identity='%s', hide_origin_host=%s, hide_route_record=%s, hide_session_id=%s, pseudonymize_subscriber_id=%s, fraud_check_realm_consistency=%s)",
		dea_conf->hidden_id ? (char *)dea_conf->hidden_id : "(not set)",
		dea_conf->hide_origin_host ? "on" : "off",
		dea_conf->hide_route_record ? "on" : "off",
		dea_conf->hide_session_id ? "on" : "off",
		dea_conf->pseudonymize_subscriber_id ? "on" : "off",
		dea_conf->fraud_check_realm_consistency ? "on" : "off");

	return 0;
}

/* Unload */
void fd_ext_fini(void)
{
	TRACE_ENTRY();

	dea_stats_fini();

	if (dea_fwd_req_hdl) {
		CHECK_FCT_DO( fd_rt_fwd_unregister(dea_fwd_req_hdl, NULL), );
	}
	if (dea_fwd_ans_hdl) {
		CHECK_FCT_DO( fd_rt_fwd_unregister(dea_fwd_ans_hdl, NULL), );
	}

	if (dea_sid_hdl) {
		CHECK_FCT_DO( fd_sess_handler_destroy(&dea_sid_hdl, NULL), );
	}

	/* Destroy the internal realms list */
	while (!FD_IS_LIST_EMPTY(&dea_conf->internal_realms)) {
		struct dea_realm * r = dea_conf->internal_realms.next->o;
		fd_list_unlink(&r->chain);
		free(r->name);
		free(r);
	}

	/* Destroy the interconnect rules list */
	while (!FD_IS_LIST_EMPTY(&dea_conf->interconnect_rules)) {
		struct dea_interconnect_rule * r = dea_conf->interconnect_rules.next->o;
		fd_list_unlink(&r->chain);
		while (!FD_IS_LIST_EMPTY(&r->allowed_apps)) {
			struct dea_app_id * a = r->allowed_apps.next->o;
			fd_list_unlink(&a->chain);
			free(a);
		}
		free(r->realm);
		free(r);
	}

	if (dea_conf->hidden_id) {
		free(dea_conf->hidden_id);
		dea_conf->hidden_id = NULL;
	}

	return;
}

EXTENSION_ENTRY("app_dea", dea_entry);
