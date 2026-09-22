/*
 * app_dea : Diameter Edge Agent extension for freeDiameter.
 * See app_dea.h and extensions/app_dea/README for the architecture.
 */

#include "app_dea.h"

struct fd_hook_data_hdl * dea_hook_hdl = NULL;

struct dict_object * dea_avp_origin_host = NULL;
struct dict_object * dea_avp_origin_realm = NULL;
struct dict_object * dea_avp_destination_realm = NULL;
struct dict_object * dea_avp_route_record = NULL;

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

	/* Reserve a per-message data slot to carry the real identity of a topology-hidden
	 * request over to its matching answer (see dea_hiding.c) */
	CHECK_FCT( fd_hook_data_register( sizeof(struct fd_hook_permsgdata), dea_pmd_init, dea_pmd_fini, &dea_hook_hdl ) );

	/* Register the topology hiding callbacks: mask on the way out, anchor point for
	 * Phase 2 processing on the way back in (see dea_fwd_ans in dea_hiding.c) */
	CHECK_FCT( fd_rt_fwd_register( dea_fwd_req, NULL, RT_FWD_REQ, &dea_fwd_req_hdl ) );
	CHECK_FCT( fd_rt_fwd_register( dea_fwd_ans, NULL, RT_FWD_ANS, &dea_fwd_ans_hdl ) );

	fd_log_notice("app_dea: extension loaded (identity='%s', hide_origin_host=%s, hide_route_record=%s)",
		dea_conf->hidden_id ? (char *)dea_conf->hidden_id : "(not set)",
		dea_conf->hide_origin_host ? "on" : "off",
		dea_conf->hide_route_record ? "on" : "off");

	return 0;
}

/* Unload */
void fd_ext_fini(void)
{
	TRACE_ENTRY();

	if (dea_fwd_req_hdl) {
		CHECK_FCT_DO( fd_rt_fwd_unregister(dea_fwd_req_hdl, NULL), );
	}
	if (dea_fwd_ans_hdl) {
		CHECK_FCT_DO( fd_rt_fwd_unregister(dea_fwd_ans_hdl, NULL), );
	}

	/* Destroy the internal realms list */
	while (!FD_IS_LIST_EMPTY(&dea_conf->internal_realms)) {
		struct dea_realm * r = dea_conf->internal_realms.next->o;
		fd_list_unlink(&r->chain);
		free(r->name);
		free(r);
	}
	if (dea_conf->hidden_id) {
		free(dea_conf->hidden_id);
		dea_conf->hidden_id = NULL;
	}

	return;
}

EXTENSION_ENTRY("app_dea", dea_entry);
