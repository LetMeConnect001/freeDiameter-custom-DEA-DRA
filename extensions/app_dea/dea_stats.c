/*
 * app_dea : Phase 4 -- privacy-aware operational counters.
 *
 * Every counter here is a bare integer count of an event category (e.g. "how many requests were
 * topology-hidden"), never a per-message value or any AVP content -- safe to expose to any log
 * level, dashboard, or metrics pipeline without re-introducing the leakage Phase 1/2/2.5 were
 * built to prevent. If a future metric needs to break counts down by realm or peer, that
 * breakdown must itself stay at the granularity of "which configured internal_realm /
 * interconnect_realm", never the raw AVP value taken from a message.
 *
 * Follows the same periodic-thread + signal-triggered dump pattern as the dbg_monitor extension
 * (see extensions/dbg_monitor/dbg_monitor.c): a background thread dumps counters every
 * `stats_interval` seconds (config, default 300s; 0 disables the periodic dump -- the
 * signal-triggered one below still works), and sending SIGUSR2 to the daemon triggers an
 * immediate dump. SIGUSR2 is the same signal dbg_monitor uses for its own status dump; multiple
 * extensions independently registering the same signal is an established pattern in this
 * codebase (fd_event_trig_regcb takes a module name precisely to support this -- SIGUSR1 alone
 * is already shared by six other extensions), so if both dbg_monitor and app_dea are loaded, one
 * SIGUSR2 triggers both dumps.
 */

#include "app_dea.h"
#include <signal.h>

#ifndef DEA_STATS_SIGNAL
#define DEA_STATS_SIGNAL SIGUSR2
#endif

static const char * const dea_stat_names[DEA_STAT_COUNT] = {
	[DEA_STAT_REQUESTS_SEEN]			= "requests_seen",
	[DEA_STAT_EXTERNAL_REQUESTS]			= "external_requests",
	[DEA_STAT_TOPOLOGY_MASKED]			= "topology_masked",
	[DEA_STAT_SESSION_ID_MINTED]			= "session_id_minted",
	[DEA_STAT_SESSION_ID_REUSED]			= "session_id_reused",
	[DEA_STAT_SUBSCRIBER_PSEUDONYMIZED]		= "subscriber_pseudonymized",
	[DEA_STAT_INTERCONNECT_ALLOWED]		= "interconnect_allowed",
	[DEA_STAT_INTERCONNECT_REJECTED_NO_RULE]	= "interconnect_rejected_no_rule",
	[DEA_STAT_INTERCONNECT_REJECTED_APP]		= "interconnect_rejected_app",
	[DEA_STAT_FRAUD_MISMATCH_DETECTED]		= "fraud_mismatch_detected",
	[DEA_STAT_FRAUD_REJECTED]			= "fraud_rejected",
};

static pthread_mutex_t dea_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t dea_stats_counters[DEA_STAT_COUNT];

static pthread_t dea_stats_thr = (pthread_t)NULL;

void dea_stats_inc(enum dea_stat_id id)
{
	if (((int)id < 0) || (id >= DEA_STAT_COUNT))
		return;

	CHECK_POSIX_DO( pthread_mutex_lock(&dea_stats_lock), return );
	dea_stats_counters[id]++;
	CHECK_POSIX_DO( pthread_mutex_unlock(&dea_stats_lock), );
}

void dea_stats_dump(void)
{
	uint64_t snapshot[DEA_STAT_COUNT];
	int i;

	CHECK_POSIX_DO( pthread_mutex_lock(&dea_stats_lock), return );
	memcpy(snapshot, dea_stats_counters, sizeof(snapshot));
	CHECK_POSIX_DO( pthread_mutex_unlock(&dea_stats_lock), );

	fd_log_notice("app_dea: --- operational counters ---");
	for (i = 0; i < DEA_STAT_COUNT; i++) {
		fd_log_notice("app_dea:   %-32s %llu", dea_stat_names[i], (unsigned long long) snapshot[i]);
	}
	fd_log_notice("app_dea: --- end of counters ---");
}

/* SIGUSR2 handler, see fd_event_trig_regcb */
static void dea_stats_sig(void)
{
	dea_stats_dump();
}

static void * dea_stats_thr_fct(void * arg)
{
	(void)arg;

	fd_log_threadname("app_dea/stats");

	while (1) {
		sleep(dea_conf->stats_interval);
		dea_stats_dump();
	}

	return NULL;
}

int dea_stats_init(void)
{
	CHECK_FCT( fd_event_trig_regcb(DEA_STATS_SIGNAL, "app_dea", dea_stats_sig) );

	if (dea_conf->stats_interval > 0) {
		CHECK_POSIX( pthread_create(&dea_stats_thr, NULL, dea_stats_thr_fct, NULL) );
	}

	return 0;
}

void dea_stats_fini(void)
{
	if (dea_stats_thr) {
		CHECK_FCT_DO( fd_thr_term(&dea_stats_thr), );
	}
}
