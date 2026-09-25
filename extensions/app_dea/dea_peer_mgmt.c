/*
 * app_dea : Phase 4 -- peer visibility (discovery) and live peer add.
 *
 * Two independent, opt-in mechanisms, both disabled unless their config file path is set:
 *
 * 1. DISCOVERY: fd_peer_validate_register() fires for every CER received from a peer not
 *    already in fd_g_peers, BEFORE the daemon decides whether to accept it (libfdcore.h:
 *    "This callback is called when a new connection is being established from an unknown peer,
 *    after the CER is received."). We record the candidate (Diameter-Id, Realm) and ALWAYS set
 *    *auth = 0 ("unknown" -- defer to the daemon's own default). This changes NOTHING about
 *    whether the connection is accepted: freeDiameter's documented default ("reject unknown
 *    connections", libfdcore.h:456) still applies exactly as without this extension loaded. We
 *    are purely observing traffic that is already being rejected, not authorizing anything.
 *
 * 2. LIVE PEER ADD: on SIGUSR2 (shared with dea_stats.c's own SIGUSR2 handler -- see that file's
 *    module comment for why registering the same signal from multiple independent handlers in
 *    this codebase is an established, safe pattern), if pending_peer_add_file exists, each line
 *    is parsed and turned into a fd_peer_add() call -- the exact same runtime API freeDiameter's
 *    own ConnectPeer config-parsing path uses internally (confirmed: fd_peer_add's orig_dbg
 *    parameter doc lists "conf" as one of several call sites, i.e. config parsing is just one
 *    caller among others; the API is genuinely meant for runtime use). The peer connects without
 *    restarting freeDiameterd. The file is deleted after processing (successfully added or not:
 *    a permanently-broken pending line would otherwise re-fail forever on every SIGUSR2).
 *
 * Pending-add file format: one peer per line, semicolon-separated key=value pairs (deliberately
 * NOT JSON: this file is written by the webui's Python backend and read here in C, so the
 * simplest format both sides can produce/parse without a JSON library was chosen). Example:
 *   diamid=hss1.epc.mnc001.mcc999.3gppnetwork.org;connect_to=10.0.0.5,10.0.0.6;port=3868;realm=epc.mnc001.mcc999.3gppnetwork.org;no_tls=1;tc_timer=30
 * Recognized keys: diamid (required), connect_to (comma-separated IPs/hostnames), port, realm,
 * tc_timer, tw_timer, tls_prio, no_tls, prefer_tcp, no_tcp, no_sctp, no_ip, no_ipv6,
 * tls_old_method (booleans: key=1 to set, absent = unset).
 */

#include "app_dea.h"
#include <netdb.h>
#include <sys/socket.h>

/* Upper bound on any single identity/realm/hostname string this file will ever store or parse,
 * matching this codebase's own convention (libfdproto.h: "#define HOST_NAME_MAX 512"). Applied
 * both to CER-derived data in the discovery path (untrusted network input, from any peer that
 * can reach our listening port, BEFORE authentication) and to pending-add file fields (trusted
 * source -- our own webui -- but bounded anyway as defense in depth, not a single point of
 * failure). Diameter AVPs can in principle carry up to ~16MB of data (24-bit length field); none
 * of that is a valid hostname, so refusing anything past a sane bound is correct, not just safe. */
#define DEA_MAX_IDLEN HOST_NAME_MAX

/* ---------------------------------------------------------------------- */
/* Discovery                                                              */
/* ---------------------------------------------------------------------- */

struct dea_candidate {
	struct fd_list	chain;
	os0_t		diamid;
	size_t		diamidlen;
	os0_t		realm;		/* may be NULL if the CER did not carry one */
	size_t		realmlen;
	time_t		first_seen;
	time_t		last_seen;
	uint32_t	attempts;
};

static pthread_mutex_t dea_candidates_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fd_list dea_candidates = FD_LIST_INITIALIZER(dea_candidates);

/* Cap the candidate list so a flood of CERs from many distinct unknown identities cannot grow
 * this list without bound; oldest-seen entries are evicted first. Generous for any realistic
 * interconnect (a handful to a few dozen real candidate peers), well short of memory pressure. */
#define DEA_MAX_CANDIDATES 256

static void write_discovered_peers_locked(void)
{
	struct fd_list * li;
	FILE * f;
	os0_t tmp_path;
	size_t pathlen;
	int first = 1;

	if (!dea_conf->discovered_peers_file)
		return;

	pathlen = strlen((char *)dea_conf->discovered_peers_file);
	CHECK_MALLOC_DO( tmp_path = malloc(pathlen + 5), return ); /* + ".tmp\0" */
	memcpy(tmp_path, dea_conf->discovered_peers_file, pathlen);
	memcpy(tmp_path + pathlen, ".tmp", 5);

	f = fopen((char *)tmp_path, "w");
	if (!f) {
		TRACE_DEBUG(INFO, "app_dea: unable to open '%s' for writing discovered peers", tmp_path);
		free(tmp_path);
		return;
	}

	fprintf(f, "[\n");
	for (li = dea_candidates.next; li != &dea_candidates; li = li->next) {
		struct dea_candidate * c = li->o;
		fprintf(f, "%s  {\"diameter_id\": \"%.*s\", \"realm\": \"%.*s\", \"first_seen\": %lld, \"last_seen\": %lld, \"attempts\": %u}",
			first ? "" : ",\n",
			(int)c->diamidlen, (char *)c->diamid,
			(int)c->realmlen, c->realm ? (char *)c->realm : "",
			(long long)c->first_seen, (long long)c->last_seen, c->attempts);
		first = 0;
	}
	fprintf(f, "%s]\n", first ? "" : "\n");

	fclose(f);
	rename((char *)tmp_path, (char *)dea_conf->discovered_peers_file);
	free(tmp_path);
}

/* fd_peer_validate_register callback: see file header. Never changes *auth away from 0. */
static int dea_peer_discover_cb(struct peer_info * info, int * auth, int (**cb2)(struct peer_info *))
{
	struct fd_list * li;
	struct dea_candidate * found = NULL;
	time_t now = time(NULL);

	(void)cb2;
	*auth = 0; /* always defer to the daemon's own default (reject unknown) */

	if (!dea_conf->discovered_peers_file)
		return 0; /* discovery disabled: observe nothing, still defer decision */

	if (!info->pi_diamid || !info->pi_diamidlen)
		return 0;

	/* Defensive bound on attacker-controlled input: this callback runs for CER from ANY host
	 * that can reach our listening port, before any authentication. Refuse to store (but do
	 * NOT change *auth, and do NOT error out -- just silently skip recording) anything that
	 * does not look like a real, sane Diameter Identity / Realm. */
	if ((info->pi_diamidlen > DEA_MAX_IDLEN)
		|| (info->runtime.pir_realm && (info->runtime.pir_realmlen > DEA_MAX_IDLEN))
		|| !fd_os_is_valid_DiameterIdentity((uint8_t *)info->pi_diamid, info->pi_diamidlen)) {
		TRACE_DEBUG(INFO, "app_dea: ignoring CER from a peer with an oversized or invalid "
			"Origin-Host/Origin-Realm (diamidlen=%zu) -- not recorded as a discovery candidate",
			info->pi_diamidlen);
		return 0;
	}

	CHECK_POSIX( pthread_mutex_lock(&dea_candidates_lock) );

	for (li = dea_candidates.next; li != &dea_candidates; li = li->next) {
		struct dea_candidate * c = li->o;
		if (fd_os_cmp(c->diamid, c->diamidlen, info->pi_diamid, info->pi_diamidlen) == 0) {
			found = c;
			break;
		}
	}

	if (found) {
		found->last_seen = now;
		found->attempts++;
	} else {
		struct dea_candidate * c;
		int count = 0;

		for (li = dea_candidates.next; li != &dea_candidates; li = li->next)
			count++;

		if (count >= DEA_MAX_CANDIDATES) {
			/* Evict the oldest (list is append-ordered, so the head is the oldest). */
			struct dea_candidate * oldest = dea_candidates.next->o;
			fd_list_unlink(&oldest->chain);
			free(oldest->diamid);
			if (oldest->realm)
				free(oldest->realm);
			free(oldest);
		}

		CHECK_MALLOC_DO( c = malloc(sizeof(struct dea_candidate)),
			{ pthread_mutex_unlock(&dea_candidates_lock); return 0; } );
		memset(c, 0, sizeof(struct dea_candidate));
		fd_list_init(&c->chain, c);

		c->diamid = os0dup(info->pi_diamid, info->pi_diamidlen);
		c->diamidlen = info->pi_diamidlen;
		if (info->runtime.pir_realm) {
			c->realm = os0dup((os0_t)info->runtime.pir_realm, info->runtime.pir_realmlen);
			c->realmlen = info->runtime.pir_realmlen;
		}
		c->first_seen = now;
		c->last_seen = now;
		c->attempts = 1;

		fd_list_insert_before(&dea_candidates, &c->chain);

		fd_log_notice("app_dea: discovered candidate peer '%.*s' (realm '%.*s') -- not configured, "
			"see %s to add it",
			(int)c->diamidlen, (char *)c->diamid,
			(int)c->realmlen, c->realm ? (char *)c->realm : "",
			(char *)dea_conf->discovered_peers_file);
	}

	write_discovered_peers_locked();

	CHECK_POSIX_DO( pthread_mutex_unlock(&dea_candidates_lock), );

	return 0;
}

/* ---------------------------------------------------------------------- */
/* Live peer add                                                          */
/* ---------------------------------------------------------------------- */

struct dea_pending_peer {
	char *	diamid;
	char *	connect_to;	/* comma-separated, not yet split */
	int	port;
	char *	realm;
	int	tc_timer;
	int	tw_timer;
	char *	tls_prio;
	int	no_tls, prefer_tcp, no_tcp, no_sctp, no_ip, no_ipv6, tls_old_method;
};

static void free_pending(struct dea_pending_peer * p)
{
	free(p->diamid);
	free(p->connect_to);
	free(p->realm);
	free(p->tls_prio);
	memset(p, 0, sizeof(*p));
}

/* Reject a value that's absurdly long before it's ever strdup'd -- see DEA_MAX_IDLEN's comment.
 * connect_to holds a comma-separated LIST of hosts, so it gets a generous multiple instead of
 * the single-identity bound. */
static int value_too_long(const char * val, size_t max)
{
	return strnlen(val, max + 1) > max;
}

/* Parse one "key=value;key=value;..." line into *out. Returns 0 on success (out->diamid set and
 * within bounds), or -1 if the line has no diamid, or any field is oversized (malformed / bogus
 * / hostile line, silently skipped by the caller -- see dea_peer_mgmt_sig). */
static int parse_pending_line(char * line, struct dea_pending_peer * out)
{
	char * saveptr = NULL;
	char * tok;

	memset(out, 0, sizeof(*out));

	/* A whole line longer than this cannot contain anything valid anyway (worst case: one huge
	 * connect_to list); reject outright rather than parse a near-1KB line field by field. */
	if (strnlen(line, 8192) >= 8192)
		return -1;

	for (tok = strtok_r(line, ";", &saveptr); tok; tok = strtok_r(NULL, ";", &saveptr)) {
		char * eq = strchr(tok, '=');
		char * key, * val;
		if (!eq)
			continue;
		*eq = '\0';
		key = tok;
		val = eq + 1;

		if (!strcmp(key, "diamid")) {
			if (value_too_long(val, DEA_MAX_IDLEN)) return -1;
			free(out->diamid); out->diamid = strdup(val);
		}
		else if (!strcmp(key, "connect_to")) {
			if (value_too_long(val, DEA_MAX_IDLEN * 16)) return -1; /* several hosts, comma-separated */
			free(out->connect_to); out->connect_to = strdup(val);
		}
		else if (!strcmp(key, "port")) { out->port = atoi(val); }
		else if (!strcmp(key, "realm")) {
			if (value_too_long(val, DEA_MAX_IDLEN)) return -1;
			free(out->realm); out->realm = strdup(val);
		}
		else if (!strcmp(key, "tc_timer")) { out->tc_timer = atoi(val); }
		else if (!strcmp(key, "tw_timer")) { out->tw_timer = atoi(val); }
		else if (!strcmp(key, "tls_prio")) {
			if (value_too_long(val, 128)) return -1;
			free(out->tls_prio); out->tls_prio = strdup(val);
		}
		else if (!strcmp(key, "no_tls")) { out->no_tls = atoi(val); }
		else if (!strcmp(key, "prefer_tcp")) { out->prefer_tcp = atoi(val); }
		else if (!strcmp(key, "no_tcp")) { out->no_tcp = atoi(val); }
		else if (!strcmp(key, "no_sctp")) { out->no_sctp = atoi(val); }
		else if (!strcmp(key, "no_ip")) { out->no_ip = atoi(val); }
		else if (!strcmp(key, "no_ipv6")) { out->no_ipv6 = atoi(val); }
		else if (!strcmp(key, "tls_old_method")) { out->tls_old_method = atoi(val); }
	}

	if (!out->diamid)
		return -1;
	if (!fd_os_is_valid_DiameterIdentity((uint8_t *)out->diamid, strlen(out->diamid)))
		return -1;
	if (out->port < 0 || out->port > 65535)
		return -1;

	return 0;
}

/* Resolve one ConnectTo string (IP literal or hostname) and add it to eps via fd_ep_add_merge,
 * the same helper freeDiameter's own core uses to build endpoint lists (libfdcore.h). */
static void add_connect_to(struct fd_list * eps, const char * host)
{
	struct addrinfo hints, * res, * ai;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(host, NULL, &hints, &res);
	if (ret != 0) {
		TRACE_DEBUG(INFO, "app_dea: unable to resolve ConnectTo '%s': %s", host, gai_strerror(ret));
		return;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		CHECK_FCT_DO( fd_ep_add_merge(eps, (sSA *)ai->ai_addr, ai->ai_addrlen, EP_FL_CONF), );
	}

	freeaddrinfo(res);
}

static void add_one_peer(struct dea_pending_peer * p)
{
	struct peer_info info;
	int ret;

	memset(&info, 0, sizeof(info));

	info.pi_diamid = p->diamid;
	info.pi_diamidlen = strlen(p->diamid);

	info.config.pic_flags.pro3 = p->no_ip ? PI_P3_IPv6 : (p->no_ipv6 ? PI_P3_IP : PI_P3_DEFAULT);
	info.config.pic_flags.pro4 = p->no_sctp ? PI_P4_TCP : (p->no_tcp ? PI_P4_SCTP : PI_P4_DEFAULT);
	info.config.pic_flags.alg = p->prefer_tcp ? PI_ALGPREF_TCP : PI_ALGPREF_SCTP;
	info.config.pic_flags.sec = p->tls_old_method ? PI_SEC_TLS_OLD : (p->no_tls ? PI_SEC_NONE : PI_SEC_DEFAULT);

	if (p->realm)
		info.config.pic_realm = p->realm;
	if (p->port > 0)
		info.config.pic_port = (uint16_t)p->port;
	if (p->tc_timer > 0)
		info.config.pic_tctimer = p->tc_timer;
	if (p->tw_timer > 0)
		info.config.pic_twtimer = p->tw_timer;
	if (p->tls_prio)
		info.config.pic_priority = p->tls_prio;

	fd_list_init(&info.pi_endpoints, NULL);
	if (p->connect_to) {
		char * saveptr = NULL;
		char * tok;
		for (tok = strtok_r(p->connect_to, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
			while (*tok == ' ') tok++;
			if (*tok)
				add_connect_to(&info.pi_endpoints, tok);
		}
	}

	ret = fd_peer_add(&info, "app_dea live add", NULL, NULL);
	if (ret == 0) {
		fd_log_notice("app_dea: live-added peer '%s' (no restart)", p->diamid);
	} else if (ret == EEXIST) {
		fd_log_notice("app_dea: peer '%s' is already configured, ignoring live-add request", p->diamid);
	} else {
		fd_log_error("app_dea: fd_peer_add('%s') failed: %s", p->diamid, strerror(ret));
		/* fd_peer_add failed: pi_endpoints was NOT taken over by the core, free what we built. */
		while (!FD_IS_LIST_EMPTY(&info.pi_endpoints)) {
			struct fd_endpoint * ep = info.pi_endpoints.next->o;
			fd_list_unlink(&ep->chain);
			free(ep);
		}
	}
}

/* Must be large enough to hold the longest line parse_pending_line() is willing to accept
 * (connect_to alone is allowed up to DEA_MAX_IDLEN*16), plus room for every other field and the
 * "key=" overhead -- kept as one generous, explicit constant so the two stay in sync instead of
 * silently drifting apart. */
#define DEA_PENDING_LINE_MAX (DEA_MAX_IDLEN * 20)

void dea_peer_mgmt_sig(void)
{
	FILE * f;
	char * line;

	if (!dea_conf->pending_peer_add_file)
		return;

	f = fopen((char *)dea_conf->pending_peer_add_file, "r");
	if (!f)
		return; /* no pending file: nothing to do, not an error */

	CHECK_MALLOC_DO( line = malloc(DEA_PENDING_LINE_MAX), { fclose(f); return; } );

	while (fgets(line, DEA_PENDING_LINE_MAX, f)) {
		struct dea_pending_peer p;
		size_t len = strlen(line);

		if (len && line[len-1] == '\n') {
			line[len-1] = '\0';
			len--;
		} else if (!feof(f)) {
			/* The line didn't fit in the buffer and wasn't at EOF: it's longer than any
			 * legitimate entry we'd ever generate. Refuse it AND resynchronize by
			 * discarding the rest of that oversized line, instead of misparsing its
			 * remainder as if it were a fresh, unrelated line on the next iteration. */
			int c;
			TRACE_DEBUG(INFO, "app_dea: discarding an oversized pending-peer-add line (>%d bytes)", DEA_PENDING_LINE_MAX);
			do { c = fgetc(f); } while (c != '\n' && c != EOF);
			continue;
		}

		if (!line[0])
			continue;

		if (parse_pending_line(line, &p) == 0) {
			add_one_peer(&p);
		} else {
			TRACE_DEBUG(INFO, "app_dea: skipping malformed or oversized pending-peer-add line");
		}
		free_pending(&p);
	}

	free(line);
	fclose(f);
	remove((char *)dea_conf->pending_peer_add_file);
}

int dea_peer_mgmt_init(void)
{
	if (dea_conf->discovered_peers_file) {
		CHECK_FCT( fd_peer_validate_register(dea_peer_discover_cb) );
	}
	return 0;
}
